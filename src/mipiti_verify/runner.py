"""Orchestrator: pull pending assertions, verify, submit results."""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .client import MipitiClient
from .verifiers import get_verifier

console = Console(stderr=True)


class Runner:
    """Orchestrates the pull → verify → submit flow."""

    def __init__(
        self,
        client: MipitiClient,
        project_root: str = ".",
        tier2_provider: str | None = None,
        tier2_model: str | None = None,
        tier2_api_key: str | None = None,
        ollama_url: str = "http://localhost:11434",
        oidc_token: str | None = None,
        dry_run: bool = False,
        reverify: bool = False,
        verbose: bool = False,
    ) -> None:
        self.client = client
        self.project_root = Path(project_root).resolve()
        self.tier2_provider_name = tier2_provider
        self.tier2_model = tier2_model
        self.tier2_api_key = tier2_api_key
        self.ollama_url = ollama_url
        # Fetch attestation audience from backend
        _aud = ""
        try:
            _config = client.get_verification_config()
            _aud = _config.get("attestation_audience", "")
        except Exception:
            pass  # backend may not support this endpoint yet
        self.oidc_token = oidc_token or _auto_detect_oidc(_aud)
        self.dry_run = dry_run
        self.reverify = reverify
        self.verbose = verbose

    def run(self, model_id: str) -> dict[str, Any]:
        """Execute full verification pipeline. Returns summary report."""
        details: list[dict[str, Any]] = []

        # --- Tier 1 ---
        t1_results, t1_details = self._run_tier(model_id, tier=1)
        details.extend(t1_details)

        t1_run_id = ""
        if t1_results and not self.dry_run:
            resp = self.client.submit_results(
                model_id,
                pipeline=_pipeline_metadata(),
                results=t1_results,
                oidc_token=self.oidc_token,
            )
            t1_run_id = resp.get("run_id", "")

        # --- Tier 2 ---
        t2_results, t2_details = self._run_tier(model_id, tier=2)
        details.extend(t2_details)

        t2_run_id = ""
        if t2_results and not self.dry_run:
            resp = self.client.submit_results(
                model_id,
                pipeline=_pipeline_metadata(),
                results=t2_results,
                oidc_token=self.oidc_token,
            )
            t2_run_id = resp.get("run_id", "")

        # --- Sufficiency ---
        suff_results = self._run_sufficiency(model_id)

        return {
            "tier1_pass": sum(1 for r in t1_results if r["result"] == "pass"),
            "tier1_fail": sum(1 for r in t1_results if r["result"] == "fail"),
            "tier1_skip": sum(1 for r in t1_results if r["result"] == "skipped"),
            "tier2_pass": sum(1 for r in t2_results if r["result"] == "pass"),
            "tier2_fail": sum(1 for r in t2_results if r["result"] == "fail"),
            "tier2_skip": sum(1 for r in t2_results if r["result"] == "skipped"),
            "suff_sufficient": sum(1 for r in suff_results if r["result"] == "sufficient"),
            "suff_insufficient": sum(1 for r in suff_results if r["result"] == "insufficient"),
            "suff_skip": sum(1 for r in suff_results if r["result"] == "skipped"),
            "tier1_run_id": t1_run_id,
            "tier2_run_id": t2_run_id,
            "dry_run": self.dry_run,
            "details": details,
        }

    def _run_tier(
        self, model_id: str, tier: int
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Run verification for a single tier. Returns (api_results, detail_records)."""
        if self.reverify:
            pending = self.client.get_all_assertions(model_id)
        else:
            pending = self.client.get_pending(model_id, tier=tier)
        controls = pending.get("controls", {})
        if not controls:
            if self.verbose:
                console.print(f"  No tier {tier} assertions pending")
            return [], []

        total = sum(len(assertions) for assertions in controls.values())
        results: list[dict[str, Any]] = []
        details: list[dict[str, Any]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Tier {tier}: verifying {total} assertions", total=total)

            for _ctrl_id, assertions in controls.items():
                for assertion in assertions:
                    a_id = assertion["id"]
                    a_type = assertion["type"]

                    if tier == 1:
                        result = self._verify_tier1(assertion)
                    else:
                        result = self._verify_tier2(assertion)

                    results.append({
                        "assertion_id": a_id,
                        "tier": tier,
                        "result": result["status"],
                        "details": result["details"],
                        "reasoning": result.get("reasoning", ""),
                        "reviewer": result.get("reviewer", f"mipiti-verify:{a_type}"),
                    })
                    details.append({
                        "assertion_id": a_id,
                        "type": a_type,
                        "tier": tier,
                        "passed": result["status"] == "pass",
                        "details": result["details"],
                    })
                    progress.advance(task)

        return results, details

    def _verify_tier1(self, assertion: dict) -> dict[str, Any]:
        """Run Tier 1 mechanical verification."""
        a_type = assertion["type"]
        params = assertion.get("params", {})

        verifier = get_verifier(a_type)
        if verifier is None:
            return {"status": "skipped", "details": f"No verifier for type '{a_type}'"}

        try:
            result = verifier.verify(params, self.project_root)
            return {
                "status": "pass" if result.passed else "fail",
                "details": result.details,
            }
        except Exception as e:
            return {"status": "fail", "details": f"Verifier error: {e}"}

    def _verify_tier2(self, assertion: dict) -> dict[str, Any]:
        """Run Tier 2 semantic verification using AI provider."""
        tier2_prompt = assertion.get("tier2_prompt", "")
        if not tier2_prompt:
            return {"status": "skipped", "details": "No tier2_prompt provided"}

        if self.tier2_provider_name is None:
            return {"status": "skipped", "details": "No --tier2-provider specified"}

        # Read source file for context
        params = assertion.get("params", {})
        source_file = params.get("file", "")
        source_code = ""
        if source_file:
            fpath = self.project_root / source_file
            if fpath.is_file():
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    # For pattern_matches/pattern_absent, center context around
                    # the match rather than taking the file head — ensures the
                    # reviewer sees the relevant code even in large files.
                    pattern = params.get("pattern", "")
                    a_type = assertion.get("type", "")
                    if len(content) > 16000 and pattern and a_type in ("pattern_matches", "pattern_absent"):
                        import re
                        match = re.search(pattern, content)
                        if match:
                            center = match.start()
                            # Take ~8K chars before and after the match
                            start = max(0, center - 8000)
                            end = min(len(content), center + 8000)
                            prefix = "... (truncated)\n" if start > 0 else ""
                            suffix = "\n... (truncated)" if end < len(content) else ""
                            content = prefix + content[start:end] + suffix
                        else:
                            content = content[:16000] + "\n... (truncated)"
                    elif len(content) > 16000:
                        content = content[:16000] + "\n... (truncated)"
                    source_code = content
                except Exception:
                    pass

        try:
            from .tier2 import get_provider

            provider = get_provider(
                self.tier2_provider_name,
                model=self.tier2_model,
                api_key=self.tier2_api_key,
                ollama_url=self.ollama_url,
            )
            passed, reasoning = provider.evaluate(tier2_prompt, source_code)
            return {
                "status": "pass" if passed else "fail",
                "details": reasoning[:500],
                "reasoning": reasoning,
                "reviewer": f"ai:{self.tier2_provider_name}/{self.tier2_model or 'default'}",
            }
        except ImportError as e:
            return {"status": "skipped", "details": f"Provider not available: {e}"}
        except Exception as e:
            return {"status": "fail", "details": f"Tier 2 error: {e}"}

    def _run_sufficiency(self, model_id: str) -> list[dict[str, Any]]:
        """Run collective sufficiency evaluation for controls marked as evidence complete."""
        try:
            pending = self.client.get_pending_sufficiency(model_id)
        except Exception as e:
            if self.verbose:
                console.print(f"  Sufficiency API not available: {e}")
            return []

        controls = pending.get("controls", {})
        if not controls:
            if self.verbose:
                console.print("  No controls pending sufficiency evaluation")
            return []

        if self.tier2_provider_name is None:
            if self.verbose:
                console.print("  Skipping sufficiency: no --tier2-provider specified")
            return [{"control_id": cid, "result": "skipped", "details": "No provider"} for cid in controls]

        results: list[dict[str, Any]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Sufficiency: evaluating {len(controls)} controls", total=len(controls)
            )

            for ctrl_id, ctrl_data in controls.items():
                prompt = ctrl_data.get("sufficiency_prompt", "")
                if not prompt:
                    results.append({"control_id": ctrl_id, "result": "skipped", "details": "No prompt"})
                    progress.advance(task)
                    continue

                try:
                    from .tier2 import get_provider

                    provider = get_provider(
                        self.tier2_provider_name,
                        model=self.tier2_model,
                        api_key=self.tier2_api_key,
                        ollama_url=self.ollama_url,
                    )
                    # No source code for sufficiency — platform-side evaluation
                    # uses assertion descriptions + params, not actual source
                    passed, reasoning = provider.evaluate(prompt, "")
                    result = "sufficient" if passed else "insufficient"
                    results.append({
                        "control_id": ctrl_id,
                        "result": result,
                        "details": reasoning[:500],
                    })
                except Exception as e:
                    results.append({
                        "control_id": ctrl_id,
                        "result": "skipped",
                        "details": f"Error: {e}",
                    })
                progress.advance(task)

        # Submit results
        if results and not self.dry_run:
            submittable = [r for r in results if r["result"] in ("sufficient", "insufficient")]
            if submittable:
                try:
                    self.client.submit_sufficiency_results(
                        model_id,
                        pipeline=_pipeline_metadata(),
                        results=submittable,
                    )
                except Exception as e:
                    if self.verbose:
                        console.print(f"  Failed to submit sufficiency results: {e}")

        return results


def _auto_detect_oidc(audience: str = "") -> str:
    """Auto-detect OIDC token from CI environment."""
    # GitHub Actions
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if url and token:
        try:
            import httpx

            if audience:
                aud_url = f"{url}&audience={audience}" if "?" in url else f"{url}?audience={audience}"
            else:
                aud_url = url
            resp = httpx.get(aud_url, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            return resp.json().get("value", "")
        except Exception:
            pass

    # GitLab CI
    gl_token = os.environ.get("CI_JOB_JWT_V2", "")
    if gl_token:
        return gl_token

    return ""


def _pipeline_metadata() -> dict[str, str]:
    """Build pipeline metadata from environment."""
    # GitHub Actions
    if os.environ.get("GITHUB_ACTIONS"):
        return {
            "provider": "github_actions",
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_url": f"{os.environ.get('GITHUB_SERVER_URL', '')}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}",
            "commit_sha": os.environ.get("GITHUB_SHA", ""),
            "branch": os.environ.get("GITHUB_REF", ""),
        }

    # GitLab CI
    if os.environ.get("GITLAB_CI"):
        return {
            "provider": "gitlab_ci",
            "run_id": os.environ.get("CI_PIPELINE_ID", ""),
            "run_url": os.environ.get("CI_PIPELINE_URL", ""),
            "commit_sha": os.environ.get("CI_COMMIT_SHA", ""),
            "branch": os.environ.get("CI_COMMIT_REF_NAME", ""),
        }

    # Local / unknown
    return {
        "provider": "local",
        "run_id": "",
        "run_url": "",
        "commit_sha": "",
        "branch": "",
    }
