"""Orchestrator: pull pending assertions, verify, submit results."""

from __future__ import annotations

import hashlib
import json
import os
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .client import MipitiClient
from .sigstore_signer import sign_verification_statement
from .verifiers import get_verifier
from .workspace_key_signer import WorkspaceKeySigner

console = Console(stderr=True)


def compute_content_hash(
    all_assertions: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> str:
    """Compute SHA-256 hash of assertion content + verdicts.

    Binds what CI verified (assertion definitions) to what it concluded
    (pass/fail). The backend validates this hash at submission time to
    detect modifications between CI pull and result submission.
    """
    verdict_map = {r["assertion_id"]: r["result"] for r in results}
    records = []
    for a in all_assertions:
        aid = a.get("id", "")
        verdict = verdict_map.get(aid, "skipped")
        records.append({
            "assertion_id": aid,
            "type": a.get("type", ""),
            "params": a.get("params", {}),
            "description": a.get("description", ""),
            "verdict": verdict,
        })
    records.sort(key=lambda x: x["assertion_id"])
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


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
        sigstore_tuf_url: str | None = None,
        sigstore_trust_config_path: str | None = None,
        workspace_signing_key_path: str | None = None,
        signing_prefer: str = "sigstore",
        dry_run: bool = False,
        reverify: bool = True,
        verbose: bool = False,
        repo: str = "",
        changed_files: set[str] | None = None,
        concurrency: int = 1,
        component_id: str | None = None,
        auto_component_path: bool = True,
    ) -> None:
        self.client = client
        self.project_root = Path(project_root).resolve()
        self.repo = repo or _auto_detect_repo(self.project_root)
        self.component_id = component_id
        self.auto_component_path = auto_component_path
        self._component_path_resolved = False
        self.tier2_provider_name = tier2_provider
        self.tier2_model = tier2_model
        self.tier2_api_key = tier2_api_key
        self.ollama_url = ollama_url
        # The raw OIDC token is used only locally to mint a Sigstore bundle
        # (see _sign_with_sigstore); it is never transmitted to Mipiti. For
        # Sigstore signing, the token MUST have `aud=sigstore` — Fulcio
        # and sigstore-python's IdentityToken validator both require it.
        self.oidc_token = oidc_token or _auto_detect_oidc("sigstore")
        self.sigstore_tuf_url = sigstore_tuf_url or os.environ.get(
            "MIPITI_SIGSTORE_TUF_URL", ""
        ) or None
        self.sigstore_trust_config_path = sigstore_trust_config_path or os.environ.get(
            "MIPITI_SIGSTORE_TRUST_CONFIG", ""
        ) or None

        # Workspace-ECDSA fallback signer. Used when:
        #   (a) no OIDC token is available (Jenkins / Buildkite / self-managed
        #       GitLab without ID tokens), OR
        #   (b) the operator explicitly picks workspace-key over sigstore via
        #       ``signing_prefer="workspace"`` (e.g. policy / testing).
        # Auto-detected from MIPITI_WORKSPACE_SIGNING_KEY env var when the
        # CLI flag is omitted, mirroring the `oidc_token` auto-detect pattern.
        key_path = workspace_signing_key_path or os.environ.get(
            "MIPITI_WORKSPACE_SIGNING_KEY", ""
        ) or None
        self.workspace_signer: WorkspaceKeySigner | None = None
        if key_path:
            try:
                self.workspace_signer = WorkspaceKeySigner(key_path)
            except ValueError as e:
                # Bad key file is a hard error — surfacing it as silent fall-
                # through to "submit unsigned" would defeat the operator's
                # explicit signing intent.
                raise ValueError(f"--workspace-signing-key load failed: {e}") from e

        prefer = (signing_prefer or "sigstore").lower()
        if prefer not in ("sigstore", "workspace"):
            raise ValueError(
                f"--signing-prefer must be 'sigstore' or 'workspace' "
                f"(got {signing_prefer!r})"
            )
        self.signing_prefer = prefer

        self.dry_run = dry_run
        self._developer_key = client.key_scope == "developer"
        self.reverify = reverify
        self.verbose = verbose
        self.changed_files = changed_files
        self.concurrency = max(1, concurrency)

    def _sign_with_workspace_key(self, content_hash: str) -> tuple[str, str]:
        """Sign ``content_hash`` with the workspace ECDSA key.

        Returns ``(signature_b64, signed_hex)`` accepted by the backend's
        ``signature`` + ``signed_hash`` body fields, or ``("", "")`` if no
        workspace key is configured. Failures are logged and also return
        empty strings — the run still submits unsigned, mirroring the
        Sigstore fallback path.
        """
        if self.workspace_signer is None:
            return "", ""
        try:
            return self.workspace_signer.sign(content_hash)
        except Exception as e:
            console.print(
                f"  [yellow]Workspace-key signing failed: {e} — submitting without attestation[/yellow]"
            )
            return "", ""

    def _choose_attestation(
        self,
        *,
        model_id: str,
        tier: int,
        content_hash: str,
        pipeline: dict[str, Any],
        assertions: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> tuple[str, str, str]:
        """Pick the attestation path per ``signing_prefer`` precedence.

        Returns ``(bundle, signature, signed_hash)`` — exactly one of
        ``bundle`` or (``signature`` + ``signed_hash``) is populated when
        signing succeeds; all empty when no signer is available or both
        signers fail. Sigstore wins by default; ``signing_prefer="workspace"``
        forces the workspace-ECDSA path even when an OIDC token is present.
        """
        bundle, signature, signed_hash = "", "", ""

        if self.oidc_token and self.signing_prefer != "workspace":
            bundle = self._sign_with_sigstore(
                model_id=model_id,
                tier=tier,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=assertions,
                results=results,
            )
            if bundle:
                if self.verbose:
                    console.print(f"  [dim]Tier {tier} attestation: sigstore[/dim]")
                return bundle, "", ""
            # Sigstore failed — fall through to workspace key if available.

        if self.workspace_signer is not None:
            signature, signed_hash = self._sign_with_workspace_key(content_hash)
            if signature:
                if self.verbose:
                    console.print(f"  [dim]Tier {tier} attestation: workspace-ecdsa[/dim]")
                return "", signature, signed_hash

        if self.verbose:
            console.print(f"  [dim]Tier {tier} attestation: none (submitting unsigned)[/dim]")
        return "", "", ""

    def _sign_with_sigstore(
        self,
        *,
        model_id: str,
        tier: int,
        content_hash: str,
        pipeline: dict[str, Any],
        assertions: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> str:
        """Build a DSSE attestation for this tier's run and wrap it in a
        Sigstore bundle.

        Returns the bundle as a JSON string, or "" when no OIDC token is
        available (self-hosted / non-OIDC CI). Failures are logged and also
        return "" — the run still submits; it just lacks attestation. The
        bundle's DSSE envelope carries the assertion + verdict payload
        directly, making it self-contained for offline auditor verification.
        """
        if not self.oidc_token:
            return ""
        try:
            return sign_verification_statement(
                self.oidc_token,
                model_id=model_id,
                tier=tier,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=assertions,
                results=results,
                tuf_url=self.sigstore_tuf_url,
                trust_config_path=self.sigstore_trust_config_path,
            )
        except Exception as e:
            console.print(
                f"  [yellow]Sigstore signing failed: {e} — submitting without attestation[/yellow]"
            )
            return ""

    def _resolve_component_path(self, model_id: str) -> None:
        """When ``--component CMP`` is set and the component declares a
        ``path`` (e.g., ``services/auth`` for a monorepo sub-component),
        join that path onto ``project_root`` so assertion paths resolve
        relative to the component's directory.

        Idempotent — safe to call multiple times. No-ops when:
          - ``--component`` is not set (CLI verifies the whole repo).
          - ``--no-component-path`` was passed (operator opted out, e.g.
            because they're already invoking the CLI from the component
            sub-directory).
          - the component has no declared ``path`` (component lives at
            repo root).
          - the model fetch fails (network error, auth error, etc.) —
            we log a warning and fall back to the unmodified
            ``project_root`` rather than abort.
        """
        if self._component_path_resolved:
            return
        self._component_path_resolved = True
        if not self.component_id or not self.auto_component_path:
            return
        try:
            model = self.client.get_model(model_id)
        except Exception as e:
            if self.verbose:
                console.print(
                    f"  [yellow]Could not fetch model to resolve component path: {e}[/yellow]"
                )
            return
        components = model.get("components") or []
        target = next(
            (c for c in components if c.get("id") == self.component_id),
            None,
        )
        if target is None:
            if self.verbose:
                console.print(
                    f"  [yellow]Component {self.component_id!r} not found on model;"
                    " using --project-root as-is[/yellow]"
                )
            return
        comp_path = (target.get("path") or "").strip().strip("/")
        if not comp_path:
            return
        new_root = (self.project_root / comp_path).resolve()
        if self.verbose:
            console.print(
                f"  [dim]Component {self.component_id!r} declares path "
                f"{comp_path!r} → resolving assertion paths under {new_root}[/dim]"
            )
        self.project_root = new_root

    def run(self, model_id: str) -> dict[str, Any]:
        """Execute full verification pipeline. Returns summary report."""
        self._resolve_component_path(model_id)
        details: list[dict[str, Any]] = []

        # --- Tier 1 ---
        t1_results, t1_details, t1_assertions = self._run_tier(model_id, tier=1)
        details.extend(t1_details)

        pipeline = _pipeline_metadata()

        t1_run_id = ""
        if t1_results and not self.dry_run and not self._developer_key:
            content_hash = compute_content_hash(t1_assertions, t1_results)
            bundle, signature, signed_hash = self._choose_attestation(
                model_id=model_id,
                tier=1,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=t1_assertions,
                results=t1_results,
            )
            resp = self.client.submit_results(
                model_id,
                pipeline=pipeline,
                results=t1_results,
                bundle=bundle,
                signature=signature,
                signed_hash=signed_hash,
                content_hash=content_hash,
            )
            t1_run_id = resp.get("run_id", "")

        # --- Tier 2 ---
        t2_results, t2_details, t2_assertions = self._run_tier(model_id, tier=2)
        details.extend(t2_details)

        t2_run_id = ""
        if t2_results and not self.dry_run and not self._developer_key:
            content_hash = compute_content_hash(t2_assertions, t2_results)
            bundle, signature, signed_hash = self._choose_attestation(
                model_id=model_id,
                tier=2,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=t2_assertions,
                results=t2_results,
            )
            resp = self.client.submit_results(
                model_id,
                pipeline=pipeline,
                results=t2_results,
                bundle=bundle,
                signature=signature,
                signed_hash=signed_hash,
                content_hash=content_hash,
            )
            t2_run_id = resp.get("run_id", "")

        # --- Sufficiency ---
        # Evaluated server-side at assertion submission. Fetch for display.
        suff_all: list[dict[str, Any]] = []
        try:
            vr = self.client.get_verification_report(model_id)
            for ctrl in vr.get("control_details", []):
                suff = ctrl.get("sufficiency")
                if suff and suff.get("status") in ("sufficient", "insufficient"):
                    suff_all.append({
                        "control_id": ctrl.get("control_id", ""),
                        "result": suff["status"],
                        "details": suff.get("details", ""),
                    })
        except Exception:
            pass

        # Compute combined content hash across both tiers for attestation
        all_verified = t1_assertions + t2_assertions
        all_results = t1_results + t2_results
        combined_content_hash = compute_content_hash(all_verified, all_results) if all_verified else ""

        return {
            "tier1_pass": sum(1 for r in t1_results if r["result"] == "pass"),
            "tier1_fail": sum(1 for r in t1_results if r["result"] == "fail"),
            "tier1_skip": sum(1 for r in t1_results if r["result"] == "skipped"),
            "tier2_pass": sum(1 for r in t2_results if r["result"] == "pass"),
            "tier2_fail": sum(1 for r in t2_results if r["result"] == "fail"),
            "tier2_skip": sum(1 for r in t2_results if r["result"] == "skipped"),
            "suff_sufficient": sum(1 for r in suff_all if r["result"] == "sufficient"),
            "suff_insufficient": sum(1 for r in suff_all if r["result"] == "insufficient"),
            "suff_skip": 0,
            "tier1_run_id": t1_run_id,
            "tier2_run_id": t2_run_id,
            "content_hash": combined_content_hash,
            "dry_run": self.dry_run,
            "developer_key": self._developer_key,
            "details": details,
            "suff_details": suff_all,
        }

    def _run_tier(
        self, model_id: str, tier: int
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Run verification for a single tier. Returns (api_results, detail_records, all_assertions)."""
        if self.reverify:
            pending = self.client.get_all_assertions(model_id, repo=self.repo)
        else:
            pending = self.client.get_pending(model_id, tier=tier, repo=self.repo)
        controls = pending.get("controls", {})
        # Merge assumption assertions into the same verification pass
        for as_id, as_assertions in pending.get("assumptions", {}).items():
            controls[as_id] = as_assertions
        if not controls:
            if self.verbose:
                console.print(f"  No tier {tier} assertions pending")
            return [], [], []

        # Filter by component — only verify assertions for controls in this component
        if self.component_id:
            # Fetch controls to determine which belong to this component
            try:
                ctrl_data = self.client.get_controls(model_id, component_id=self.component_id)
                component_ctrl_ids = {c["id"] for c in ctrl_data.get("controls", [])}
                filtered_by_cmp: dict[str, list] = {}
                for ctrl_id, assertions in controls.items():
                    if ctrl_id in component_ctrl_ids:
                        filtered_by_cmp[ctrl_id] = assertions
                if self.verbose:
                    skipped_cmp = len(controls) - len(filtered_by_cmp)
                    if skipped_cmp:
                        console.print(f"  Tier {tier}: skipped {skipped_cmp} control(s) (different component)")
                controls = filtered_by_cmp
                if not controls:
                    return [], [], []
            except Exception as e:
                console.print(f"  [yellow]Warning: component filter failed ({e}), verifying all[/yellow]")

        # Filter to assertions referencing changed files when --changed-files is set.
        # Assertions without a file param are always included (can't be scoped).
        if self.changed_files is not None:
            filtered: dict[str, list] = {}
            skipped = 0
            for ctrl_id, assertions in controls.items():
                kept = []
                for a in assertions:
                    a_file = a.get("params", {}).get("file", "")
                    if not a_file or a_file in self.changed_files:
                        kept.append(a)
                    else:
                        skipped += 1
                if kept:
                    filtered[ctrl_id] = kept
            if self.verbose and skipped:
                console.print(f"  Tier {tier}: skipped {skipped} assertions (files unchanged)")
            controls = filtered
            if not controls:
                return [], [], []

        total = sum(len(assertions) for assertions in controls.values())
        results: list[dict[str, Any]] = []
        details: list[dict[str, Any]] = []

        # Flatten assertions for processing
        all_assertions = [
            a for _ctrl_id, assertions in controls.items() for a in assertions
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Tier {tier}: verifying {total} assertions", total=total)

            if tier == 2 and self.concurrency > 1:
                # Parallel tier2 verification
                futures = {}
                with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                    for assertion in all_assertions:
                        future = pool.submit(self._verify_tier2, assertion)
                        futures[future] = assertion
                    for future in as_completed(futures):
                        assertion = futures[future]
                        a_id = assertion["id"]
                        a_type = assertion["type"]
                        result = future.result()
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
                            "skipped": result["status"] == "skipped",
                            "details": result["details"],
                        })
                        progress.advance(task)
            else:
                # Sequential (tier1 or concurrency=1)
                for assertion in all_assertions:
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
                        "skipped": result["status"] == "skipped",
                        "details": result["details"],
                    })
                    progress.advance(task)

        return results, details, all_assertions

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

        # Read source content for context
        params = assertion.get("params", {})
        a_type = assertion.get("type", "")
        # For file_hash, tier 2 reviews the code that pins the hash (scope_file),
        # not the hashed file itself.
        if a_type == "file_hash":
            source_file = params.get("scope_file", "")
        else:
            source_file = params.get("file", "")
        source_code = ""
        # For target-based assertions (e.g., feature_description), use
        # platform-injected content instead of reading from disk.
        # No truncation — content must match what Tier 1 verified via
        # resolve_content(). If it exceeds the provider's context window,
        # the provider will fail naturally with an informative error.
        if not source_file and params.get("target_content"):
            source_code = params["target_content"]
        elif source_file:
            from .verifiers import safe_resolve_path, PathTraversalError
            try:
                fpath = safe_resolve_path(self.project_root, source_file)
            except PathTraversalError:
                fpath = None
            if fpath and fpath.is_file():
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    # If scope_start/scope_end provided, extract scoped section
                    # for tier 2 review — more focused and token-efficient.
                    # scope_start only: from match to EOF
                    # scope_end only: from BOF to match
                    # both: from scope_start to scope_end
                    scope_start = params.get("scope_start", "")
                    scope_end = params.get("scope_end", "")
                    if (scope_start or scope_end) and a_type in ("pattern_matches", "pattern_absent", "file_hash"):
                        import re
                        s_pos = 0
                        e_pos = len(content)
                        if scope_start:
                            s_match = re.search(scope_start, content, re.MULTILINE)
                            if s_match:
                                s_pos = s_match.start()
                        if scope_end:
                            search_from = s_pos if scope_start else 0
                            e_match = re.search(scope_end, content[search_from:], re.MULTILINE)
                            if e_match:
                                e_pos = search_from + e_match.start()
                        content = content[s_pos:e_pos]
                    # For pattern_matches/pattern_absent, center context around
                    # the match rather than taking the file head — ensures the
                    # reviewer sees the relevant code even in large files.
                    pattern = params.get("pattern", "")
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
                    # For function_exists/class_exists, locate the definition
                    # and center context around it so the tier 2 reviewer can
                    # see the implementation body, not just the file head.
                    elif len(content) > 16000 and a_type in ("function_exists", "class_exists"):
                        import re
                        name = params.get("name", "")
                        if name:
                            if a_type == "function_exists":
                                def_pat = rf'^[ \t]*(async\s+)?def\s+{re.escape(name)}\s*\('
                            else:
                                def_pat = rf'^[ \t]*class\s+{re.escape(name)}[\s(:]'
                            match = re.search(def_pat, content, re.MULTILINE)
                            if match:
                                center = match.start()
                                # Bias toward showing the body (4K before, 12K after)
                                start = max(0, center - 4000)
                                end = min(len(content), center + 12000)
                                prefix = "... (truncated)\n" if start > 0 else ""
                                suffix = "\n... (truncated)" if end < len(content) else ""
                                content = prefix + content[start:end] + suffix
                            else:
                                content = content[:16000] + "\n... (truncated)"
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
            boundary_token = assertion.get("tier2_boundary_token", "")
            passed, reasoning = provider.evaluate(tier2_prompt, source_code, boundary_token)
            return {
                "status": "pass" if passed else "fail",
                "details": reasoning,
                "reasoning": reasoning,
                "reviewer": f"ai:{self.tier2_provider_name}/{self.tier2_model or 'default'}",
            }
        except ImportError as e:
            return {"status": "skipped", "details": f"Provider not available: {e}"}
        except Exception as e:
            return {"status": "fail", "details": f"Tier 2 error: {e}"}



def _auto_detect_repo(project_root: Path) -> str:
    """Auto-detect repository name from CI environment or git remote."""
    # GitHub Actions
    gh_repo = os.environ.get("GITHUB_REPOSITORY", "")
    if gh_repo:
        return gh_repo
    # GitLab CI
    gl_repo = os.environ.get("CI_PROJECT_PATH", "")
    if gl_repo:
        return gl_repo
    # Git remote
    try:
        import subprocess
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=str(project_root),
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            for prefix in ("git@github.com:", "https://github.com/",
                           "git@gitlab.com:", "https://gitlab.com/"):
                if url.startswith(prefix):
                    return url[len(prefix):].removesuffix(".git")
    except Exception:
        pass
    return ""


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
