"""CLI entry point for mipiti-verify."""

from __future__ import annotations

import json
import os
import sys

import click
from rich.console import Console
from rich.table import Table

from .client import MipitiClient
from .runner import Runner

# Force unbuffered output so CI and MCP tool runners see progress in real-time.
# Python buffers stdout/stderr when not connected to a TTY (CI, pipes, subprocesses).
os.environ.setdefault("PYTHONUNBUFFERED", "1")


# SAN-prefix → OIDC-issuer registry. Maps the auditor-pinned SAN to
# the issuer the auditor implicitly trusts when they pin that SAN
# (e.g. pinning `https://github.com/Customer/...` means the auditor
# trusts only GitHub Actions OIDC for that workflow). Defense-in-depth
# on top of Fulcio's own issuer↔SAN-prefix policy: if Fulcio policy
# ever drifts to accept a non-GitHub OIDC token for a github.com SAN,
# this registry catches the divergence at the auditor.
#
# We deliberately do NOT read the bundle's own OIDC-issuer cert
# extension to derive the expected issuer. The bundle's own claim
# about its issuer is exactly what `policy.Identity()` is supposed
# to verify — using it as the expected value would let a forged
# bundle declare any issuer it likes and pass the pin trivially.
#
# Self-hosted issuers (GitHub Enterprise Server, self-managed GitLab)
# don't appear here — auditors using those must pass --expected-issuer
# explicitly, the same way they pass an explicit --expected-ci-identity
# for those environments.
_KNOWN_ISSUER_BY_SAN_PREFIX = {
    "https://github.com/": "https://token.actions.githubusercontent.com",
    "https://gitlab.com/": "https://gitlab.com",
}


def _infer_issuer(expected_ci_identity: str | None) -> str | None:
    """Infer the OIDC issuer from the auditor-pinned SAN.

    Returns the issuer URL when the SAN matches a known prefix
    (github.com, gitlab.com), None otherwise. Auditors with
    self-hosted issuers must pass --expected-issuer explicitly.
    """
    if not expected_ci_identity:
        return None
    for prefix, issuer in _KNOWN_ISSUER_BY_SAN_PREFIX.items():
        if expected_ci_identity.startswith(prefix):
            return issuer
    return None


def _derive_ci_identity_from_env() -> str | None:
    """Derive a Fulcio SAN from CI env vars when running inside a known
    CI provider. Returns None if no recognized env present.

    GitHub Actions:
        SAN = ${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}
        e.g. https://github.com/owner/repo/.github/workflows/verify.yml@refs/heads/main
        (GITHUB_WORKFLOW_REF format already includes the repo + path + @ref)

    GitLab CI:
        SAN = ${CI_PROJECT_URL}//${CI_CONFIG_PATH}@${CI_COMMIT_REF_NAME}
        e.g. https://gitlab.com/group/project//.gitlab-ci.yml@main
    """
    gh_server = os.environ.get("GITHUB_SERVER_URL", "")
    gh_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if gh_server and gh_workflow_ref:
        return f"{gh_server}/{gh_workflow_ref}"
    gl_url = os.environ.get("CI_PROJECT_URL", "")
    gl_path = os.environ.get("CI_CONFIG_PATH", "")
    gl_ref = os.environ.get("CI_COMMIT_REF_NAME", "")
    if gl_url and gl_path and gl_ref:
        return f"{gl_url}//{gl_path}@{gl_ref}"
    return None

console = Console()


@click.group()
@click.version_option(package_name="mipiti-verify")
def main() -> None:
    """Turnkey CI verification for Mipiti threat model assertions."""


@main.command()
@click.argument("model_id", required=False, default=None)
@click.option("--all", "run_all", is_flag=True, help="Verify all models in the API key's workspace")
@click.option("--api-key", envvar="MIPITI_API_KEY", help="Mipiti API key")
@click.option("--base-url", envvar="MIPITI_BASE_URL", default=None, help="API base URL")
@click.option("--project-root", type=click.Path(exists=True), default=".", help="Project root directory")
@click.option(
    "--tier2-provider",
    type=click.Choice(["openai", "anthropic", "ollama"], case_sensitive=False),
    default=None,
    help="AI provider for Tier 2 semantic verification",
)
@click.option("--tier2-model", default=None, help="Model name (e.g. gpt-4o, claude-sonnet-4-5-20250514)")
@click.option("--tier2-api-key", default=None, help="Provider API key (or OPENAI_API_KEY / ANTHROPIC_API_KEY)")
@click.option("--ollama-url", default="http://localhost:11434", help="Ollama endpoint URL")
@click.option("--oidc-token", default=None, help="OIDC token used locally to mint a Sigstore bundle (auto-detected from GitHub Actions / GitLab CI)")
@click.option("--sigstore-tuf-url", default=None, help="Custom Sigstore TUF root URL for private deployments (default: public sigstore.dev)")
@click.option("--sigstore-trust-config", "sigstore_trust_config_path", default=None, type=click.Path(exists=True, dir_okay=False), help="Path to a pre-downloaded Sigstore ClientTrustConfig JSON (no outbound TUF fetch)")
@click.option(
    "--workspace-signing-key",
    "workspace_signing_key_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    envvar="MIPITI_WORKSPACE_SIGNING_KEY",
    help=(
        "PEM ECDSA P-256 private key for workspace-attested submission. "
        "Used when no OIDC token is available (Jenkins, Buildkite, "
        "self-managed GitLab without ID tokens), or when "
        "--signing-prefer=workspace. The matching public key must be "
        "registered on the Mipiti workspace."
    ),
)
@click.option(
    "--signing-prefer",
    default="sigstore",
    type=click.Choice(["sigstore", "workspace"], case_sensitive=False),
    help=(
        "When both an OIDC token and a workspace key are available, prefer "
        "this signer. Default: sigstore (publicly verifiable transparency "
        "log). Use 'workspace' to force the ECDSA path (e.g. for policy "
        "or testing)."
    ),
)
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "github"], case_sensitive=False),
    default="text",
    help="Output format",
)
@click.option("--dry-run", is_flag=True, help="Run verifiers but don't submit results")
@click.option("--reverify/--no-reverify", default=True, help="Re-verify all assertions, not just pending (default: on)")
@click.option("--verbose", is_flag=True, help="Show per-assertion detail")
@click.option("--repo", default="", help="Repository name (e.g. org/repo). Auto-detected from GITHUB_REPOSITORY, CI_PROJECT_PATH, or git remote.")
@click.option("--changed-files", "changed_files_path", default=None, help="File with changed paths (one per line, e.g. git diff --name-only). Only assertions referencing these files are verified. Use '-' for stdin.")
@click.option("--concurrency", default=1, type=int, help="Max concurrent Tier 2 LLM calls (default: 1, sequential). Tune based on your API rate limits.")
@click.option("--component", "component_id", default=None, help="Component ID to scope verification (only verify assertions for controls in this component). Auto-detect from git remote if not specified.")
@click.option(
    "--component-path/--no-component-path",
    "auto_component_path",
    default=True,
    help=(
        "When --component is set, automatically resolve the component's "
        "declared 'path' under --project-root for monorepos (e.g., "
        "services/auth). Pass --no-component-path when invoking the CLI "
        "from inside the component sub-directory to avoid double-prefixing. "
        "Default: on."
    ),
)
def run(
    model_id: str | None,
    run_all: bool,
    api_key: str | None,
    base_url: str | None,
    project_root: str,
    tier2_provider: str | None,
    tier2_model: str | None,
    tier2_api_key: str | None,
    ollama_url: str,
    oidc_token: str | None,
    sigstore_tuf_url: str | None,
    sigstore_trust_config_path: str | None,
    workspace_signing_key_path: str | None,
    signing_prefer: str,
    output_format: str,
    dry_run: bool,
    reverify: bool,
    verbose: bool,
    repo: str,
    changed_files_path: str | None,
    concurrency: int,
    component_id: str | None,
    auto_component_path: bool,
) -> None:
    """Run verification against pending assertions for MODEL_ID.

    Use --all to verify all models in the workspace associated with the API key.
    Use --no-reverify to only verify pending assertions.
    """
    if not model_id and not run_all:
        console.print("[red]Error:[/red] Provide MODEL_ID or use --all")
        sys.exit(1)

    try:
        client = MipitiClient(api_key=api_key, base_url=base_url)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    # Resolve model IDs to verify
    if run_all:
        try:
            models = client.list_models()
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to list models: {e}")
            client.close()
            sys.exit(1)
        model_ids = [m["id"] for m in models]
        if not model_ids:
            console.print("[yellow]No models found in workspace.[/yellow]")
            client.close()
            return
        console.print(f"Verifying {len(model_ids)} model(s)...")
    else:
        model_ids = [model_id]

    # Parse changed files list
    changed_files: set[str] | None = None
    if changed_files_path is not None:
        if changed_files_path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(changed_files_path, encoding="utf-8") as f:
                lines = f.read().splitlines()
        changed_files = {line.strip().replace("\\", "/") for line in lines if line.strip()}
        if verbose:
            console.print(f"Changed files filter: {len(changed_files)} file(s)")

    try:
        runner = Runner(
            client=client,
            project_root=project_root,
            tier2_provider=tier2_provider,
            tier2_model=tier2_model,
            tier2_api_key=tier2_api_key,
            ollama_url=ollama_url,
            oidc_token=oidc_token,
            sigstore_tuf_url=sigstore_tuf_url,
            sigstore_trust_config_path=sigstore_trust_config_path,
            workspace_signing_key_path=workspace_signing_key_path,
            signing_prefer=signing_prefer,
            dry_run=dry_run,
            reverify=reverify,
            verbose=verbose,
            repo=repo,
            changed_files=changed_files,
            concurrency=concurrency,
            component_id=component_id,
            auto_component_path=auto_component_path,
        )
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        client.close()
        sys.exit(1)

    has_failures = False
    all_reports: list[dict] = []

    for mid in model_ids:
        if run_all:
            console.print(f"\n[bold]--- {mid} ---[/bold]")
        try:
            report = runner.run(mid)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            has_failures = True
            continue

        report["model_id"] = mid
        all_reports.append(report)

        if (
            report.get("tier1_fail", 0) > 0
            or report.get("tier2_fail", 0) > 0
            or report.get("suff_insufficient", 0) > 0
            or (output_format == "github" and report.get("tier2_skip", 0) > 0)
        ):
            has_failures = True

        if not run_all:
            # Single model — output immediately
            if output_format == "json":
                click.echo(json.dumps(report, indent=2))
            elif output_format == "github":
                _github_output(report)
            else:
                _text_output(report, verbose)

    client.close()

    if run_all:
        if output_format == "json":
            click.echo(json.dumps(all_reports, indent=2))
        elif output_format == "github":
            for report in all_reports:
                _github_output(report)
        else:
            for report in all_reports:
                _text_output(report, verbose)
            # Summary
            total = len(all_reports)
            failed = sum(
                1 for r in all_reports
                if r.get("tier1_fail", 0) > 0 or r.get("tier2_fail", 0) > 0 or r.get("suff_insufficient", 0) > 0
            )
            console.print(f"\n[bold]Summary:[/bold] {total} model(s) verified, "
                          f"[green]{total - failed} passed[/green], "
                          f"[red]{failed} failed[/red]")

    if has_failures:
        sys.exit(1)


@main.command()
@click.argument("assertions_file", type=click.Path(exists=True))
@click.option("--project-root", type=click.Path(exists=True), default=".", help="Project root directory")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "github"], case_sensitive=False),
    default="text",
    help="Output format",
)
@click.option("--verbose", is_flag=True, help="Show per-assertion detail")
def check(
    assertions_file: str,
    project_root: str,
    output_format: str,
    verbose: bool,
) -> None:
    """Verify assertions locally from a JSON file (no API key needed).

    ASSERTIONS_FILE is a JSON file containing an array of assertion objects,
    each with "type", "params", and "description" fields. Only Tier 1
    (mechanical) verification is performed.

    Example file:

    \b
    [
      {"type": "function_exists", "params": {"file": "app/auth.py", "name": "verify_token"}, "description": "Auth token verification exists"},
      {"type": "pattern_matches", "params": {"file": "nginx.conf", "pattern": "Strict-Transport-Security"}, "description": "HSTS header configured"}
    ]
    """
    from pathlib import Path

    from .verifiers import get_verifier

    try:
        with open(assertions_file, encoding="utf-8") as f:
            assertions = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"[red]Error:[/red] Failed to read assertions file: {e}")
        sys.exit(1)

    if not isinstance(assertions, list):
        console.print("[red]Error:[/red] Assertions file must contain a JSON array")
        sys.exit(1)

    root = Path(project_root).resolve()
    results: list[dict] = []
    passed_count = 0
    failed_count = 0
    skipped_count = 0

    for i, assertion in enumerate(assertions):
        a_type = assertion.get("type", "")
        params = assertion.get("params", {})
        desc = assertion.get("description", f"assertion[{i}]")
        a_id = assertion.get("id", f"local_{i:03d}")

        verifier = get_verifier(a_type)
        if verifier is None:
            results.append({"id": a_id, "type": a_type, "description": desc, "passed": False, "details": f"No verifier for type '{a_type}'"})
            skipped_count += 1
            continue

        try:
            result = verifier.verify(params, root)
            results.append({"id": a_id, "type": a_type, "description": desc, "passed": result.passed, "details": result.details})
            if result.passed:
                passed_count += 1
            else:
                failed_count += 1
        except Exception as e:
            results.append({"id": a_id, "type": a_type, "description": desc, "passed": False, "details": f"Verifier error: {e}"})
            failed_count += 1

    report = {"passed": passed_count, "failed": failed_count, "skipped": skipped_count, "total": len(assertions), "results": results}

    if output_format == "json":
        click.echo(json.dumps(report, indent=2))
    elif output_format == "github":
        for r in results:
            if not r["passed"]:
                click.echo(f"::error title=Check Failed::{r['id']} ({r['type']}): {r['details']}")
        if failed_count:
            click.echo(f"::error title=Check Summary::{failed_count} failures out of {len(assertions)} assertions")
        else:
            click.echo(f"::notice title=Check Passed::{passed_count} assertions verified locally")
    else:
        console.print(f"\n[bold]Local Check Results[/bold]\n")
        console.print(f"  [green]{passed_count} pass[/green]  [red]{failed_count} fail[/red]  [yellow]{skipped_count} skip[/yellow]")
        if verbose or failed_count:
            console.print()
            for r in results:
                color = "green" if r["passed"] else "red"
                console.print(f"  [{color}]{r['id']}[/{color}] ({r['type']}): {r['details']}")
                if verbose:
                    console.print(f"    {r['description']}")
        console.print()

    if failed_count > 0:
        sys.exit(1)


@main.command()
@click.argument("assertion_type")
@click.option("--param", "-p", multiple=True, help="Assertion parameter as key=value (repeatable)")
@click.option("--project-root", type=click.Path(exists=True), default=".", help="Project root directory")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format",
)
def verify(
    assertion_type: str,
    param: tuple[str, ...],
    project_root: str,
    output_format: str,
) -> None:
    """Verify a single assertion locally (no API key needed).

    Run a Tier 1 mechanical check against the local codebase.

    \b
    Examples:
      mipiti-verify verify function_exists -p file=app/auth.py -p name=verify_token
      mipiti-verify verify pattern_matches -p file=nginx.conf -p pattern="Strict-Transport-Security"
      mipiti-verify verify dependency_exists -p manifest=requirements.txt -p package=bcrypt
      mipiti-verify verify import_present -p file=app/main.py -p module=fastapi
    """
    from pathlib import Path

    from .verifiers import get_verifier

    verifier = get_verifier(assertion_type)
    if verifier is None:
        if output_format == "json":
            click.echo(json.dumps({"passed": False, "type": assertion_type, "details": f"No verifier for type '{assertion_type}'"}))
        else:
            console.print(f"[red]FAIL[/red] No verifier for type '{assertion_type}'")
        sys.exit(1)

    params: dict[str, str] = {}
    for p in param:
        if "=" not in p:
            console.print(f"[red]Error:[/red] Invalid param '{p}' — use key=value format")
            sys.exit(1)
        key, value = p.split("=", 1)
        params[key] = value

    root = Path(project_root).resolve()
    try:
        result = verifier.verify(params, root)
    except Exception as e:
        if output_format == "json":
            click.echo(json.dumps({"passed": False, "type": assertion_type, "params": params, "details": f"Verifier error: {e}"}))
        else:
            console.print(f"[red]FAIL[/red] ({assertion_type}) Verifier error: {e}")
        sys.exit(1)

    if output_format == "json":
        click.echo(json.dumps({"passed": result.passed, "type": assertion_type, "params": params, "details": result.details}))
    else:
        color = "green" if result.passed else "red"
        label = "PASS" if result.passed else "FAIL"
        console.print(f"[{color}]{label}[/{color}] ({assertion_type}) {result.details}")

    if not result.passed:
        sys.exit(1)


@main.command(name="list")
@click.argument("model_id")
@click.option("--api-key", envvar="MIPITI_API_KEY", help="Mipiti API key")
@click.option("--base-url", envvar="MIPITI_BASE_URL", default=None, help="API base URL")
def list_pending(model_id: str, api_key: str | None, base_url: str | None) -> None:
    """Show pending assertions summary for MODEL_ID."""
    try:
        client = MipitiClient(api_key=api_key, base_url=base_url)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    try:
        t1 = client.get_pending(model_id, tier=1)
        t2 = client.get_pending(model_id, tier=2)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        client.close()

    table = Table(title=f"Pending Assertions for {model_id}")
    table.add_column("Control")
    table.add_column("Tier 1", justify="right")
    table.add_column("Tier 2", justify="right")

    all_ctrls = sorted(set(list(t1.get("controls", {}).keys()) + list(t2.get("controls", {}).keys())))
    for ctrl_id in all_ctrls:
        t1_count = len(t1.get("controls", {}).get(ctrl_id, []))
        t2_count = len(t2.get("controls", {}).get(ctrl_id, []))
        table.add_row(ctrl_id, str(t1_count), str(t2_count))

    console.print(table)


@main.command()
@click.argument("model_id")
@click.option("--api-key", envvar="MIPITI_API_KEY", help="Mipiti API key")
@click.option("--base-url", envvar="MIPITI_BASE_URL", default=None, help="API base URL")
def report(model_id: str, api_key: str | None, base_url: str | None) -> None:
    """Show verification report for MODEL_ID."""
    try:
        client = MipitiClient(api_key=api_key, base_url=base_url)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    try:
        data = client.get_verification_report(model_id)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        client.close()

    console.print(f"\n[bold]Verification Report — {model_id}[/bold]\n")

    t1 = data.get("tier1", {})
    t2 = data.get("tier2", {})
    console.print(f"  Tier 1: [green]{t1.get('pass', 0)} pass[/green]  "
                  f"[red]{t1.get('fail', 0)} fail[/red]  "
                  f"[yellow]{t1.get('pending', 0)} pending[/yellow]")
    console.print(f"  Tier 2: [green]{t2.get('pass', 0)} pass[/green]  "
                  f"[red]{t2.get('fail', 0)} fail[/red]  "
                  f"[yellow]{t2.get('pending', 0)} pending[/yellow]")

    console.print(f"\n  Controls: [green]{data.get('controls_fully_verified', 0)} verified[/green]  "
                  f"[yellow]{data.get('controls_partially_verified', 0)} partial[/yellow]  "
                  f"[red]{data.get('controls_unverified', 0)} unverified[/red]")

    drift = data.get("drift_items", [])
    if drift:
        console.print(f"\n  [red]Drift detected: {len(drift)} assertion(s) regressed[/red]")

    suff = data.get("sufficiency")
    if suff:
        console.print(f"\n  Sufficiency: [green]{suff.get('sufficient', 0)} sufficient[/green]  "
                      f"[red]{suff.get('insufficient', 0)} insufficient[/red]  "
                      f"[yellow]{suff.get('pending', 0)} pending[/yellow]  "
                      f"({suff.get('total_marked', 0)} marked complete)")

    coherence = data.get("coherence_warnings", 0)
    if coherence:
        console.print(f"\n  [yellow]Coherence warnings: {coherence} assertion(s) flagged as incoherent[/yellow]")

    console.print()


def _text_output(report: dict, verbose: bool) -> None:
    """Pretty-print verification results."""
    console.print(f"\n[bold]Verification Results[/bold]\n")
    console.print(f"  Tier 1: [green]{report.get('tier1_pass', 0)} pass[/green]  "
                  f"[red]{report.get('tier1_fail', 0)} fail[/red]  "
                  f"[yellow]{report.get('tier1_skip', 0)} skip[/yellow]")
    console.print(f"  Tier 2: [green]{report.get('tier2_pass', 0)} pass[/green]  "
                  f"[red]{report.get('tier2_fail', 0)} fail[/red]  "
                  f"[yellow]{report.get('tier2_skip', 0)} skip[/yellow]")

    suff_total = report.get("suff_sufficient", 0) + report.get("suff_insufficient", 0) + report.get("suff_skip", 0)
    if suff_total > 0:
        console.print(f"  Sufficiency: [green]{report.get('suff_sufficient', 0)} sufficient[/green]  "
                      f"[red]{report.get('suff_insufficient', 0)} insufficient[/red]  "
                      f"[yellow]{report.get('suff_skip', 0)} skip[/yellow]")
        # Show per-control gap details for insufficient controls
        for sd in report.get("suff_details", []):
            if sd.get("result") == "insufficient":
                details = sd.get("details", "").strip()
                if details:
                    console.print(f"    [red]{sd['control_id']}[/red]: [blue]{details}[/blue]")

    t2s = report.get("tier2_skip", 0)
    if t2s:
        console.print(f"\n  [yellow]{t2s} tier2 skipped — no provider configured. Controls cannot reach verified status without tier 2.[/yellow]")

    if report.get("dry_run"):
        console.print("\n  [yellow]Dry run — results not submitted[/yellow]")
    elif report.get("developer_key"):
        console.print("\n  [yellow]Developer key — results not submitted. Use a verifier key (mv_) for CI.[/yellow]")
    else:
        console.print(f"\n  Submitted: tier1 run={report.get('tier1_run_id', 'n/a')}  "
                      f"tier2 run={report.get('tier2_run_id', 'n/a')}")

    if verbose:
        for detail in report.get("details", []):
            status_color = "green" if detail["passed"] else "red"
            console.print(f"  [{status_color}]{detail['assertion_id']}[/{status_color}] "
                          f"({detail['type']}) tier={detail['tier']}: {detail['details']}")
    console.print()


def _github_output(report: dict) -> None:
    """Print GitHub Actions annotations with per-assertion detail."""
    details = report.get("details", [])
    # Group by tier for clear output
    for tier in (1, 2):
        tier_details = [d for d in details if d.get("tier") == tier]
        if not tier_details:
            continue
        click.echo(f"::group::Tier {tier} — assertion verification")
        passed = [d for d in tier_details if d["passed"]]
        skipped = [d for d in tier_details if d.get("skipped")]
        failed = [d for d in tier_details if not d["passed"] and not d.get("skipped")]
        for d in passed:
            click.echo(f"  \u2713 {d['assertion_id']} ({d['type']}) tier{tier}: {d['details']}")
        for d in skipped:
            click.echo(f"::warning title=Tier {tier} Skipped::{d['assertion_id']} "
                       f"({d['type']}): {d['details']}")
        for d in failed:
            click.echo(f"::error title=Tier {tier} Failed::{d['assertion_id']} "
                       f"({d['type']}): {d['details']}")
        click.echo("::endgroup::")

    # Write content hash to GITHUB_OUTPUT for attestation steps
    content_hash = report.get("content_hash", "")
    if content_hash:
        gh_output = os.environ.get("GITHUB_OUTPUT", "")
        if gh_output:
            with open(gh_output, "a") as f:
                f.write(f"content_hash={content_hash}\n")

    t1f = report.get("tier1_fail", 0)
    t2f = report.get("tier2_fail", 0)
    t2s = report.get("tier2_skip", 0)
    if t1f or t2f:
        click.echo(f"::error title=Verification Summary::{t1f} tier1 failures, {t2f} tier2 failures")
    else:
        total = report.get("tier1_pass", 0) + report.get("tier2_pass", 0)
        msg = f"{total} assertions verified"
        if t2s:
            click.echo(f"::error title=Tier 2 Skipped::{t2s} tier2 assertions skipped — no provider configured. Controls cannot reach verified status without tier 2.")
        click.echo(f"::notice title=Verification Passed::{msg}")

    # Sufficiency gaps — separate section after verification results
    suff_details = report.get("suff_details", [])
    insufficient = [sd for sd in suff_details if sd.get("result") == "insufficient"]
    if insufficient:
        click.echo(f"::group::Sufficiency — coverage gaps ({len(insufficient)} controls)")
        for sd in insufficient:
            details = sd.get("details", "").strip()
            if details:
                ctrl_id = sd["control_id"]
                for line in details.split("\n"):
                    line = line.strip()
                    if line:
                        click.echo(f"::warning title=Insufficient Coverage::{ctrl_id}: {line}")
        click.echo("::endgroup::")


def _resolve_pubkey_from_jwks(fingerprint: str, key_url: str):
    """Fetch the JWKS at `key_url`, find the JWK whose `kid` matches
    `fingerprint`, and reconstruct an EC public key.

    Defaults to the production Mipiti JWKS endpoint when key_url is
    empty, mirroring the pre-existing HTML auditor behaviour.

    Returns (public_key, fingerprint, key_url_used). Raises SystemExit
    on any failure (network error, JWK not present) so the caller can
    use this from the audit command directly.
    """
    import base64
    if not key_url:
        key_url = "https://api.mipiti.io/.well-known/jwks"
        console.print(f"  Using default JWKS: {key_url}")
    try:
        import httpx
        resp = httpx.get(key_url, timeout=10)
        resp.raise_for_status()
        jwks = resp.json()
    except httpx.HTTPError as e:
        console.print(f"  [red]Failed to fetch JWKS: {e}[/red]")
        raise SystemExit(1)

    jwk = None
    for k in jwks.get("keys", []):
        if k.get("kid") == fingerprint:
            jwk = k
            break
    if jwk is None:
        console.print(f"  [red]Key {fingerprint[:16]}... not found in JWKS[/red]")
        raise SystemExit(1)

    from cryptography.hazmat.primitives.asymmetric import ec
    x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return pub_numbers.public_key(), fingerprint, key_url


def _resolve_pubkey_from_anchor(
    anchor_url: str,
    expected_san: str,
    expected_issuer: str | None,
    sigstore_tuf_url: str | None = None,
    sigstore_trust_config_path: str | None = None,
):
    """Resolve a public key by validating a Sigstore Rekor anchor bundle.

    Anchor flow (alternative to JWKS for vendor-survivability):
      1. Fetch the bundle from `anchor_url`.
      2. Validate against the public Sigstore trust root: Fulcio cert
         chain, Rekor inclusion proof, DSSE signature.
      3. Pin the bundle's SAN to `expected_san` (out-of-band-known
         Mipiti workflow identity). Fail-closed without a SAN pin.
      4. Extract the manifest payload (canonical JSON: kid, kty, crv,
         x, y, alg, use, anchored_at, anchored_by_workflow).
      5. Recover the EC public key from the manifest's `x`/`y`.

    Returns (public_key, manifest_kid, anchor_url). Raises SystemExit
    on any failure (network, structural, signature-invalid, SAN
    mismatch).

    The recovered public key is independently verifiable years after
    the original report was issued, with no dependency on Mipiti's
    JWKS endpoint or any Mipiti-controlled infrastructure.
    """
    import base64
    import json

    if not expected_san:
        # The fail-closed precedent matches `--expected-issuer` alone:
        # an unpinned anchor would let an attacker substitute any
        # validly-signed Sigstore bundle (e.g., from their own GitHub
        # repo) and have the verifier accept it as Mipiti's. Refuse
        # to proceed.
        console.print(
            "[red]Error:[/red] --rekor-anchor requires --expected-anchor-identity. "
            "An anchor without a pinned SAN provides no defense — any validly-"
            "signed Sigstore bundle would be accepted regardless of who signed it. "
            "Pin the canonical Mipiti workflow SAN, e.g. "
            "'https://github.com/Mipiti/mipiti/.github/workflows/anchor-signing-key.yml@refs/heads/main'."
        )
        raise SystemExit(2)

    console.print(f"  Anchor URL: {anchor_url}")
    try:
        import httpx
        resp = httpx.get(anchor_url, timeout=15)
        resp.raise_for_status()
        bundle_bytes = resp.content
    except httpx.HTTPError as e:
        console.print(f"  [red]Failed to fetch anchor bundle: {e}[/red]")
        raise SystemExit(1)

    # Sigstore bundle parsing + verification reuses the same code path
    # the JSON-audit dispatch uses for assertion-submission bundles.
    # The payload is bytes (the canonical JSON manifest); we recover
    # them from the verified DSSE envelope before parsing as JSON.
    try:
        from sigstore.models import Bundle, ClientTrustConfig
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError as e:
        console.print(f"  [red]sigstore-python not installed: {e}[/red]")
        raise SystemExit(1)

    try:
        bundle = Bundle.from_json(bundle_bytes.decode("utf-8"))
    except Exception as e:
        console.print(f"  [red]Anchor bundle is not a valid Sigstore bundle: {e}[/red]")
        raise SystemExit(1)

    # Build the Sigstore Verifier — same trust-root resolution the
    # JSON-audit path uses (--sigstore-tuf-url for online pinning,
    # --sigstore-trust-config for fully offline air-gapped review).
    try:
        if sigstore_trust_config_path:
            tc = ClientTrustConfig.from_json(
                open(sigstore_trust_config_path, "r").read()
            )
            verifier = Verifier._from_trust_config(tc)
        elif sigstore_tuf_url:
            from sigstore._internal.tuf import TrustUpdater
            tu = TrustUpdater(sigstore_tuf_url, offline=False)
            tc = tu.get_trust_config()
            verifier = Verifier._from_trust_config(tc)
        else:
            verifier = Verifier.production()
    except Exception as e:
        console.print(f"  [red]Failed to initialize Sigstore verifier: {e}[/red]")
        raise SystemExit(1)

    # Pin the SAN. Issuer optional; required only for self-hosted
    # OIDC providers per the same precedent in the JSON-audit path.
    issuer = expected_issuer or _infer_issuer(expected_san)
    if not issuer:
        console.print(
            "[red]Error:[/red] could not infer issuer from "
            f"--expected-anchor-identity={expected_san!r}. Pass "
            "--expected-anchor-issuer explicitly for self-hosted OIDC."
        )
        raise SystemExit(2)
    policy = Identity(identity=expected_san, issuer=issuer)

    # Verify the bundle's signature + cert chain + Rekor inclusion
    # proof against the chosen trust root, AND that the cert SAN
    # matches the auditor's pin. `verify_dsse` returns the (type,
    # payload_bytes) tuple; payload_bytes is the canonical manifest
    # we control on the producer side.
    try:
        type_, payload_bytes = verifier.verify_dsse(bundle, policy)
    except Exception as e:
        console.print(f"  [red]Anchor signature INVALID: {e}[/red]")
        raise SystemExit(1)

    try:
        manifest = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        console.print(f"  [red]Anchor manifest is not valid JSON: {e}[/red]")
        raise SystemExit(1)
    if not isinstance(manifest, dict):
        console.print("  [red]Anchor manifest is not a JSON object.[/red]")
        raise SystemExit(1)

    required = ("kid", "kty", "crv", "x", "y")
    missing = [k for k in required if k not in manifest]
    if missing:
        console.print(f"  [red]Anchor manifest missing fields: {missing}[/red]")
        raise SystemExit(1)
    if manifest["kty"] != "EC" or manifest["crv"] != "P-256":
        console.print(
            f"  [red]Anchor manifest has unexpected key type "
            f"({manifest['kty']}/{manifest['crv']}); expected EC/P-256.[/red]"
        )
        raise SystemExit(1)

    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        x = int.from_bytes(base64.urlsafe_b64decode(manifest["x"] + "=="), "big")
        y = int.from_bytes(base64.urlsafe_b64decode(manifest["y"] + "=="), "big")
    except Exception as e:
        console.print(f"  [red]Anchor manifest x/y not valid base64url: {e}[/red]")
        raise SystemExit(1)
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    pub_key = pub_numbers.public_key()

    console.print(
        f"  Anchor verified: SAN matches {expected_san}, manifest kid={manifest['kid'][:16]}..."
    )
    return pub_key, manifest["kid"], anchor_url


def _verify_anchor_bundle_bytes(
    bundle_bytes: bytes,
    expected_san: str,
    expected_issuer: str | None,
    sigstore_tuf_url: str | None = None,
    sigstore_trust_config_path: str | None = None,
):
    """Validate a Sigstore bundle (raw bytes) against the public Sigstore
    trust root and the auditor's SAN pin, then extract the (kid, pubkey)
    pair from the signed manifest.

    Shared helper between URL-based anchor resolution
    (`_resolve_pubkey_from_anchor`) and snapshot-based resolution
    (`_resolve_pubkey_from_rekor_snapshot`). Returns
    (public_key, manifest_kid). Raises ValueError on any failure so
    the caller can decide whether to fail the whole audit (URL path)
    or skip this entry and try the next (snapshot path iterating
    over multiple bundles).
    """
    import base64
    import json

    if not expected_san:
        raise ValueError("anchor SAN pin is required (fail-closed precedent)")

    try:
        from sigstore.models import Bundle, ClientTrustConfig
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError as e:
        raise ValueError(f"sigstore-python not installed: {e}")

    try:
        bundle = Bundle.from_json(bundle_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"not a valid Sigstore bundle: {e}")

    try:
        if sigstore_trust_config_path:
            tc = ClientTrustConfig.from_json(
                open(sigstore_trust_config_path, "r").read()
            )
            verifier = Verifier._from_trust_config(tc)
        elif sigstore_tuf_url:
            from sigstore._internal.tuf import TrustUpdater
            tu = TrustUpdater(sigstore_tuf_url, offline=False)
            tc = tu.get_trust_config()
            verifier = Verifier._from_trust_config(tc)
        else:
            verifier = Verifier.production()
    except Exception as e:
        raise ValueError(f"failed to initialize Sigstore verifier: {e}")

    issuer = expected_issuer or _infer_issuer(expected_san)
    if not issuer:
        raise ValueError(
            f"could not infer issuer from SAN={expected_san!r}; pass "
            "--expected-anchor-issuer explicitly for self-hosted OIDC"
        )
    policy = Identity(identity=expected_san, issuer=issuer)

    try:
        _, payload_bytes = verifier.verify_dsse(bundle, policy)
    except Exception as e:
        raise ValueError(f"signature INVALID: {e}")

    try:
        manifest = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"manifest not valid JSON: {e}")
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not a JSON object")

    required = ("kid", "kty", "crv", "x", "y")
    missing = [k for k in required if k not in manifest]
    if missing:
        raise ValueError(f"manifest missing fields: {missing}")
    if manifest["kty"] != "EC" or manifest["crv"] != "P-256":
        raise ValueError(
            f"unexpected key type ({manifest['kty']}/{manifest['crv']}); "
            "expected EC/P-256"
        )

    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        x = int.from_bytes(base64.urlsafe_b64decode(manifest["x"] + "=="), "big")
        y = int.from_bytes(base64.urlsafe_b64decode(manifest["y"] + "=="), "big")
    except Exception as e:
        raise ValueError(f"manifest x/y not valid base64url: {e}")
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return pub_numbers.public_key(), manifest["kid"]


def _resolve_pubkey_from_rekor_snapshot(
    snapshot_dir: str,
    expected_san: str,
    expected_issuer: str | None,
    target_kid: str,
    sigstore_tuf_url: str | None = None,
    sigstore_trust_config_path: str | None = None,
):
    """Resolve the report's signing key from a directory of pre-saved
    Sigstore anchor bundles — fully offline / air-gapped.

    The auditor captures matching anchor bundles at report-receipt
    time (e.g., via cosign / sigstore CLI / a one-time fetch from a
    public mirror) and passes the directory at audit time. Combined
    with `--sigstore-trust-config <tuf.json>`, the entire verification
    chain is offline-replayable years later with no live Mipiti or
    Rekor access required.

    Iterates `<snapshot_dir>/*.sigstore`, validates each bundle
    against the public Sigstore trust root + SAN pin (skipping
    individual invalid entries), returns the first whose manifest's
    `kid` matches `target_kid`. Raises SystemExit(1) if no match.

    Returns (public_key, manifest_kid, snapshot_dir).
    """
    if not expected_san:
        console.print(
            "[red]Error:[/red] --rekor-entry-snapshot requires "
            "--expected-anchor-identity. An anchor without a pinned "
            "SAN provides no defense — any validly-signed Sigstore "
            "bundle in the snapshot dir would be accepted regardless "
            "of who signed it."
        )
        raise SystemExit(2)

    import os.path
    import glob

    if not os.path.isdir(snapshot_dir):
        console.print(
            f"[red]Error:[/red] --rekor-entry-snapshot {snapshot_dir!r} is "
            "not a directory."
        )
        raise SystemExit(1)

    bundle_paths = sorted(glob.glob(os.path.join(snapshot_dir, "*.sigstore")))
    if not bundle_paths:
        console.print(
            f"[red]Error:[/red] no *.sigstore bundle files in {snapshot_dir!r}. "
            "Auditors capture matching anchor bundles at report-receipt time "
            "(e.g., via the sigstore CLI or cosign) and pass the directory."
        )
        raise SystemExit(1)

    console.print(f"  Snapshot dir: {snapshot_dir} ({len(bundle_paths)} bundle(s))")
    console.print(f"  Target kid:   {target_kid[:16]}...")

    skipped = 0
    for path in bundle_paths:
        try:
            with open(path, "rb") as f:
                bundle_bytes = f.read()
        except OSError as e:
            console.print(f"  [yellow]skipping {path}: {e}[/yellow]")
            skipped += 1
            continue
        try:
            pub_key, manifest_kid = _verify_anchor_bundle_bytes(
                bundle_bytes,
                expected_san=expected_san,
                expected_issuer=expected_issuer,
                sigstore_tuf_url=sigstore_tuf_url,
                sigstore_trust_config_path=sigstore_trust_config_path,
            )
        except ValueError as e:
            # Skip individual bad entries — the snapshot might have
            # bundles for unrelated reports / kids / past key rotations.
            console.print(f"  [dim]{os.path.basename(path)}: {e}[/dim]")
            skipped += 1
            continue
        if manifest_kid == target_kid:
            console.print(
                f"  Snapshot match: {os.path.basename(path)}, "
                f"SAN={expected_san}, kid={manifest_kid[:16]}..."
            )
            return pub_key, manifest_kid, snapshot_dir

    console.print(
        f"  [red]No bundle in {snapshot_dir!r} matches kid {target_kid[:16]}... "
        f"({len(bundle_paths)} candidate(s), {skipped} skipped).[/red]"
    )
    raise SystemExit(1)


def _audit_html_report(
    content: str,
    key_url: str,
    pre_resolved=None,
    snapshot_resolver=None,
) -> None:
    """Verify a signed HTML report.

    `pre_resolved`, when given, is a (public_key, kid) tuple from
    `_resolve_pubkey_from_anchor` — the auditor opted into the
    Rekor-anchor trust path. We confirm the report's embedded
    fingerprint matches the anchor manifest's `kid` (defends against
    a valid anchor for a different key being substituted), then use
    the anchor-resolved public key. JWKS is bypassed entirely.

    `snapshot_resolver`, when given, is a callable
    `(target_kid: str) -> (public_key, kid)` that resolves the public
    key by searching a directory of pre-saved Sigstore bundles for
    one whose manifest matches the report's fingerprint. Used for
    fully offline / air-gapped review. Takes precedence over
    `pre_resolved` and JWKS lookup; cannot be combined with the
    URL-based anchor path (mutually exclusive at the audit() entry).
    """
    import base64
    import hashlib
    import re

    console.print("\n[bold]Signed Report Verification[/bold]")
    console.print("=" * 40)

    # Anchor on `\n<!--` (the producer-appended separator) so
    # `content[:sig_match.start()]` excludes the `\n` that's outside
    # the signed bytes.
    sig_match = re.search(
        r"\n<!-- mipiti-report-signature:([a-f0-9]+):([A-Za-z0-9+/=]+) -->\s*$",
        content,
    )
    if not sig_match:
        console.print("  [red]No signature found in report[/red]")
        console.print("  This report was not signed by a Mipiti instance.")
        raise SystemExit(1)

    fingerprint = sig_match.group(1)
    sig_b64 = sig_match.group(2)
    console.print(f"  Key fingerprint: {fingerprint}")

    signed_content = content[:sig_match.start()]
    content_hash = hashlib.sha256(signed_content.encode("utf-8")).digest()

    console.print("\n[bold]Document Signature (ECDSA P-256)[/bold]")
    if snapshot_resolver is not None:
        pub_key, anchor_kid, _ = snapshot_resolver(fingerprint)
        # snapshot_resolver picked the entry that already matches
        # `fingerprint`; the consistency check below is a defense
        # against a buggy resolver returning the wrong tuple.
        if anchor_kid != fingerprint:
            console.print(
                f"  [red]Snapshot resolver returned kid {anchor_kid[:16]}... "
                f"but report fingerprint is {fingerprint[:16]}.[/red]"
            )
            raise SystemExit(1)
    elif pre_resolved is not None:
        pub_key, anchor_kid = pre_resolved
        if anchor_kid != fingerprint:
            console.print(
                f"  [red]Anchor manifest kid {anchor_kid[:16]}... does not "
                f"match report fingerprint {fingerprint[:16]}...[/red]"
            )
            console.print(
                "  The supplied anchor binds a different signing key than the "
                "one that signed this report. Refusing to verify."
            )
            raise SystemExit(1)
    else:
        pub_key, _, _ = _resolve_pubkey_from_jwks(fingerprint, key_url)

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    try:
        sig = base64.b64decode(sig_b64)
        pub_key.verify(sig, content_hash, ec.ECDSA(hashes.SHA256()))
        console.print("  Signature:       [green]VALID[/green]")
        console.print("  Document has not been modified since the platform generated it.")
    except Exception as e:
        console.print(f"  Signature:       [red]INVALID — {e}[/red]")
        raise SystemExit(1)

    console.print("\n[green bold]Report integrity verified.[/green bold]\n")


# Byte-range PDF signing scheme: the producer (backend exporter) appends
# `\n%MIPITI_PDFSIG_v1{<1024-byte payload>}MIPITI_PDFSIG_END\n` after the
# PDF's %%EOF. Payload = `<fingerprint>:<base64_sig>` space-padded to a
# fixed length. The signature covers the bytes outside the payload —
# i.e., the original PDF plus the start/end markers themselves.
_PDF_SIG_START = b"\n%MIPITI_PDFSIG_v1{"
_PDF_SIG_END = b"}MIPITI_PDFSIG_END\n"
_PDF_SIG_PAYLOAD_LEN = 1024

# Audit envelope embedded in PDFs that need to support identity-pinning
# flags. Producer gzips + base64-encodes the JSON audit envelope (the
# same shape `mipiti-verify audit archive.json` consumes) and writes
# it between these markers BEFORE the signature block — so the byte-
# range signature naturally covers the envelope bytes.
_PDF_AUDIT_START = b"\n%MIPITI_AUDIT_v1{"
_PDF_AUDIT_END = b"}MIPITI_AUDIT_END\n"


def _extract_pdf_audit_envelope(pdf_bytes: bytes):
    """Extract the embedded audit envelope from a signed PDF.

    Returns the parsed envelope dict, or None if no envelope is
    present (legacy PDFs signed before the envelope was embedded, or
    PDFs whose embedding got stripped by re-saving).

    On structural defect (malformed base64, malformed gzip, malformed
    JSON, JSON not a dict) prints a clean error and raises SystemExit
    rather than letting the caller proceed with a half-parsed pin —
    the auditor's CI sees a non-zero exit, not a Python traceback.
    """
    import base64, gzip, json

    start_idx = pdf_bytes.find(_PDF_AUDIT_START)
    if start_idx < 0:
        return None
    payload_start = start_idx + len(_PDF_AUDIT_START)
    end_idx = pdf_bytes.find(_PDF_AUDIT_END, payload_start)
    if end_idx < 0:
        console.print("  [red]Audit envelope start marker found but no end marker — refusing to proceed.[/red]")
        raise SystemExit(1)

    encoded = pdf_bytes[payload_start:end_idx]
    try:
        compressed = base64.b64decode(encoded, validate=True)
        raw = gzip.decompress(compressed)
        envelope = json.loads(raw)
    except Exception as e:
        console.print(f"  [red]Failed to decode audit envelope: {e}[/red]")
        raise SystemExit(1)

    if not isinstance(envelope, dict):
        console.print("  [red]Audit envelope is not a JSON object — refusing to proceed.[/red]")
        raise SystemExit(1)
    return envelope


def _audit_pdf_report(
    pdf_bytes: bytes,
    key_url: str,
    pre_resolved=None,
    snapshot_resolver=None,
) -> None:
    """Verify a signed PDF report (byte-range scheme).

    Trust model is the same as `_audit_html_report`: extract the embedded
    fingerprint, recover the public key (JWKS by default, or via the
    Rekor-anchor `pre_resolved` tuple when the auditor opted into
    URL-based independent-of-JWKS verification, or via the
    `snapshot_resolver` callable for offline directory-based resolution),
    recompute SHA-256 over the bytes outside the payload, ECDSA-verify.
    """
    import base64
    import hashlib

    console.print("\n[bold]Signed PDF Report Verification[/bold]")
    console.print("=" * 40)

    start_idx = pdf_bytes.find(_PDF_SIG_START)
    if start_idx < 0:
        console.print("  [red]No signature block found in PDF[/red]")
        console.print("  This PDF was not signed by a Mipiti instance, or the")
        console.print("  signature was stripped (e.g., re-saved through a")
        console.print("  different PDF tool, or printed-to-PDF rather than")
        console.print("  exported from Mipiti directly).")
        raise SystemExit(1)
    payload_start = start_idx + len(_PDF_SIG_START)
    end_idx = pdf_bytes.find(_PDF_SIG_END, payload_start)
    if end_idx < 0 or (end_idx - payload_start) != _PDF_SIG_PAYLOAD_LEN:
        console.print("  [red]Malformed signature block in PDF[/red]")
        console.print(f"  Expected {_PDF_SIG_PAYLOAD_LEN} payload bytes, found "
                      f"{end_idx - payload_start if end_idx >= 0 else 'no terminator'}.")
        raise SystemExit(1)

    try:
        payload = pdf_bytes[payload_start:end_idx].rstrip(b" ").decode("ascii")
    except UnicodeDecodeError:
        console.print("  [red]Signature payload contains non-ASCII bytes[/red]")
        raise SystemExit(1)
    fingerprint, sep, sig_b64 = payload.partition(":")
    if not sep or not fingerprint or not sig_b64:
        console.print("  [red]Signature payload has unexpected shape[/red]")
        console.print("  Expected `<fingerprint>:<base64_sig>` inside markers.")
        raise SystemExit(1)
    console.print(f"  Key fingerprint: {fingerprint}")

    covered = pdf_bytes[:payload_start] + pdf_bytes[end_idx:]
    content_hash = hashlib.sha256(covered).digest()

    console.print("\n[bold]Document Signature (ECDSA P-256)[/bold]")
    if snapshot_resolver is not None:
        pub_key, anchor_kid, _ = snapshot_resolver(fingerprint)
        if anchor_kid != fingerprint:
            console.print(
                f"  [red]Snapshot resolver returned kid {anchor_kid[:16]}... "
                f"but PDF fingerprint is {fingerprint[:16]}.[/red]"
            )
            raise SystemExit(1)
    elif pre_resolved is not None:
        pub_key, anchor_kid = pre_resolved
        if anchor_kid != fingerprint:
            console.print(
                f"  [red]Anchor manifest kid {anchor_kid[:16]}... does not "
                f"match PDF fingerprint {fingerprint[:16]}...[/red]"
            )
            console.print(
                "  The supplied anchor binds a different signing key than the "
                "one that signed this PDF. Refusing to verify."
            )
            raise SystemExit(1)
    else:
        pub_key, _, _ = _resolve_pubkey_from_jwks(fingerprint, key_url)

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    try:
        sig = base64.b64decode(sig_b64)
        pub_key.verify(sig, content_hash, ec.ECDSA(hashes.SHA256()))
        console.print("  Signature:       [green]VALID[/green]")
        console.print("  PDF has not been modified since the platform generated it.")
    except Exception as e:
        console.print(f"  Signature:       [red]INVALID — {e}[/red]")
        raise SystemExit(1)

    console.print("\n[green bold]Report integrity verified.[/green bold]\n")


@main.command()
@click.argument("package_file", type=click.Path(exists=True))
@click.option("--key-url", default="", help="JWKS URL for the Mipiti instance (e.g. https://api.mipiti.io/.well-known/jwks)")
@click.option(
    "--sigstore-tuf-url",
    default=None,
    help=(
        "Custom Sigstore TUF root URL — fetches trust metadata from this URL "
        "instead of the public Sigstore production at audit time. ONLINE: the "
        "audit reaches out to the URL on every invocation. For fully offline "
        "/ air-gapped verification, use --sigstore-trust-config with a "
        "pre-downloaded ClientTrustConfig JSON file. Mutually exclusive with "
        "--sigstore-trust-config (if both are supplied, --sigstore-trust-config "
        "wins). If your sigstore-python build doesn't expose the trust-config "
        "API, this flag fails loudly rather than silently falling back to "
        "public Sigstore."
    ),
)
@click.option(
    "--sigstore-trust-config",
    "sigstore_trust_config_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help=(
        "Path to a pre-downloaded Sigstore ClientTrustConfig JSON file. Use "
        "this for fully offline / air-gapped verification — no outbound "
        "request to any Sigstore TUF host at audit time. Obtain the file "
        "out-of-band (e.g., snapshot the public TUF state into a file via the "
        "sigstore CLI), commit it to the audit-running repository, and pin it "
        "with this flag."
    ),
)
@click.option(
    "--expected-model-id",
    "expected_model_id",
    default=None,
    help=(
        "Pin the expected Mipiti model ID on the bundle's in-toto DSSE "
        "predicate. Defends against cross-model substitution: a real, "
        "cryptographically-valid audit package for a different model cannot "
        "be passed off as the auditor's intended model. The model ID is "
        "extracted from the bundle's signed predicate, not from the "
        "package's outer metadata (which is unsigned)."
    ),
)
@click.option(
    "--expected-commit-sha",
    "expected_commit_sha",
    default=None,
    help=(
        "Pin the expected source-code commit SHA on the bundle's in-toto "
        "DSSE predicate's pipeline.commit_sha. Defends against replay: a "
        "real, cryptographically-valid audit package from an older "
        "verification run (different commit) cannot be passed off as an "
        "audit of the release the auditor is certifying. The commit SHA "
        "lives in the bundle's signed predicate, so attackers cannot forge "
        "it without the customer's CI OIDC."
    ),
)
@click.option(
    "--expected-ci-identity",
    "expected_ci_identity",
    default=None,
    envvar="MIPITI_VERIFY_CI_IDENTITY",
    help=(
        "Pin the expected Fulcio Subject Alternative Name on every embedded "
        "Sigstore bundle in the audit package. Defends against the 'compromised "
        "Mipiti' scenario: a fabricated report containing a Sigstore bundle bound "
        "to an attacker-controlled Fulcio identity will fail verification because "
        "its SAN will not match the customer's known CI identity. Example: "
        "'https://github.com/Customer/repo/.github/workflows/verify.yml@refs/heads/main'. "
        "Reads MIPITI_VERIFY_CI_IDENTITY env var when omitted — convenient for "
        "audit-running CI workflows that pin to a different generator workflow. "
        "See --ci-identity-from-env for auto-derivation in single-workflow setups."
    ),
)
@click.option(
    "--ci-identity-from-env",
    "ci_identity_from_env",
    is_flag=True,
    default=False,
    help=(
        "Auto-derive --expected-ci-identity from CI env vars when running in a "
        "known CI provider (GitHub Actions, GitLab CI). Use when the workflow "
        "running 'mipiti-verify audit' IS the same workflow that produced the "
        "report being audited (single-workflow defense check). For audit "
        "running in a different workflow than generation, set MIPITI_VERIFY_CI_IDENTITY "
        "explicitly to the generator workflow's SAN instead. Reusable workflow "
        "caveat: GITHUB_WORKFLOW_REF refers to the *caller's* workflow, while "
        "Fulcio binds the SAN to the workflow that actually executed — when "
        "auditing inside a reusable workflow stack, pin --expected-ci-identity "
        "explicitly to the SAN Fulcio actually issued for."
    ),
)
@click.option(
    "--expected-issuer",
    "expected_issuer",
    default=None,
    help=(
        "Pin the expected OIDC issuer on every embedded Sigstore bundle. "
        "Optional for github.com / gitlab.com SANs — derived from the "
        "auditor-pinned SAN prefix. Required for self-hosted issuers "
        "(GitHub Enterprise Server, self-managed GitLab) where the SAN "
        "prefix doesn't unambiguously identify the issuer. The issuer "
        "is NOT read from the bundle's own cert claim — that would let "
        "a forged bundle declare any issuer it likes. Examples: "
        "'https://token.actions.githubusercontent.com' for GitHub Actions, "
        "'https://gitlab.com' for GitLab.com, "
        "'https://gitlab.example.com' for self-managed GitLab."
    ),
)
@click.option(
    "--expected-workspace-key",
    "expected_workspace_key_fingerprint",
    default=None,
    help=(
        "Pin the expected workspace ECDSA public-key fingerprint on every "
        "embedded workspace-signed submission. Defends against the 'compromised "
        "Mipiti' scenario: a fabricated report containing a workspace signature "
        "from an attacker-held key will fail verification because the "
        "recomputed fingerprint of the public key actually used for "
        "verification will not match the customer's known workspace key. "
        "The fingerprint is the SHA-256 hex of the DER SubjectPublicKeyInfo "
        "encoding of the workspace's registered public key (visible in the "
        "workspace settings UI)."
    ),
)
@click.option(
    "--rekor-anchor",
    "rekor_anchor_url",
    default=None,
    help=(
        "URL to a Sigstore-signed anchor bundle binding the platform's "
        "signing key to a known Mipiti CI workflow identity. When supplied, "
        "the verifier resolves the public key from the anchor manifest "
        "(after validating Fulcio cert chain + Rekor inclusion proof + DSSE "
        "signature against the public Sigstore trust root) instead of "
        "fetching it from the platform's JWKS endpoint. Defends against "
        "vendor-survivability: a 2026 report can still be verified in 2030 "
        "even if the originating Mipiti instance is offline. Requires "
        "--expected-anchor-identity (the canonical Mipiti workflow SAN, "
        "out-of-band-pinned by the auditor)."
    ),
)
@click.option(
    "--expected-anchor-identity",
    "expected_anchor_identity",
    default=None,
    help=(
        "Pin the SAN of the Sigstore-Fulcio identity that signed the "
        "anchor bundle. Required with --rekor-anchor. Example for SaaS: "
        "'https://github.com/Mipiti/mipiti/.github/workflows/anchor-signing-key.yml@refs/heads/main'. "
        "On-prem operators pin their own anchoring workflow's SAN. "
        "Without this pin the anchor is meaningless — any validly-signed "
        "Sigstore bundle would be accepted regardless of who signed it."
    ),
)
@click.option(
    "--expected-anchor-issuer",
    "expected_anchor_issuer",
    default=None,
    help=(
        "Pin the OIDC issuer of the anchor bundle's signing identity. "
        "Optional for github.com / gitlab.com SANs (derived from the SAN "
        "prefix, same as --expected-issuer). Required for self-hosted "
        "issuers where the SAN prefix doesn't unambiguously identify the "
        "issuer. Example: 'https://token.actions.githubusercontent.com'."
    ),
)
@click.option(
    "--rekor-entry-snapshot",
    "rekor_entry_snapshot_dir",
    default=None,
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    help=(
        "Directory of pre-saved Sigstore anchor bundles (`*.sigstore` "
        "files) — fully offline / air-gapped resolution path. The auditor "
        "captures matching anchor bundles at report-receipt time (e.g., "
        "via the sigstore CLI or by snapshotting from any public mirror) "
        "and passes the directory at audit time. Combined with "
        "`--sigstore-trust-config <tuf.json>`, the entire verification "
        "chain is offline-replayable indefinitely with no live Mipiti or "
        "Rekor access required. Requires --expected-anchor-identity for "
        "the SAN pin. Mutually exclusive with --rekor-anchor."
    ),
)
def audit(
    package_file: str,
    key_url: str,
    sigstore_tuf_url: str | None,
    sigstore_trust_config_path: str | None,
    expected_model_id: str | None,
    expected_commit_sha: str | None,
    expected_ci_identity: str | None,
    ci_identity_from_env: bool,
    expected_issuer: str | None,
    expected_workspace_key_fingerprint: str | None,
    rekor_anchor_url: str | None,
    expected_anchor_identity: str | None,
    expected_anchor_issuer: str | None,
    rekor_entry_snapshot_dir: str | None,
) -> None:
    """Verify an audit package, signed HTML report, or signed PDF report.

    For HTML reports: verifies the ECDSA document signature embedded as a
    trailing HTML comment, proving the report has not been modified since
    the platform generated it.

    For PDF reports: verifies the byte-range ECDSA signature appended after
    the PDF's %%EOF (the same fingerprint-keyed JWKS trust anchor as the
    HTML scheme — `mipiti-verify audit report.pdf`). PDF readers tolerate
    the trailing signature block; the rendered document is unchanged.

    For JSON audit packages: cryptographically verifies the Sigstore bundle
    (signature chain → Fulcio root; Rekor Merkle inclusion proof; SCT), the
    platform's ECDSA content-integrity signature, and lists all assertion
    results with reasoning. Verification is fully offline once the Sigstore
    trust root has been cached on the verifying host; use --sigstore-tuf-url
    to point at a pinned trust root for air-gapped review.

    Identity pinning (defense against compromised-platform forgery): pin the
    customer's expected upstream identity via --expected-ci-identity or
    --ci-identity-from-env (Sigstore submissions) and/or --expected-workspace-key
    (workspace-ECDSA submissions). With these pins, a fabricated report
    containing upstream evidence bound to a different identity than the
    customer's CI fails verification regardless of how clean the platform's
    outer signature appears. The OIDC issuer is derived from the auditor-
    pinned SAN's prefix (github.com → GitHub Actions, gitlab.com → GitLab);
    self-hosted issuers require explicit --expected-issuer. Workspace-key
    pinning recomputes the fingerprint from the public key actually used
    for verification, so a forged package cannot pass the pin by attaching
    an attacker-held key while claiming the customer's fingerprint.

    Vendor-survivability (defense against loss-of-platform): pass
    --rekor-anchor and --expected-anchor-identity to resolve the
    platform's signing key independently of JWKS reachability. The
    verifier fetches the anchor bundle (a Sigstore-signed manifest
    binding the platform's public key to a known Mipiti CI identity,
    recorded in the public Rekor transparency log), validates it
    against the public Sigstore trust root, confirms the SAN matches
    the auditor's pin, and recovers the public key from the manifest.
    Useful when the originating Mipiti instance is offline / wound
    down — the chain remains verifiable for as long as Rekor remains
    publicly replicated.

    Air-gapped review: pass --rekor-entry-snapshot DIR pointing at a
    directory of pre-saved Sigstore anchor bundles (`*.sigstore`
    files) captured at report-receipt time. Combined with
    --sigstore-trust-config (a snapshotted TUF root), the entire
    verification chain is offline-replayable indefinitely with no
    live Mipiti or Rekor access required. Mutually exclusive with
    --rekor-anchor (URL-based one-shot vs directory-based search).
    """
    # Resolve --ci-identity-from-env to an explicit SAN. Precedence:
    # explicit flag (or MIPITI_VERIFY_CI_IDENTITY env var) > auto-derive
    # flag > none. When both are set we surface a notice on divergence
    # so the auditor knows which value actually took effect.
    if ci_identity_from_env:
        derived = _derive_ci_identity_from_env()
        if not expected_ci_identity:
            if derived:
                expected_ci_identity = derived
                console.print(
                    f"[dim]--ci-identity-from-env: auto-derived {derived!r} from CI env[/dim]"
                )
            else:
                console.print(
                    "[red]Error:[/red] --ci-identity-from-env set but no recognized CI "
                    "env vars present (GITHUB_WORKFLOW_REF, CI_PROJECT_URL, …). Either "
                    "run inside GitHub Actions / GitLab CI, or pin --expected-ci-identity "
                    "explicitly."
                )
                raise SystemExit(2)
        elif derived and derived != expected_ci_identity:
            console.print(
                f"[yellow]Note: --ci-identity-from-env would auto-derive "
                f"{derived!r}, but explicit --expected-ci-identity / "
                f"MIPITI_VERIFY_CI_IDENTITY={expected_ci_identity!r} takes "
                f"precedence.[/yellow]"
            )

    # Validation: --expected-issuer alone is meaningless. policy.Identity
    # requires both identity (SAN) and issuer; without a SAN to bind to,
    # the issuer would be silently dropped (UnsafeNoOp chosen instead).
    # Treat as a usage error so auditors don't believe they're getting
    # issuer enforcement when they aren't.
    if expected_issuer and not expected_ci_identity:
        console.print(
            "[red]Error:[/red] --expected-issuer requires --expected-ci-identity "
            "(or --ci-identity-from-env / MIPITI_VERIFY_CI_IDENTITY). "
            "Pinning the issuer alone provides no SAN check; the issuer "
            "is silently unused without a SAN to bind to."
        )
        raise SystemExit(2)

    # Validation: --expected-model-id / --expected-commit-sha without
    # --expected-ci-identity is a usage error. The predicate fields
    # are signed by Fulcio, but Fulcio signs whatever predicate the
    # OIDC-token-holder supplies — an attacker minting a bundle under
    # their *own* CI's OIDC can craft any predicate values matching
    # the auditor's pins. Without a SAN pin constraining whose OIDC
    # was used, predicate pins do not provide compromised-platform
    # defense. The flag's documented purpose is compromised-platform
    # defense, so accepting this configuration silently would let
    # misconfiguration ship to production. Same precedent as
    # --expected-issuer alone (which has zero effect): fail closed.
    if (expected_model_id or expected_commit_sha) and not expected_ci_identity:
        console.print(
            "[red]Error:[/red] --expected-model-id / --expected-commit-sha "
            "require --expected-ci-identity (or --ci-identity-from-env / "
            "MIPITI_VERIFY_CI_IDENTITY). Without a SAN pin constraining whose "
            "OIDC produced the bundle, an attacker minting under their own "
            "CI's OIDC can craft any predicate values matching your pins — "
            "the predicate pins offer no compromised-platform defense on "
            "their own."
        )
        raise SystemExit(2)

    # Validation: --expected-anchor-identity / --expected-anchor-issuer
    # are meaningful only with --rekor-anchor or --rekor-entry-snapshot.
    # Without either, we'd be silently accepting (or refusing) pins the
    # auditor explicitly configured — clean usage error instead.
    if (expected_anchor_identity or expected_anchor_issuer) and not (
        rekor_anchor_url or rekor_entry_snapshot_dir
    ):
        console.print(
            "[red]Error:[/red] --expected-anchor-identity / "
            "--expected-anchor-issuer require --rekor-anchor or "
            "--rekor-entry-snapshot. Without an anchor URL or local "
            "snapshot directory to validate, these pins have nothing to "
            "apply to."
        )
        raise SystemExit(2)

    if rekor_anchor_url and rekor_entry_snapshot_dir:
        console.print(
            "[red]Error:[/red] --rekor-anchor and --rekor-entry-snapshot "
            "are mutually exclusive. The first fetches a single bundle "
            "from a URL; the second resolves from a local directory of "
            "pre-saved bundles."
        )
        raise SystemExit(2)

    # Resolve the anchor up-front for the URL path. The recovered
    # (pubkey, kid) tuple is threaded into _audit_html_report /
    # _audit_pdf_report so they bypass JWKS entirely. Anchor
    # resolution itself fails-closed on a missing SAN pin (per
    # `_resolve_pubkey_from_anchor`).
    anchor_pre_resolved = None
    if rekor_anchor_url:
        console.print("\n[bold]Resolving signing key via Rekor anchor (URL)[/bold]")
        console.print("=" * 40)
        pub_key, anchor_kid, _ = _resolve_pubkey_from_anchor(
            anchor_url=rekor_anchor_url,
            expected_san=expected_anchor_identity or "",
            expected_issuer=expected_anchor_issuer,
            sigstore_tuf_url=sigstore_tuf_url,
            sigstore_trust_config_path=sigstore_trust_config_path,
        )
        anchor_pre_resolved = (pub_key, anchor_kid)

    # The snapshot path resolves LAZILY because it needs the report's
    # fingerprint to pick the matching bundle from the directory.
    # Build a closure the audit functions call once they extract the
    # fingerprint from the artifact.
    snapshot_resolver = None
    if rekor_entry_snapshot_dir:
        console.print(
            "\n[bold]Snapshot mode: resolving via local Sigstore bundles[/bold]"
        )
        console.print("=" * 40)

        def _make_snapshot_resolver(dir_, san, issuer, tuf_url, tc_path):
            def _resolve(target_kid: str):
                return _resolve_pubkey_from_rekor_snapshot(
                    snapshot_dir=dir_,
                    expected_san=san,
                    expected_issuer=issuer,
                    target_kid=target_kid,
                    sigstore_tuf_url=tuf_url,
                    sigstore_trust_config_path=tc_path,
                )
            return _resolve

        snapshot_resolver = _make_snapshot_resolver(
            rekor_entry_snapshot_dir,
            expected_anchor_identity or "",
            expected_anchor_issuer,
            sigstore_tuf_url,
            sigstore_trust_config_path,
        )

    import hashlib
    import base64

    # Bound the input size before reading. Real audit packages are a
    # few MB at most (DSSE bundle + assertion results); 64 MB is
    # generous headroom. Without a cap, a maliciously large file
    # (gigabytes) could OOM the auditor's CI runner — Click's
    # `type=click.Path(exists=True)` only validates that the file
    # exists, not its size.
    _MAX_PACKAGE_SIZE = 64 * 1024 * 1024
    try:
        package_size = os.path.getsize(package_file)
    except OSError as e:
        console.print(f"[red]Error:[/red] cannot stat {package_file!r}: {e}")
        raise SystemExit(1)
    if package_size > _MAX_PACKAGE_SIZE:
        console.print(
            f"[red]Error:[/red] audit package is too large "
            f"({package_size:,} bytes > {_MAX_PACKAGE_SIZE:,} byte limit). "
            "Real audit packages are a few MB at most; refusing to load a "
            "gigabyte-sized file to avoid memory exhaustion."
        )
        raise SystemExit(1)

    # PDFs are binary; sniff the magic before attempting a UTF-8 read.
    # The signed-PDF scheme appends a byte-range signature after %%EOF
    # which the verifier resolves the same way as the HTML scheme:
    # JWKS-keyed public-key lookup by fingerprint, ECDSA-P256 verify.
    # When the PDF additionally carries an audit envelope (Sigstore
    # bundles, workspace-ECDSA signatures, content_integrity payload),
    # we ALSO dispatch through the JSON audit code path so identity-
    # pinning flags work end-to-end.
    with open(package_file, "rb") as f:
        head = f.read(8)
    if head.startswith(b"%PDF-"):
        with open(package_file, "rb") as f:
            pdf_bytes = f.read()
        _audit_pdf_report(
            pdf_bytes, key_url,
            pre_resolved=anchor_pre_resolved,
            snapshot_resolver=snapshot_resolver,
        )

        envelope = _extract_pdf_audit_envelope(pdf_bytes)
        pinning_requested = bool(
            expected_ci_identity
            or expected_workspace_key_fingerprint
            or expected_model_id
            or expected_commit_sha
        )
        if envelope is None:
            if pinning_requested:
                console.print(
                    "[red]Error:[/red] identity-pinning flags "
                    "(--expected-ci-identity / --expected-workspace-key / "
                    "--expected-model-id / --expected-commit-sha) require an "
                    "audit envelope embedded in the PDF. This PDF carries a "
                    "valid document signature but no upstream evidence "
                    "(Sigstore bundles, workspace-ECDSA signatures), so the "
                    "pinning configuration would silently provide no defense. "
                    "Re-export the PDF from a Mipiti instance new enough to "
                    "embed the envelope, or use the JSON audit archive "
                    "(/api/models/<id>/export/full)."
                )
                raise SystemExit(2)
            return
        # Envelope present — re-encode as JSON and fall through to the
        # JSON-audit code path. Setting `content` to the JSON string
        # naturally avoids the HTML branch (no <!DOCTYPE / <html prefix)
        # so we land at `pkg = json.loads(content)` below.
        import json as _j
        content = _j.dumps(envelope)
        # Skip past the legacy file-read step; the rest of audit()
        # continues operating on `content`.
        # (No return here — fall through to JSON dispatch.)
    else:
        # Force UTF-8 — HTML reports and JSON audit packages are UTF-8
        # by construction; relying on the platform default (cp1252 on
        # Windows) crashes on any non-ASCII byte (e.g. a curly quote
        # or em-dash) with UnicodeDecodeError.
        with open(package_file, encoding="utf-8") as f:
            content = f.read()

    # Detect HTML report vs JSON audit package
    if content.strip().startswith("<!DOCTYPE") or content.strip().startswith("<html"):
        # Identity-pinning flags only apply to JSON audit packages —
        # HTML reports don't carry the upstream evidence (Sigstore
        # bundles, workspace-ECDSA submission signatures) that those
        # flags pin against. Same fail-closed precedent as
        # `--expected-issuer` alone: the auditor explicitly asked for
        # an enforcement that the input format cannot deliver, so
        # silently proceeding with exit 0 would let a misconfigured
        # CI gate go green when the pin was effectively dropped.
        # Auditors who want to verify HTML report integrity should
        # invoke without pin flags; for compromised-platform defense
        # they must use a JSON audit package.
        if (
            expected_ci_identity
            or expected_workspace_key_fingerprint
            or expected_model_id
            or expected_commit_sha
        ):
            console.print(
                "[red]Error:[/red] identity-pinning flags "
                "(--expected-ci-identity / --expected-workspace-key / "
                "--expected-model-id / --expected-commit-sha) only apply to "
                "JSON audit packages. HTML reports do not carry the upstream "
                "evidence those flags pin against, so the configuration "
                "would silently provide no defense. Re-run with a JSON audit "
                "package, or remove the pin flags if you only need to verify "
                "HTML report integrity."
            )
            raise SystemExit(2)
        _audit_html_report(
            content, key_url,
            pre_resolved=anchor_pre_resolved,
            snapshot_resolver=snapshot_resolver,
        )
        return

    pkg = json.loads(content)

    # Defensive: a malformed audit package (top-level not a JSON object,
    # or required object fields with wrong types) shouldn't crash the
    # auditor's CI gate with a Python traceback. Treat structural
    # defects as failures with a clean error message — the security
    # outcome is the same as a clean rejection (auditor's CI sees a
    # non-zero exit), and the message is actionable.
    if not isinstance(pkg, dict):
        console.print(
            "[red]Error:[/red] audit package must be a JSON object at the "
            f"top level (got {type(pkg).__name__}). Refusing to verify a "
            "structurally-invalid package."
        )
        raise SystemExit(1)

    console.print("\n[bold]Audit Package Verification[/bold]")
    console.print("=" * 40)
    has_failure = False
    provenance_verified = False  # Bundle verify_artifact succeeded.
    content_verified = False  # content_integrity signature verify succeeded.

    # --- Provenance ---
    console.print("\n[bold]Provenance (Sigstore)[/bold]")
    prov_raw = pkg.get("provenance")
    prov = prov_raw if isinstance(prov_raw, dict) else {}
    bundle_json = prov.get("bundle", "")
    if not isinstance(bundle_json, str):
        bundle_json = ""
    content_hash_str = ""
    ci_raw = pkg.get("content_integrity")
    ci = ci_raw if isinstance(ci_raw, dict) else {}
    content_hash_str = ci.get("results_hash", "") if isinstance(ci, dict) else ""
    if not isinstance(content_hash_str, str):
        content_hash_str = ""
    if bundle_json:
        try:
            from sigstore.models import Bundle, ClientTrustConfig
            from sigstore.verify import Verifier, policy

            bundle = Bundle.from_json(bundle_json)
            cert = bundle.signing_certificate

            # Cryptographic verification — fully offline when
            # --sigstore-trust-config is supplied (no outbound to any
            # Sigstore TUF host at audit time). Binds the bundle to
            # the content hash the platform signed in CI.
            if content_hash_str:
                # Trust-config resolution priority:
                #   1. --sigstore-trust-config (frozen JSON, offline).
                #   2. --sigstore-tuf-url (TUF URL, still online for
                #      metadata fetch).
                #   3. Default: public Sigstore production.
                # When the auditor supplies a custom trust root, use it
                # — never silently fall back to public Sigstore. The
                # whole point of the flag is to pin verification against
                # a specific trust root (air-gapped customer Sigstore,
                # frozen snapshot, etc.). Falling back would replace the
                # auditor's chosen security guarantee with the public
                # one without telling them.
                if sigstore_trust_config_path or sigstore_tuf_url:
                    if not hasattr(Verifier, "_from_trust_config"):
                        raise RuntimeError(
                            "this build of sigstore-python does not expose "
                            "Verifier._from_trust_config; --sigstore-tuf-url "
                            "and --sigstore-trust-config cannot be honored. "
                            "Upgrade sigstore-python or remove the flag to "
                            "use the public Sigstore trust root."
                        )
                    if sigstore_trust_config_path:
                        from pathlib import Path
                        data = Path(sigstore_trust_config_path).read_text(
                            encoding="utf-8"
                        )
                        trust_config = ClientTrustConfig.from_json(data)
                    else:
                        trust_config = ClientTrustConfig.from_tuf(
                            sigstore_tuf_url, offline=False
                        )
                    verifier = Verifier._from_trust_config(trust_config)
                else:
                    verifier = Verifier.production()
                # Identity policy: when the auditor pinned an expected
                # CI identity client-side, enforce it. Without the pin,
                # fall back to UnsafeNoOp — defends only against the
                # weaker threat model of "platform behaving honestly,
                # is the bundle internally consistent." With the pin,
                # also defends against "platform compromised, fabricated
                # bundle from attacker-controlled identity" — the
                # bundle's Fulcio SAN must match the auditor's known
                # CI identity, otherwise the platform's outer signature
                # cannot launder it.
                #
                # Issuer resolution: explicit --expected-issuer wins;
                # otherwise we map the auditor-pinned SAN's prefix to
                # the known OIDC issuer (github.com, gitlab.com). We
                # never read the bundle's own claim — that would let
                # the bundle self-attest its issuer and bypass the pin.
                # For self-hosted issuers the auditor must pin
                # --expected-issuer explicitly.
                resolved_issuer = expected_issuer or _infer_issuer(expected_ci_identity)
                if expected_ci_identity and not resolved_issuer:
                    console.print(
                        "  [red]Identity policy: cannot infer OIDC issuer from "
                        "the pinned SAN — pin --expected-issuer explicitly "
                        "(self-hosted GitHub Enterprise Server / self-managed "
                        "GitLab require this).[/red]"
                    )
                    has_failure = True
                else:
                    try:
                        if expected_ci_identity and resolved_issuer:
                            sig_policy = policy.Identity(
                                identity=expected_ci_identity,
                                issuer=resolved_issuer,
                            )
                        else:
                            sig_policy = policy.UnsafeNoOp()
                        # Use verify_dsse instead of verify_artifact so
                        # we can extract the in-toto Statement and check
                        # the auditor's pins on its predicate fields
                        # (model_id, commit_sha). verify_dsse verifies
                        # the trust chain, signature, and Rekor inclusion;
                        # we manually verify the artifact-binding by
                        # comparing the Statement's Subject digest to
                        # sha256(content_hash_str.encode()) — the same
                        # check verify_artifact would perform internally.
                        payload_type, payload_bytes = verifier.verify_dsse(
                            bundle, sig_policy
                        )
                        if payload_type != "application/vnd.in-toto+json":
                            raise ValueError(
                                f"unexpected DSSE payload type: {payload_type!r} "
                                "(expected 'application/vnd.in-toto+json')"
                            )
                        statement = json.loads(payload_bytes)
                        expected_subject_digest = hashlib.sha256(
                            content_hash_str.encode("utf-8")
                        ).hexdigest()
                        subjects = statement.get("subject", []) or []
                        if not any(
                            isinstance(s, dict)
                            and s.get("digest", {}).get("sha256")
                            == expected_subject_digest
                            for s in subjects
                        ):
                            raise ValueError(
                                "Bundle Subject digest does not match "
                                "sha256(content_integrity.results_hash); the "
                                "bundle was signed for a different artifact "
                                "than the package claims."
                            )
                        provenance_verified = True
                        console.print("  Bundle signature: [green]VERIFIED[/green]")
                        console.print("  Rekor inclusion:  [green]VERIFIED[/green] (Merkle proof checked)")
                        if expected_ci_identity and resolved_issuer:
                            issuer_note = "" if expected_issuer else " (issuer derived from SAN prefix)"
                            console.print(
                                f"  Identity policy:  [green]MATCHED[/green] "
                                f"(SAN={expected_ci_identity!r}, issuer={resolved_issuer!r}){issuer_note}"
                            )
                        else:
                            console.print(
                                "  Identity policy:  [yellow]SKIPPED[/yellow] "
                                "(no --expected-ci-identity pinned)"
                            )

                        # Extract predicate fields and check
                        # --expected-model-id / --expected-commit-sha pins.
                        # The predicate is part of the in-toto Statement
                        # signed inside the DSSE envelope, so its fields
                        # are cryptographically bound (an attacker cannot
                        # tamper without invalidating the bundle). We do
                        # NOT read these fields from the package's outer
                        # JSON metadata — those are unsigned and forgeable.
                        predicate = statement.get("predicate") or {}
                        if not isinstance(predicate, dict):
                            predicate = {}
                        bundle_model_id = predicate.get("model_id") or ""
                        pipeline_field = predicate.get("pipeline") or {}
                        if not isinstance(pipeline_field, dict):
                            pipeline_field = {}
                        bundle_commit_sha = pipeline_field.get("commit_sha") or ""
                        if expected_model_id:
                            if bundle_model_id == expected_model_id:
                                console.print(
                                    f"  Model ID pin:    [green]MATCHED[/green] "
                                    f"(predicate.model_id = {bundle_model_id!r})"
                                )
                            else:
                                console.print(
                                    f"  Model ID pin:    [red]MISMATCH[/red] "
                                    f"(expected {expected_model_id!r}, "
                                    f"bundle predicate has {bundle_model_id!r}). "
                                    "The audit package is for a different model "
                                    "than the auditor pinned."
                                )
                                has_failure = True
                        if expected_commit_sha:
                            if bundle_commit_sha == expected_commit_sha:
                                console.print(
                                    f"  Commit SHA pin:  [green]MATCHED[/green] "
                                    f"(predicate.pipeline.commit_sha = "
                                    f"{bundle_commit_sha!r})"
                                )
                            else:
                                console.print(
                                    f"  Commit SHA pin:  [red]MISMATCH[/red] "
                                    f"(expected {expected_commit_sha!r}, "
                                    f"bundle predicate has {bundle_commit_sha!r}). "
                                    "The audit package binds to a different "
                                    "commit than the auditor pinned — possible "
                                    "replay of an older verification run."
                                )
                                has_failure = True
                    except Exception as verr:
                        console.print(f"  Bundle signature: [red]FAILED — {verr}[/red]")
                        has_failure = True
            else:
                console.print("  [yellow]No content_hash in package — cannot cryptographically verify[/yellow]")
                # Bundle is present but there is nothing for it to bind
                # to (no results_hash). The platform produces bundles
                # together with content_integrity.results_hash; a
                # bundle without the corresponding hash is a malformed
                # / tampered package shape. Fail unconditionally
                # (regardless of pins) — accepting the package as
                # VERIFIED via a workspace-ECDSA fallback would emit
                # "VERIFIED — content intact" while a Sigstore bundle
                # the auditor sees in the package was effectively
                # ignored, which is misleading.
                console.print(
                    "  [red]The package contains a Sigstore bundle but no "
                    "content_integrity.results_hash for it to bind to. "
                    "Refusing to accept a structurally malformed package "
                    "where the bundle is present but cannot be verified.[/red]"
                )
                has_failure = True

            # Informational output only — the bundle has already
            # been cryptographically verified above (verify_dsse +
            # Subject digest binding + identity / predicate pins).
            # Each access is wrapped so a sigstore-python attribute
            # rename doesn't fail the audit verdict on what is
            # purely human-readable.
            try:
                console.print(f"  Certificate:      {cert.subject.rfc4514_string() or '(none)'}")
            except Exception:
                pass
            for label, attr in (
                ("Not before:      ", "not_valid_before_utc"),
                ("Not after:       ", "not_valid_after_utc"),
            ):
                try:
                    val = getattr(cert, attr).isoformat()
                    console.print(f"  {label}{val}")
                except Exception:
                    pass

            # Rekor entry UUID — derived from the bundle JSON
            # directly so we don't depend on sigstore-python's
            # introspection accessors (which were public protobuf
            # fields in 3.x but are hidden behind a private `_inner`
            # in 4.x). The bundle JSON path
            # `verificationMaterial.tlogEntries[0].canonicalizedBody`
            # is part of the documented sigstore-bundle/v0.3 spec.
            #
            # UUID derivation: SHA-256(0x00 || canonicalized_body)
            # per RFC 6962 leaf hashing — Rekor's Merkle-tree leaf
            # hash, which is the canonical retrieval key for the
            # public Rekor API (`rekor-cli get --uuid <UUID>` or
            # `GET https://rekor.sigstore.dev/api/v1/log/entries/<UUID>`).
            # log_index is a non-canonical secondary identifier;
            # UUID is what API consumers should pin against.
            #
            # The bundle's inclusion proof is already self-contained
            # (Merkle path + Rekor-signed checkpoint) and was
            # verified by verify_dsse — printing the UUID is for
            # auditors who want an out-of-band cross-check against
            # the public Rekor log without going through this tool.
            try:
                bundle_dict = json.loads(bundle_json)
                tlog_entries = (
                    bundle_dict.get("verificationMaterial", {})
                    .get("tlogEntries", [])
                )
                if tlog_entries:
                    canonical_b64 = tlog_entries[0].get("canonicalizedBody", "")
                    if canonical_b64:
                        body_bytes = base64.b64decode(canonical_b64)
                        leaf_hash = hashlib.sha256(b"\x00" + body_bytes).hexdigest()
                        console.print(f"  Rekor entry UUID: {leaf_hash}")
                        console.print(
                            f"  Independent lookup: rekor-cli get --uuid {leaf_hash}"
                        )
            except Exception:
                pass
        except Exception as e:
            console.print(f"  Bundle:           [red]INVALID — {e}[/red]")
            has_failure = True
    else:
        console.print("  [yellow]No Sigstore provenance in package[/yellow]")
        # When the auditor pinned any bundle-binding property
        # (--expected-ci-identity / --expected-model-id /
        # --expected-commit-sha), the absence of a Sigstore bundle is
        # itself a failure: a compromised platform fabricating a
        # report could simply omit the upstream evidence to bypass
        # pinning. Silently passing on a package with no evidence
        # defeats the auditor's intent.
        if expected_ci_identity or expected_model_id or expected_commit_sha:
            console.print(
                "  [red]A bundle-binding pin (--expected-ci-identity / "
                "--expected-model-id / --expected-commit-sha) was set but "
                "the package carries no Sigstore bundle. Pin enforcement is "
                "impossible without upstream evidence; a compromised "
                "platform could fabricate reports without bundles to bypass "
                "the pin.[/red]"
            )
            has_failure = True

    # --- Content Integrity ---
    console.print("\n[bold]Content Integrity (ECDSA P-256)[/bold]")
    ci_raw = pkg.get("content_integrity")
    # Normalise to dict-or-None: a malformed package (e.g.,
    # "content_integrity": "string" or [...]) must not crash audit()
    # at `ci.get("signature")` below.
    ci = ci_raw if isinstance(ci_raw, dict) else None

    # Canonical hash binding check — runs whenever the package claims
    # a results_hash, regardless of signature presence. The Sigstore
    # bundle (when present) binds to results_hash; if the package's
    # actual verification_run.results don't canonicalize to that hash,
    # the bundle is committing to a stale or forged claim and the
    # package is internally inconsistent. Without this top-level
    # check, a forged package with a real Sigstore bundle bound to
    # one hash and tampered results would slip through whenever
    # content_integrity carried no ECDSA signature.
    stored_hash = ""
    if ci and isinstance(ci, dict) and ci.get("results_hash"):
        try:
            results_for_hash = pkg["verification_run"]["results"]
            canonical = json.dumps(
                results_for_hash, sort_keys=True, separators=(",", ":")
            )
            computed_hash = (
                f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
            )
            stored_hash = ci["results_hash"]
            console.print(f"  Results hash:    {stored_hash}")
            console.print(f"  Recomputed hash: {computed_hash}")
            if computed_hash == stored_hash:
                console.print("  Hash match:      [green]YES[/green]")
            else:
                console.print(
                    "  Hash match:      [red]NO — results may have been "
                    "modified[/red]"
                )
                has_failure = True
        except (KeyError, TypeError) as e:
            console.print(f"  Hash check:      [red]FAILED — {e}[/red]")
            has_failure = True

    # The audit envelope may carry a `key_source` field declaring which
    # signing path produced this verification run. Three independently
    # verifiable paths are supported (see the Mipiti documentation page
    # "Evidence-driven Verification"); the verifier branches on this
    # discriminator so each path is checked appropriately:
    #
    #   "sigstore"            — Sigstore provenance: a Fulcio-issued
    #                           short-lived certificate plus a Rekor
    #                           transparency-log inclusion proof, both
    #                           verified above against Sigstore's
    #                           public trust root. This is the
    #                           canonical trust anchor for the row;
    #                           any redundant content_integrity
    #                           signature is not re-checked here.
    #   "platform"            — server-notarized via the issuer's
    #                           ECDSA P-256 key. The signing key is
    #                           published in the issuer's JWKS
    #                           endpoint (`/.well-known/jwks`), and
    #                           older retired keys remain published
    #                           there too so reports signed under
    #                           rotated keys still verify
    #                           indefinitely. The embedded
    #                           public_key_pem is the verifier input.
    #   "workspace"           — customer-uploaded ECDSA P-256 key.
    #                           Customers upload these in Workspace
    #                           Settings > Security > Signing Key for
    #                           CI systems that don't issue OIDC
    #                           tokens (Jenkins, Buildkite, air-gapped
    #                           runners, etc.). The embedded
    #                           public_key_pem is the verifier input;
    #                           the embedded workspace_id binds the
    #                           key to the workspace that owns the
    #                           threat model.
    #   "unverifiable_orphan" — the row's fingerprint does not appear
    #                           in the issuer's published key set
    #                           (JWKS / retired-keys history /
    #                           workspace-uploaded keys). The local
    #                           signature half cannot be checked, but
    #                           when the row carries Sigstore
    #                           provenance the report remains verified
    #                           via that path. Pinning
    #                           --expected-workspace-key on an
    #                           unresolved fingerprint is treated as
    #                           a hard fail since the pin's intent
    #                           cannot be satisfied.
    #
    # Audit envelopes without a `key_source` field (older issuer
    # builds) fall through to the legacy fingerprint-blind PEM
    # verification — same behaviour as before this discriminator was
    # introduced, so older packages continue to verify unchanged.
    key_source = ci.get("key_source", "") if ci else ""

    if ci and ci.get("signature"):
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            # stored_hash was set above by the canonical-hash check.
            # If results_hash was missing entirely, recover here so
            # the signature verify still has something to check
            # against — though that case implies a malformed package
            # (signature without a hash to sign over) and will fail
            # the verify call shortly after.
            if not stored_hash:
                stored_hash = ci.get("results_hash", "")

            # Verify signature
            pub_pem = ci.get("public_key_pem", "")
            if key_source == "sigstore":
                # The Sigstore bundle path above is authoritative for
                # this row; skip the redundant content_integrity verify
                # entirely. `provenance_verified` already reflects the
                # bundle's verdict.
                console.print(
                    "  Signature:       [cyan]SKIPPED[/cyan] "
                    "(Sigstore provenance is the trust anchor for this row)"
                )
                # Identity-pin enforcement still applies even for
                # sigstore rows: if the auditor pinned
                # --expected-workspace-key, we recompute the fingerprint
                # from public_key_pem (when populated) and compare it
                # to the pin. Match = pin satisfied; mismatch = forged-
                # key attack or wrong pin. Without pub_pem we can't do
                # the comparison cryptographically — fail explicitly.
                if expected_workspace_key_fingerprint:
                    if not pub_pem:
                        console.print(
                            "  [red]--expected-workspace-key was pinned but the "
                            "package has no public_key_pem to recompute the "
                            "fingerprint from.[/red]"
                        )
                        has_failure = True
                    else:
                        pub_key = serialization.load_pem_public_key(pub_pem.encode())
                        der_bytes = pub_key.public_bytes(
                            serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                        computed_fp = hashlib.sha256(der_bytes).hexdigest()
                        if computed_fp == expected_workspace_key_fingerprint:
                            console.print(
                                f"  Identity pin:    [green]MATCHED[/green] "
                                f"(workspace key = {expected_workspace_key_fingerprint!r})"
                            )
                        else:
                            console.print(
                                f"  Identity pin:    [red]MISMATCH[/red] "
                                f"(expected {expected_workspace_key_fingerprint!r}, "
                                f"got {computed_fp!r})."
                            )
                            has_failure = True
            elif pub_pem:
                pub_key = serialization.load_pem_public_key(pub_pem.encode())
                sig = base64.b64decode(ci["signature"])
                pub_key.verify(sig, stored_hash.encode(), ec.ECDSA(hashes.SHA256()))
                content_verified = True
                # Recompute the fingerprint from the public key actually
                # used for verification, using the same canonical
                # algorithm the platform uses (SHA-256 of the DER
                # SubjectPublicKeyInfo encoding). Without this, the
                # package's `key_fingerprint` field is just metadata —
                # a forged package could attach an attacker-controlled
                # PEM (which signs anything the attacker wants) and
                # claim any fingerprint it likes, defeating the
                # --expected-workspace-key pin.
                der_bytes = pub_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                computed_fp = hashlib.sha256(der_bytes).hexdigest()
                claimed_fp = ci.get("key_fingerprint", "")
                console.print(f"  Key fingerprint: {computed_fp}")
                console.print("  Signature:       [green]VALID[/green]")
                if claimed_fp and claimed_fp != computed_fp:
                    console.print(
                        f"  Fingerprint:     [red]CLAIM MISMATCH[/red] "
                        f"(package claims {claimed_fp!r}, "
                        f"recomputed from public_key_pem is {computed_fp!r}). "
                        "The package's stated fingerprint does not match the "
                        "key actually used for verification — possible forgery."
                    )
                    has_failure = True
                # Identity pin: when the auditor supplied
                # --expected-workspace-key, the recomputed fingerprint
                # of the public key actually used for verification MUST
                # match the customer's known workspace key. Mismatch =
                # either a platform-notarized submission (workspace
                # path wasn't used) or a forged signature from a
                # different key. Either way, the auditor wanted strict
                # matching, so fail loudly.
                if expected_workspace_key_fingerprint:
                    if computed_fp == expected_workspace_key_fingerprint:
                        console.print(
                            f"  Identity pin:    [green]MATCHED[/green] "
                            f"(workspace key = {expected_workspace_key_fingerprint!r})"
                        )
                    else:
                        console.print(
                            f"  Identity pin:    [red]MISMATCH[/red] "
                            f"(expected {expected_workspace_key_fingerprint!r}, "
                            f"got {computed_fp!r}). Possible causes: this submission "
                            "was platform-notarized rather than workspace-signed, "
                            "or the report was forged with a different key."
                        )
                        has_failure = True
                else:
                    console.print(
                        "  Identity pin:    [yellow]SKIPPED[/yellow] "
                        "(no --expected-workspace-key pinned)"
                    )
            elif key_source == "unverifiable_orphan":
                # The issuer's published key set has no entry for this
                # row's fingerprint, so the local signature can't be
                # cryptographically verified here. When the row carries
                # Sigstore provenance (verified above), that is the
                # canonical trust anchor and the report remains
                # verified — surfaced as a yellow note rather than a
                # hard fail. When the auditor pinned
                # --expected-workspace-key the pin's intent cannot be
                # satisfied without a resolvable key, so fail.
                fp = ci.get("key_fingerprint", "")
                console.print(
                    f"  Signature:       [yellow]UNRESOLVED[/yellow] — "
                    f"issuer's published key set has no entry for this row's "
                    f"fingerprint ({fp[:16]}…). When Sigstore provenance is "
                    "present (above), that is the canonical trust anchor and "
                    "the report remains verified."
                )
                if expected_workspace_key_fingerprint:
                    console.print(
                        "  [red]--expected-workspace-key was pinned but the "
                        "row's fingerprint did not resolve to any known key.[/red]"
                    )
                    has_failure = True
            else:
                console.print("  [yellow]No public key in package — cannot verify signature[/yellow]")
                if expected_workspace_key_fingerprint:
                    console.print(
                        "  [red]--expected-workspace-key was pinned but the "
                        "package has no public_key_pem to recompute the "
                        "fingerprint from.[/red]"
                    )
                    has_failure = True
        except Exception as e:
            console.print(f"  Signature:       [red]INVALID — {e}[/red]")
            has_failure = True
    else:
        console.print("  [yellow]No content integrity signature in package[/yellow]")
        # Same logic as the missing-bundle case: when the auditor pinned
        # the workspace key, omitting the content_integrity signature is
        # itself a failure. A compromised platform could otherwise drop
        # the signature to bypass the pin.
        if expected_workspace_key_fingerprint:
            console.print(
                "  [red]--expected-workspace-key was pinned but the package "
                "carries no content_integrity signature. The pin's intent "
                "(workspace-signed submissions) cannot be satisfied without "
                "a signature to verify.[/red]"
            )
            has_failure = True

    # --- Results ---
    # Normalise pkg sub-fields to their expected types so a forged
    # package with mismatched types (e.g. `"controls": []` instead of
    # an object, `"assertions_by_control": "string"`, `"sufficiency":
    # null`) doesn't crash the auditor's CI gate with AttributeError
    # mid-loop. Same hardening pattern applied to content_integrity
    # earlier; the security outcome is unchanged either way (exit
    # non-zero), but the message stays clean instead of being a Python
    # traceback.
    vr_raw = pkg.get("verification_run")
    vr = vr_raw if isinstance(vr_raw, dict) else {}
    results_raw = vr.get("results", [])
    results = results_raw if isinstance(results_raw, list) else []
    controls_raw = pkg.get("controls")
    controls_map = controls_raw if isinstance(controls_raw, dict) else {}
    assertions_raw = pkg.get("assertions_by_control")
    assertions_map = assertions_raw if isinstance(assertions_raw, dict) else {}
    sufficiency_raw = pkg.get("sufficiency")
    sufficiency_map = sufficiency_raw if isinstance(sufficiency_raw, dict) else {}

    # Group results by control. Use defensive .get so that a forged
    # package with missing fields produces a structural failure rather
    # than an uncaught KeyError traceback in the auditor's CI gate.
    # Missing `result` is treated as not-pass — we never want a
    # structural defect to be silently counted as success.
    by_ctrl: dict = {}
    malformed_count = 0
    for r in results:
        if not isinstance(r, dict):
            malformed_count += 1
            continue
        aid = r.get("assertion_id")
        if not aid:
            malformed_count += 1
            continue
        # Find which control this assertion belongs to
        ctrl_id = None
        for cid, asserts in assertions_map.items():
            if not isinstance(asserts, list):
                continue
            if any(isinstance(a, dict) and a.get("id") == aid for a in asserts):
                ctrl_id = cid
                break
        by_ctrl.setdefault(ctrl_id or "unknown", []).append(r)

    total_pass = sum(
        1 for r in results
        if isinstance(r, dict) and r.get("result") == "pass"
    )
    total_fail = sum(
        1 for r in results
        if not isinstance(r, dict) or r.get("result") != "pass"
    )
    if malformed_count:
        console.print(
            f"\n  [red]{malformed_count} malformed result entr"
            f"{'y' if malformed_count == 1 else 'ies'} (missing required "
            "fields). Treating as failure to avoid silent acceptance of "
            "structurally-invalid packages.[/red]"
        )
        has_failure = True
    ctrl_count = len(by_ctrl)
    suff_count = sum(
        1 for s in sufficiency_map.values()
        if isinstance(s, dict) and s.get("status") == "sufficient"
    )
    insuff_count = sum(
        1 for s in sufficiency_map.values()
        if isinstance(s, dict) and s.get("status") == "insufficient"
    )

    console.print(f"\n[bold]Results ({len(results)} assertions, {ctrl_count} controls)[/bold]")

    for ctrl_id, ctrl_results in sorted(by_ctrl.items()):
        ctrl_raw = controls_map.get(ctrl_id, {})
        ctrl = ctrl_raw if isinstance(ctrl_raw, dict) else {}
        desc = ctrl.get("description", "")
        console.print(f"\n  [bold]{ctrl_id}[/bold]  {desc}")

        for r in ctrl_results:
            passed = r.get("result") == "pass"
            icon = "[green]✓[/green]" if passed else "[red]✗[/red]"
            tier = r.get("tier", "?")
            details_raw = r.get("details", "")
            details = details_raw if isinstance(details_raw, str) else ""
            reasoning_raw = r.get("reasoning", details)
            reasoning = reasoning_raw if isinstance(reasoning_raw, str) else ""
            aid = r.get("assertion_id", "<unknown>")
            console.print(f"    {icon} {aid}  Tier {tier} {'PASS' if passed else 'FAIL'}")
            if reasoning:
                # Show full reasoning for failures, first line for passes
                if not passed:
                    for line in reasoning.split("\n"):
                        console.print(f"      {line}")
                    has_failure = True
                else:
                    first_line = reasoning.split(".")[0] + "." if "." in reasoning else reasoning[:100]
                    console.print(f"      {first_line}")

        # Sufficiency
        suff_raw = sufficiency_map.get(ctrl_id, {})
        suff = suff_raw if isinstance(suff_raw, dict) else {}
        suff_status = suff.get("status", "pending")
        suff_details = suff.get("details", "")
        if suff_status == "sufficient":
            console.print(f"    Sufficiency: [green]SUFFICIENT[/green]")
        elif suff_status == "insufficient":
            console.print(f"    Sufficiency: [blue]INSUFFICIENT[/blue]")
            if suff_details:
                console.print(f"      {suff_details}")
        else:
            console.print(f"    Sufficiency: [yellow]{suff_status}[/yellow]")

    # --- Verdict ---
    # Emit a verdict that accurately describes what was actually
    # verified. Without this, a package with no signatures (provenance
    # missing AND content_integrity missing) and no failed results
    # would print "VERIFIED — provenance authentic, content intact" —
    # both claims false. Track which checks succeeded and tailor the
    # text accordingly.
    console.print()
    if has_failure or total_fail > 0:
        console.print(f"[red bold]Verdict: FAILED[/red bold] — {total_pass}/{len(results)} assertions pass, "
                       f"{suff_count}/{ctrl_count} controls sufficient")
    elif not provenance_verified and not content_verified:
        # No cryptographic verification ran. Don't claim authenticity.
        console.print(
            f"[yellow bold]Verdict: UNVERIFIED[/yellow bold] — no Sigstore "
            f"provenance and no content_integrity signature were verified. "
            f"This package contains no cryptographic evidence of authenticity. "
            f"{total_pass}/{len(results)} assertions pass, "
            f"{suff_count}/{ctrl_count} controls sufficient"
        )
    elif insuff_count > 0:
        verified_parts = []
        if provenance_verified:
            verified_parts.append("provenance authentic")
        if content_verified:
            verified_parts.append("content intact")
        prefix = ", ".join(verified_parts) + ", " if verified_parts else ""
        console.print(f"[blue bold]Verdict: PARTIALLY VERIFIED[/blue bold] — "
                       f"{prefix}"
                       f"{total_pass}/{len(results)} assertions pass, "
                       f"{suff_count}/{ctrl_count} controls sufficient ({insuff_count} insufficient)")
    else:
        verified_parts = []
        if provenance_verified:
            verified_parts.append("provenance authentic")
        if content_verified:
            verified_parts.append("content intact")
        prefix = ", ".join(verified_parts) + ", " if verified_parts else ""
        console.print(f"[green bold]Verdict: VERIFIED[/green bold] — {prefix}"
                       f"{total_pass}/{len(results)} assertions pass, "
                       f"{suff_count}/{ctrl_count} controls sufficient")
    console.print()

    sys.exit(1 if (has_failure or total_fail > 0) else 0)
