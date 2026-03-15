"""CLI entry point for mipiti-verify."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

from .client import MipitiClient
from .runner import Runner

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
@click.option("--oidc-token", default=None, help="OIDC token for CI attestation (or auto-detect)")
@click.option(
    "--output",
    "output_format",
    type=click.Choice(["text", "json", "github"], case_sensitive=False),
    default="text",
    help="Output format",
)
@click.option("--dry-run", is_flag=True, help="Run verifiers but don't submit results")
@click.option("--reverify", is_flag=True, help="Re-verify all assertions, not just pending")
@click.option("--verbose", is_flag=True, help="Show per-assertion detail")
@click.option("--repo", default="", help="Repository name (e.g. org/repo). Auto-detected from GITHUB_REPOSITORY, CI_PROJECT_PATH, or git remote.")
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
    output_format: str,
    dry_run: bool,
    reverify: bool,
    verbose: bool,
    repo: str,
) -> None:
    """Run verification against pending assertions for MODEL_ID.

    Use --all to verify all models in the workspace associated with the API key.
    Use --reverify to re-verify all assertions (not just pending).
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

    runner = Runner(
        client=client,
        project_root=project_root,
        tier2_provider=tier2_provider,
        tier2_model=tier2_model,
        tier2_api_key=tier2_api_key,
        ollama_url=ollama_url,
        oidc_token=oidc_token,
        dry_run=dry_run,
        reverify=reverify,
        verbose=verbose,
        repo=repo,
    )

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

    if report.get("dry_run"):
        console.print("\n  [yellow]Dry run — results not submitted[/yellow]")
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
        passed = [d for d in tier_details if d["passed"]]
        failed = [d for d in tier_details if not d["passed"]]
        for d in passed:
            click.echo(f"  \u2713 {d['assertion_id']} ({d['type']}) tier{tier}: {d['details']}")
        for d in failed:
            click.echo(f"::error title=Verification Failed::{d['assertion_id']} "
                       f"({d['type']}): {d['details']}")
    t1f = report.get("tier1_fail", 0)
    t2f = report.get("tier2_fail", 0)
    if t1f or t2f:
        click.echo(f"::error title=Verification Summary::{t1f} tier1 failures, {t2f} tier2 failures")
    else:
        total = report.get("tier1_pass", 0) + report.get("tier2_pass", 0)
        click.echo(f"::notice title=Verification Passed::{total} assertions verified")


@main.command()
@click.argument("package_file", type=click.Path(exists=True))
def audit(package_file: str) -> None:
    """Verify an audit package independently.

    Checks OIDC provenance, content integrity (platform ECDSA signature),
    and lists all assertion results with reasoning.
    """
    import hashlib
    import base64

    with open(package_file) as f:
        pkg = json.load(f)

    console.print("\n[bold]Audit Package Verification[/bold]")
    console.print("=" * 40)
    has_failure = False

    # --- Provenance ---
    console.print("\n[bold]Provenance (OIDC)[/bold]")
    prov = pkg.get("provenance")
    if prov and prov.get("oidc_token"):
        try:
            import jwt
            from jwt import PyJWKClient

            token = prov["oidc_token"]
            jwks_url = prov.get("jwks_url", "")
            if not jwks_url:
                console.print("  [yellow]No JWKS URL — cannot verify OIDC token[/yellow]")
            else:
                client = PyJWKClient(jwks_url)
                signing_key = client.get_signing_key_from_jwt(token)
                claims = jwt.decode(
                    token, signing_key.key, algorithms=["RS256"],
                    audience="api.mipiti.io", options={"verify_exp": False},
                )
                console.print(f"  Issuer:      {claims.get('iss', 'unknown')}")
                console.print(f"  Repository:  {claims.get('repository', 'unknown')}")
                console.print(f"  Branch:      {claims.get('ref', 'unknown')}")
                console.print(f"  Commit:      {claims.get('sha', 'unknown')}")
                console.print(f"  Environment: {claims.get('environment', 'unknown')}")
                console.print(f"  Actor:       {claims.get('actor', 'unknown')}")
                console.print(f"  Run:         {claims.get('run_id', 'unknown')}")
                console.print("  Signature:   [green]VALID[/green]")
        except Exception as e:
            console.print(f"  Signature:   [red]INVALID — {e}[/red]")
            has_failure = True
    else:
        console.print("  [yellow]No OIDC provenance in package[/yellow]")

    # --- Content Integrity ---
    console.print("\n[bold]Content Integrity (ECDSA P-256)[/bold]")
    ci = pkg.get("content_integrity")
    if ci and ci.get("signature"):
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            # Recompute hash from results
            results = pkg["verification_run"]["results"]
            canonical = json.dumps(results, sort_keys=True, separators=(",", ":"))
            computed_hash = f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
            stored_hash = ci["results_hash"]

            console.print(f"  Results hash:    {stored_hash}")
            console.print(f"  Recomputed hash: {computed_hash}")
            if computed_hash == stored_hash:
                console.print("  Hash match:      [green]YES[/green]")
            else:
                console.print("  Hash match:      [red]NO — results may have been modified[/red]")
                has_failure = True

            # Verify signature
            pub_pem = ci.get("public_key_pem", "")
            if pub_pem:
                pub_key = serialization.load_pem_public_key(pub_pem.encode())
                sig = base64.b64decode(ci["signature"])
                pub_key.verify(sig, stored_hash.encode(), ec.ECDSA(hashes.SHA256()))
                console.print(f"  Key fingerprint: {ci.get('key_fingerprint', 'unknown')}")
                console.print("  Signature:       [green]VALID[/green]")
            else:
                console.print("  [yellow]No public key in package — cannot verify signature[/yellow]")
        except Exception as e:
            console.print(f"  Signature:       [red]INVALID — {e}[/red]")
            has_failure = True
    else:
        console.print("  [yellow]No content integrity signature in package[/yellow]")

    # --- Results ---
    results = pkg.get("verification_run", {}).get("results", [])
    controls_map = pkg.get("controls", {})
    assertions_map = pkg.get("assertions_by_control", {})
    sufficiency_map = pkg.get("sufficiency", {})

    # Group results by control
    by_ctrl: dict = {}
    for r in results:
        aid = r["assertion_id"]
        # Find which control this assertion belongs to
        ctrl_id = None
        for cid, asserts in assertions_map.items():
            if any(a["id"] == aid for a in asserts):
                ctrl_id = cid
                break
        by_ctrl.setdefault(ctrl_id or "unknown", []).append(r)

    total_pass = sum(1 for r in results if r["result"] == "pass")
    total_fail = sum(1 for r in results if r["result"] != "pass")
    ctrl_count = len(by_ctrl)
    suff_count = sum(1 for s in sufficiency_map.values() if s.get("status") == "sufficient")
    insuff_count = sum(1 for s in sufficiency_map.values() if s.get("status") == "insufficient")

    console.print(f"\n[bold]Results ({len(results)} assertions, {ctrl_count} controls)[/bold]")

    for ctrl_id, ctrl_results in sorted(by_ctrl.items()):
        ctrl = controls_map.get(ctrl_id, {})
        desc = ctrl.get("description", "")
        console.print(f"\n  [bold]{ctrl_id}[/bold]  {desc}")

        for r in ctrl_results:
            passed = r["result"] == "pass"
            icon = "[green]✓[/green]" if passed else "[red]✗[/red]"
            tier = r.get("tier", "?")
            details = r.get("details", "")
            reasoning = r.get("reasoning", details)
            console.print(f"    {icon} {r['assertion_id']}  Tier {tier} {'PASS' if passed else 'FAIL'}")
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
        suff = sufficiency_map.get(ctrl_id, {})
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
    console.print()
    if has_failure or total_fail > 0:
        console.print(f"[red bold]Verdict: FAILED[/red bold] — {total_pass}/{len(results)} assertions pass, "
                       f"{suff_count}/{ctrl_count} controls sufficient")
    elif insuff_count > 0:
        console.print(f"[blue bold]Verdict: PARTIALLY VERIFIED[/blue bold] — "
                       f"{total_pass}/{len(results)} assertions pass, "
                       f"{suff_count}/{ctrl_count} controls sufficient ({insuff_count} insufficient)")
    else:
        console.print(f"[green bold]Verdict: VERIFIED[/green bold] — provenance authentic, content intact, "
                       f"{total_pass}/{len(results)} assertions pass, "
                       f"{suff_count}/{ctrl_count} controls sufficient")
    console.print()

    sys.exit(1 if (has_failure or total_fail > 0) else 0)
