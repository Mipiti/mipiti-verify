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
@click.argument("model_id")
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
@click.option("--verbose", is_flag=True, help="Show per-assertion detail")
def run(
    model_id: str,
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
    verbose: bool,
) -> None:
    """Run verification against pending assertions for MODEL_ID."""
    try:
        client = MipitiClient(api_key=api_key, base_url=base_url)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    runner = Runner(
        client=client,
        project_root=project_root,
        tier2_provider=tier2_provider,
        tier2_model=tier2_model,
        tier2_api_key=tier2_api_key,
        ollama_url=ollama_url,
        oidc_token=oidc_token,
        dry_run=dry_run,
        verbose=verbose,
    )

    try:
        report = runner.run(model_id)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        client.close()

    if output_format == "json":
        click.echo(json.dumps(report, indent=2))
    elif output_format == "github":
        _github_output(report)
    else:
        _text_output(report, verbose)

    if (
        report.get("tier1_fail", 0) > 0
        or report.get("tier2_fail", 0) > 0
        or report.get("suff_insufficient", 0) > 0
    ):
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
    """Print GitHub Actions annotations."""
    for detail in report.get("details", []):
        if not detail["passed"]:
            click.echo(f"::error title=Verification Failed::{detail['assertion_id']} "
                       f"({detail['type']}): {detail['details']}")
    t1f = report.get("tier1_fail", 0)
    t2f = report.get("tier2_fail", 0)
    if t1f or t2f:
        click.echo(f"::error title=Verification Summary::{t1f} tier1 failures, {t2f} tier2 failures")
    else:
        total = report.get("tier1_pass", 0) + report.get("tier2_pass", 0)
        click.echo(f"::notice title=Verification Passed::{total} assertions verified")
