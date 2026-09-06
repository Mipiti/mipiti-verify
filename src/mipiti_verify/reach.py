"""Reach attestation: which lines of its mechanism's file did a test run?

The second of the two commands in the package that run tests, and like
``attest-dependence`` it belongs in the customer's own test job. Each
nominated test is run alone under the language's coverage tool through the
project's runner adapter, and the lines it executed in the mechanism's
file are recorded per test as ``reached: [{file, lines}]``, the same shape
``attest-tests --coverage`` records from a coverage.py context report.
Only the mechanism's file is kept: the verifier needs no more, and a whole
per-test coverage map would bloat the statement.

Running one test at a time is what makes this a claim about *that* test:
an aggregate report can only say the suite reached a line.

Suite mode (``run_suite_reach``) is for a harness that cannot run one test
alone. The suite runs once under coverage and what it reached in each
mechanism's file is recorded per nominated test as ``suite_reached``, with
``predicate.reach_scope = "suite"``. That is a different statement:
per-test reach is undefined for such a harness, so the record says what
the suite reached and never ``reached``; the verifier reads it as
information and leaves the reach fact unknown.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from .attestation import AttestationError
from .languages.adapters import (
    OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, AdapterError, DisableError, RunnerAdapter,
    parse_mechanism,
)
from .languages.adapters._common import run_command, temp_dir

PAIR_TIMEOUT_SECONDS = 300
TOTAL_TIMEOUT_SECONDS = 1800
REASON_BUDGET_EXHAUSTED = "not run: reach budget exhausted"
REASON_NO_REPORT = "no coverage report"
KIND_REACH = "reach"
# ``predicate.reach_scope``: what a reach record's coverage is scoped to.
REACH_SCOPE_TEST = "test"
REACH_SCOPE_SUITE = "suite"


def executed_lines(report: Path, project_root: Path) -> dict[str, set[int]]:
    """``{project-relative file: executed lines}`` for a single-test run.

    The package's coverage readers are used when present; the adapters'
    own reader (which knows exactly the formats they emit) otherwise.
    """
    try:
        from .coverage_readers import read_coverage
    except ImportError:
        read_coverage = None
    if read_coverage is not None:
        try:
            parsed = read_coverage(report, project_root)
            merged = parsed.all_lines() if hasattr(parsed, "all_lines") else None
            if isinstance(merged, dict):
                return {str(k).replace("\\", "/"): set(int(n) for n in v) for k, v in merged.items()}
        except Exception:  # noqa: BLE001
            pass
    from .languages.adapters.coverage_read import executed_lines as _fallback

    return _fallback(report, project_root)


def run_reach_pair(
    project_root: Path,
    test: str,
    mechanism: str,
    *,
    adapter: RunnerAdapter,
    timeout: int = PAIR_TIMEOUT_SECONDS,
) -> dict:
    """Run one test alone under coverage; ``{status, reached | reason}``."""
    try:
        mech = parse_mechanism(mechanism)
    except DisableError as e:
        return {"status": OUTCOME_ERROR, "reason": str(e)}
    with temp_dir("mipiti-reach-") as tmp:
        try:
            report = adapter.run_with_coverage(test, timeout=timeout, work_dir=Path(tmp))
        except (AdapterError, DisableError) as e:
            return {"status": OUTCOME_ERROR, "reason": str(e)}
        outcome = getattr(adapter, "last_outcome", None)
        status = outcome.status if outcome is not None else "passed"
        if status == OUTCOME_ERROR:
            return {"status": OUTCOME_ERROR, "reason": outcome.note or "the coverage run produced no outcome"}
        try:
            lines = executed_lines(Path(report), project_root)
        except Exception as e:  # noqa: BLE001
            return {"status": OUTCOME_ERROR, "reason": f"cannot read the coverage report: {e}"}
    hit = sorted(lines.get(mech.file, set()))
    reached = [{"file": mech.file, "lines": hit}] if hit else []
    return {"status": status, "reached": reached}


def run_reach(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    adapter: RunnerAdapter,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    total_timeout: int = TOTAL_TIMEOUT_SECONDS,
    progress: Optional[Callable[[str, str, str], None]] = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Run every pair and return a summary in the shape ``build_statement``
    takes: one test entry per pair with its outcome under coverage and the
    lines it reached in the mechanism's file.

    The budget rules match ``run_dependence``: a pair that would start
    after ``total_timeout`` is spent is recorded as ``error`` with a
    ``reason``, as is a pair whose coverage run could not happen, so every
    requested pair is present and none is read as evidence it did not
    produce.
    """
    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    tests: list[dict] = []
    counts = {"passed": 0, "failed": 0, "errors": 0}
    not_run = 0
    started = clock()
    for test, mechanism in pairs:
        leaf = test.rsplit("::", 1)[-1]
        entry = {"id": test, "name": leaf, "mechanism": mechanism}
        if total_timeout > 0 and clock() - started >= total_timeout:
            not_run += 1
            counts["errors"] += 1
            entry.update({"status": OUTCOME_ERROR, "reason": REASON_BUDGET_EXHAUSTED})
            tests.append(entry)
            if progress is not None:
                progress(test, mechanism, f"{OUTCOME_ERROR} ({REASON_BUDGET_EXHAUSTED})")
            continue
        record = run_reach_pair(project_root, test, mechanism, adapter=adapter, timeout=timeout)
        status = record["status"]
        counts["errors" if status == OUTCOME_ERROR else status] += 1
        entry["status"] = status
        if "reached" in record:
            entry["reached"] = record["reached"]
        if record.get("reason"):
            entry["reason"] = record["reason"]
        tests.append(entry)
        if progress is not None:
            if record.get("reason"):
                progress(test, mechanism, f"{status} ({record['reason']})")
            else:
                n = sum(len(r["lines"]) for r in record.get("reached", []))
                progress(test, mechanism, f"{status}, {n} line(s) of the mechanism file reached")
    return {
        "totals": {
            "total": len(tests),
            "passed": counts["passed"],
            "failed": counts["failed"],
            "skipped": 0,
            "errors": counts["errors"],
        },
        "tests": tests,
        "not_run": not_run,
        "runner": adapter.name,
    }


# ---------------------------------------------------------------------------
# Suite mode: one whole-suite run under coverage
# ---------------------------------------------------------------------------

def run_suite_reach(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    suite_cmd: str,
    coverage_file: str,
    adapter: RunnerAdapter,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    progress: Optional[Callable[[str, str, str], None]] = None,
) -> dict:
    """Suite-level reach, for harnesses that cannot run one test alone.

    The suite command runs ONCE with ``timeout``; the coverage report it
    writes at ``coverage_file`` is read with the package's readers, and
    every nominated test records the lines the suite executed in its
    mechanism's file as ``suite_reached`` -- never ``reached``, which is a
    claim about one test that a whole-suite run cannot make. Each entry's
    ``status`` is the suite command's exit (``passed`` on 0, ``failed``
    otherwise); a run that could not happen, or a report that is missing
    or unreadable, is ``error`` with the reason for every pair. The result
    has the shape ``run_reach`` returns, so the attestation is the same
    ``kind: "reach"`` record; the caller marks it ``reach_scope = "suite"``.
    """
    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    if not suite_cmd.strip() or not coverage_file.strip():
        raise AttestationError("Suite mode needs both --suite-cmd and --coverage-file.")
    argv = shlex.split(suite_cmd)
    report_path = project_root / coverage_file
    tests: list[dict] = []
    counts = {"passed": 0, "failed": 0, "errors": 0}

    def record(test: str, mechanism: str, status: str, *, reason: str = "",
               suite_reached: Optional[list] = None) -> None:
        counts["errors" if status == OUTCOME_ERROR else status] += 1
        entry = {"id": test, "name": test.rsplit("::", 1)[-1], "mechanism": mechanism,
                 "status": status}
        if reason:
            entry["reason"] = reason
        elif suite_reached is not None:
            entry["suite_reached"] = suite_reached
        tests.append(entry)
        if progress is not None:
            if reason:
                progress(test, mechanism, f"{status} ({reason})")
            else:
                n = sum(len(r["lines"]) for r in suite_reached or [])
                progress(test, mechanism, f"{status}, the suite reached {n} line(s) of the mechanism file")

    def fan_out(status: str, reason: str) -> None:
        for test, mechanism in pairs:
            record(test, mechanism, status, reason=reason)

    try:
        report_path.unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        fan_out(OUTCOME_ERROR, f"cannot remove a stale report: {e}")
        return _suite_summary(tests, counts, adapter)

    code, _out, _err, note = run_command(argv, cwd=project_root, timeout=timeout, runner=runner)
    if note:
        fan_out(OUTCOME_ERROR, note)
        return _suite_summary(tests, counts, adapter)
    if not report_path.exists():
        fan_out(OUTCOME_ERROR, REASON_NO_REPORT)
        return _suite_summary(tests, counts, adapter)
    try:
        from .coverage_readers import read_coverage

        lines = {str(k).replace("\\", "/"): set(int(n) for n in v)
                 for k, v in read_coverage(report_path, project_root).all_lines().items()}
    except Exception as e:  # noqa: BLE001 - any unreadable report is the same error
        fan_out(OUTCOME_ERROR, f"cannot read the coverage report: {e}")
        return _suite_summary(tests, counts, adapter)
    status = OUTCOME_PASSED if code == 0 else OUTCOME_FAILED
    for test, mechanism in pairs:
        try:
            mech = parse_mechanism(mechanism)
        except DisableError as e:
            record(test, mechanism, OUTCOME_ERROR, reason=str(e))
            continue
        hit = sorted(lines.get(mech.file, set()))
        record(test, mechanism, status,
               suite_reached=[{"file": mech.file, "lines": hit}] if hit else [])
    return _suite_summary(tests, counts, adapter)


def _suite_summary(tests: list[dict], counts: dict, adapter: RunnerAdapter) -> dict:
    return {
        "totals": {
            "total": len(tests),
            "passed": counts["passed"],
            "failed": counts["failed"],
            "skipped": 0,
            "errors": counts["errors"],
        },
        "tests": tests,
        "not_run": 0,
        "runner": adapter.name,
    }
