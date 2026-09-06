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
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from .attestation import AttestationError
from .languages.adapters import (
    OUTCOME_ERROR, AdapterError, DisableError, RunnerAdapter, parse_mechanism,
)
from .languages.adapters._common import temp_dir

PAIR_TIMEOUT_SECONDS = 300
TOTAL_TIMEOUT_SECONDS = 1800
REASON_BUDGET_EXHAUSTED = "not run: reach budget exhausted"
KIND_REACH = "reach"


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
