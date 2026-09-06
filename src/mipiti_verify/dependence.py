"""Dependence attestation: does a test fail once its mechanism is disabled?

This is one of the two commands in the package that run tests, and it runs
them in the customer's own test job, never during verification. Each
``(test, mechanism)`` pair is run once with the mechanism disabled through
the project's runner adapter (``languages.adapters``): an import-time stub
for Python, a mocking setup file for jest / vitest / mocha, and a
compile-checked source mutation, restored byte-for-byte afterwards, for
every other language. The outcome is recorded as a fact. A test that fails
without the mechanism depends on it. A test that still passes proves
nothing about the mechanism, and the record says so. A pair whose
mechanism could not be disabled, or whose mutated tree did not compile,
is recorded as ``error`` with the reason, which the verifier reads as
unknown, never as either outcome.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from .attestation import AttestationError
from .languages.adapters import (
    OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, AdapterError, DisableError,
    RunnerAdapter, detect_adapter, language_of,
)
from .languages.adapters._common import run_command

PAIR_TIMEOUT_SECONDS = 300
# Budget for the whole run, across pairs. Pairs that would start after it is
# spent are recorded as not run, so the attestation still names every pair
# that was asked for and a reader can tell "not run" from "ran and errored".
TOTAL_TIMEOUT_SECONDS = 1800
REASON_BUDGET_EXHAUSTED = "not run: dependence budget exhausted"
# Suite mode: the outcome comes from the report the whole-suite run wrote.
REASON_SKIPPED = "skipped under mutation"
REASON_NOT_IN_REPORT = "not in report"
REASON_NO_REPORT = "no report"
REASON_AMBIGUOUS = "names more than one test in the report"

__all__ = [
    "OUTCOME_ERROR", "OUTCOME_FAILED", "OUTCOME_PASSED", "PAIR_TIMEOUT_SECONDS",
    "REASON_BUDGET_EXHAUSTED", "REASON_NOT_IN_REPORT", "REASON_NO_REPORT",
    "REASON_SKIPPED", "TOTAL_TIMEOUT_SECONDS", "adapter_for", "group_by_mechanism",
    "outcome_of", "pairs_from_assertions", "parse_pair", "run_dependence",
    "run_pair", "run_suite_dependence", "suite_outcome", "test_selector",
]


def parse_pair(text: str) -> tuple[str, str]:
    """``(test, mechanism)`` from ``<test>=<file>::<symbol>``."""
    test, sep, mechanism = str(text or "").partition("=")
    test = test.strip()
    mechanism = mechanism.strip()
    if not sep or not test or "::" not in mechanism:
        raise AttestationError(
            f"Pair {text!r} is not <test>=<file>::<symbol>."
        )
    file, _, symbol = mechanism.partition("::")
    if not file.strip() or not symbol.strip():
        raise AttestationError(
            f"Pair {text!r} names no mechanism file or symbol."
        )
    return test, mechanism


def pairs_from_assertions(payload: dict) -> list[tuple[str, str]]:
    """The ``(test, mechanism)`` pairs a model's assertions name.

    Every ``test_attested`` assertion with a ``mechanism`` param contributes
    one pair; the rest say nothing about dependence.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    groups = []
    for key in ("controls", "assumptions"):
        block = payload.get(key) or {}
        if isinstance(block, dict):
            groups.extend(block.values())
    for assertions in groups:
        for a in assertions or []:
            if not isinstance(a, dict) or a.get("type") != "test_attested":
                continue
            params = a.get("params") or {}
            test = str(params.get("test") or params.get("pattern") or "").strip()
            mechanism = str(params.get("mechanism") or "").strip()
            if not test or "::" not in mechanism:
                continue
            pair = (test, mechanism)
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)
    return pairs


def test_selector(test: str) -> list[str]:
    """pytest arguments that select one test (see the pytest adapter)."""
    from .languages.adapters.pytest_ import test_selector as _selector

    return _selector(test)


def outcome_of(returncode: int, marker_written: bool) -> str:
    """The recorded outcome for a pytest exit status.

    pytest exits 0 when every selected test passed, 1 when one failed, and
    other codes when the run could not happen (interrupted, usage error,
    nothing collected). Only the first two say anything about dependence.
    """
    if marker_written:
        return OUTCOME_ERROR
    if returncode == 0:
        return OUTCOME_PASSED
    if returncode == 1:
        return OUTCOME_FAILED
    return OUTCOME_ERROR


def adapter_for(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    runner_name: str = "",
    run_cmd: str = "",
    coverage_cmd: str = "",
    coverage_file: str = "",
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> RunnerAdapter:
    """The adapter the pairs run through: the named one, the generic
    command adapter when a run command is given, else the one the project's
    files name, with the mechanisms' language breaking a tie."""
    languages = {language_of(m.partition("::")[0]) for _, m in pairs}
    languages.discard("")
    prefer = next(iter(languages)) if len(languages) == 1 else ""
    return detect_adapter(
        project_root, runner_name, run_cmd=run_cmd, coverage_cmd=coverage_cmd,
        coverage_file=coverage_file, prefer_language=prefer, runner=runner,
    )


def run_pair(
    project_root: Path,
    test: str,
    mechanism: str,
    *,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    adapter: Optional[RunnerAdapter] = None,
) -> dict:
    """Run one test with its mechanism disabled and record the outcome."""
    if adapter is None:
        adapter = adapter_for(project_root, [(test, mechanism)], runner=runner)
    try:
        with adapter.disable(mechanism) as handle:
            outcome = adapter.run(test, env=handle.env, timeout=timeout)
            reason = handle.failure_reason()
            if reason and outcome.status != OUTCOME_ERROR:
                outcome.status, outcome.note = OUTCOME_ERROR, reason
    except (DisableError, AdapterError) as e:
        record = {"mechanism": mechanism, "status": OUTCOME_ERROR, "returncode": -1,
                  "note": str(e)}
        return record
    record = {"mechanism": mechanism, "status": outcome.status, "returncode": outcome.returncode}
    if outcome.note:
        record["note"] = outcome.note
    return record


def run_dependence(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    total_timeout: int = TOTAL_TIMEOUT_SECONDS,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    progress: Optional[Callable[[str, str, str], None]] = None,
    clock: Callable[[], float] = time.monotonic,
    adapter: Optional[RunnerAdapter] = None,
) -> dict:
    """Run every pair and return a summary in the shape ``build_statement``
    takes: one test entry per pair, its ``status`` the outcome, and
    ``fails_without`` naming the mechanism that was disabled.

    ``total_timeout`` bounds the whole run. Once it is spent no further pair
    is started; each remaining pair is still recorded, as ``error`` with a
    ``reason`` saying it was not run, so every requested pair is present and
    an unrun pair is never read as evidence either way. A pair that ran but
    produced no outcome (the mechanism could not be disabled, the mutated
    tree did not compile, the runner selected no test, the run timed out)
    is ``error`` with the reason as well. The summary carries ``not_run``
    with the count and ``runner`` with the adapter's name.
    """
    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    if adapter is None:
        adapter = adapter_for(project_root, pairs, runner=runner)
    tests: list[dict] = []
    counts = {"passed": 0, "failed": 0, "errors": 0}
    not_run = 0
    started = clock()
    for test, mechanism in pairs:
        leaf = test.rsplit("::", 1)[-1]
        if total_timeout > 0 and clock() - started >= total_timeout:
            not_run += 1
            counts["errors"] += 1
            tests.append({
                "id": test,
                "name": leaf,
                "status": OUTCOME_ERROR,
                "fails_without": [{
                    "mechanism": mechanism,
                    "status": OUTCOME_ERROR,
                    "reason": REASON_BUDGET_EXHAUSTED,
                }],
            })
            if progress is not None:
                progress(test, mechanism, f"{OUTCOME_ERROR} ({REASON_BUDGET_EXHAUSTED})")
            continue
        record = run_pair(project_root, test, mechanism, timeout=timeout, runner=runner, adapter=adapter)
        status = record["status"]
        counts["errors" if status == OUTCOME_ERROR else status] += 1
        item = {"mechanism": mechanism, "status": status}
        if status == OUTCOME_ERROR and record.get("note"):
            item["reason"] = record["note"]
        tests.append({
            "id": test,
            "name": leaf,
            "status": status,
            "fails_without": [item],
        })
        if progress is not None:
            progress(test, mechanism, status if not item.get("reason") else f"{status} ({item['reason']})")
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
# Suite mode: one whole-suite run per mechanism
# ---------------------------------------------------------------------------

def group_by_mechanism(pairs: list[tuple[str, str]]) -> list[tuple[str, list[str]]]:
    """``[(mechanism, [tests...])]`` in first-seen order, tests deduplicated
    per mechanism. One disable and one suite run serve every test that
    names the same mechanism."""
    order: list[str] = []
    tests: dict[str, list[str]] = {}
    for test, mechanism in pairs:
        if mechanism not in tests:
            order.append(mechanism)
            tests[mechanism] = []
        if test not in tests[mechanism]:
            tests[mechanism].append(test)
    return [(m, tests[m]) for m in order]


def suite_outcome(report_status: Optional[str]) -> tuple[str, str]:
    """``(outcome, reason)`` for a test's status in the suite's JUnit report.

    ``passed`` and ``failed`` are what they say; ``error`` from the report is
    the test not passing (an exception under the disabled mechanism), so it
    carries no reason and reads as dependence. A ``skipped`` test produced no
    outcome, and a test absent from the report was never run: both are
    ``error`` with a reason, which the verifier reads as unknown.
    """
    if report_status == OUTCOME_PASSED:
        return OUTCOME_PASSED, ""
    if report_status == OUTCOME_FAILED:
        return OUTCOME_FAILED, ""
    if report_status == OUTCOME_ERROR:
        return OUTCOME_ERROR, ""
    if report_status == "skipped":
        return OUTCOME_ERROR, REASON_SKIPPED
    return OUTCOME_ERROR, REASON_NOT_IN_REPORT


def _junit_ids_for(test: str) -> list[str]:
    """The JUnit ``classname::name`` forms a pytest node id may appear under.

    A pair is nominated the way a person or an agent writes it, as a node id
    (``tests/test_guard.py::TestX::test_y``); pytest's JUnit report records
    the same test as ``tests.test_guard.TestX::test_y``. Exact forms only: the
    module path with ``/`` as ``.`` and the suffix dropped, with any class
    segments joined by ``.`` and the last segment as the name. A bare name is
    returned as itself.
    """
    if "::" not in test:
        return [test]
    path, *rest = test.split("::")
    if not rest:
        return [test]
    name = rest[-1].split("[", 1)[0]
    module = path
    for ext in (".py",):
        if module.endswith(ext):
            module = module[: -len(ext)]
    module = module.replace("\\", "/").strip("/").replace("/", ".")
    classes = ".".join(rest[:-1])
    classname = f"{module}.{classes}" if classes else module
    return [f"{classname}::{name}", test, name]


def _report_status(summary: dict, test: str) -> tuple[Optional[str], str]:
    """The named test's status in a parsed report, or ``(None, reason)``.

    Matched exactly on the nominated form first, then on the JUnit id a
    pytest node id maps to; a bare name last, so a node id never widens to
    every test of that name in another module unless nothing else matched."""
    from .verifiers.tests import _names_test

    entries = summary.get("tests") or []
    for candidate in _junit_ids_for(test):
        matched = [t for t in entries if _names_test(t, candidate)]
        if len(matched) > 1:
            return None, REASON_AMBIGUOUS
        if matched:
            return str(matched[0].get("status") or ""), ""
    return None, REASON_NOT_IN_REPORT


def run_suite_dependence(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    suite_cmd: str,
    suite_junit: str,
    adapter: RunnerAdapter,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    total_timeout: int = TOTAL_TIMEOUT_SECONDS,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    progress: Optional[Callable[[str, str, str], None]] = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Dependence from whole-suite runs, for harnesses that cannot select
    one test.

    Pairs are grouped by mechanism. For each distinct mechanism the adapter
    disables it (same gate, same restore as ``run_dependence``), the suite
    command runs once with ``timeout``, and the JUnit report it wrote gives
    every nominated test naming that mechanism its outcome
    (``suite_outcome``). A gate failure, a run that could not happen, or a
    missing report is ``error`` with the reason for every pair on that
    mechanism. ``total_timeout`` is spent across mechanisms: a mechanism
    that would start after it records every pair as not run. The result
    has the shape ``run_dependence`` returns, so the attestation is the
    same ``kind: "dependence"`` record.
    """
    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    if not suite_cmd.strip() or not suite_junit.strip():
        raise AttestationError("Suite mode needs both --suite-cmd and --suite-junit.")
    argv = shlex.split(suite_cmd)
    report_path = project_root / suite_junit
    tests: list[dict] = []
    counts = {"passed": 0, "failed": 0, "errors": 0}
    not_run = 0
    started = clock()

    def record(test: str, mechanism: str, status: str, reason: str = "") -> None:
        counts["errors" if status == OUTCOME_ERROR else status] += 1
        item = {"mechanism": mechanism, "status": status}
        if reason:
            item["reason"] = reason
        tests.append({
            "id": test, "name": test.rsplit("::", 1)[-1], "status": status,
            "fails_without": [item],
        })
        if progress is not None:
            progress(test, mechanism, f"{status} ({reason})" if reason else status)

    for mechanism, names in group_by_mechanism(pairs):
        if total_timeout > 0 and clock() - started >= total_timeout:
            for test in names:
                not_run += 1
                record(test, mechanism, OUTCOME_ERROR, REASON_BUDGET_EXHAUSTED)
            continue
        try:
            report_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            for test in names:
                record(test, mechanism, OUTCOME_ERROR, f"cannot remove a stale report: {e}")
            continue
        try:
            with adapter.disable(mechanism) as handle:
                _code, _out, err, note = run_command(
                    argv, cwd=project_root, env=handle.env, timeout=timeout, runner=runner)
                failure = handle.failure_reason()
        except (DisableError, AdapterError) as e:
            for test in names:
                record(test, mechanism, OUTCOME_ERROR, str(e))
            continue
        if note or failure:
            for test in names:
                record(test, mechanism, OUTCOME_ERROR, note or failure)
            continue
        if not report_path.is_file():
            for test in names:
                record(test, mechanism, OUTCOME_ERROR, REASON_NO_REPORT)
            continue
        try:
            summary = parse_junit_report(report_path)
        except AttestationError as e:
            for test in names:
                record(test, mechanism, OUTCOME_ERROR, str(e))
            continue
        for test in names:
            status, reason = _report_status(summary, test)
            if status is None:
                record(test, mechanism, OUTCOME_ERROR, reason)
                continue
            outcome, reason = suite_outcome(status)
            record(test, mechanism, outcome, reason)
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


def parse_junit_report(path: Path) -> dict:
    from .attestation import parse_junit

    return parse_junit(path)
