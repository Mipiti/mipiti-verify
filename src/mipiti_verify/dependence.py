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

import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from .attestation import AttestationError
from .languages.adapters import (
    OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, AdapterError, DisableError,
    RunnerAdapter, detect_adapter, language_of,
)

PAIR_TIMEOUT_SECONDS = 300
# Budget for the whole run, across pairs. Pairs that would start after it is
# spent are recorded as not run, so the attestation still names every pair
# that was asked for and a reader can tell "not run" from "ran and errored".
TOTAL_TIMEOUT_SECONDS = 1800
REASON_BUDGET_EXHAUSTED = "not run: dependence budget exhausted"

__all__ = [
    "OUTCOME_ERROR", "OUTCOME_FAILED", "OUTCOME_PASSED", "PAIR_TIMEOUT_SECONDS",
    "REASON_BUDGET_EXHAUSTED", "TOTAL_TIMEOUT_SECONDS", "adapter_for",
    "outcome_of", "pairs_from_assertions", "parse_pair", "run_dependence",
    "run_pair", "test_selector",
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

