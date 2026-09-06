"""Dependence attestation: does a test fail once its mechanism is disabled?

This is the one command in the package that runs tests, and it runs them in
the customer's own test job, never during verification. Each ``(test,
mechanism)`` pair is run once with the mechanism replaced by a stub (see
``_disable_plugin``); the outcome is recorded as a fact. A test that fails
without the mechanism depends on it. A test that still passes proves
nothing about the mechanism, and the record says so.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional

from .attestation import AttestationError, base_test_name

PAIR_TIMEOUT_SECONDS = 300

OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_ERROR = "error"


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
    """pytest arguments that select one test.

    A ``path::name`` node id is used as given. A bare name -- or a
    ``classname::name`` id from a JUnit report, whose dotted prefix pytest
    cannot select by -- becomes a ``-k`` expression on the function name.
    """
    text = str(test or "").strip()
    if "::" in text:
        head = text.split("::", 1)[0]
        if head.endswith(".py") or "/" in head:
            return [text]
        text = text.rsplit("::", 1)[-1]
    return ["-k", base_test_name(text)]


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


def run_pair(
    project_root: Path,
    test: str,
    mechanism: str,
    *,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
) -> dict:
    """Run one test with its mechanism disabled and record the outcome."""
    call = runner or subprocess.run
    with tempfile.TemporaryDirectory(prefix="mipiti-dep-") as tmp:
        marker = Path(tmp) / "marker"
        env = dict(os.environ)
        env["MIPITI_DISABLE_MECHANISM"] = mechanism
        env["MIPITI_DISABLE_MARKER"] = str(marker)
        argv = [
            sys.executable, "-m", "pytest", "-q",
            "-p", "mipiti_verify._disable_plugin",
            *test_selector(test),
        ]
        try:
            completed = call(
                argv, cwd=str(project_root), env=env,
                capture_output=True, text=True, timeout=timeout,
            )
            returncode = int(completed.returncode)
            note = ""
        except subprocess.TimeoutExpired:
            returncode = -1
            note = f"timed out after {timeout}s"
        except OSError as e:
            returncode = -1
            note = f"could not start pytest: {e}"
        marker_written = marker.is_file()
        if marker_written and not note:
            try:
                note = marker.read_text(encoding="utf-8").strip()
            except OSError:
                note = "mechanism could not be disabled"
    outcome = outcome_of(returncode, marker_written)
    record = {"mechanism": mechanism, "status": outcome, "returncode": returncode}
    if note:
        record["note"] = note
    return record


def run_dependence(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
    progress: Optional[Callable[[str, str, str], None]] = None,
) -> dict:
    """Run every pair and return a summary in the shape ``build_statement``
    takes: one test entry per pair, its ``status`` the outcome, and
    ``fails_without`` naming the mechanism that was disabled."""
    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    tests: list[dict] = []
    counts = {"passed": 0, "failed": 0, "errors": 0}
    for test, mechanism in pairs:
        record = run_pair(project_root, test, mechanism, timeout=timeout, runner=runner)
        status = record["status"]
        counts["errors" if status == OUTCOME_ERROR else status] += 1
        leaf = test.rsplit("::", 1)[-1]
        tests.append({
            "id": test,
            "name": leaf,
            "status": status,
            "fails_without": [{"mechanism": mechanism, "status": status}],
        })
        if progress is not None:
            progress(test, mechanism, status)
    return {
        "totals": {
            "total": len(tests),
            "passed": counts["passed"],
            "failed": counts["failed"],
            "skipped": 0,
            "errors": counts["errors"],
        },
        "tests": tests,
    }
