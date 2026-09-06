"""Strategy B: dependence and reach from a hook-instrumented build.

The mutation strategy rewrites a mechanism's source and recompiles for
every mechanism. A compiled codebase that would rather build once can
instead place a *tripwire* inside the mechanism's own body, gated out of
production builds by a build flag. The tripwire reads
``MIPITI_DISABLE_MECHANISM`` and, when it equals its own mechanism id,
aborts with a message carrying ``mipiti-hook <file>::<symbol> at
<file>:<line>``. This module builds once with the hooks on, runs each
nominated test with its mechanism named, and reads the outcome.

A hook is customer-placed, so two checks guard against a misplaced one and
both are recorded in the attestation:

1. *Location proof.* Dependence is credited only when the abort output
   carries the marker and its ``file:line`` falls inside the mechanism's
   exactly located span. A test that failed without the marker records
   ``error`` (it could be any failure); a marker outside the span records
   ``error`` too. The location is recorded as ``hook_location``.
2. *Control run.* Before the pairs, every nominated test runs once with
   the variable set to a value no hook should answer to. Every test must
   pass; otherwise a hook fires regardless of the value, no pair can be
   credited, and the run stops with ``error`` on every pair.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .attestation import AttestationError
from .languages.adapters import (
    OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, AdapterError, DisableError,
    RunnerAdapter, parse_mechanism,
)
from .languages.adapters._common import REASON_NOT_ISOLATED, temp_dir

PAIR_TIMEOUT_SECONDS = 300
TOTAL_TIMEOUT_SECONDS = 1800
STRATEGY_HOOK = "hook"
STRATEGY_MUTATION = "mutation"
ENV_MECHANISM = "MIPITI_DISABLE_MECHANISM"
CONTROL_PREFIX = "mipiti-control-"

REASON_BUDGET_EXHAUSTED = "not run: dependence budget exhausted"
REASON_NO_MARKER = "test failed without the hook firing"
REASON_OUTSIDE = "hook fired outside the mechanism"
REASON_OTHER_HOOK = "a hook for a different mechanism fired"
REASON_CONTROL_FAILED = "hook fires unconditionally (control run failed)"

MARKER_RE = re.compile(r"mipiti-hook\s+(?P<mechanism>\S+)\s+at\s+(?P<file>\S+?):(?P<line>\d+)\b")


@dataclass(frozen=True)
class HookMarker:
    mechanism: str
    file: str
    line: int

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


def parse_marker(output: str) -> Optional[HookMarker]:
    """The first ``mipiti-hook <mechanism> at <file>:<line>`` in the output."""
    m = MARKER_RE.search(str(output or ""))
    if m is None:
        return None
    return HookMarker(m.group("mechanism"), m.group("file").replace("\\", "/"), int(m.group("line")))


_TYPE_KINDS = ("impl", "struct", "class")
_GO_RECEIVER = r"^func\s*\(\s*\w*\s*\*?\s*{name}(?:\[[^\]]*\])?\s*\)\s*(\w+)\s*\("


def mechanism_spans(project_root: Path, mechanism: str) -> tuple[list[tuple[int, int]], str]:
    """The mechanism's exactly located line spans, or ``([], reason)``.

    A function, method, or ``kind:name`` is one span, located exactly
    (``scope == "symbol"``), the same rule the mutation strategy requires. A
    type (``impl:T``, ``class:T``, or a bare name that is a type) is the
    type's own exactly located body where the language keeps methods inside
    it, and in Go the union of the receiver's exactly located methods.
    """
    from .languages.definitions import SCOPE_SYMBOL, language_of, locate
    from .verifiers.tests import mechanism_kinds

    try:
        mech = parse_mechanism(mechanism)
    except DisableError as e:
        return [], str(e)
    path = project_root / mech.file
    if not path.is_file():
        return [], f"{mech.file} is not a file under the project root"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [], f"cannot read {mech.file}: {e}"
    language = language_of(mech.file)

    def exact(kind: str, name: str):
        found = locate(content, kind, name, language=language)
        if found is None:
            return None, False
        return ((found.start_line, found.end_line) if found.scope == SCOPE_SYMBOL else None), True

    symbol = f"{mech.kind}:{mech.name}" if mech.kind and mech.kind not in _TYPE_KINDS else mech.name
    kinds, name = mechanism_kinds(symbol)
    seen_block = False
    if mech.kind not in _TYPE_KINDS:
        for kind in kinds:
            span, seen = exact(kind, name)
            if span is not None:
                return [span], ""
            seen_block = seen_block or seen
    if mech.kind in _TYPE_KINDS or not mech.owner:
        span, seen = exact("class", mech.name)
        if span is not None:
            return [span], ""
        seen_block = seen_block or seen
        if language == "go":
            spans = []
            for m in re.finditer(_GO_RECEIVER.format(name=re.escape(mech.name)), content, re.M):
                span, seen = exact("method", f"{mech.name}.{m.group(1)}")
                if span is not None:
                    spans.append(span)
                seen_block = seen_block or seen
            if spans:
                return spans, ""
    if seen_block:
        return [], REASON_NOT_ISOLATED
    return [], f"{symbol} is not defined in {mech.file}"


def mechanism_span(project_root: Path, mechanism: str) -> tuple[Optional[tuple[int, int]], str]:
    """The first of ``mechanism_spans``, for callers that need one range."""
    spans, reason = mechanism_spans(project_root, mechanism)
    return (spans[0] if spans else None), reason


def _relative(project_root: Path, file: str) -> str:
    path = Path(file)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(project_root.resolve()).as_posix()
        except (ValueError, OSError):
            return path.as_posix()
    return path.as_posix()


def marker_within(project_root: Path, mechanism: str, marker: HookMarker) -> tuple[bool, str]:
    """Whether the marker's ``file:line`` lies inside one of the mechanism's
    exactly located spans; ``(False, reason)`` otherwise.

    The file must be the mechanism's file: the same project-relative path,
    or a bare file name equal to its name (a Java stack frame carries no
    directory). A path under another directory is another file.
    """
    if marker.mechanism != mechanism:
        return False, REASON_OTHER_HOOK
    spans, reason = mechanism_spans(project_root, mechanism)
    if not spans:
        return False, f"{REASON_OUTSIDE}: {reason}"
    mech = parse_mechanism(mechanism)
    rel = _relative(project_root, marker.file)
    same_file = rel == mech.file or ("/" not in rel and rel == Path(mech.file).name)
    if not same_file:
        return False, f"{REASON_OUTSIDE}: fired in {rel}"
    for start, end in spans:
        if start <= marker.line <= end:
            return True, ""
    ranges = ", ".join(f"{s}-{e}" for s, e in spans)
    return False, f"{REASON_OUTSIDE}: fired at line {marker.line}, the definition spans {ranges}"


def classify_hook_run(status: str, note: str, output: str, project_root: Path,
                      mechanism: str) -> tuple[str, str, str]:
    """``(outcome, reason, hook_location)`` for one test run with its
    mechanism named.

    A passing test did not depend on the mechanism. A failing test is
    dependence only with the location proof: the marker for this mechanism,
    inside its span. A run that could not happen keeps its own reason.
    """
    if status == OUTCOME_PASSED:
        return OUTCOME_PASSED, "", ""
    if status == OUTCOME_ERROR and note and parse_marker(output) is None:
        return OUTCOME_ERROR, note, ""
    marker = parse_marker(output)
    if marker is None:
        return OUTCOME_ERROR, REASON_NO_MARKER, ""
    inside, reason = marker_within(project_root, mechanism, marker)
    if not inside:
        return OUTCOME_ERROR, reason, marker.location
    return OUTCOME_FAILED, "", marker.location


def control_id() -> str:
    return CONTROL_PREFIX + secrets.token_hex(6)


def control_run(adapter: RunnerAdapter, tests: list[str], *, timeout: int,
                mechanism: Optional[str] = None) -> dict:
    """Every nominated test once with a value no hook answers to."""
    ident = mechanism or control_id()
    results = []
    status = OUTCOME_PASSED
    for test in tests:
        try:
            outcome = adapter.hook_run(test, ident, timeout=timeout)
            entry = {"id": test, "status": outcome.status}
            if outcome.note:
                entry["reason"] = outcome.note
        except AdapterError as e:
            entry = {"id": test, "status": OUTCOME_ERROR, "reason": str(e)}
        if entry["status"] != OUTCOME_PASSED:
            status = OUTCOME_FAILED
        results.append(entry)
    return {"status": status, "mechanism": ident, "tests": results}


def _unique_tests(pairs: list[tuple[str, str]]) -> list[str]:
    seen: list[str] = []
    for test, _ in pairs:
        if test not in seen:
            seen.append(test)
    return seen


def run_hook_dependence(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    adapter: RunnerAdapter,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    total_timeout: int = TOTAL_TIMEOUT_SECONDS,
    progress: Optional[Callable[[str, str, str], None]] = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Build once with hooks on, run the control run, then every pair with
    its mechanism named. The summary has ``run_dependence``'s shape plus
    ``strategy`` and ``control_run`` for the record."""
    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    if not adapter.supports_hooks:
        raise AttestationError(adapter.hook_refusal)
    tests_out: list[dict] = []
    counts = {"passed": 0, "failed": 0, "errors": 0}
    not_run = 0
    started = clock()
    names = _unique_tests(pairs)

    def record(test: str, mechanism: str, status: str, reason: str = "", location: str = "") -> None:
        counts["errors" if status == OUTCOME_ERROR else status] += 1
        item = {"mechanism": mechanism, "status": status}
        if reason:
            item["reason"] = reason
        if location:
            item["hook_location"] = location
        tests_out.append({
            "id": test, "name": test.rsplit("::", 1)[-1], "status": status, "fails_without": [item],
        })
        if progress is not None:
            progress(test, mechanism, f"{status} ({reason})" if reason else status)

    def summary(control: Optional[dict]) -> dict:
        return {
            "totals": {
                "total": len(tests_out), "passed": counts["passed"], "failed": counts["failed"],
                "skipped": 0, "errors": counts["errors"],
            },
            "tests": tests_out,
            "not_run": not_run,
            "runner": adapter.name,
            "strategy": STRATEGY_HOOK,
            "control_run": control,
        }

    with temp_dir("mipiti-hook-") as tmp:
        try:
            adapter.hook_build(names, timeout=timeout, work_dir=Path(tmp))
        except AdapterError as e:
            for test, mechanism in pairs:
                record(test, mechanism, OUTCOME_ERROR, f"hook build failed: {e}")
            return summary(None)
        control = control_run(adapter, names, timeout=timeout)
        if control["status"] != OUTCOME_PASSED:
            for test, mechanism in pairs:
                record(test, mechanism, OUTCOME_ERROR, REASON_CONTROL_FAILED)
            return summary(control)
        for test, mechanism in pairs:
            if total_timeout > 0 and clock() - started >= total_timeout:
                not_run += 1
                record(test, mechanism, OUTCOME_ERROR, REASON_BUDGET_EXHAUSTED)
                continue
            try:
                outcome = adapter.hook_run(test, mechanism, timeout=timeout)
            except AdapterError as e:
                record(test, mechanism, OUTCOME_ERROR, str(e))
                continue
            status, reason, location = classify_hook_run(
                outcome.status, outcome.note, adapter.last_output, project_root, mechanism)
            record(test, mechanism, status, reason, location)
    return summary(control)


class _HookCoverageView:
    """The face ``run_reach`` needs, over a hook build: coverage runs go
    to ``hook_run_with_coverage`` with no mechanism named."""

    def __init__(self, adapter: RunnerAdapter) -> None:
        self._adapter = adapter
        self.name = adapter.name

    @property
    def last_outcome(self):
        return self._adapter.last_outcome

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        return self._adapter.hook_run_with_coverage(test_id, timeout=timeout, work_dir=work_dir)


def run_hook_reach(
    project_root: Path,
    pairs: list[tuple[str, str]],
    *,
    adapter: RunnerAdapter,
    timeout: int = PAIR_TIMEOUT_SECONDS,
    total_timeout: int = TOTAL_TIMEOUT_SECONDS,
    progress: Optional[Callable[[str, str, str], None]] = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Reach against the hook build: built once, each test alone under
    coverage with no mechanism named."""
    from .reach import run_reach

    if not pairs:
        raise AttestationError("No (test, mechanism) pairs to run.")
    if not adapter.supports_hooks:
        raise AttestationError(adapter.hook_refusal)
    with temp_dir("mipiti-hook-") as tmp:
        try:
            adapter.hook_build(_unique_tests(pairs), timeout=timeout, work_dir=Path(tmp))
        except AdapterError as e:
            tests = [{"id": t, "name": t.rsplit("::", 1)[-1], "mechanism": m, "status": OUTCOME_ERROR,
                      "reason": f"hook build failed: {e}"} for t, m in pairs]
            return {
                "totals": {"total": len(tests), "passed": 0, "failed": 0, "skipped": 0, "errors": len(tests)},
                "tests": tests, "not_run": 0, "runner": adapter.name, "strategy": STRATEGY_HOOK,
            }
        summary = run_reach(project_root, pairs, adapter=_HookCoverageView(adapter), timeout=timeout,
                            total_timeout=total_timeout, progress=progress, clock=clock)
    summary["strategy"] = STRATEGY_HOOK
    return summary
