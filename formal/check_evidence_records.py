"""Formal verification of how test-evidence records compose.

A ``test_attested`` verdict reads up to three signed records: the
test-result record (the test ran and passed), a reach record (what the test
executed, run alone) and a dependence record (how the test fared with its
mechanism disabled). The verdict is one bit and three facts. Which record
may supply which is an invariant of the type, and it is checked here over
EVERY combination of the record states, through the real verifier:

  R1  ``passed`` only when a test-result record at the verification commit
      names the test passed; a reach or dependence record never evidences
      a pass
  R2  ``evidence_hash`` is the test-result record's definition hash when it
      carries one, and empty otherwise
  R3  ``reached`` is True/False only from the test-result record's own
      per-test coverage; failing that, from a reach record at the same
      commit naming the same mechanism (or none) that was actually run;
      otherwise unknown
  R4  ``depends`` is True/False only from a dependence record at the same
      commit naming the same mechanism that was actually run; otherwise
      unknown
  R5  an assertion naming no mechanism gets neither fact
  R6  an entry that carries a ``reason`` (the pair was not run) never
      yields False: an outcome that was never produced is not evidence
      either way
  R7  a suite-scope reach record (``reach_scope = "suite"``, one
      whole-suite run, entries carrying ``suite_reached``) never sets
      ``reached``: whatever it says the suite executed, the fact comes
      from the other records or stays unknown, and when it stays unknown
      with such a record present the verdict says so
      (``reach_scope == "suite"``)
  R8  the enumeration exercises the whole schema: every field the
      test-result schema declares (record-level optional fields, every
      per-test field, every nested field) is carried by at least one
      enumerated statement, and no enumerated statement carries a field the
      schema does not declare. A schema addition without a matching axis
      value, or an emitted field the schema has not caught up with, fails
      the run

The space is the product of eight axes. Every statement is built once per
axis value and reused; the verifier reads them through its own loader,
handed the envelopes in memory, so the sweep stays fast.

Usage:
    python formal/check_evidence_records.py
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Tuple
from unittest.mock import patch

_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))

from mipiti_verify.attestation import build_statement, sign_statement  # noqa: E402
from mipiti_verify.verifiers import get_verifier  # noqa: E402
from mipiti_verify.verifiers import tests as tests_mod  # noqa: E402

_SCHEMA = Path(_ROOT) / "schemas" / "test-result-v1.schema.json"

COMMIT = "abc123def456abc123def456abc123def456abcd"
OTHER_COMMIT = "f" * 40
TEST = "test_missing_token_is_refused"
OTHER_TEST = "test_unrelated_arithmetic"
MECHANISM = "app/guard.py::require_token"
OTHER_MECHANISM = "app/guard.py::Limiter.allow"
DEFINITION_SHA = "9d2b" * 16

# The mechanism file: ``require_token`` occupies lines 4-7, ``Limiter.allow``
# lines 13-14. Reach is "an attested line inside the mechanism's span".
GUARD_SRC = '''"""A mechanism under test."""


def require_token(request):
    if not request.get("token"):
        raise PermissionError("no token")
    return True


class Limiter:
    def __init__(self, limit=3):
        self.limit = limit

    def allow(self, count):
        return count <= self.limit
'''
REACHING = [{"file": "app/guard.py", "lines": [5, 6]}]
MISSING = [{"file": "app/guard.py", "lines": [14]}]

# Environment the reader consults: the commit under verification, whether a
# CI identity could sign, and the customer key. Scrubbed so the unsigned
# no-CI / no-key configuration is what the sweep runs under everywhere.
_ENV = (
    "GITHUB_SHA", "CI_COMMIT_SHA", "CIRCLE_SHA1", "BUILDKITE_COMMIT",
    "GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL", "CI_CONFIG_PATH",
    "CI_COMMIT_REF_NAME", "SIGSTORE_ID_TOKEN", "MIPITI_ATTESTATION_PUBLIC_KEY",
)


@contextmanager
def _no_ci_no_key() -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in _ENV}
    try:
        for k in _ENV:
            os.environ.pop(k, None)
        yield
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


# ---------------------------------------------------------------------------
# Axes
# ---------------------------------------------------------------------------

TEST_RESULT = ("absent", "passed", "skipped", "failed", "other")
TR_COMMIT = ("matches", "differs")
DEFINITION = ("absent", "present")
COVERAGE = ("absent", "reaches", "misses")
REACH = ("absent", "same_reaching", "same_missing", "unnamed_reaching", "other_mechanism",
         "unrun_with_reason", "commit_differs")
DEPENDENCE = ("absent", "fails_without_failed", "hook_fails_without_failed", "fails_without_passed",
              "other_mechanism", "unrun_with_reason", "commit_differs")
ASSERTION_MECHANISM = ("absent", "present")
# A suite-scope reach record alongside: what the suite reached in the
# mechanism's file, or a suite run that did not touch it.
SUITE_REACH = ("absent", "suite_reaching", "suite_missing")


# Every field path the enumeration emits, recorded as statements are built
# (``tests[].reached[].lines``), for R8.
EMITTED_PATHS: set = set()


# Paths the schema declares as open maps (``additionalProperties``): their
# keys are data, not fields, so nothing below them is a path on either side.
OPEN_MAPS: set = set()


def _record_paths(node: object, prefix: str, into: set) -> None:
    if prefix in OPEN_MAPS:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else key
            into.add(path)
            _record_paths(value, path, into)
    elif isinstance(node, list):
        for item in node:
            _record_paths(item, prefix + "[]", into)


def _schema_paths(schema: dict, prefix: str = "") -> set:
    """Every declared field path, walked the same way the emitted ones are."""
    out: set = set()
    if schema.get("additionalProperties") not in (None, False) and not schema.get("properties"):
        OPEN_MAPS.add(prefix)  # keys are data (``coverage``, ``environment``), not fields
    for key, spec in (schema.get("properties") or {}).items():
        path = f"{prefix}.{key}" if prefix else key
        out.add(path)
        out |= _schema_paths(spec, path)
    items = schema.get("items")
    if isinstance(items, dict):
        out |= _schema_paths(items, prefix + "[]")
    return out


def _envelope(statement: dict) -> str:
    _record_paths(statement["predicate"], "", EMITTED_PATHS)
    envelope, provenance = sign_statement(statement)  # unsigned: nothing here could sign
    assert provenance == "unsigned"
    return envelope


def _test_result(state: str, commit: str, definition: str, coverage: str) -> str | None:
    if state == "absent":
        return None
    if state == "other":
        tests = [{"id": f"tests.test_guard::{OTHER_TEST}", "name": OTHER_TEST,
                  "classname": "tests.test_guard", "status": "passed"}]
    else:
        entry = {"id": f"tests.test_guard::{TEST}", "name": TEST,
                 "classname": "tests.test_guard", "status": state}
        if definition == "present":
            entry["file"] = "tests/test_guard.py"
            entry["definition_sha256"] = DEFINITION_SHA
            entry["definition_scope"] = "symbol"
            entry["parser"] = "ast"
        if coverage == "reaches":
            entry["reached"] = REACHING
        elif coverage == "misses":
            entry["reached"] = MISSING
        # A second, passing test keeps the run itself green, so the named
        # test's own status is the only thing that decides.
        tests = [entry, {"id": f"tests.test_guard::{OTHER_TEST}", "name": OTHER_TEST,
                         "classname": "tests.test_guard", "status": "passed"}]
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for t in tests:
        counts[t["status"]] += 1
    summary = {"totals": {"total": len(tests), **counts}, "tests": tests}
    statement = build_statement(
        commit=COMMIT if commit == "matches" else OTHER_COMMIT,
        summary=summary, invocation=["pytest", "-q"], selected_pattern="",
        # Record-level facts the verdict does not turn on, carried so the
        # enumeration exercises them: the run's nominated environment (the
        # assertion names no ``env`` requirement) and the run's lines-per-path
        # summary beside the per-test coverage it was derived from.
        environment={"FEATURE_AUTH": "on"} if state == "passed" else None,
        coverage={"app/guard.py": 2} if coverage != "absent" else None,
    )
    return _envelope(statement)


def _reach(state: str) -> str | None:
    if state == "absent":
        return None
    commit = OTHER_COMMIT if state == "commit_differs" else COMMIT
    entry: dict = {"id": f"tests.test_guard::{TEST}", "name": TEST, "status": "passed"}
    if state != "unnamed_reaching":
        entry["mechanism"] = OTHER_MECHANISM if state == "other_mechanism" else MECHANISM
    if state == "unrun_with_reason":
        entry.update({"status": "error", "reason": "no coverage tool for this runner"})
    elif state == "same_missing":
        entry["reached"] = MISSING
    else:
        entry["reached"] = REACHING
    errors = int(state == "unrun_with_reason")
    summary = {"totals": {"total": 1, "passed": 1 - errors, "failed": 0, "skipped": 0, "errors": errors},
               "tests": [entry]}
    return _envelope(build_statement(commit=commit, summary=summary, invocation=[], kind="reach"))


def _suite_reach(state: str) -> str | None:
    if state == "absent":
        return None
    entry = {"id": f"tests.test_guard::{TEST}", "name": TEST, "status": "passed",
             "mechanism": MECHANISM,
             "suite_reached": REACHING if state == "suite_reaching" else MISSING}
    summary = {"totals": {"total": 1, "passed": 1, "failed": 0, "skipped": 0, "errors": 0},
               "tests": [entry]}
    return _envelope(build_statement(commit=COMMIT, summary=summary, invocation=[],
                                     kind="reach", reach_scope="suite"))


def _dependence(state: str) -> str | None:
    if state == "absent":
        return None
    commit = OTHER_COMMIT if state == "commit_differs" else COMMIT
    mechanism = OTHER_MECHANISM if state == "other_mechanism" else MECHANISM
    status = "passed" if state == "fails_without_passed" else "failed"
    item: dict = {"mechanism": mechanism, "status": status}
    if state == "unrun_with_reason":
        item = {"mechanism": mechanism, "status": "error", "reason": "mutated tree does not compile"}
    extra = None
    if state == "hook_fails_without_failed":
        # The same fact from a hook-instrumented build: the record names the
        # strategy, where the tripwire sits, and the control run that showed
        # the hooks answer to nothing when no mechanism is named.
        item["hook_location"] = "app/guard.c:12"
        extra = {
            "strategy": "hook",
            "control_run": {
                "status": "passed", "mechanism": "<none>",
                "tests": [{"id": f"tests.test_guard::{TEST}", "status": "passed"},
                          {"id": f"tests.test_guard::{OTHER_TEST}", "status": "error",
                           "reason": "not selected for the control run"}],
            },
        }
    entry = {"id": f"tests.test_guard::{TEST}", "name": TEST, "status": item["status"],
             "fails_without": [item]}
    counts = {"passed": int(item["status"] == "passed"), "failed": int(item["status"] == "failed"),
              "skipped": 0, "errors": int(item["status"] == "error")}
    summary = {"totals": {"total": 1, **counts}, "tests": [entry]}
    return _envelope(build_statement(commit=commit, summary=summary, invocation=[], kind="dependence",
                                     predicate_extra=extra))


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------

def _expected(tr: str, tr_commit: str, definition: str, coverage: str,
              reach: str, dependence: str, mechanism: str) -> tuple[bool, str, object, object]:
    """``(passed, evidence_hash, reached, depends)`` from the facts alone."""
    passed = tr == "passed" and tr_commit == "matches"
    if not passed:
        return False, "", None, None
    evidence_hash = f"sha256:{DEFINITION_SHA}" if definition == "present" else ""
    if mechanism == "absent":
        return True, evidence_hash, None, None
    # R3: the test-result record's own coverage first.
    if coverage == "reaches":
        reached: object = True
    elif coverage == "misses":
        reached = False
    elif reach in ("same_reaching", "unnamed_reaching"):
        reached = True
    elif reach == "same_missing":
        reached = False
    else:  # absent, other mechanism, unrun (reason), commit differs
        reached = None
    # R4
    if dependence in ("fails_without_failed", "hook_fails_without_failed"):
        depends: object = True
    elif dependence == "fails_without_passed":
        depends = False
    else:
        depends = None
    return True, evidence_hash, reached, depends


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------

def check_records() -> Tuple[int, dict, List[str]]:
    violations: List[str] = []
    checked = 0
    per_property = {k: 0 for k in ("R1", "R2", "R3", "R4", "R5", "R6", "R7")}

    # Build every statement once per axis value.
    test_results = {
        (tr, c, d, cov): _test_result(tr, c, d, cov)
        for tr in TEST_RESULT for c in TR_COMMIT for d in DEFINITION for cov in COVERAGE
    }
    reaches = {r: _reach(r) for r in REACH}
    suite_reaches = {r: _suite_reach(r) for r in SUITE_REACH}
    dependences = {d: _dependence(d) for d in DEPENDENCE}

    project = Path(tempfile.mkdtemp(prefix="mipiti-formal-records-"))
    try:
        (project / ".git").mkdir()
        (project / ".git" / "HEAD").write_text(COMMIT)
        (project / "app").mkdir()
        (project / "app" / "guard.py").write_text(GUARD_SRC)
        verifier = get_verifier("test_attested")
        current: list = []

        def in_memory(_root: Path) -> list:
            return list(current)

        with _no_ci_no_key(), patch.object(tests_mod, "load_attestations", in_memory):
            for tr, c, d, cov, r, sr, dep, mech in itertools.product(
                    TEST_RESULT, TR_COMMIT, DEFINITION, COVERAGE, REACH, SUITE_REACH, DEPENDENCE,
                    ASSERTION_MECHANISM):
                current = [e for e in (test_results[(tr, c, d, cov)], reaches[r], suite_reaches[sr],
                                       dependences[dep]) if e]
                params = {"test": TEST}
                if mech == "present":
                    params["mechanism"] = MECHANISM
                result = verifier.verify(params, project)
                # The oracle takes no suite-reach argument: R7 is that the
                # axis cannot move any expected value.
                exp_passed, exp_hash, exp_reached, exp_depends = _expected(tr, c, d, cov, r, dep, mech)
                where = (f"test_result={tr}/{c} definition={d} coverage={cov} reach={r} "
                         f"suite_reach={sr} dependence={dep} mechanism={mech}")
                checked += 1

                per_property["R1"] += 1
                if result.passed != exp_passed:
                    violations.append(f"R1: {where}: passed={result.passed}, expected {exp_passed} ({result.details})")
                    continue
                per_property["R2"] += 1
                if result.evidence_hash != exp_hash:
                    violations.append(f"R2: {where}: evidence_hash={result.evidence_hash!r}, expected {exp_hash!r}")
                if mech == "absent":
                    per_property["R5"] += 1
                    if result.reached is not None or result.depends is not None:
                        violations.append(f"R5: {where}: facts stated with no mechanism named: "
                                          f"reached={result.reached} depends={result.depends}")
                else:
                    per_property["R3"] += 1
                    if result.reached is not exp_reached:
                        violations.append(f"R3: {where}: reached={result.reached}, expected {exp_reached}")
                    per_property["R4"] += 1
                    if result.depends is not exp_depends:
                        violations.append(f"R4: {where}: depends={result.depends}, expected {exp_depends}")
                    if r == "unrun_with_reason" and cov == "absent":
                        per_property["R6"] += 1
                        if result.reached is False:
                            violations.append(f"R6: {where}: an unrun reach entry yielded reached=False")
                    if dep == "unrun_with_reason":
                        per_property["R6"] += 1
                        if result.depends is False:
                            violations.append(f"R6: {where}: an unrun dependence entry yielded depends=False")
                    per_property["R7"] += 1
                    exp_scope = "suite" if (exp_passed and sr != "absent" and exp_reached is None) else ""
                    if result.reach_scope != exp_scope:
                        violations.append(f"R7: {where}: reach_scope={result.reach_scope!r}, expected {exp_scope!r}")
                if mech == "absent" and result.reach_scope:
                    violations.append(f"R7: {where}: reach_scope stated with no mechanism named")
    finally:
        shutil.rmtree(project, ignore_errors=True)
    return checked, per_property, violations


def declared_paths() -> set:
    return _schema_paths(json.loads(_SCHEMA.read_text(encoding="utf-8")))


def check_schema_coverage(declared: set) -> Tuple[int, List[str]]:
    """R8: emitted field paths and declared field paths are the same set."""
    violations: List[str] = []
    for path in sorted(declared - EMITTED_PATHS):
        violations.append(f"R8: schema field {path!r} is never emitted by the enumeration; add an axis value for it")
    for path in sorted(EMITTED_PATHS - declared):
        violations.append(f"R8: emitted field {path!r} is not declared by the schema")
    return len(declared | EMITTED_PATHS), violations


def main() -> int:
    print("=" * 70)
    print("TEST EVIDENCE RECORDS")
    print("=" * 70)
    space = (len(TEST_RESULT) * len(TR_COMMIT) * len(DEFINITION) * len(COVERAGE)
             * len(REACH) * len(SUITE_REACH) * len(DEPENDENCE) * len(ASSERTION_MECHANISM))
    print(f"\nEnumerating {space} record combinations through the real verifier "
          f"(8 axes: {len(TEST_RESULT)} x {len(TR_COMMIT)} x {len(DEFINITION)} x {len(COVERAGE)} "
          f"x {len(REACH)} x {len(SUITE_REACH)} x {len(DEPENDENCE)} x {len(ASSERTION_MECHANISM)})...\n")
    started = time.monotonic()
    declared = declared_paths()  # also settles which maps are open, before any statement is built
    checked, per_property, violations = check_records()
    schema_checked, schema_violations = check_schema_coverage(declared)
    violations += schema_violations
    elapsed = time.monotonic() - started

    if violations:
        print(f"FAILED ({len(violations)} violation(s) in {elapsed:.2f}s)")
        for v in violations[:50]:
            print(f"  {v}")
        if len(violations) > 50:
            print(f"  ... and {len(violations) - 50} more")
        return 1

    print(f"  R1 pass only from a test-result record at the commit:  {per_property['R1']} checks")
    print(f"  R2 evidence_hash from the record's definition hash:     {per_property['R2']} checks")
    print(f"  R3 reached from own coverage, else a run reach record:  {per_property['R3']} checks")
    print(f"  R4 depends from a run dependence record at the commit:  {per_property['R4']} checks")
    print(f"  R5 no mechanism named, no facts:                        {per_property['R5']} checks")
    print(f"  R6 an unrun entry never yields False:                   {per_property['R6']} checks")
    print(f"  R7 a suite-scope reach record never sets reached:       {per_property['R7']} checks")
    print(f"  R8 every schema field emitted, every emitted field declared: {schema_checked} field paths")
    print(f"\n{'=' * 70}")
    print("ALL EVIDENCE RECORD PROPERTIES VERIFIED")
    print(f"  Combinations: {checked} (exhaustive over the 8 axes) in {elapsed:.2f}s")
    print(f"{'=' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
