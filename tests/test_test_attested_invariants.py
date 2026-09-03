"""Exhaustive check of what a test attestation is allowed to establish.

The acceptance decision is a predicate over a handful of independent
dimensions, so the whole space is small enough to enumerate rather than
sample. Every state is reached by breadth-first search from a valid
attestation, mutating one field per step, and each is judged twice: once by
the verifier and once by an oracle written directly from the invariants
below. A disagreement is a defect in whichever is wrong.

Sampled tests find the failures someone thought of. The defects this file
exists to catch were all of the other kind: a guard that silently did not
apply because two operands were both empty, and a claim satisfied by a test
that was collected but never ran.
"""

from __future__ import annotations

from collections import deque
from itertools import product

import pytest

from mipiti_verify.attestation import PREDICATE_TYPE, PROVENANCE_UNSIGNED
from mipiti_verify.verifiers import get_verifier

COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
NAMED = "test_auth_is_enforced"

# Dimensions of the acceptance decision. The first value of each is the one a
# sound attestation carries, so the all-first state is the BFS root.
SPACE = {
    "commit": ("match", "mismatch", "absent"),
    "outcome": ("passed", "failed", "missing"),
    "matched_count": ("many", "one", "zero"),
    "totals": ("ok", "all_skipped", "with_failure", "incoherent", "negative"),
    "named": ("passed", "skipped", "failed", "absent", "duplicate", "legacy_string"),
}
FIELDS = tuple(SPACE)


def _tests_for(named: str) -> list:
    """The run's per-test records for a given treatment of the named test."""
    filler = [
        {"id": f"t::test_filler_{i}", "name": f"test_filler_{i}",
         "classname": "t", "status": "passed"}
        for i in range(2)
    ]
    entry = {"id": f"t::{NAMED}", "name": NAMED, "classname": "t"}
    if named == "absent":
        # A neighbouring name that a substring match would have accepted.
        return filler + [{"id": f"t::{NAMED}_todo", "name": f"{NAMED}_todo",
                          "classname": "t", "status": "passed"}]
    if named == "legacy_string":
        return filler + [f"t::{NAMED}"]
    if named == "duplicate":
        return filler + [dict(entry, status="passed"),
                         dict(entry, classname="u", id=f"u::{NAMED}", status="passed")]
    return filler + [dict(entry, status=named)]


def _totals_for(tests: list, shape: str) -> dict:
    """Totals describing that run, then bent into the requested shape."""
    def status_of(t):
        return t.get("status") if isinstance(t, dict) else "passed"

    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for t in tests:
        s = status_of(t)
        counts["errors" if s == "error" else s if s in counts else "passed"] += 1
    totals = dict(counts, total=len(tests))

    if shape == "all_skipped":
        return {"total": len(tests), "passed": 0, "failed": 0,
                "skipped": len(tests), "errors": 0}
    if shape == "with_failure":
        if totals["passed"]:
            totals = dict(totals, passed=totals["passed"] - 1,
                          failed=totals["failed"] + 1)
        else:
            totals = dict(totals, failed=totals["failed"] + 1,
                          total=totals["total"] + 1)
        return totals
    if shape == "incoherent":
        return dict(totals, total=totals["total"] + 7)
    if shape == "negative":
        return dict(totals, skipped=-1)
    return totals


def build(state: dict) -> tuple[dict, str]:
    """The statement a state describes, and the commit it is verified against."""
    tests = _tests_for(state["named"])
    totals = _totals_for(tests, state["totals"])
    predicate = {
        "invocation": ["pytest"],
        "totals": totals,
        "selected": {
            "pattern": "",
            "matched_count": {"many": len(tests), "one": 1, "zero": 0}[
                state["matched_count"]],
        },
        "tests": tests,
        "ci": {"provider": "github", "run_id": "1", "run_url": "", "workflow": "w"},
    }
    if state["outcome"] != "missing":
        predicate["outcome"] = state["outcome"]
    if state["commit"] == "match":
        predicate["commit"] = COMMIT
    elif state["commit"] == "mismatch":
        predicate["commit"] = OTHER_COMMIT

    return (
        {"_type": "https://in-toto.io/Statement/v1",
         "predicateType": PREDICATE_TYPE, "predicate": predicate},
        COMMIT,
    )


# ---------------------------------------------------------------------------
# The invariants, as an oracle
# ---------------------------------------------------------------------------

def oracle(statement: dict, test_name: str, commit: str) -> bool:
    """Whether the invariants permit this attestation to establish the claim.

    Written from the properties rather than from the implementation, so that
    agreement between the two is evidence and not a tautology.
    """
    p = statement.get("predicate") or {}
    totals = p.get("totals") or {}
    tests = p.get("tests") or []

    # I1  bound to the tree under verification, both sides present
    attested = str(p.get("commit") or "")
    if not attested or not commit or attested != commit:
        return False

    # I2  totals describe a run that could have happened
    try:
        parts = {k: int(totals.get(k) or 0)
                 for k in ("total", "passed", "failed", "skipped", "errors")}
    except (TypeError, ValueError):
        return False
    if any(v < 0 for v in parts.values()):
        return False
    if parts["passed"] + parts["failed"] + parts["skipped"] + parts["errors"] != parts["total"]:
        return False

    # I3  the records and the totals agree on how many tests there were
    if tests and len(tests) != parts["total"]:
        return False

    # I4  the run as a whole passed, and did so non-vacuously
    if p.get("outcome") != "passed":
        return False
    if int((p.get("selected") or {}).get("matched_count") or 0) <= 0:
        return False
    if parts["passed"] <= 0 or parts["failed"] or parts["errors"]:
        return False

    # I5  exactly one structured record names the test, and it passed
    named = [t for t in tests
             if isinstance(t, dict)
             and test_name in (str(t.get("id") or ""), str(t.get("name") or ""))]
    if len(named) != 1:
        return False
    return named[0].get("status") == "passed"


def verdict(state: dict) -> bool:
    statement, commit = build(state)
    return get_verifier("test_attested")._check(
        statement, NAMED, commit, PROVENANCE_UNSIGNED).passed


def _neighbours(state: dict):
    """States one single-field mutation away."""
    for field in FIELDS:
        for value in SPACE[field]:
            if value != state[field]:
                yield dict(state, **{field: value})


def _bfs_all_states() -> list[dict]:
    root = {f: SPACE[f][0] for f in FIELDS}
    seen = {tuple(root[f] for f in FIELDS)}
    order = [root]
    queue = deque([root])
    while queue:
        for nxt in _neighbours(queue.popleft()):
            key = tuple(nxt[f] for f in FIELDS)
            if key not in seen:
                seen.add(key)
                order.append(nxt)
                queue.append(nxt)
    return order


ALL_STATES = _bfs_all_states()


def test_bfs_reaches_the_entire_space():
    """The search covers every combination, so nothing below is sampled."""
    assert len(ALL_STATES) == len(list(product(*SPACE.values())))


def test_the_root_of_the_search_is_accepted():
    """A sound attestation verifies. Without this the suite could pass by
    rejecting everything."""
    assert verdict(ALL_STATES[0]) is True


def test_verifier_and_invariants_agree_on_every_state():
    disagreements = []
    for state in ALL_STATES:
        statement, commit = build(state)
        expected = oracle(statement, NAMED, commit)
        if verdict(state) != expected:
            disagreements.append(
                f"{state}: verifier={not expected}, invariants={expected}")
    assert not disagreements, "\n".join(disagreements[:10])


def test_every_accepted_state_satisfies_each_invariant():
    """Stated separately from the oracle so an accepting state is checked
    against the properties one at a time, and a failure names which."""
    for state in ALL_STATES:
        if not verdict(state):
            continue
        assert state["commit"] == "match", f"accepted unbound attestation: {state}"
        assert state["outcome"] == "passed", f"accepted a run that did not pass: {state}"
        assert state["matched_count"] != "zero", f"accepted an empty selection: {state}"
        assert state["totals"] == "ok", f"accepted incoherent totals: {state}"
        assert state["named"] == "passed", f"accepted without the named test passing: {state}"


def test_no_single_weakening_of_a_valid_attestation_is_accepted():
    """Every one-step mutation away from an accepted state is rejected.

    This is the property a guard that fails open violates: it holds for the
    mismatch case while quietly not holding when the field is absent.
    """
    accepted = [s for s in ALL_STATES if verdict(s)]
    assert accepted
    for state in accepted:
        for neighbour in _neighbours(state):
            if verdict(neighbour):
                assert neighbour in accepted, (
                    f"weakening {state} into {neighbour} was accepted")


@pytest.mark.parametrize("field,value", [
    ("commit", "absent"), ("commit", "mismatch"),
    ("outcome", "missing"), ("outcome", "failed"),
    ("matched_count", "zero"),
    ("totals", "all_skipped"), ("totals", "incoherent"), ("totals", "negative"),
    ("named", "skipped"), ("named", "failed"),
    ("named", "absent"), ("named", "legacy_string"), ("named", "duplicate"),
])
def test_each_defect_alone_is_enough_to_reject(field, value):
    """No single defect depends on another to be caught."""
    state = dict({f: SPACE[f][0] for f in FIELDS}, **{field: value})
    assert verdict(state) is False, f"{field}={value} was accepted on its own"
