"""A dependence pair that recorded no outcome says why, in the details only."""

from mipiti_verify.verifiers.tests import (
    _dependence_reason,
    _depends_on_mechanism,
    _evidence_facts,
    _facts_sentence,
)

COMMIT = "a" * 40
MECH = "app/auth.py::require_token"


def _statement(reason: str = "", status: str = "error") -> dict:
    item = {"mechanism": MECH, "status": status}
    if reason:
        item["reason"] = reason
    return {"predicate": {"commit": COMMIT, "kind": "dependence",
                          "tests": [{"id": "tests/test_a.py::test_rejects", "name": "test_rejects",
                                     "status": status, "fails_without": [item]}]}}


def test_a_reason_leaves_the_fact_unknown_and_is_reported():
    dep = [_statement("x.go is not in a git checkout (or git is not installed), so a source mutation could not be proven restored")]
    assert _depends_on_mechanism(dep, "test_rejects", COMMIT, MECH) is None
    assert "git checkout" in _dependence_reason(dep, "test_rejects", COMMIT, MECH)
    facts = _evidence_facts({"definition_sha256": "f" * 64}, "test_rejects", {"mechanism": MECH},
                            None, dep, COMMIT)
    assert "depends" not in facts
    assert facts["depends_reason"].startswith("x.go is not in a git checkout")
    sentence = _facts_sentence(facts, True)
    assert "fails without mechanism: not established (x.go is not in a git checkout" in sentence


def test_an_outcome_carries_no_reason():
    dep = [_statement(status="failed")]
    assert _depends_on_mechanism(dep, "test_rejects", COMMIT, MECH) is True
    assert _dependence_reason(dep, "test_rejects", COMMIT, MECH) == ""
    facts = _evidence_facts({}, "test_rejects", {"mechanism": MECH}, None, dep, COMMIT)
    assert facts["depends"] is True and "depends_reason" not in facts
    assert "fails without mechanism: yes" in _facts_sentence(facts, True)


def test_another_commit_explains_nothing():
    dep = [_statement("budget exhausted")]
    assert _dependence_reason(dep, "test_rejects", "b" * 40, MECH) == ""
