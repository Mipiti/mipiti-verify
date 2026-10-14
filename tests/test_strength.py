"""Each clause's evidence strength is recomputed from the package's own record
(``clause_strength``), with the platform's rules: a strength the record does
not give is reported, never passed over."""

import json
from pathlib import Path

import pytest

from mipiti_verify import strength

CASES = json.loads((Path(__file__).parent / "fixtures" / "strength_cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[f"case{i}" for i in range(len(CASES))])
def test_the_rules_compose_as_the_platform_does(case):
    """Every case the platform's composition decided, decided the same here:
    every class, origin, verification state and clause shape the fixture
    spans, at every tier."""
    assert strength.compose_clause(case["clause"]) == case["expected"]


def test_the_fixture_spans_every_tier():
    tiers = {c["expected"]["tier"] for c in CASES}
    assert tiers == set(strength.TIER_ORDER)
    assert {c["expected"]["covered"] for c in CASES} == {True, False}


def _package(tier="witnessed", control_tier="witnessed", covered=True, basis="now"):
    import copy

    # A copy: a test that tampers with the package's edge leaves the cases alone.
    edge = copy.deepcopy(next(c["clause"]["edges"][0] for c in CASES
                              if c["expected"] == {"covered": True, "tier": "witnessed"}
                              and c["clause"]["clause_class"] == "runtime"))
    return {"clause_strength": {"C1": {
        "basis": basis, "soundness_tier": control_tier, "clauses": [{
            "clause_id": "c1", "clause": "the handler rejects a forged token",
            "quantifier": "unknown", "clause_class": "runtime", "required_origin": "inferred",
            "covered": covered, "tier": tier,
            "evidence": [{"evidence_id": "a1", "kind": "assertion", "passes_now": True,
                          "expired": False}],
            "edges": [edge]}]}}}


def test_a_consistent_package_reads_consistent():
    report = strength.check(_package())
    (control,) = report.controls
    assert control.consistent and report.inconsistent == []
    assert control.recomputed == "witnessed"


@pytest.mark.parametrize("tampered", [
    {"tier": "sound", "control_tier": "sound"},
    {"control_tier": "constructed"},
    {"covered": False},
], ids=["clause-raised", "control-raised", "coverage-changed"])
def test_a_strength_the_record_does_not_give_is_reported(tampered):
    report = strength.check(_package(**tampered))
    assert [c.control_id for c in report.inconsistent] == ["C1"]


def test_an_edge_tampered_to_fail_is_reported():
    pkg = _package()
    pkg["clause_strength"]["C1"]["clauses"][0]["edges"][0]["tier1"] = "fail"
    assert [c.control_id for c in strength.check(pkg).inconsistent] == ["C1"]


def test_a_strength_stated_as_judged_is_not_recomputed_and_names_no_edges():
    pkg = _package(basis="at_evaluation")
    pkg["clause_strength"]["C1"]["clauses"][0]["edges"] = []
    (control,) = strength.check(pkg).controls
    assert control.consistent and control.basis == "at_evaluation"


def test_a_package_without_the_section_states_nothing():
    assert strength.check({}).controls == []


# --- the audit command ----------------------------------------------------------------


def _audit_file(tmp_path, section) -> str:
    """A minimal workspace-signed package carrying ``clause_strength``."""
    import base64
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    stored = "sha256:" + hashlib.sha256(b"[]").hexdigest()
    sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
    pkg = {
        "model": {"id": "m1", "title": "t", "feature_description": "fd", "version": 1,
                  "assets": [], "attackers": [], "trust_boundaries": []},
        "control_objectives": [], "controls": [],
        "verification_run": {"id": "r1", "pipeline": {}, "results": [], "submitted_at": ""},
        "provenance": None,
        "content_integrity": {"results_hash": stored,
                              "signature": base64.b64encode(sig).decode(),
                              "public_key_pem": pub_pem},
        "generated_at": "", "assertions_by_control": {}, "sufficiency": {},
        **section,
    }
    path = tmp_path / "pkg.json"
    path.write_text(json.dumps(pkg), encoding="utf-8")
    return str(path)


def test_the_audit_states_each_strength_recomputed(tmp_path):
    from click.testing import CliRunner

    from mipiti_verify.cli import main

    result = CliRunner().invoke(main, ["audit", _audit_file(tmp_path, _package()), "--full"])
    assert result.exit_code == 0, result.output
    assert "Evidence strength" in result.output
    assert "C1: witnessed" in result.output


def test_a_strength_the_evidence_does_not_give_fails_the_audit(tmp_path):
    from click.testing import CliRunner

    from mipiti_verify.cli import main

    raised = _package(tier="sound", control_tier="sound")
    result = CliRunner().invoke(main, ["audit", _audit_file(tmp_path, raised), "--full"])
    assert result.exit_code == 1
    assert "not what its evidence gives" in result.output
