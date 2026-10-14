"""What each declared control was checked against is re-checked from the
package (``declared_commitments``): each clause's and finding's id from its
words, and a control served sufficient against the declaration's conclusion
rule. A record that disagrees with itself or its served status is reported,
never passed over."""

import copy
import json
from pathlib import Path

import pytest

from mipiti_verify import commitments

CASES = json.loads((Path(__file__).parent / "fixtures" / "commitment_cases.json").read_text())

TEXT = "Requests without a valid session token are rejected before the handler runs."


@pytest.mark.parametrize("case", CASES["clauses"], ids=[f"clause{i}" for i in
                                                        range(len(CASES["clauses"]))])
def test_a_clause_fingerprint_is_the_platforms(case):
    """Case, spacing and Unicode form folded as the platform folds them."""
    assert commitments.clause_fingerprint(case["text"]) == case["fingerprint"]


@pytest.mark.parametrize("case", CASES["findings"], ids=[f"finding{i}" for i in
                                                         range(len(CASES["findings"]))])
def test_a_finding_id_is_the_platforms(case):
    assert commitments.finding_id(case["text"]) == case["finding_id"]


def test_the_fixture_folds_unicode_form_for_clauses_and_not_for_findings():
    composed, decomposed = CASES["clauses"][2], CASES["clauses"][3]
    assert composed["text"] != decomposed["text"]
    assert composed["fingerprint"] == decomposed["fingerprint"]
    assert CASES["findings"][2]["finding_id"] != CASES["findings"][3]["finding_id"]


def test_two_clauses_that_read_alike_keep_two_ids():
    first, second = commitments.clause_ids(["Rejects forged tokens", "rejects  FORGED tokens"])
    assert second == first + "_1"


def _package(status="sufficient", *, findings=None, dismissed=True, completed=True,
             nothing_text="no-op", description=TEXT):
    import hashlib

    clauses = ["Removes the transition that admits a request without a valid token",
               '"before the handler runs" commits to a property of the implementation']
    found = [{"finding_id": commitments.finding_id(t), "text": t, "dismissed": dismissed}
             for t in (findings if findings is not None
                       else ["The text may also commit to logging each rejection"])]
    return {
        "controls": [{"id": "C1", "description": description,
                      "sufficiency": {"status": status, "details": "", "stale": False}}],
        "declared_commitments": {"C1": {
            "basis": "declaration",
            "declaration_hash": "d" * 64,
            "description_hash": hashlib.sha256(TEXT.encode()).hexdigest(),
            "declared_by": "u_1", "declared_at": "2026-10-01T00:00:00+00:00",
            "clauses": [{"clause_id": cid, "kind": "edit", "index": i, "text": t}
                        for i, (cid, t) in enumerate(zip(commitments.clause_ids(clauses),
                                                         clauses))],
            "cross_check": {"completed": True, "computed_at": "", "llm_model_name": "m",
                            "findings": found} if completed else None,
            "nothing_spans": [{"start": 0, "end": 5, "text": nothing_text}],
        }},
    }


def test_a_consistent_record_reads_consistent():
    report = commitments.check(_package())
    (control,) = report.controls
    assert control.consistent and report.inconsistent == []
    assert control.served == "sufficient" and control.open_findings == []


def test_a_package_without_the_section_states_nothing():
    assert commitments.check({}).controls == []


@pytest.mark.parametrize("tamper, words", [
    (lambda p: p["declared_commitments"]["C1"]["clauses"][0].update(text="Something else"),
     "is not the clause its words name"),
    (lambda p: p["declared_commitments"]["C1"]["cross_check"]["findings"][0].update(
        text="Another finding"), "is not the finding its words name"),
    (lambda p: p["controls"][0].update(description=TEXT + " Also logs."),
     "another text than the control's"),
], ids=["clause-reworded", "finding-reworded", "text-changed"])
def test_a_record_that_disagrees_with_itself_is_reported(tamper, words):
    pkg = copy.deepcopy(_package())
    tamper(pkg)
    (control,) = commitments.check(pkg).inconsistent
    assert any(words in p for p in control.problems)


@pytest.mark.parametrize("kwargs, words", [
    ({"dismissed": False}, "no person dismissed"),
    ({"completed": False}, "without a completed cross-check"),
    ({"nothing_text": None}, "no longer read"),
], ids=["open-finding", "no-cross-check", "span-unread"])
def test_a_control_served_sufficient_against_its_rule_is_reported(kwargs, words):
    (control,) = commitments.check(_package(**kwargs)).inconsistent
    assert any(words in p for p in control.problems)


@pytest.mark.parametrize("kwargs", [{"dismissed": False}, {"completed": False},
                                    {"nothing_text": None}])
def test_an_insufficient_control_may_stand_on_an_open_record(kwargs):
    """The rule bounds only a sufficient verdict: an open finding is why a
    control reads insufficient, never an inconsistency of it."""
    (control,) = commitments.check(_package("insufficient", **kwargs)).controls
    assert control.consistent


def test_a_stale_record_may_be_of_another_text():
    pkg = _package("stale", description=TEXT + " Also logs.")
    (control,) = commitments.check(pkg).controls
    assert control.consistent


# --- the audit command ----------------------------------------------------------------


def _audit_file(tmp_path, pkg) -> str:
    """A minimal workspace-signed package carrying ``declared_commitments``."""
    import base64
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    stored = "sha256:" + hashlib.sha256(b"[]").hexdigest()
    sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
    full = {
        "model": {"id": "m1", "title": "t", "feature_description": "fd", "version": 1,
                  "assets": [], "attackers": [], "trust_boundaries": []},
        "control_objectives": [],
        "verification_run": {"id": "r1", "pipeline": {}, "results": [], "submitted_at": ""},
        "provenance": None,
        "content_integrity": {"results_hash": stored,
                              "signature": base64.b64encode(sig).decode(),
                              "public_key_pem": pub_pem},
        "generated_at": "", "assertions_by_control": {}, "sufficiency": {},
        **pkg,
    }
    path = tmp_path / "pkg.json"
    path.write_text(json.dumps(full), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("flags", [["--full"], []], ids=["full", "summary"])
def test_the_audit_states_each_declared_control(tmp_path, flags):
    from click.testing import CliRunner

    from mipiti_verify.cli import main

    result = CliRunner().invoke(main, ["audit", _audit_file(tmp_path, _package())] + flags)
    assert result.exit_code == 0, result.output
    assert "Declared controls" in result.output
    if flags:
        assert "declared by u_1" in result.output
        assert "cross-check finding (dismissed)" in result.output
    else:
        assert "1 declared control(s); no open cross-check finding" in result.output


@pytest.mark.parametrize("flags", [["--full"], []], ids=["full", "summary"])
def test_a_sufficient_control_with_an_open_finding_fails_the_audit(tmp_path, flags):
    from click.testing import CliRunner

    from mipiti_verify.cli import main

    result = CliRunner().invoke(
        main, ["audit", _audit_file(tmp_path, _package(dismissed=False))] + flags)
    assert result.exit_code == 1
    assert "no person dismissed" in " ".join(result.output.split())
