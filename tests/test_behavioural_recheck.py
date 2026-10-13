"""The group decisions an audit package states, and the re-check of the
certificates and proofs an analysis decision rests on.

The checkers are faked here except in the last test, which runs the pinned
Apalache on a small certificate when one is installed."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil

import pytest
from click.testing import CliRunner

from mipiti_verify import behavioural as B
from mipiti_verify.cli import main

MODULE = ("---- MODULE Cert_M ----\nEXTENDS Integers\nVARIABLE\n  \\* @type: Int;\n  x\n"
          "CInit == TRUE\nInit == x = 0\nNext == x' = x\n====\n")
INVARIANT = ("---- MODULE Cert_M_inv ----\nEXTENDS Cert_M\nIndInv == x = 0\n"
             "InitInv == IndInv\nProp == x = 0\n====\n")
PROOF = ("---- MODULE Cert_M_proof ----\nEXTENDS Cert_M\nTHEOREM TRUE\n  OBVIOUS\n====\n")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _cert(**over) -> dict:
    return {"obligation_id": "ob1", "claim_id": "P1", "attacker_class": "c1",
            "key_hash": "k1", "module_name": "Cert_M", "module_text": MODULE,
            "module_hash": _sha(MODULE), "invariant": INVARIANT,
            "invariant_source": "p_and_type", "invariant_hash": "cands",
            "form": "state", "apalache_rev": B.APALACHE_VERSION,
            "outcome": B.CERTIFIED, "computed_at": "", "stored": True, **over}


def _proof(**over) -> dict:
    return {"obligation_id": "ob1", "claim_id": "P1", "key_hash": "p1",
            "module_name": "Cert_M", "module_text": MODULE, "module_hash": _sha(MODULE),
            "invariant_hash": _sha(INVARIANT), "proof_text": PROOF,
            "tlapm_rev": B.TLAPM_VERSION, "outcome": B.PROVED,
            "step_backends": {"3: THEOREM TRUE": "smt"}, "step_seconds": 5.0,
            "computed_at": "", **over}


def _section(group_extra=None, design=None) -> dict:
    static = {"group_id": 1, "members": ["C1"], "disposition": "covered",
              "source": "static", "reading": "covered_by_analysis", "analysis": {},
              "certificate": [_cert()], "proof": [_proof()], **(group_extra or {})}
    judged = {"group_id": 2, "members": ["C2"], "disposition": "covered",
              "source": "judge", "reading": "judged_covered"}
    obj = {"co_id": "CO-01", "input_hash": "h", "judged": True, "groups": [static, judged]}
    if design is not None:
        obj["design"] = design
    return {"readings": {}, "objectives": [obj],
            "inherited": {"objectives": [{"owner": "parent", "co_id": "CO-09",
                                          "groups": [judged]}]}}


@pytest.fixture
def no_tools(monkeypatch):
    monkeypatch.setattr(B, "find_apalache", lambda: (None, "Apalache is not installed"))
    monkeypatch.setattr(B, "find_tlapm", lambda: (None, "tlapm is not installed"))


@pytest.fixture
def tools(monkeypatch):
    """Checkers that answer as configured, recording what they were given."""
    calls = {"apalache": [], "tlapm": []}
    answers = {"apalache": [("init", "holds", ""), ("step", "holds", ""),
                            ("property", "holds", "")],
               "tlapm": {"exit": 0, "timed_out": False, "statuses": {"1": "proved"}}}
    monkeypatch.setattr(B, "find_apalache", lambda: ("/fake/apalache.jar", ""))
    monkeypatch.setattr(B, "find_tlapm", lambda: ("/fake/tlapm", ""))

    def apalache(jar, name, module, invariant, form, timeout):
        calls["apalache"].append((name, module, invariant, form))
        return answers["apalache"]

    def tlapm(exe, name, module, proof, *, step_seconds, timeout):
        calls["tlapm"].append((name, module, proof, step_seconds))
        return answers["tlapm"]

    monkeypatch.setattr(B, "run_apalache", apalache)
    monkeypatch.setattr(B, "run_tlapm", tlapm)
    return calls, answers


# --- reading -----------------------------------------------------------------------------


def test_every_decision_is_read_with_its_source():
    design = {"standing": "satisfied_by_design", "reading": "satisfied_by_design",
              "certificate": [_cert()]}
    out = B.decisions({"objective_judgements": _section(design=design)})
    assert [(d.co_id, d.subject, d.source, d.reading) for d in out] == [
        ("CO-01", "group 1", "static", "covered_by_analysis"),
        ("CO-01", "group 2", "judge", "judged_covered"),
        ("CO-01", "design", "design", "satisfied_by_design"),
        ("parent:CO-09", "inherited group 2", "judge", "judged_covered"),
    ]
    assert out[0].certificates and out[0].proofs
    # A judge's answer carries no certificate, whatever the row holds.
    judged = {"group_id": 3, "source": "judge", "reading": "judged_covered",
              "certificate": [_cert()]}
    (d,) = B.decisions({"objective_judgements": {"objectives": [
        {"co_id": "CO-02", "groups": [judged]}]}})
    assert d.certificates == []


def test_a_package_without_the_section_has_no_decisions():
    assert B.decisions({}) == [] and B.decisions({"objective_judgements": "x"}) == []


# --- certificates ---------------------------------------------------------------------


@pytest.mark.parametrize("over,status", [
    ({"module_hash": "0" * 64}, B.FAILED),
    ({"outcome": "not_certified"}, B.FAILED),
    ({"module_text": ""}, B.FAILED),
    ({"module_name": "Other"}, B.FAILED),
    ({"apalache_rev": "0.50.0"}, B.NOT_RECHECKED),
    ({"stored": False}, B.MISSING),
])
def test_a_certificate_is_bound_to_its_texts_before_anything_runs(tools, over, status):
    calls, _ = tools
    assert B.recheck_certificate(_cert(**over), "/fake/apalache.jar", 10).status == status
    assert calls["apalache"] == []


def test_a_certificate_holds_only_when_the_three_checks_hold_here(tools):
    calls, answers = tools
    r = B.recheck_certificate(_cert(), "/fake/apalache.jar", 10)
    assert r.status == B.RECHECKED
    assert calls["apalache"] == [("Cert_M", MODULE, INVARIANT, "state")]
    answers["apalache"] = [("init", "holds", ""), ("step", "fails", "")]
    r = B.recheck_certificate(_cert(), "/fake/apalache.jar", 10)
    assert r.status == B.FAILED and "step" in r.detail
    # A checker that could not answer is not a refutation.
    answers["apalache"] = [("init", "error", "parse error")]
    assert B.recheck_certificate(_cert(), "/fake/apalache.jar", 10).status == B.NOT_RECHECKED
    answers["apalache"] = [("init", "holds", ""), ("step", "timeout", "")]
    assert B.recheck_certificate(_cert(), "/fake/apalache.jar", 10).status == B.NOT_RECHECKED
    # Without Apalache the binding is still checked, and nothing is claimed.
    assert B.recheck_certificate(_cert(), None, 10).status == B.NOT_RECHECKED
    assert B.recheck_certificate(_cert(module_hash="x"), None, 10).status == B.FAILED


# --- proofs ---------------------------------------------------------------------------


@pytest.mark.parametrize("over,cert,status", [
    ({"module_hash": "0" * 64}, _cert(), B.FAILED),
    ({"invariant_hash": _sha("another invariant")}, _cert(), B.FAILED),
    ({}, _cert(module_text="---- MODULE Cert_M ----\n====\n",
               module_hash=_sha("---- MODULE Cert_M ----\n====\n")), B.FAILED),
    ({}, None, B.FAILED),
    ({}, _cert(stored=False), B.FAILED),
    ({"outcome": "holds_certified"}, _cert(), B.FAILED),
    ({"tlapm_rev": "abc1234"}, _cert(), B.NOT_RECHECKED),
])
def test_a_proof_is_of_its_certificate_before_anything_runs(tools, over, cert, status):
    calls, _ = tools
    assert B.recheck_proof(_proof(**over), cert, "/fake/tlapm", 10).status == status
    assert calls["tlapm"] == []


def test_a_proof_holds_only_when_every_obligation_closes_here(tools):
    calls, answers = tools
    assert B.recheck_proof(_proof(), _cert(), "/fake/tlapm", 10).status == B.RECHECKED
    # At the step limit it was checked under.
    assert calls["tlapm"] == [("Cert_M", MODULE, PROOF, 5.0)]
    answers["tlapm"] = {"exit": 1, "timed_out": False,
                        "statuses": {"1": "proved", "2": "failed"}}
    assert B.recheck_proof(_proof(), _cert(), "/fake/tlapm", 10).status == B.FAILED
    answers["tlapm"] = {"exit": None, "timed_out": True, "statuses": {}}
    assert B.recheck_proof(_proof(), _cert(), "/fake/tlapm", 10).status == B.NOT_RECHECKED
    answers["tlapm"] = {"exit": 0, "timed_out": False, "statuses": {}}
    assert B.recheck_proof(_proof(), _cert(), "/fake/tlapm", 10).status == B.NOT_RECHECKED
    assert B.recheck_proof(_proof(), _cert(), None, 10).status == B.NOT_RECHECKED


def test_a_report_settles_only_what_ran(no_tools):
    report = B.check({"objective_judgements": _section()})
    assert not report.failed
    assert {r.status for r in report.rechecks()} == {B.NOT_RECHECKED}
    assert len(report.unsettled()) == 2 and set(report.tools_missing) == {"apalache", "tlapm"}
    # A decision a judge answered rests on no certificate of its own.
    off = B.check({"objective_judgements": _section()}, run_tools=False)
    assert set(off.tools_missing) == {"all"}


# --- the audit command ----------------------------------------------------------------


def _package(tmp_path, section) -> str:
    """A minimal workspace-signed package (as the identity-pinning tests
    build one) carrying ``section``."""
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
        "objective_judgements": section,
    }
    path = tmp_path / "pkg.json"
    path.write_text(json.dumps(pkg), encoding="utf-8")
    return str(path)


def test_the_audit_lists_each_decisions_source_and_rechecks(tmp_path, tools):
    result = CliRunner().invoke(main, ["audit", _package(tmp_path, _section()), "--full"])
    assert result.exit_code == 0, result.output
    assert "Group decisions" in result.output
    assert "CO-01 group 1: analysis covered" in result.output
    assert "CO-01 group 2: judge covered" in result.output
    assert "certificate of ob1: RE-CHECKED" in result.output
    assert "proof of ob1: RE-CHECKED" in result.output
    assert "Certificates & proofs:  RE-CHECKED (2/2 re-checked here)" in result.output


def test_a_certificate_that_does_not_hold_up_fails_the_audit(tmp_path, tools):
    bad = _section(group_extra={"certificate": [_cert(module_hash="0" * 64)]})
    result = CliRunner().invoke(main, ["audit", _package(tmp_path, bad)])
    assert result.exit_code == 1
    assert "module text does not hash" in result.output


def test_a_certificate_not_rechecked_is_a_caveat_or_a_failure_on_request(tmp_path, no_tools):
    path = _package(tmp_path, _section())
    result = CliRunner().invoke(main, ["audit", path])
    assert result.exit_code == 0, result.output
    assert "not re-checked here" in result.output
    result = CliRunner().invoke(main, ["audit", path, "--require-recheck"])
    assert result.exit_code == 1
    assert "--require-recheck" in result.output


def test_a_decision_crediting_with_no_certificate_at_all_is_said_so(tools):
    bare = _section(group_extra={"certificate": [], "proof": []})
    report = B.check({"objective_judgements": bare})
    (missing,) = report.unsettled()
    assert missing.status == B.MISSING and "carries no certificate" in missing.detail
    # A judge's covered answer rests on no certificate of its own.
    assert all(r.status == B.MISSING for r in report.rechecks())


def test_a_certificate_the_package_does_not_carry_is_never_passed_over(tmp_path, tools):
    missing = _section(group_extra={"certificate": [{
        "obligation_id": "ob1", "key_hash": "k9", "stored": False}], "proof": []})
    path = _package(tmp_path, missing)
    result = CliRunner().invoke(main, ["audit", path, "--full"])
    assert result.exit_code == 0
    assert "MISSING" in result.output
    assert CliRunner().invoke(main, ["audit", path, "--require-recheck"]).exit_code == 1


# --- the pinned Apalache, where installed -----------------------------------------------


def _apalache_installed() -> bool:
    if not (os.environ.get("APALACHE_JAR") or shutil.which("apalache-mc")):
        return False
    return B.find_apalache()[0] is not None


@pytest.mark.skipif(not _apalache_installed(), reason="the pinned Apalache is not installed")
def test_a_real_certificate_is_rechecked_and_a_wrong_one_refuted():
    jar, _ = B.find_apalache()
    assert B.recheck_certificate(_cert(), jar, 300).status == B.RECHECKED
    wrong = INVARIANT.replace("Prop == x = 0", "Prop == x = 1")
    assert B.recheck_certificate(_cert(invariant=wrong), jar, 300).status == B.FAILED
