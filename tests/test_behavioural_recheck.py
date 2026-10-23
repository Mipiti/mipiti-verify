"""The group decisions an audit package states, and the re-check of the
certificates and proofs an analysis decision rests on.

The certificate and proof are the platform's own, read from the design proof
bundle in ``tests/fixtures/design-bundle`` (a certificate and a proof of one
obligation of a synthetic model). The checkers are faked here except in the
last tests, which run the pinned tools on them where they are installed."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from pathlib import Path

import pytest
from click.testing import CliRunner

from mipiti_verify import behavioural as B
from mipiti_verify import design_bundle as DB
from mipiti_verify.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "design-bundle"
BUNDLE = DB.read((FIXTURE / "design-proof-bundle.tar.gz").read_bytes())
_CERT_ROW = BUNDLE.json("certificates.json")[0]
_PROOF_ROW = BUNDLE.json("proofs.json")[0]
MODULE_NAME = _CERT_ROW["module_name"]
MODULE = BUNDLE.text(f"modules/{_CERT_ROW['key_hash']}/{MODULE_NAME}.tla")
INVARIANT = _CERT_ROW["invariant"]
PROOF = _PROOF_ROW["proof_text"]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _cert(**over) -> dict:
    return {**_CERT_ROW, "module_text": MODULE, "stored": True, **over}


def _proof(**over) -> dict:
    return {**_PROOF_ROW, "module_text": MODULE, **over}


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


FAKE = B.LocalTools("/fake/apalache.jar", "/fake/tlapm")


@pytest.fixture
def no_tools(monkeypatch):
    monkeypatch.setattr(B, "find_apalache", lambda: (None, "Apalache is not installed"))
    monkeypatch.setattr(B, "find_tlapm", lambda: (None, "tlapm is not installed"))


@pytest.fixture
def tools(monkeypatch):
    """Checkers that answer as configured, recording what they were given."""
    calls = {"apalache": [], "tlapm": []}
    answers = {"apalache": [("init", "holds", ""), ("step", "holds", ""),
                            ("property", "holds", ""), ("init state", "fails", ""),
                            ("start state", "fails", "")],
               "tlapm": {"exit": 0, "timed_out": False, "statuses": {"1": "proved"}}}
    monkeypatch.setattr(B, "local_tools", lambda: (FAKE, {}))

    def apalache(tools, name, module, invariant, form, timeout):
        calls["apalache"].append((name, module, invariant, form))
        return answers["apalache"]

    def tlapm(tools, name, module, proof, *, step_seconds, timeout):
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


# --- what a certificate must be about ----------------------------------------------------


def test_the_platforms_certificate_and_proof_are_about_their_module_and_claim():
    assert B.certificate_problems(MODULE, MODULE_NAME, INVARIANT, "step", "one_way") == []
    assert B.proof_problems(PROOF, MODULE, MODULE_NAME, INVARIANT, "step") == []


_MUTANTS = [
    ("Prop == ClaimStep_0", "Prop == TRUE", "not the module's claim"),
    ("EXTENDS Cert_030f7e6c67, Apalache", "EXTENDS Cert_030f7e6c67, Apalache, Naturals",
     "extend exactly"),
    ("InitInv == Assign /\\ IndInv", "InitInv == Assign", "InitInv is not"),
    ("  /\\ fl2 = Gen(1)", "  /\\ fl2 = Gen(1)\n  /\\ now = 0", "Assign's 'now = 0'"),
    ("CInit == H = 0 /\\", "CInit == H = 0 /\\ H = 1 /\\", "does not bind one constant"),
    ("Hi_0_0 = 2\n", "Hi_0_0 = 2 /\\ Extra = 1\n", "exactly the module's constants"),
    ("CInit == H = 0", "CInit == H = Inst", "does not bind one constant to a value"),
    ("IndInv ==\n", "Init == TRUE\nIndInv ==\n", "redefines Init"),
    ("IndInv ==\n", "ASSUME FALSE\nIndInv ==\n", "declares"),
    ("  /\\ Inv_7\n", "  /\\ Inv_7\n  /\\ Elsewhere\n", "IndInv is not a conjunction"),
]


@pytest.mark.parametrize("old,new,why", _MUTANTS)
def test_a_certificate_that_could_hold_without_checking_the_claim_is_refused(old, new, why):
    assert old in INVARIANT
    problems = B.certificate_problems(MODULE, MODULE_NAME, INVARIANT.replace(old, new),
                                      "step", "one_way")
    assert any(why in p for p in problems), problems


def test_a_certificate_of_another_kind_or_form_is_refused():
    # An availability claim is certified through Answerable, as a state property.
    assert B.certificate_problems(MODULE, MODULE_NAME, INVARIANT, "step", "availability")
    assert B.certificate_problems(MODULE, MODULE_NAME, INVARIANT, "state", "one_way")


_PROOF_MUTANTS = [
    ("BY InitHolds, StepHolds, PropHolds, PTL DEF Spec", "OMITTED", "omits a step"),
    ("THEOREM Holds == Spec => [][Prop]_vars", "THEOREM Holds == Init => IndInv",
     "theorem Holds is not"),
    ("THEOREM InitHolds", "AXIOM Cheat == FALSE\nTHEOREM InitHolds", "declares"),
    ("EXTENDS Cert_030f7e6c67, FiniteSetTheorems, TLAPS",
     "EXTENDS Cert_030f7e6c67, FiniteSetTheorems, TLAPS, Other", "libraries only"),
    ("Prop == ClaimStep_0", "Prop == TRUE", "Prop is not the certificate's"),
    ("  /\\ Inv_7\n", "  /\\ Inv_6\n", "IndInv is not the certificate's"),
]


@pytest.mark.parametrize("old,new,why", _PROOF_MUTANTS)
def test_a_proof_that_is_not_of_the_claim_at_every_scope_is_refused(old, new, why):
    assert old in PROOF
    problems = B.proof_problems(PROOF.replace(old, new), MODULE, MODULE_NAME, INVARIANT,
                                "step")
    assert any(why in p for p in problems), problems


# --- certificates ---------------------------------------------------------------------


@pytest.mark.parametrize("over,status", [
    ({"module_hash": "0" * 64}, B.FAILED),
    ({"outcome": "not_certified"}, B.FAILED),
    ({"module_text": ""}, B.FAILED),
    ({"module_name": "Other"}, B.FAILED),
    ({"invariant": INVARIANT.replace("Prop == ClaimStep_0", "Prop == TRUE")}, B.FAILED),
    ({"apalache_rev": "0.50.0"}, B.NOT_RECHECKED),
    ({"stored": False}, B.MISSING),
])
def test_a_certificate_is_checked_before_anything_runs(tools, over, status):
    calls, _ = tools
    assert B.recheck_certificate(_cert(**over), FAKE, 10).status == status
    assert calls["apalache"] == []


def test_a_certificate_holds_only_when_the_checks_hold_and_are_not_vacuous(tools):
    calls, answers = tools
    r = B.recheck_certificate(_cert(), FAKE, 10)
    assert r.status == B.RECHECKED
    assert calls["apalache"] == [(MODULE_NAME, MODULE, INVARIANT, "step")]
    answers["apalache"] = [("init", "holds", ""), ("step", "fails", "")]
    r = B.recheck_certificate(_cert(), FAKE, 10)
    assert r.status == B.FAILED and "step" in r.detail
    # No state the checks start from: they hold of nothing.
    answers["apalache"] = [("init", "holds", ""), ("step", "holds", ""),
                           ("property", "holds", ""), ("init state", "holds", "")]
    r = B.recheck_certificate(_cert(), FAKE, 10)
    assert r.status == B.FAILED and "vacuously" in r.detail
    # A checker that could not answer is not a refutation.
    answers["apalache"] = [("init", "error", "parse error")]
    assert B.recheck_certificate(_cert(), FAKE, 10).status == B.NOT_RECHECKED
    answers["apalache"] = [("init", "holds", ""), ("step", "timeout", "")]
    assert B.recheck_certificate(_cert(), FAKE, 10).status == B.NOT_RECHECKED
    # Without Apalache the certificate is still checked, and nothing is claimed.
    assert B.recheck_certificate(_cert(), None, 10).status == B.NOT_RECHECKED
    assert B.recheck_certificate(_cert(module_hash="x"), None, 10).status == B.FAILED


# --- proofs ---------------------------------------------------------------------------


@pytest.mark.parametrize("over,cert,status", [
    ({"module_hash": "0" * 64}, _cert(), B.FAILED),
    ({"invariant_hash": _sha("another invariant")}, _cert(), B.FAILED),
    ({}, None, B.FAILED),
    ({}, _cert(stored=False), B.FAILED),
    ({"outcome": "holds_certified"}, _cert(), B.FAILED),
    ({"proof_text": PROOF.replace("BY InitHolds, StepHolds, PropHolds, PTL DEF Spec",
                                  "OMITTED")}, _cert(), B.FAILED),
    ({"tlapm_rev": "3edc73c"}, _cert(), B.NOT_RECHECKED),
])
def test_a_proof_is_of_its_certificate_before_anything_runs(tools, over, cert, status):
    calls, _ = tools
    assert B.recheck_proof(_proof(**over), cert, FAKE, 10).status == status
    assert calls["tlapm"] == []


def test_a_proof_holds_only_when_every_obligation_closes_here(tools):
    calls, answers = tools
    assert B.recheck_proof(_proof(), _cert(), FAKE, 10).status == B.RECHECKED
    # At the step limit it was checked under.
    assert calls["tlapm"] == [(MODULE_NAME, MODULE, PROOF, _PROOF_ROW["step_seconds"])]
    answers["tlapm"] = {"exit": 1, "timed_out": False,
                        "statuses": {"1": "proved", "2": "failed"}}
    assert B.recheck_proof(_proof(), _cert(), FAKE, 10).status == B.FAILED
    answers["tlapm"] = {"exit": None, "timed_out": True, "statuses": {}}
    assert B.recheck_proof(_proof(), _cert(), FAKE, 10).status == B.NOT_RECHECKED
    answers["tlapm"] = {"exit": 0, "timed_out": False, "statuses": {}}
    assert B.recheck_proof(_proof(), _cert(), FAKE, 10).status == B.NOT_RECHECKED
    assert B.recheck_proof(_proof(), _cert(), None, 10).status == B.NOT_RECHECKED


# --- the commands are the platform's ---------------------------------------------------


def _script_commands() -> list:
    """The commands the bundle's recheck.sh runs, as the platform wrote
    them, with its variables bound."""
    out = []
    for line in BUNDLE.text("recheck.sh").splitlines():
        if '(cd "$WORK" && ' not in line:
            continue
        inner = line[line.index("&& ") + 3:line.index(") > ")]
        inner = (inner.replace('"$WORK"', "/W").replace('"$APALACHE_JAR"', "/J")
                 .replace('"$TLAPM"', "/T"))
        out.append(shlex.split(inner))
    return out


def test_the_commands_are_the_ones_the_platform_runs():
    local = B.LocalTools("/J", "/T")
    *checks, prover = _script_commands()
    form = _CERT_ROW["form"]
    inv_name = B._module_name(INVARIANT)
    assert checks == [local.apalache("/W", args, inv_name) for _c, args in
                      B.apalache_checks(form)]
    proof_name = B._module_name(PROOF)
    assert prover == local.prover("/W", proof_name, _PROOF_ROW["step_seconds"])


def test_the_image_runs_the_same_commands_with_no_network():
    image = B.ImageTools("img@sha256:" + "0" * 64)
    argv = image.prover("/host/work", "P_proof", 20.0)
    run = image.container(argv, "/host/work", "n")
    assert run[:3] == ["docker", "run", "--rm"] and "--network=none" in run
    assert run[run.index("--volume") + 1] == "/host/work:/work"
    assert run[run.index("--entrypoint") + 1] == B.IMAGE_TLAPM
    assert run[-len(argv) + 1:] == argv[1:] and "/work/cache" in argv


def test_a_report_settles_only_what_ran(no_tools):
    report = B.check({"objective_judgements": _section()})
    assert not report.failed
    assert {r.status for r in report.rechecks()} == {B.NOT_RECHECKED}
    assert len(report.unsettled()) == 2 and set(report.tools_missing) == {"apalache", "tlapm"}
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
    assert "certificate of FlagStays: RE-CHECKED" in result.output
    assert "proof of FlagStays: RE-CHECKED" in result.output
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
    assert all(r.status == B.MISSING for r in report.rechecks())


def test_a_certificate_the_package_does_not_carry_is_never_passed_over(tmp_path, tools):
    missing = _section(group_extra={"certificate": [{
        "obligation_id": "ob1", "key_hash": "k9", "stored": False}], "proof": []})
    path = _package(tmp_path, missing)
    result = CliRunner().invoke(main, ["audit", path, "--full"])
    assert result.exit_code == 0
    assert "MISSING" in result.output
    assert CliRunner().invoke(main, ["audit", path, "--require-recheck"]).exit_code == 1


# --- the pinned tools, where installed -----------------------------------------------------


def _installed() -> tuple:
    tools, missing = B.local_tools()
    return tools, missing


@pytest.mark.skipif(bool(_installed()[1].get("apalache")),
                    reason="the pinned Apalache is not installed")
def test_the_platforms_certificate_is_rechecked_and_a_wrong_one_refuted():
    tools, _ = _installed()
    assert B.recheck_certificate(_cert(), tools, 600).status == B.RECHECKED
    empty = INVARIANT.replace("Lo_0_0 = 0 /\\ Hi_0_0 = 2", "Lo_0_0 = 3 /\\ Hi_0_0 = 2")
    r = B.recheck_certificate(_cert(invariant=empty), tools, 600)
    assert r.status == B.FAILED and "vacuously" in r.detail


@pytest.mark.skipif(bool(_installed()[1].get("tlapm")),
                    reason="the pinned tlapm is not installed")
def test_the_platforms_proof_is_rechecked():
    tools, _ = _installed()
    assert B.recheck_proof(_proof(), _cert(), tools, 900).status == B.RECHECKED
