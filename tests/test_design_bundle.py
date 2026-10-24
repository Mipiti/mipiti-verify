"""The check of a design proof bundle: the archive is read safely, the
manifest's signature and hashes hold, its coverage and decisions agree with
what it lists, and each certificate and proof is checked, and with
``--recheck`` re-run. The bundle is the platform's, in
``tests/fixtures/design-bundle``, signed with a key made for it."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mipiti_verify import behavioural as B
from mipiti_verify import design_bundle as DB
from mipiti_verify.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "design-bundle"
ARCHIVE = FIXTURE / "design-proof-bundle.tar.gz"
KEY = FIXTURE / "platform-key.pem"
ROOT = Path(__file__).parent.parent


def _key():
    return serialization.load_pem_public_key(KEY.read_bytes())


def _pack(files: dict, members=None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(f"design-proof-bundle/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info, data in members or ():
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def _files() -> dict:
    return dict(DB.read(ARCHIVE.read_bytes()).files)


def _resigned(change) -> tuple:
    """The fixture with ``change(files)`` applied, its manifest rewritten
    over the files as changed and signed by a new key: a bundle whose
    signature holds, to show what is checked beyond it."""
    files = _files()
    change(files)
    manifest = json.loads(files["manifest.json"])
    manifest["files"] = {n: hashlib.sha256(d).hexdigest() for n, d in sorted(files.items())
                         if n not in ("manifest.json", "signature.json")}
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    files["signature.json"] = json.dumps({
        "algorithm": "ECDSA-P256-SHA256", "signed": "manifest.json",
        "signature_der_b64": base64.b64encode(
            key.sign(files["manifest.json"], ec.ECDSA(hashes.SHA256()))).decode(),
        "public_key_pem": pub.public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo
                                           ).decode(),
        "key_fingerprint": DB.fingerprint(pub)}).encode()
    return DB.Bundle(files), pub


def _edit_json(files, name, fn):
    value = json.loads(files[name])
    fn(value)
    files[name] = json.dumps(value).encode()


# --- the platform's bundle -------------------------------------------------------------


def test_the_platforms_bundle_verifies():
    result = DB.check(DB.read(ARCHIVE.read_bytes()), _key())
    assert result.problems == [] and not result.failed
    assert result.coverage == {"obligations": 2, "certified": 0, "proved": 1,
                               "to_judge": 1, "not_evaluated": 0}
    assert [(r.kind, r.status) for r in result.rechecks] == [
        ("certificate", B.NOT_RECHECKED), ("proof", B.NOT_RECHECKED)]


def test_the_command_verifies_it_and_says_what_it_did_not_run():
    out = CliRunner().invoke(main, ["design-bundle", str(ARCHIVE), "--platform-pubkey",
                                    str(KEY)])
    assert out.exit_code == 0, out.output
    assert "VERIFIED" in out.output and "pass --recheck" in out.output
    assert "1 proved, 0 certified, 1 to the judge" in out.output


def test_the_key_is_looked_up_in_the_jwks_by_the_bundles_fingerprint(monkeypatch):
    from mipiti_verify import cli

    asked = []

    def jwks(fp, url):
        asked.append((fp, url))
        return _key(), fp, url or "default"

    monkeypatch.setattr(cli, "_resolve_pubkey_from_jwks", jwks)
    out = CliRunner().invoke(main, ["design-bundle", str(ARCHIVE), "--key-url", "https://k"])
    assert out.exit_code == 0, out.output
    assert asked == [(DB.fingerprint(_key()), "https://k")]


# --- the signature and the files ---------------------------------------------------------


def test_a_bundle_signed_by_another_key_is_refused():
    bundle, _pub = _resigned(lambda f: None)
    result = DB.check(bundle, _key())
    assert any("other than the platform's" in p for p in result.problems)


def test_a_changed_file_is_refused():
    files = _files()
    files["obligations.json"] = files["obligations.json"].replace(b"to_judge", b"proved")
    result = DB.check(DB.Bundle(files), _key())
    assert any("obligations.json does not hash" in p for p in result.problems)


def test_a_file_the_manifest_does_not_name_is_refused():
    files = {**_files(), "extra.tla": b"---- MODULE extra ----\n====\n"}
    result = DB.check(DB.Bundle(files), _key())
    assert any("extra.tla is in the bundle and not named" in p for p in result.problems)


def test_a_file_the_manifest_names_and_the_bundle_lacks_is_refused():
    files = _files()
    del files["recheck.sh"]
    result = DB.check(DB.Bundle(files), _key())
    assert any("recheck.sh is named by the manifest" in p for p in result.problems)


def test_another_format_is_refused():
    bundle, pub = _resigned(lambda f: _edit_json(f, "manifest.json",
                                                 lambda m: m.update(format=1)))
    result = DB.check(bundle, pub)
    assert result.failed and "format 1" in result.problems[0]


# --- what the bundle states, beyond its signature ------------------------------------------


def test_coverage_the_obligations_do_not_give_is_refused():
    bundle, pub = _resigned(lambda f: _edit_json(
        f, "manifest.json", lambda m: m["coverage"].update(proved=2, to_judge=0)))
    result = DB.check(bundle, pub)
    assert any("coverage the manifest states" in p for p in result.problems)


def test_an_objective_satisfied_by_design_resting_on_the_judge_is_refused():
    bundle, pub = _resigned(lambda f: _edit_json(
        f, "objectives.json", lambda o: o["CO-02"].update(standing="satisfied_by_design")))
    result = DB.check(bundle, pub)
    assert any("CO-02 is stated satisfied by design" in p for p in result.problems)


def test_a_certificate_of_another_kind_is_refused():
    bundle, pub = _resigned(lambda f: _edit_json(
        f, "certificates.json", lambda rows: rows[0].update(kind="always")))
    result = DB.check(bundle, pub)
    assert any("certificate is of another kind" in p for p in result.problems)


def test_a_proved_obligation_without_its_proof_is_refused():
    def drop(files):
        _edit_json(files, "proofs.json", lambda rows: rows.clear())
        for name in [n for n in files if n.startswith("proofs/")]:
            del files[name]
    bundle, pub = _resigned(drop)
    result = DB.check(bundle, pub)
    assert any("decided proved and the bundle holds no proof" in p for p in result.problems)


def test_a_listed_text_that_is_not_the_file_it_names_is_refused():
    def swap(files):
        key = json.loads(files["certificates.json"])[0]["key_hash"]
        name = next(n for n in files if n.startswith(f"modules/{key}/") and "_p_and_type" in n)
        files[name] = files[name].replace(b"Prop == ClaimStep_0", b"Prop == TRUE")
    bundle, pub = _resigned(swap)
    result = DB.check(bundle, pub)
    assert any("module and invariant are not in the bundle as listed" in p
               for p in result.problems)


def test_a_certificate_that_could_hold_without_its_claim_fails_without_running():
    def weaken(files):
        def row(rows):
            rows[0]["invariant"] = rows[0]["invariant"].replace("Prop == ClaimStep_0",
                                                                "Prop == TRUE")
        _edit_json(files, "certificates.json", row)
        cert = json.loads(files["certificates.json"])[0]
        name = next(n for n in files if n.startswith(f"modules/{cert['key_hash']}/")
                    and "_p_and_type" in n)
        files[name] = cert["invariant"].encode()
    bundle, pub = _resigned(weaken)
    result = DB.check(bundle, pub)
    assert result.failed and result.rechecks[0].status == B.FAILED
    assert "not the module's claim" in result.rechecks[0].detail


# --- reading the archive -----------------------------------------------------------------


def _member(name, kind=tarfile.REGTYPE, data=b"x", link=""):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(data) if kind == tarfile.REGTYPE else 0
    info.linkname = link
    return info, data if kind == tarfile.REGTYPE else None


@pytest.mark.parametrize("member,why", [
    (_member("design-proof-bundle/../evil"), "not a plain path"),
    (_member("/etc/passwd"), "outside"),
    (_member("other/file"), "outside"),
    (_member("design-proof-bundle/a/./b"), "not a plain path"),
    (_member("design-proof-bundle/link", tarfile.SYMTYPE, link="/etc/passwd"),
     "not a regular file"),
    (_member("design-proof-bundle/dir", tarfile.DIRTYPE), "not a regular file"),
    (_member("design-proof-bundle/README.txt"), "appears twice"),
])
def test_an_archive_that_is_not_a_plain_bundle_is_refused(member, why):
    with pytest.raises(DB.BundleError, match=why):
        DB.read(_pack(_files(), [member]))


def test_an_archive_past_the_bounds_is_refused(monkeypatch):
    monkeypatch.setattr(DB, "MAX_BYTES", 1000)
    with pytest.raises(DB.BundleError, match="more than"):
        DB.read(ARCHIVE.read_bytes())


def test_what_is_not_an_archive_is_refused_by_the_command(tmp_path):
    bad = tmp_path / "b.tar.gz"
    bad.write_bytes(b"not an archive")
    out = CliRunner().invoke(main, ["design-bundle", str(bad), "--platform-pubkey", str(KEY)])
    assert out.exit_code == 1 and "Not a design proof bundle" in out.output


# --- re-checking ---------------------------------------------------------------------


@pytest.fixture
def fake_tools(monkeypatch):
    ran = []

    def apalache(tools, name, module, invariant, form, timeout):
        ran.append(("apalache", name))
        return [("init", "holds", ""), ("step", "holds", ""), ("property", "holds", ""),
                ("init state", "fails", ""), ("start state", "fails", "")]

    def tlapm(tools, name, module, proof, *, step_seconds, timeout):
        ran.append(("tlapm", name))
        return {"exit": 0, "timed_out": False, "statuses": {"1": "proved"}}

    monkeypatch.setattr(B, "run_apalache", apalache)
    monkeypatch.setattr(B, "run_tlapm", tlapm)
    monkeypatch.setattr(B, "resolve_tools",
                        lambda mode, image="": (B.LocalTools("/j", "/t"), {}))
    return ran


def test_recheck_runs_every_certificate_and_proof(fake_tools):
    out = CliRunner().invoke(main, ["design-bundle", str(ARCHIVE), "--platform-pubkey",
                                    str(KEY), "--recheck", "--jobs", "2"])
    assert out.exit_code == 0, out.output
    assert sorted(k for k, _ in fake_tools) == ["apalache", "tlapm"]
    assert "1: 1 re-checked" in out.output and "VERIFIED" in out.output


def test_recheck_without_the_tools_fails(monkeypatch):
    monkeypatch.setattr(B, "resolve_tools", lambda mode, image="": (
        B.LocalTools("", ""), {"apalache": "Apalache is not installed"}))
    out = CliRunner().invoke(main, ["design-bundle", str(ARCHIVE), "--platform-pubkey",
                                    str(KEY), "--recheck"])
    assert out.exit_code == 1
    assert "Apalache is not installed" in out.output and "FAILED" in out.output


def test_a_sample_is_drawn_by_its_seed_alone():
    def picks(seed):
        bundle, pub = _resigned(lambda f: None)
        return DB.check(bundle, pub, sample=1, seed=seed).rechecks
    # One obligation is decided by a certificate here, so any sample of one
    # is that one; what matters is that the draw is the seed's.
    assert [r.key for r in picks(7)] == [r.key for r in picks(7)]
    result = DB.check(DB.read(ARCHIVE.read_bytes()), _key(), sample=1, seed=1)
    assert result.not_sampled == 0


# --- the tools image ----------------------------------------------------------------------


def _content_key() -> str:
    h = hashlib.sha256()
    for rel in ("design-check/Dockerfile", "design-check/tlapm-ls4-fpu.patch"):
        data = (ROOT / rel).read_bytes()
        h.update(f"{rel}\0{len(data)}\0".encode())
        h.update(data)
    return h.hexdigest()[:16]


def test_the_pinned_image_is_the_one_built_from_this_tree():
    pin = json.loads((ROOT / "src" / "mipiti_verify" / "design_check_image.json").read_text())
    assert pin["key"] == _content_key()
    assert pin["image"] == "" or pin["image"].startswith(
        "ghcr.io/mipiti/mipiti-design-check@sha256:")
    assert DB.pinned_image() == pin["image"]


def test_the_image_holds_the_tool_releases_the_verifier_pins():
    dockerfile = (ROOT / "design-check" / "Dockerfile").read_text()
    assert f"releases/download/v{B.APALACHE_VERSION}/apalache.tgz" in dockerfile
    assert f"({B.TLAPM_BUILD})" in dockerfile and B.TLAPM_METHODS in dockerfile
