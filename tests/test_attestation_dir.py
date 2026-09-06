"""Attestations live under the project root unless MIPITI_ATTESTATION_DIR says otherwise."""

from pathlib import Path

from mipiti_verify.attestation import ATTESTATION_DIR, attestation_dir, load_attestations


def test_default_is_under_the_project_root(tmp_path, monkeypatch):
    monkeypatch.delenv("MIPITI_ATTESTATION_DIR", raising=False)
    assert attestation_dir(tmp_path) == tmp_path / ATTESTATION_DIR


def test_absolute_override(tmp_path, monkeypatch):
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("MIPITI_ATTESTATION_DIR", str(other))
    assert attestation_dir(tmp_path / "root") == other


def test_relative_override_is_under_the_root(tmp_path, monkeypatch):
    monkeypatch.setenv("MIPITI_ATTESTATION_DIR", "out/att")
    assert attestation_dir(tmp_path) == tmp_path / "out" / "att"


def test_reads_follow_the_override(tmp_path, monkeypatch):
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "tests-abc.json").write_text('{"x": 1}', encoding="utf-8")
    monkeypatch.setenv("MIPITI_ATTESTATION_DIR", str(other))
    assert load_attestations(tmp_path / "root") == ['{"x": 1}']
