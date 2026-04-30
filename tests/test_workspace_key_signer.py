"""Tests for the workspace-ECDSA fallback signer."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from mipiti_verify.workspace_key_signer import WorkspaceKeySigner


def _write_p256_key(tmp_path: Path) -> Path:
    """Write a freshly generated unencrypted P-256 PEM and return its path."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "ws.pem"
    path.write_bytes(pem)
    return path


def test_load_p256_pem(tmp_path: Path) -> None:
    path = _write_p256_key(tmp_path)
    signer = WorkspaceKeySigner(path)
    # Sign a known digest to confirm the key loaded.
    digest_hex = hashlib.sha256(b"hello").hexdigest()
    signature_b64, signed_hex = signer.sign(f"sha256:{digest_hex}")
    assert signed_hex == digest_hex
    assert base64.b64decode(signature_b64)


def test_missing_file_raises_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Cannot read workspace signing key"):
        WorkspaceKeySigner(tmp_path / "nope.pem")


def test_invalid_pem_raises_value_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a real PEM")
    with pytest.raises(ValueError, match="not a valid unencrypted PEM private key"):
        WorkspaceKeySigner(bad)


def test_rsa_key_rejected(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "rsa.pem"
    path.write_bytes(pem)
    with pytest.raises(ValueError, match="not an EC private key"):
        WorkspaceKeySigner(path)


def test_wrong_curve_rejected(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "p384.pem"
    path.write_bytes(pem)
    with pytest.raises(ValueError, match="P-256"):
        WorkspaceKeySigner(path)


def test_signature_verifies_against_public_key(tmp_path: Path) -> None:
    """End-to-end: signer output verifies under the matching public key."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "ws.pem"
    path.write_bytes(pem)
    signer = WorkspaceKeySigner(path)

    payload = b'{"some":"canonical-json"}'
    digest_hex = hashlib.sha256(payload).hexdigest()
    signature_b64, signed_hex = signer.sign(f"sha256:{digest_hex}")
    assert signed_hex == digest_hex

    sig_der = base64.b64decode(signature_b64)
    digest_bytes = bytes.fromhex(signed_hex)
    # Should not raise — verifies the DER ECDSA signature over the digest.
    key.public_key().verify(sig_der, digest_bytes, ec.ECDSA(hashes.SHA256()))


def test_accepts_bare_hex_without_prefix(tmp_path: Path) -> None:
    path = _write_p256_key(tmp_path)
    signer = WorkspaceKeySigner(path)
    digest_hex = hashlib.sha256(b"x").hexdigest()
    signature_b64, signed_hex = signer.sign(digest_hex)  # no "sha256:" prefix
    assert signed_hex == digest_hex
    assert signature_b64


def test_rejects_malformed_hex(tmp_path: Path) -> None:
    path = _write_p256_key(tmp_path)
    signer = WorkspaceKeySigner(path)
    # 16 hex chars instead of 64 — wrong digest size.
    with pytest.raises(ValueError, match="SHA-256 digest size"):
        signer.sign("sha256:deadbeefdeadbeef")
