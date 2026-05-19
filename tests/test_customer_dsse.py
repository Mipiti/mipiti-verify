"""Offline round-trip tests for the customer-keyed DSSE attestation path.

Fully in-repo and network-free: a P-256 keypair is generated, used to
sign a verification run via ``customer_dsse_signer``, and verified via
``customer_dsse_verifier``. Negative tests cover the wrong key, a
tampered payload, a subject-digest mismatch, and the fingerprint-pin
mismatch (the vendor-independence gate).
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mipiti_verify.customer_dsse_signer import (
    BUNDLE_KIND,
    PAYLOAD_TYPE,
    compute_pae,
    sign_verification_statement,
)
from mipiti_verify.customer_dsse_verifier import (
    CustomerDsseVerificationError,
    key_fingerprint,
    verify_customer_dsse_bundle,
)


def _gen_key(tmp_path, name="key.pem", passphrase: str | None = None):
    """Generate a P-256 private key, write it as PEM, return (path, key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )
    path = tmp_path / name
    path.write_bytes(pem)
    return path, key


def _pub_pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _fp(key) -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


_CONTENT_HASH = "sha256:" + hashlib.sha256(b"verdicts").hexdigest()


def _sign(tmp_path, **overrides):
    key_path, key = _gen_key(tmp_path)
    kwargs = dict(
        model_id="m1",
        tier=1,
        content_hash=_CONTENT_HASH,
        pipeline={"provider": "jenkins", "commit_sha": "abc123"},
        assertions=[{"id": "a1", "type": "file_based"}],
        results=[{"assertion_id": "a1", "result": "pass"}],
        key_path=str(key_path),
    )
    kwargs.update(overrides)
    return sign_verification_statement(**kwargs), key


class TestPaeContract:
    def test_pae_matches_dsse_v1_spec_byte_for_byte(self) -> None:
        payload = b'{"_type":"x"}'
        pae = compute_pae(payload)
        ptype = PAYLOAD_TYPE.encode()
        expected = (
            b"DSSEv1 "
            + str(len(ptype)).encode()
            + b" "
            + ptype
            + b" "
            + str(len(payload)).encode()
            + b" "
            + payload
        )
        assert pae == expected

    def test_pae_matches_sigstore_internal_pae(self) -> None:
        """Our PAE must equal sigstore-python's internal _pae for the
        same payload type + payload (cross-impl byte-identity)."""
        from sigstore.dsse import Envelope, _pae

        payload = b'{"_type":"https://in-toto.io/Statement/v1"}'
        assert compute_pae(payload) == _pae(Envelope._TYPE, payload)


class TestRoundTrip:
    def test_sign_then_verify_passes(self, tmp_path) -> None:
        bundle_json, key = _sign(tmp_path)
        bundle = json.loads(bundle_json)
        assert bundle["kind"] == BUNDLE_KIND
        assert bundle["v"] == 1
        assert bundle["payloadType"] == PAYLOAD_TYPE

        result = verify_customer_dsse_bundle(
            bundle_json,
            content_hash=_CONTENT_HASH,
            expected_fingerprint=_fp(key),
        )
        assert result.key_fingerprint == _fp(key)
        assert result.predicate["model_id"] == "m1"
        assert result.predicate["pipeline"]["commit_sha"] == "abc123"
        assert result.statement["predicateType"].endswith(
            "/v1/verification-run"
        )

    def test_content_hash_accepts_bare_hex(self, tmp_path) -> None:
        bundle_json, key = _sign(tmp_path)
        bare = _CONTENT_HASH[len("sha256:"):]
        result = verify_customer_dsse_bundle(
            bundle_json,
            content_hash=bare,
            expected_fingerprint=_fp(key),
        )
        assert result.key_fingerprint == _fp(key)

    def test_statement_bytes_are_canonical_sorted_nfc(self, tmp_path) -> None:
        bundle_json, _ = _sign(tmp_path)
        payload = base64.b64decode(json.loads(bundle_json)["payload"])
        stmt = json.loads(payload)
        # Top-level keys are sorted (json.dumps sort_keys=True).
        recanon = json.dumps(
            stmt, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        assert payload == recanon

    def test_fingerprint_helper_matches_canonical_algo(self, tmp_path) -> None:
        _, key = _gen_key(tmp_path)
        assert key_fingerprint(_pub_pem(key)) == _fp(key)


class TestEncryptedKey:
    def test_passphrase_protected_key_round_trip(self, tmp_path) -> None:
        key_path, key = _gen_key(tmp_path, passphrase="s3cret")
        bundle_json = sign_verification_statement(
            model_id="m1",
            tier=2,
            content_hash=_CONTENT_HASH,
            pipeline={},
            assertions=[],
            results=[],
            key_path=str(key_path),
            passphrase="s3cret",
        )
        result = verify_customer_dsse_bundle(
            bundle_json,
            content_hash=_CONTENT_HASH,
            expected_fingerprint=_fp(key),
        )
        assert result.key_fingerprint == _fp(key)

    def test_wrong_passphrase_is_hard_error(self, tmp_path) -> None:
        key_path, _ = _gen_key(tmp_path, passphrase="s3cret")
        with pytest.raises(ValueError, match="passphrase"):
            sign_verification_statement(
                model_id="m1",
                tier=1,
                content_hash=_CONTENT_HASH,
                pipeline={},
                assertions=[],
                results=[],
                key_path=str(key_path),
                passphrase="wrong",
            )


class TestNegative:
    def test_wrong_key_fails_signature(self, tmp_path) -> None:
        """A bundle re-keyed with a different public key fails step 2."""
        bundle_json, _ = _sign(tmp_path)
        bundle = json.loads(bundle_json)
        _, other = _gen_key(tmp_path, name="other.pem")
        bundle["public_key_pem"] = _pub_pem(other)
        with pytest.raises(CustomerDsseVerificationError, match="step 2"):
            verify_customer_dsse_bundle(
                json.dumps(bundle),
                content_hash=_CONTENT_HASH,
                expected_fingerprint=_fp(other),
            )

    def test_tampered_payload_fails_signature(self, tmp_path) -> None:
        bundle_json, key = _sign(tmp_path)
        bundle = json.loads(bundle_json)
        payload = json.loads(base64.b64decode(bundle["payload"]))
        payload["predicate"]["model_id"] = "tampered"
        bundle["payload"] = base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        with pytest.raises(CustomerDsseVerificationError, match="step 2"):
            verify_customer_dsse_bundle(
                json.dumps(bundle),
                content_hash=_CONTENT_HASH,
                expected_fingerprint=_fp(key),
            )

    def test_subject_digest_mismatch_fails(self, tmp_path) -> None:
        """Correct signature, but the report's content_hash differs from
        the Statement subject digest — step 4 catches it."""
        bundle_json, key = _sign(tmp_path)
        other_hash = "sha256:" + hashlib.sha256(b"different").hexdigest()
        with pytest.raises(CustomerDsseVerificationError, match="step 4"):
            verify_customer_dsse_bundle(
                bundle_json,
                content_hash=other_hash,
                expected_fingerprint=_fp(key),
            )

    def test_fingerprint_pin_mismatch_fails(self, tmp_path) -> None:
        """Valid signature + correct subject, but the pinned fingerprint
        is a different key — the vendor-independence gate (step 3)."""
        bundle_json, _ = _sign(tmp_path)
        _, other = _gen_key(tmp_path, name="other.pem")
        with pytest.raises(CustomerDsseVerificationError, match="step 3"):
            verify_customer_dsse_bundle(
                bundle_json,
                content_hash=_CONTENT_HASH,
                expected_fingerprint=_fp(other),
            )

    def test_missing_expected_fingerprint_refuses(self, tmp_path) -> None:
        bundle_json, _ = _sign(tmp_path)
        with pytest.raises(
            CustomerDsseVerificationError, match="expected_fingerprint"
        ):
            verify_customer_dsse_bundle(
                bundle_json,
                content_hash=_CONTENT_HASH,
                expected_fingerprint="",
            )

    def test_wrong_bundle_kind_fails(self, tmp_path) -> None:
        bundle_json, key = _sign(tmp_path)
        bundle = json.loads(bundle_json)
        bundle["kind"] = "something-else"
        with pytest.raises(CustomerDsseVerificationError, match="step 1"):
            verify_customer_dsse_bundle(
                json.dumps(bundle),
                content_hash=_CONTENT_HASH,
                expected_fingerprint=_fp(key),
            )

    def test_invalid_tier_rejected_at_sign(self, tmp_path) -> None:
        key_path, _ = _gen_key(tmp_path)
        with pytest.raises(ValueError, match="tier"):
            sign_verification_statement(
                model_id="m1",
                tier=3,
                content_hash=_CONTENT_HASH,
                pipeline={},
                assertions=[],
                results=[],
                key_path=str(key_path),
            )

    def test_non_p256_key_rejected_at_sign(self, tmp_path) -> None:
        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        kp = tmp_path / "p384.pem"
        kp.write_bytes(pem)
        with pytest.raises(ValueError, match="P-256"):
            sign_verification_statement(
                model_id="m1",
                tier=1,
                content_hash=_CONTENT_HASH,
                pipeline={},
                assertions=[],
                results=[],
                key_path=str(kp),
            )
