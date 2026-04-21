"""Unit tests for the Sigstore DSSE signing helper.

Network-free: the sigstore-python client layer is mocked so these tests do
not contact Fulcio or Rekor. Integration with the public Sigstore services
is covered by a dedicated live-run workflow in CI.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.sigstore_signer import (
    _content_hash_to_bytes,
    sign_verification_statement,
)


class TestContentHashToBytes:
    def test_accepts_prefixed_digest(self) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        out = _content_hash_to_bytes(f"sha256:{digest}")
        assert out == bytes.fromhex(digest)
        assert len(out) == 32

    def test_accepts_bare_hex(self) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        assert _content_hash_to_bytes(digest) == bytes.fromhex(digest)


def _valid_hash() -> str:
    return f"sha256:{hashlib.sha256(b'payload').hexdigest()}"


class TestSignVerificationStatement:
    def test_requires_identity_token(self) -> None:
        with pytest.raises(ValueError, match="identity_token"):
            sign_verification_statement(
                "", model_id="m1", tier=1, content_hash=_valid_hash(),
                pipeline={}, assertions=[], results=[],
            )

    def test_rejects_invalid_tier(self) -> None:
        with pytest.raises(ValueError, match="tier"):
            sign_verification_statement(
                "token", model_id="m1", tier=3, content_hash=_valid_hash(),
                pipeline={}, assertions=[], results=[],
            )

    def test_rejects_non_sha256_digest(self) -> None:
        with pytest.raises(ValueError, match="sha256"):
            sign_verification_statement(
                "token", model_id="m1", tier=1, content_hash=f"sha256:{'aa'*31}",
                pipeline={}, assertions=[], results=[],
            )

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    @patch("mipiti_verify.sigstore_signer.StatementBuilder")
    def test_builds_dsse_statement_and_calls_sign_dsse(
        self,
        mock_statement_builder_cls: MagicMock,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
    ) -> None:
        # StatementBuilder() is fluent (returns self on subjects/predicate_type/
        # predicate, build returns a Statement). Wire the chain so we can
        # inspect what gets passed into the predicate.
        builder_instance = MagicMock()
        builder_instance.subjects.return_value = builder_instance
        builder_instance.predicate_type.return_value = builder_instance
        builder_instance.predicate.return_value = builder_instance
        statement_sentinel = object()
        builder_instance.build.return_value = statement_sentinel
        mock_statement_builder_cls.return_value = builder_instance

        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = '{"mediaType":"sigstore-bundle","dsseEnvelope":{}}'
        fake_signer = MagicMock()
        fake_signer.sign_dsse.return_value = fake_bundle
        cm = MagicMock()
        cm.__enter__.return_value = fake_signer
        cm.__exit__.return_value = False
        ctx = MagicMock()
        ctx.signer.return_value = cm
        mock_signing_context.from_trust_config.return_value = ctx

        content_hash = f"sha256:{hashlib.sha256(b'x').hexdigest()}"
        result = sign_verification_statement(
            "eyJ.token",
            model_id="m-abc",
            tier=1,
            content_hash=content_hash,
            pipeline={"provider": "github_actions", "commit_sha": "deadbeef"},
            assertions=[{"id": "asrt_001", "type": "function_exists"}],
            results=[{"assertion_id": "asrt_001", "tier": 1, "result": "pass"}],
        )

        assert result == '{"mediaType":"sigstore-bundle","dsseEnvelope":{}}'
        # The DSSE path is used, not sign_artifact — the bundle carries the
        # full attestation payload, not just a hash commitment.
        fake_signer.sign_dsse.assert_called_once_with(statement_sentinel)
        assert not fake_signer.sign_artifact.called

        # Predicate carries the full verification context so auditors can
        # reconstruct from the bundle alone.
        predicate_call = builder_instance.predicate.call_args.args[0]
        assert predicate_call["model_id"] == "m-abc"
        assert predicate_call["tier"] == 1
        assert predicate_call["content_hash"] == content_hash
        assert predicate_call["pipeline"]["commit_sha"] == "deadbeef"
        assert predicate_call["assertions"][0]["id"] == "asrt_001"
        assert predicate_call["results"][0]["result"] == "pass"

        # Exactly one Subject on the Statement; digest binding verified in
        # the full integration test (live Fulcio/Rekor).
        subjects_arg = builder_instance.subjects.call_args.args[0]
        assert len(subjects_arg) == 1

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    @patch("mipiti_verify.sigstore_signer.StatementBuilder")
    def test_trust_config_path_takes_precedence_over_tuf_url(
        self,
        mock_statement_builder_cls: MagicMock,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
        tmp_path,
    ) -> None:
        builder_instance = MagicMock()
        builder_instance.subjects.return_value = builder_instance
        builder_instance.predicate_type.return_value = builder_instance
        builder_instance.predicate.return_value = builder_instance
        builder_instance.build.return_value = object()
        mock_statement_builder_cls.return_value = builder_instance

        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = "{}"
        fake_signer = MagicMock()
        fake_signer.sign_dsse.return_value = fake_bundle
        cm = MagicMock()
        cm.__enter__.return_value = fake_signer
        cm.__exit__.return_value = False
        ctx = MagicMock()
        ctx.signer.return_value = cm
        mock_signing_context.from_trust_config.return_value = ctx

        cfg_path = tmp_path / "trust_config.json"
        cfg_path.write_text(
            '{"media_type": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"}'
        )

        sign_verification_statement(
            "token", model_id="m1", tier=1, content_hash=_valid_hash(),
            pipeline={}, assertions=[], results=[],
            tuf_url="https://sigstore.internal/tuf",  # should be ignored
            trust_config_path=str(cfg_path),
        )

        mock_trust_config.from_json.assert_called_once()
        mock_trust_config.from_tuf.assert_not_called()
        mock_trust_config.production.assert_not_called()
