"""Unit tests for the Sigstore signing helper.

Network-free: the sigstore-python client layer is mocked so these tests do not
contact Fulcio or Rekor. Integration with the public Sigstore services is
covered by a dedicated live-run workflow in CI.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.sigstore_signer import _content_hash_to_bytes, sign_content_hash


class TestContentHashToBytes:
    def test_accepts_prefixed_digest(self) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        out = _content_hash_to_bytes(f"sha256:{digest}")
        assert out == bytes.fromhex(digest)
        assert len(out) == 32

    def test_accepts_bare_hex(self) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        assert _content_hash_to_bytes(digest) == bytes.fromhex(digest)


class TestSignContentHash:
    def test_requires_identity_token(self) -> None:
        with pytest.raises(ValueError, match="identity_token"):
            sign_content_hash("", f"sha256:{'0'*64}")

    def test_rejects_non_sha256_digest(self) -> None:
        # 31 bytes (62 hex chars) — not a valid sha256 digest
        with pytest.raises(ValueError, match="sha256"):
            sign_content_hash("token", f"sha256:{'aa'*31}")

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    def test_signs_and_returns_bundle_json(
        self,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
    ) -> None:
        # Arrange: wire the sigstore-python context chain to return a mock
        # bundle whose to_json() yields a sentinel string.
        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = '{"mediaType":"sigstore-bundle"}'
        fake_signer = MagicMock()
        fake_signer.sign_artifact.return_value = fake_bundle
        cm = MagicMock()
        cm.__enter__.return_value = fake_signer
        cm.__exit__.return_value = False
        ctx = MagicMock()
        ctx.signer.return_value = cm
        mock_signing_context.from_trust_config.return_value = ctx

        content_hash = f"sha256:{hashlib.sha256(b'payload').hexdigest()}"
        result = sign_content_hash("eyJ...token", content_hash)

        assert result == '{"mediaType":"sigstore-bundle"}'
        # Production trust config is used when no TUF URL is supplied
        mock_trust_config.production.assert_called_once()
        mock_trust_config.from_tuf.assert_not_called()
        # The payload signed is the content_hash bytes (deterministic binding)
        fake_signer.sign_artifact.assert_called_once_with(content_hash.encode("utf-8"))

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    def test_private_tuf_url_routes_to_from_tuf(
        self,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
    ) -> None:
        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = "{}"
        fake_signer = MagicMock()
        fake_signer.sign_artifact.return_value = fake_bundle
        cm = MagicMock()
        cm.__enter__.return_value = fake_signer
        cm.__exit__.return_value = False
        ctx = MagicMock()
        ctx.signer.return_value = cm
        mock_signing_context.from_trust_config.return_value = ctx

        sign_content_hash(
            "token",
            f"sha256:{hashlib.sha256(b'x').hexdigest()}",
            tuf_url="https://sigstore.internal/tuf",
        )

        mock_trust_config.from_tuf.assert_called_once_with(
            "https://sigstore.internal/tuf", offline=False
        )
        mock_trust_config.production.assert_not_called()

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    def test_trust_config_path_takes_precedence_over_tuf_url(
        self,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
        tmp_path,
    ) -> None:
        """A pre-downloaded trust config file skips TUF fetches entirely —
        fully air-gapped signing. When both are supplied, the file wins."""
        fake_bundle = MagicMock()
        fake_bundle.to_json.return_value = "{}"
        fake_signer = MagicMock()
        fake_signer.sign_artifact.return_value = fake_bundle
        cm = MagicMock()
        cm.__enter__.return_value = fake_signer
        cm.__exit__.return_value = False
        ctx = MagicMock()
        ctx.signer.return_value = cm
        mock_signing_context.from_trust_config.return_value = ctx

        cfg_path = tmp_path / "trust_config.json"
        cfg_path.write_text('{"media_type": "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"}')

        sign_content_hash(
            "token",
            f"sha256:{hashlib.sha256(b'x').hexdigest()}",
            tuf_url="https://sigstore.internal/tuf",  # should be ignored
            trust_config_path=str(cfg_path),
        )

        mock_trust_config.from_json.assert_called_once()
        mock_trust_config.from_tuf.assert_not_called()
        mock_trust_config.production.assert_not_called()
