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
        # Bulky arrays are moved into compressed_payload — gzip+base64
        # of canonical JSON of {assertions, results}.
        assert predicate_call["encoding"] == "gzip+base64"
        import base64 as _b64, gzip as _gz, json as _json
        inner = _json.loads(
            _gz.decompress(_b64.b64decode(predicate_call["compressed_payload"]))
            .decode("utf-8")
        )
        assert inner["assertions"][0]["id"] == "asrt_001"
        assert inner["results"][0]["result"] == "pass"
        # Assertions/results are NOT also inlined — that defeats the point.
        assert "assertions" not in predicate_call
        assert "results" not in predicate_call

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

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    @patch("mipiti_verify.sigstore_signer.StatementBuilder")
    def test_compressed_payload_round_trips_to_canonical_json(
        self,
        mock_statement_builder_cls: MagicMock,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
    ) -> None:
        """encoding = "gzip+base64", compressed_payload =
        base64(gzip(canonical JSON of {assertions, results})). Mirrors
        the inversion here so a producer/consumer drift fails locally."""
        import base64
        import gzip
        import json

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

        # Realistic-shape rows; descriptions/reasoning are the bulky
        # fields that pushed bundles past 256KB pre-compression.
        assertions = [
            {
                "id": f"asrt_{i:03d}",
                "type": "function_exists",
                "params": {"name": f"check_{i}"},
                "description": "x" * 200,
            }
            for i in range(50)
        ]
        results = [
            {
                "assertion_id": f"asrt_{i:03d}",
                "tier": 2,
                "result": "pass",
                "reasoning": "x" * 200,
            }
            for i in range(50)
        ]

        sign_verification_statement(
            "token", model_id="m1", tier=2, content_hash=_valid_hash(),
            pipeline={}, assertions=assertions, results=results,
        )

        predicate = builder_instance.predicate.call_args.args[0]
        assert predicate["encoding"] == "gzip+base64"
        compressed = predicate["compressed_payload"]
        assert isinstance(compressed, str)

        recovered = json.loads(
            gzip.decompress(base64.b64decode(compressed)).decode("utf-8")
        )
        assert recovered["assertions"] == assertions
        assert recovered["results"] == results

        # Compression actually shrinks the payload — sanity-check the
        # whole point of this code path. Bulky descriptions / reasoning
        # are highly compressible.
        raw_json = json.dumps(
            {"assertions": assertions, "results": results},
            separators=(",", ":"),
            sort_keys=True,
        )
        assert len(compressed) < len(raw_json) // 2

    @patch("mipiti_verify.sigstore_signer.SigningContext")
    @patch("mipiti_verify.sigstore_signer.ClientTrustConfig")
    @patch("mipiti_verify.sigstore_signer.IdentityToken")
    @patch("mipiti_verify.sigstore_signer.StatementBuilder")
    def test_compressed_payload_uses_canonical_json(
        self,
        mock_statement_builder_cls: MagicMock,
        mock_identity: MagicMock,
        mock_trust_config: MagicMock,
        mock_signing_context: MagicMock,
    ) -> None:
        """Inner JSON uses `sort_keys=True` + tight separators so two
        identical inputs produce identical compressed bytes (the DSSE
        signature covers them)."""
        import base64
        import gzip
        import json

        builder_instance = MagicMock()
        builder_instance.subjects.return_value = builder_instance
        builder_instance.predicate_type.return_value = builder_instance
        builder_instance.predicate.return_value = builder_instance
        builder_instance.build.return_value = object()
        mock_statement_builder_cls.return_value = builder_instance

        fake_signer = MagicMock()
        fake_signer.sign_dsse.return_value = MagicMock(to_json=lambda: "{}")
        cm = MagicMock()
        cm.__enter__.return_value = fake_signer
        cm.__exit__.return_value = False
        mock_signing_context.from_trust_config.return_value = MagicMock(
            signer=lambda _identity: cm
        )

        # Same rows, different key order on input — canonical JSON
        # should produce identical compressed_payload either way.
        rows_a = {"id": "asrt_1", "type": "t", "description": "d"}
        rows_b = {"description": "d", "type": "t", "id": "asrt_1"}

        sign_verification_statement(
            "token", model_id="m1", tier=1, content_hash=_valid_hash(),
            pipeline={}, assertions=[rows_a], results=[],
        )
        comp_a = builder_instance.predicate.call_args.args[0]["compressed_payload"]

        sign_verification_statement(
            "token", model_id="m1", tier=1, content_hash=_valid_hash(),
            pipeline={}, assertions=[rows_b], results=[],
        )
        comp_b = builder_instance.predicate.call_args.args[0]["compressed_payload"]

        assert comp_a == comp_b
        # The inflated JSON also matches the canonical form on disk.
        inflated = json.loads(
            gzip.decompress(base64.b64decode(comp_a)).decode("utf-8")
        )
        assert inflated == {
            "assertions": [{"description": "d", "id": "asrt_1", "type": "t"}],
            "results": [],
        }
