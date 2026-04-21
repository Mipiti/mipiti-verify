"""Sigstore keyless signing for mipiti-verify.

Converts a short-lived OIDC identity token into a long-lived, auditor-verifiable
Sigstore bundle carrying a DSSE (Dead Simple Signing Envelope) attestation:

1. Present the OIDC token to Fulcio -> short-lived X.509 signing certificate
2. Build an in-toto Statement with the full verification context as predicate
3. Sign the Statement (via DSSE) with an ephemeral keypair; discard the key
4. Submit the signed entry to Rekor (transparency log) -> inclusion proof
5. Package the certificate, signature, envelope, and inclusion proof as a
   Sigstore bundle

The bundle is self-contained: the envelope carries the assertion + verdict
payload directly, so an auditor can extract the attestation and verify both
its signature and its semantic content from the bundle alone — no need to
co-locate the verdict data in a separate artefact. The raw OIDC token never
leaves the CI runner.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sigstore.dsse import StatementBuilder, Subject
from sigstore.models import ClientTrustConfig
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext


# In-toto predicate type for a Mipiti verification run. Versioned; changes
# to the predicate schema MUST bump the version so verifiers can distinguish
# shapes safely.
PREDICATE_TYPE = "https://mipiti.io/attestations/v1/verification-run"


def _content_hash_to_bytes(content_hash: str) -> bytes:
    """Normalise a `sha256:<hex>` content hash into raw digest bytes."""
    prefix = "sha256:"
    if content_hash.startswith(prefix):
        hex_part = content_hash[len(prefix):]
    else:
        hex_part = content_hash
    return bytes.fromhex(hex_part)


def _load_trust_config(
    tuf_url: str | None,
    trust_config_path: str | None,
) -> ClientTrustConfig:
    """Resolve the Sigstore trust config from (in priority order):

    1. `trust_config_path`: a pre-downloaded ClientTrustConfig JSON file.
       Lets air-gapped CI ship a trust snapshot obtained out-of-band, with
       zero network dependency on Sigstore hosts at signing time.
    2. `tuf_url`: a TUF-served Sigstore instance (public or private).
       Still requires outbound to the configured host.
    3. Default (neither supplied): the public Sigstore production instance
       at `tuf-repo-cdn.sigstore.dev`.
    """
    if trust_config_path:
        data = Path(trust_config_path).read_text(encoding="utf-8")
        return ClientTrustConfig.from_json(data)
    if tuf_url:
        return ClientTrustConfig.from_tuf(tuf_url, offline=False)
    return ClientTrustConfig.production()


def sign_verification_statement(
    identity_token: str,
    *,
    model_id: str,
    tier: int,
    content_hash: str,
    pipeline: dict[str, Any],
    assertions: list[dict[str, Any]],
    results: list[dict[str, Any]],
    tuf_url: str | None = None,
    trust_config_path: str | None = None,
) -> str:
    """Sign a Mipiti verification run as an in-toto DSSE attestation.

    Produces a Sigstore bundle whose DSSE envelope carries the full
    attestation payload (assertions + verdicts + pipeline metadata),
    not just a commitment to the content hash. Auditors can extract
    and verify the payload directly from the bundle.

    Args:
        identity_token: Raw OIDC JWT from the CI runner (GitHub Actions
            `ACTIONS_ID_TOKEN_REQUEST_URL` or GitLab `CI_JOB_JWT_V2`).
        model_id: ID of the Mipiti threat model under verification.
        tier: 1 (mechanical) or 2 (semantic / adversarial LLM).
        content_hash: `sha256:<hex>` digest of the canonical assertions +
            verdicts JSON. Becomes the Subject digest on the Statement.
        pipeline: CI pipeline metadata (provider, commit_sha, ref, run_id,
            run_url) — carried in the predicate for auditor context.
        assertions: Full assertion definitions that were verified (id,
            type, params, description, control/assumption ids).
        results: Per-assertion tier verdicts (assertion_id, tier, result,
            details, reasoning, reviewer).
        tuf_url: Optional custom TUF root URL (private Sigstore instance).
        trust_config_path: Optional path to a pre-downloaded Sigstore
            ClientTrustConfig JSON file; used in preference to `tuf_url`
            for fully air-gapped CI (no outbound to any TUF host).

    Returns:
        JSON-serialised Sigstore bundle (bundle_v0.3). The DSSE envelope
        inside the bundle carries an in-toto Statement whose predicate is
        the full verification payload, not just an opaque hash.

    Raises:
        ValueError if `identity_token` is empty, `tier` is not 1 or 2, or
            `content_hash` is not a parseable sha256 digest.

    Network:
        Contacts Fulcio (cert issuance) and Rekor (transparency log entry).
        The OIDC token is sent only to Fulcio, never to Mipiti's backend.
    """
    if not identity_token:
        raise ValueError("identity_token is required")
    if tier not in (1, 2):
        raise ValueError(f"tier must be 1 or 2, got {tier!r}")

    digest_bytes = _content_hash_to_bytes(content_hash)
    if len(digest_bytes) != hashlib.sha256().digest_size:
        raise ValueError(
            f"content_hash is not a sha256 digest: got {len(digest_bytes)} bytes"
        )

    hex_digest = digest_bytes.hex()

    statement = (
        StatementBuilder()
        .subjects(
            [
                Subject(
                    name=f"mipiti:verification:tier{tier}:{model_id}",
                    digest={"sha256": hex_digest},
                )
            ]
        )
        .predicate_type(PREDICATE_TYPE)
        .predicate(
            {
                "model_id": model_id,
                "tier": tier,
                "content_hash": content_hash,
                "pipeline": pipeline,
                "assertions": assertions,
                "results": results,
            }
        )
        .build()
    )

    trust_config = _load_trust_config(tuf_url, trust_config_path)
    signing_context = SigningContext.from_trust_config(trust_config)
    identity = IdentityToken(identity_token)

    with signing_context.signer(identity) as signer:
        bundle = signer.sign_dsse(statement)

    return bundle.to_json()
