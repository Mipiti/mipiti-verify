"""Sigstore keyless signing for mipiti-verify.

Converts a short-lived OIDC identity token into a long-lived, auditor-verifiable
Sigstore bundle:

1. Present the OIDC token to Fulcio -> short-lived X.509 signing certificate
2. Generate an ephemeral keypair; sign the content hash; discard the private key
3. Submit the signed entry to Rekor (transparency log) -> inclusion proof
4. Package the certificate, signature, and inclusion proof as a Sigstore bundle

The bundle is a non-secret artefact: auditors verify it against the public Rekor
log and Sigstore trust root, without needing access to Mipiti or the original
token. The raw OIDC token never leaves the CI runner.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from sigstore.models import ClientTrustConfig
from sigstore.oidc import IdentityToken
from sigstore.sign import SigningContext


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


def sign_content_hash(
    identity_token: str,
    content_hash: str,
    *,
    tuf_url: str | None = None,
    trust_config_path: str | None = None,
) -> str:
    """Sign a content hash with Sigstore and return the bundle as JSON.

    Args:
        identity_token: Raw OIDC JWT from the CI runner (e.g. GitHub Actions
            `ACTIONS_ID_TOKEN_REQUEST_URL` or GitLab `CI_JOB_JWT_V2`).
        content_hash: `sha256:<hex>` digest of the verified content.
        tuf_url: Optional custom TUF root URL (private Sigstore instance).
        trust_config_path: Optional path to a pre-downloaded Sigstore
            ClientTrustConfig JSON file; used in preference to `tuf_url` for
            fully air-gapped CI (no outbound to any TUF host).

    Returns:
        JSON-serialised Sigstore bundle (bundle_v0.3, Sigstore specification).

    Raises:
        ValueError if `identity_token` is empty or `content_hash` is not a
            parseable sha256 digest.

    Network:
        Contacts Fulcio (cert issuance) and Rekor (transparency log entry).
        The OIDC token is sent only to Fulcio, never to Mipiti's backend.
    """
    if not identity_token:
        raise ValueError("identity_token is required")

    digest_bytes = _content_hash_to_bytes(content_hash)
    if len(digest_bytes) != hashlib.sha256().digest_size:
        raise ValueError(
            f"content_hash is not a sha256 digest: got {len(digest_bytes)} bytes"
        )

    trust_config = _load_trust_config(tuf_url, trust_config_path)
    signing_context = SigningContext.from_trust_config(trust_config)
    identity = IdentityToken(identity_token)

    # sign_artifact accepts raw bytes; it recomputes the hash internally, so
    # we pass the canonical bytes that produced the digest. For integrity we
    # sign the content_hash string itself, ensuring the bundle binds the
    # exact digest Mipiti will verify.
    payload = content_hash.encode("utf-8")

    with signing_context.signer(identity) as signer:
        bundle = signer.sign_artifact(payload)

    return bundle.to_json()
