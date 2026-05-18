"""Customer-keyed offline DSSE signing for mipiti-verify.

For air-gapped and non-Sigstore CI (Jenkins, self-managed/older GitLab,
Buildkite/CircleCI without OIDC, regulated networks) that cannot reach
public Sigstore infrastructure at sign time, this module produces a
**customer-controlled, vendor-independent, offline-verifiable** attestation
expressed in the standard DSSE / in-toto format Mipiti already verifies for
the Sigstore path — not a bespoke envelope.

The customer holds an ECDSA P-256 private key locally and registers the
matching public key on their Mipiti workspace. This module:

1. Builds the same in-toto Statement shape the Sigstore path builds
   (subject ``mipiti:verification:tier<tier>:<model_id>``, subject digest
   = sha256 hex of the content hash, the v1 predicate type, gzip+base64
   compressed assertion/verdict payload).
2. Serialises the Statement canonically (``json.dumps`` with
   ``sort_keys=True`` + compact separators, UTF-8 NFC-normalised).
3. Computes the DSSE Pre-Authentication Encoding (PAE) over that payload.
4. Signs the PAE with the customer's ECDSA P-256 / SHA-256 private key
   (loaded from a PEM file, with an optional passphrase).
5. Emits a self-describing ``customer-dsse`` bundle (payload, signature,
   and the public key PEM for auditor convenience).

No Fulcio, no Rekor, no network — at sign time or verify time. Trust
derives from the auditor pinning the public-key **fingerprint**
out-of-band from the customer, never from the bundle's embedded PEM.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Reuse the exact predicate type + compression tag the Sigstore path uses,
# so a customer-DSSE Statement is shape-identical to a Sigstore one.
from .sigstore_signer import (
    _COMPRESSION_GZIP_BASE64,
    PREDICATE_TYPE,
    _content_hash_to_bytes,
)

# DSSE payload type for an in-toto Statement (the DSSE / in-toto spec
# constant; identical to what sigstore-python uses internally).
PAYLOAD_TYPE = "application/vnd.in-toto+json"

# in-toto Statement type URI (the spec constant).
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Bundle format discriminator + version.
BUNDLE_KIND = "customer-dsse"
BUNDLE_VERSION = 1


def build_statement_bytes(
    *,
    model_id: str,
    tier: int,
    content_hash: str,
    pipeline: dict[str, Any],
    assertions: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> bytes:
    """Build the canonical in-toto Statement bytes for a verification run.

    Same JSON object shape as the Sigstore path's Statement (subject name,
    subject digest, predicate type, predicate fields, gzip+base64
    compressed assertion/verdict payload). Serialised per the contract:
    ``json.dumps(statement, sort_keys=True, separators=(",", ":"))``,
    UTF-8 encoded, NFC-normalised.

    Raises ``ValueError`` if ``tier`` is not 1 or 2 or ``content_hash`` is
    not a parseable sha256 digest — same validation as the Sigstore path.
    """
    if tier not in (1, 2):
        raise ValueError(f"tier must be 1 or 2, got {tier!r}")

    digest_bytes = _content_hash_to_bytes(content_hash)
    if len(digest_bytes) != hashlib.sha256().digest_size:
        raise ValueError(
            f"content_hash is not a sha256 digest: got {len(digest_bytes)} bytes"
        )
    hex_digest = digest_bytes.hex()

    # Move the bulky arrays into compressed_payload (gzip + base64 of
    # canonical JSON of {assertions, results}) — byte-identical to the
    # Sigstore path's inner-payload construction.
    inner = json.dumps(
        {"assertions": assertions, "results": results},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    compressed_payload = base64.b64encode(gzip.compress(inner)).decode("ascii")

    statement = {
        "_type": _STATEMENT_TYPE,
        "subject": [
            {
                "name": f"mipiti:verification:tier{tier}:{model_id}",
                "digest": {"sha256": hex_digest},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "model_id": model_id,
            "tier": tier,
            "content_hash": content_hash,
            "pipeline": pipeline,
            "encoding": _COMPRESSION_GZIP_BASE64,
            "compressed_payload": compressed_payload,
        },
    }

    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":"))
    return unicodedata.normalize("NFC", canonical).encode("utf-8")


def compute_pae(payload: bytes) -> bytes:
    """Compute the DSSE Pre-Authentication Encoding over a Statement.

    Exactly per the contract / DSSE v1 spec::

        PAE = b"DSSEv1" + b" " + ascii(len(payloadType)) + b" " + payloadType
                        + b" " + ascii(len(payload))     + b" " + payload
        payloadType = b"application/vnd.in-toto+json"
        payload     = Statement bytes

    ``len(...)`` is the byte length; ``ascii(n)`` is the decimal integer
    rendered as ASCII digits. Byte-identical to sigstore-python's internal
    ``_pae`` for the same payload type and payload.
    """
    payload_type = PAYLOAD_TYPE.encode("utf-8")
    return b"".join(
        [
            b"DSSEv1",
            b" ",
            str(len(payload_type)).encode("ascii"),
            b" ",
            payload_type,
            b" ",
            str(len(payload)).encode("ascii"),
            b" ",
            payload,
        ]
    )


def _load_private_key(
    key_path: str | Path,
    passphrase: str | None,
) -> ec.EllipticCurvePrivateKey:
    """Load a PEM ECDSA P-256 private key, with an optional passphrase.

    Raises ``ValueError`` (message suitable for the CLI) on any failure:
    unreadable file, wrong/missing passphrase, non-EC key, or wrong curve.
    Mirrors ``WorkspaceKeySigner``'s validation so the customer-DSSE path
    enforces the same curve the backend verifier expects.
    """
    path = Path(key_path)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise ValueError(f"Cannot read customer signing key at {path}: {e}") from e

    password = passphrase.encode("utf-8") if passphrase else None
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except Exception as e:
        hint = (
            "is not a valid PEM private key"
            if password is None
            else "could not be decrypted with the supplied passphrase, "
            "or is not a valid PEM private key"
        )
        raise ValueError(
            f"Customer signing key at {path} {hint}: {e}"
        ) from e

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(
            f"Customer signing key at {path} is not an EC private key "
            f"(got {type(key).__name__}). Mipiti expects ECDSA P-256."
        )
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(
            f"Customer signing key at {path} uses curve "
            f"{key.curve.name!r}; Mipiti expects P-256 (secp256r1)."
        )
    return key


def sign_verification_statement(
    *,
    model_id: str,
    tier: int,
    content_hash: str,
    pipeline: dict[str, Any],
    assertions: list[dict[str, Any]],
    results: list[dict[str, Any]],
    key_path: str | Path,
    passphrase: str | None = None,
) -> str:
    """Sign a Mipiti verification run as a customer-keyed DSSE attestation.

    Produces a self-contained ``customer-dsse`` bundle (JSON string). The
    DSSE payload is an in-toto Statement carrying the full assertion +
    verdict payload, signed by the customer's ECDSA P-256 private key over
    the DSSE PAE. No network at any point.

    Args:
        model_id: ID of the Mipiti threat model under verification.
        tier: 1 (mechanical) or 2 (semantic / adversarial LLM).
        content_hash: ``sha256:<hex>`` digest of the canonical assertions +
            verdicts JSON (``runner.compute_content_hash`` output). Becomes
            the Statement subject digest (hex only, ``sha256:`` stripped).
        pipeline: CI pipeline metadata carried in the predicate.
        assertions: Full assertion definitions that were verified.
        results: Per-assertion tier verdicts.
        key_path: Path to the customer's PEM ECDSA P-256 private key.
        passphrase: Optional passphrase for an encrypted PEM key.

    Returns:
        JSON-serialised ``customer-dsse`` bundle::

            {
              "v": 1,
              "kind": "customer-dsse",
              "payloadType": "application/vnd.in-toto+json",
              "payload":     "<base64(Statement bytes)>",
              "signature":   "<base64(DER ECDSA P-256/SHA-256 over PAE)>",
              "public_key_pem": "<customer P-256 public key, PEM SPKI>"
            }

    Raises:
        ValueError if ``tier``/``content_hash`` are invalid or the key
            cannot be loaded.
    """
    key = _load_private_key(key_path, passphrase)

    payload = build_statement_bytes(
        model_id=model_id,
        tier=tier,
        content_hash=content_hash,
        pipeline=pipeline,
        assertions=assertions,
        results=results,
    )
    pae = compute_pae(payload)
    signature_der = key.sign(pae, ec.ECDSA(hashes.SHA256()))

    public_key_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )

    bundle = {
        "v": BUNDLE_VERSION,
        "kind": BUNDLE_KIND,
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature_der).decode("ascii"),
        "public_key_pem": public_key_pem,
    }
    return json.dumps(bundle)
