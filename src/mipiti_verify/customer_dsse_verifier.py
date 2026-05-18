"""Offline verifier for customer-keyed DSSE attestations.

Implements the verification algorithm from the customer-keyed offline
attestation contract — identical in the Mipiti backend submit-check and
``mipiti-verify audit``:

1. Parse the bundle; reconstruct the DSSE PAE from ``payloadType`` +
   base64-decoded ``payload``.
2. Verify ``signature`` over the PAE with ``public_key_pem`` (ECDSA
   P-256 / SHA-256).
3. ``sha256(DER SubjectPublicKeyInfo(public_key_pem))`` hex == the
   auditor's out-of-band pinned fingerprint. This is the
   vendor-independence gate — a swapped key fails here.
4. Parse the in-toto Statement from ``payload``; ``predicateType`` ==
   the v1 constant; ``subject[].digest.sha256`` == hex of the report's
   ``content_hash``.

All steps are pure-bytes: no network, no Sigstore, no Rekor. Trust
derives from the auditor pinning the public-key fingerprint from the
customer, never from the bundle's embedded PEM nor any Mipiti-stored
copy.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .customer_dsse_signer import (
    BUNDLE_KIND,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    compute_pae,
)


class CustomerDsseVerificationError(Exception):
    """Raised when a customer-DSSE bundle fails any verification step.

    The message names the failed step so callers (CLI / backend) can
    surface a precise, fail-closed diagnostic.
    """


@dataclass(frozen=True)
class CustomerDsseResult:
    """Successful verification outcome.

    ``key_fingerprint`` is the SHA-256 hex of the DER SubjectPublicKeyInfo
    of the key that actually verified the signature — the same algorithm
    the platform / workspace-key path uses. ``statement`` is the parsed
    in-toto Statement; ``predicate`` is its predicate object.
    """

    key_fingerprint: str
    statement: dict[str, Any]
    predicate: dict[str, Any]


def key_fingerprint(public_key_pem: str) -> str:
    """SHA-256 hex of the DER SubjectPublicKeyInfo of a PEM public key.

    The canonical fingerprint algorithm shared with the Mipiti platform
    and the workspace-ECDSA path. ``ValueError`` on an unparseable PEM.
    """
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"public_key_pem is not a valid PEM public key: {e}") from e
    der_bytes = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der_bytes).hexdigest()


def _content_hash_hex(content_hash: str) -> str:
    """Strip an optional ``sha256:`` prefix, returning the bare hex."""
    prefix = "sha256:"
    if content_hash.startswith(prefix):
        return content_hash[len(prefix):]
    return content_hash


def verify_customer_dsse_bundle(
    bundle_json: str,
    *,
    content_hash: str,
    expected_fingerprint: str,
) -> CustomerDsseResult:
    """Verify a ``customer-dsse`` bundle fully offline.

    Args:
        bundle_json: The bundle JSON string emitted by
            ``customer_dsse_signer.sign_verification_statement``.
        content_hash: The report's ``content_hash`` (``sha256:<hex>`` or
            bare hex). Step 4 binds the Statement subject digest to this.
        expected_fingerprint: The auditor's out-of-band pinned public-key
            fingerprint (SHA-256 hex of DER SPKI). Step 3 — the
            vendor-independence gate. **Required**; callers must never
            silently trust the bundle's embedded PEM.

    Returns:
        ``CustomerDsseResult`` on success.

    Raises:
        CustomerDsseVerificationError on any failed step (fail-closed).
    """
    if not expected_fingerprint:
        # The pin is the entire trust basis for this path; refusing to
        # proceed without it prevents a caller from accidentally
        # accepting the bundle's self-asserted key.
        raise CustomerDsseVerificationError(
            "expected_fingerprint is required: the customer-DSSE path "
            "derives trust solely from the auditor's out-of-band pinned "
            "public-key fingerprint, never from the bundle's embedded PEM."
        )

    # --- Step 1: parse the bundle, reconstruct the PAE ---
    try:
        bundle = json.loads(bundle_json)
    except Exception as e:
        raise CustomerDsseVerificationError(
            f"step 1: bundle is not valid JSON: {e}"
        ) from e
    if not isinstance(bundle, dict):
        raise CustomerDsseVerificationError(
            "step 1: bundle is not a JSON object"
        )
    if bundle.get("kind") != BUNDLE_KIND:
        raise CustomerDsseVerificationError(
            f"step 1: bundle kind is {bundle.get('kind')!r}, "
            f"expected {BUNDLE_KIND!r}"
        )
    payload_type = bundle.get("payloadType", "")
    if payload_type != PAYLOAD_TYPE:
        raise CustomerDsseVerificationError(
            f"step 1: payloadType is {payload_type!r}, "
            f"expected {PAYLOAD_TYPE!r}"
        )
    try:
        payload = base64.b64decode(bundle["payload"], validate=True)
        signature = base64.b64decode(bundle["signature"], validate=True)
    except Exception as e:
        raise CustomerDsseVerificationError(
            f"step 1: payload/signature is not valid base64: {e}"
        ) from e
    public_key_pem = bundle.get("public_key_pem", "")
    if not public_key_pem:
        raise CustomerDsseVerificationError(
            "step 1: bundle has no public_key_pem"
        )

    pae = compute_pae(payload)

    # --- Step 2: verify the signature over the PAE ---
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as e:
        raise CustomerDsseVerificationError(
            f"step 2: public_key_pem is not a valid PEM public key: {e}"
        ) from e
    if not isinstance(pub_key, ec.EllipticCurvePublicKey) or not isinstance(
        pub_key.curve, ec.SECP256R1
    ):
        raise CustomerDsseVerificationError(
            "step 2: public_key_pem is not an ECDSA P-256 (secp256r1) key"
        )
    try:
        pub_key.verify(signature, pae, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise CustomerDsseVerificationError(
            "step 2: DSSE signature does not verify over the PAE "
            "with the embedded public key"
        ) from e

    # --- Step 3: fingerprint pin (the vendor-independence gate) ---
    der_bytes = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    computed_fp = hashlib.sha256(der_bytes).hexdigest()
    if computed_fp != expected_fingerprint:
        raise CustomerDsseVerificationError(
            f"step 3: public-key fingerprint mismatch — the key that "
            f"signed this bundle ({computed_fp}) is not the auditor's "
            f"pinned key ({expected_fingerprint}). A swapped or "
            f"vendor-substituted key fails here."
        )

    # --- Step 4: parse Statement; check predicate type + subject digest ---
    try:
        statement = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise CustomerDsseVerificationError(
            f"step 4: DSSE payload is not valid JSON: {e}"
        ) from e
    if not isinstance(statement, dict):
        raise CustomerDsseVerificationError(
            "step 4: DSSE payload is not a JSON object"
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise CustomerDsseVerificationError(
            f"step 4: predicateType is {statement.get('predicateType')!r}, "
            f"expected {PREDICATE_TYPE!r}"
        )

    expected_hex = _content_hash_hex(content_hash)
    subjects = statement.get("subject", [])
    if not isinstance(subjects, list) or not subjects:
        raise CustomerDsseVerificationError(
            "step 4: Statement has no subject"
        )
    digests = {
        s.get("digest", {}).get("sha256", "")
        for s in subjects
        if isinstance(s, dict)
    }
    if expected_hex not in digests:
        raise CustomerDsseVerificationError(
            f"step 4: no subject digest matches the report content hash "
            f"(expected sha256={expected_hex}, "
            f"Statement carries {sorted(digests)})"
        )

    predicate = statement.get("predicate", {})
    if not isinstance(predicate, dict):
        predicate = {}
    return CustomerDsseResult(
        key_fingerprint=computed_fp,
        statement=statement,
        predicate=predicate,
    )
