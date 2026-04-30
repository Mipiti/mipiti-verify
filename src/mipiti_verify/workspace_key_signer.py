"""Workspace-ECDSA fallback signer for mipiti-verify.

When OIDC isn't available (Jenkins, Buildkite, self-managed GitLab without
ID tokens, air-gapped CI), customers can register an ECDSA P-256 public
key on their Mipiti workspace (`Workspace.verification_public_key`) and
keep the private half local. This module signs the per-tier
``content_hash`` with that private key so submissions still carry an
attestation that the backend can verify against the registered public
key — no Sigstore / OIDC dependency.

The signing format mirrors what the backend expects on the
``signature`` + ``signed_hash`` body fields of
``POST /api/models/{id}/verification/results``:

  - ``signed_hash`` — the hex-encoded SHA-256 of the canonical results
    payload (already computed by ``runner.compute_content_hash``; we
    strip the ``sha256:`` prefix so the wire form is just hex).
  - ``signature`` — base64-encoded raw ECDSA P-256 signature
    (DER-encoded ``ASN.1 ECDSA-Sig-Value``) over the SHA-256 digest.

Verification on the backend side uses the same hash + the workspace's
registered ``verification_public_key`` (PEM-encoded).

The private key is loaded from a PEM file on disk. The file is read
once per signer construction; the in-memory key object is reused for
every per-tier signature. On any load or sign failure, callers receive
empty strings and proceed to submit unsigned — the run still completes,
matching the "submit without attestation" fallback behaviour from
``runner._sign_with_sigstore``.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class WorkspaceKeySigner:
    """ECDSA P-256 signer that produces ``signature`` + ``signed_hash``
    pairs accepted by the Mipiti backend.

    Construction loads the PEM private key once. Loading errors raise
    ``ValueError`` with a message suitable for surfacing to the CLI.
    """

    def __init__(self, key_path: str | Path) -> None:
        path = Path(key_path)
        try:
            data = path.read_bytes()
        except OSError as e:
            raise ValueError(f"Cannot read workspace signing key at {path}: {e}") from e

        try:
            key = serialization.load_pem_private_key(data, password=None)
        except Exception as e:
            raise ValueError(
                f"Workspace signing key at {path} is not a valid unencrypted PEM private key: {e}"
            ) from e

        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError(
                f"Workspace signing key at {path} is not an EC private key "
                f"(got {type(key).__name__}). The Mipiti backend expects ECDSA P-256."
            )

        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(
                f"Workspace signing key at {path} uses curve "
                f"{key.curve.name!r}; the Mipiti backend expects P-256 (secp256r1)."
            )

        self._key = key

    def sign(self, content_hash: str) -> tuple[str, str]:
        """Sign a ``runner.compute_content_hash`` output.

        ``content_hash`` is the value produced by
        ``runner.compute_content_hash``: a string of the form
        ``sha256:<hex>``. Returns ``(signature_b64, signed_hex)`` where
        ``signed_hex`` is the bare hex form (no prefix) and
        ``signature_b64`` is the base64-encoded DER signature.
        """
        if content_hash.startswith("sha256:"):
            signed_hex = content_hash[len("sha256:"):]
        else:
            signed_hex = content_hash

        # The hash is already SHA-256; we sign its digest bytes directly.
        digest_bytes = bytes.fromhex(signed_hex)
        if len(digest_bytes) != hashlib.sha256().digest_size:
            raise ValueError(
                f"content_hash hex length {len(signed_hex)} does not match "
                f"SHA-256 digest size — refusing to sign malformed input."
            )

        signature_der = self._key.sign(digest_bytes, ec.ECDSA(hashes.SHA256()))
        signature_b64 = base64.b64encode(signature_der).decode("ascii")
        return signature_b64, signed_hex
