"""Test-result attestations: the record a CI run leaves behind.

The verifier reads; it never executes. A test result reaches verification as a
statement your CI signed about a run your own workflow performed. Nothing in
this module invokes a test command, and nothing in it should ever grow one.

The predicate is an in-toto statement carried in a DSSE-style envelope, the
shape the Sigstore path already speaks. It is published rather than private:
any CI system can emit a conforming attestation without this CLI.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PREDICATE_TYPE = "https://mipiti.io/attestations/test-result/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Where attest-tests writes and the verifier looks, relative to the project
# root. A convention rather than a parameter so an assertion never has to name
# a path, and so a repository can carry several suites' attestations at once.
ATTESTATION_DIR = ".mipiti/attestations"

# Provenance classes, strongest first. The artifact is identical across CI
# providers; only the signing identity differs, which is the axis the platform
# already classifies for verification runs.
PROVENANCE_CI_OIDC = "ci_oidc"
PROVENANCE_CUSTOMER_KEY = "customer_key"
PROVENANCE_UNSIGNED = "unsigned"


class AttestationError(Exception):
    """Raised when an attestation cannot be produced or read."""


# ---------------------------------------------------------------------------
# Reading a test report -- no execution, only parsing what CI already produced
# ---------------------------------------------------------------------------

def parse_junit(report_path: Path) -> dict:
    """Summarise a JUnit XML report into predicate ``totals`` + test names.

    JUnit XML is the universal interchange format -- pytest, jest, go-junit,
    cargo-nextest, surefire and phpunit all emit it -- so supporting it is what
    makes this CI-agnostic without a per-runner integration.

    Counts are derived from the testcase elements rather than trusting the
    suite-level attributes, which runners populate inconsistently.
    """
    try:
        tree = ET.parse(report_path)
    except (ET.ParseError, OSError) as e:
        raise AttestationError(f"Cannot read JUnit report {report_path}: {e}") from e

    cases = list(tree.getroot().iter("testcase"))
    failed = skipped = errored = 0
    names: list[str] = []
    for case in cases:
        name = case.get("name") or ""
        classname = case.get("classname") or ""
        names.append(f"{classname}::{name}" if classname else name)
        if case.find("failure") is not None:
            failed += 1
        elif case.find("error") is not None:
            errored += 1
        elif case.find("skipped") is not None:
            skipped += 1

    total = len(cases)
    return {
        "totals": {
            "total": total,
            "passed": total - failed - skipped - errored,
            "failed": failed,
            "skipped": skipped,
            "errors": errored,
        },
        "tests": names,
    }


# ---------------------------------------------------------------------------
# Building the statement
# ---------------------------------------------------------------------------

def _ci_context() -> dict:
    """The CI identifiers available from the environment, best-effort.

    Recorded for an auditor's benefit. It is NOT the trust anchor -- an
    environment variable proves nothing on its own. The signature does.
    """
    if os.environ.get("GITHUB_ACTIONS"):
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        return {
            "provider": "github",
            "run_id": run_id,
            "run_url": f"https://github.com/{repo}/actions/runs/{run_id}" if repo and run_id else "",
            "workflow": os.environ.get("GITHUB_WORKFLOW_REF", "") or os.environ.get("GITHUB_WORKFLOW", ""),
        }
    if os.environ.get("GITLAB_CI"):
        return {
            "provider": "gitlab",
            "run_id": os.environ.get("CI_PIPELINE_ID", ""),
            "run_url": os.environ.get("CI_PIPELINE_URL", ""),
            "workflow": os.environ.get("CI_JOB_NAME", ""),
        }
    if os.environ.get("CIRCLECI"):
        return {
            "provider": "circleci",
            "run_id": os.environ.get("CIRCLE_WORKFLOW_ID", ""),
            "run_url": os.environ.get("CIRCLE_BUILD_URL", ""),
            "workflow": os.environ.get("CIRCLE_JOB", ""),
        }
    if os.environ.get("BUILDKITE"):
        return {
            "provider": "buildkite",
            "run_id": os.environ.get("BUILDKITE_BUILD_ID", ""),
            "run_url": os.environ.get("BUILDKITE_BUILD_URL", ""),
            "workflow": os.environ.get("BUILDKITE_PIPELINE_SLUG", ""),
        }
    return {"provider": "", "run_id": "", "run_url": "", "workflow": ""}


def build_statement(
    *,
    commit: str,
    summary: dict,
    invocation: list[str],
    selected_pattern: str = "",
    coverage: Optional[dict] = None,
) -> dict:
    """Assemble the in-toto statement for one test run."""
    totals = summary["totals"]
    predicate: dict[str, Any] = {
        "invocation": list(invocation),
        "outcome": "passed" if (
            totals["failed"] == 0 and totals["errors"] == 0 and totals["passed"] > 0
        ) else "failed",
        "totals": totals,
        "selected": {
            "pattern": selected_pattern,
            "matched_count": totals["total"],
        },
        "tests": summary.get("tests", []),
        "ci": _ci_context(),
        "attested_at": datetime.now(timezone.utc).isoformat(),
    }
    if coverage:
        predicate["coverage"] = coverage
    predicate["commit"] = commit

    # The subject digest is a sha256 over the predicate, not the commit: an
    # in-toto Subject admits sha256 and above, and a git commit is sha1. The
    # commit it covers is carried in the predicate and is what the replay guard
    # reads; the subject digest binds the signature to this exact predicate.
    body = json.dumps(predicate, sort_keys=True, separators=(",", ":")).encode()
    return {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": [{
            "name": f"mipiti:test-result:{commit}",
            "digest": {"sha256": hashlib.sha256(body).hexdigest()},
        }],
        "predicate": predicate,
    }


# ---------------------------------------------------------------------------
# Envelope: sign and verify
# ---------------------------------------------------------------------------

def _canonical(statement: dict) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()


def sign_statement(
    statement: dict,
    *,
    identity_token: str = "",
    key_path: str = "",
    key_passphrase: str = "",
    tuf_url: Optional[str] = None,
    trust_config_path: Optional[str] = None,
) -> tuple[str, str]:
    """Sign a statement. Returns ``(serialised_attestation, provenance_class)``.

    Signing identity is chosen the same way the verification run chooses one, so
    an attestation is no weaker than the run that reads it:

    1. ``ci_oidc`` -- a CI workload identity, signed keylessly through Sigstore.
       Preferred wherever it exists, because the certificate binds the
       repository, ref and workflow, and there is no key to hold or rotate.
    2. ``customer_key`` -- an ECDSA P-256 DSSE bundle, for CI with no workload
       identity. Same envelope shape as the customer-DSSE path already used for
       verification runs.
    3. ``unsigned`` -- neither is available. Recorded as self-declared.
    """
    payload = _canonical(statement)

    if identity_token:
        return _sign_sigstore(
            statement, identity_token, tuf_url, trust_config_path,
        ), PROVENANCE_CI_OIDC

    if key_path:
        return _sign_ecdsa(payload, key_path, key_passphrase), PROVENANCE_CUSTOMER_KEY

    return json.dumps({
        "v": 1,
        "kind": "unsigned",
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
    }), PROVENANCE_UNSIGNED


def _sign_sigstore(statement, identity_token, tuf_url, trust_config_path) -> str:
    from sigstore.dsse import StatementBuilder, Subject
    from sigstore.oidc import IdentityToken
    from sigstore.sign import SigningContext

    from .sigstore_signer import _load_trust_config

    subject = statement["subject"][0]
    built = (
        StatementBuilder()
        .subjects([Subject(name=subject["name"], digest=subject["digest"])])
        .predicate_type(PREDICATE_TYPE)
        .predicate(statement["predicate"])
        .build()
    )
    ctx = SigningContext.from_trust_config(
        _load_trust_config(tuf_url, trust_config_path)
    )
    with ctx.signer(IdentityToken(identity_token)) as signer:
        return signer.sign_dsse(built).to_json()


def _sign_ecdsa(payload: bytes, key_path: str, passphrase: str) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from .customer_dsse_signer import _load_private_key, compute_pae

    key = _load_private_key(key_path, passphrase or None)
    signature = key.sign(compute_pae(payload), ec.ECDSA(hashes.SHA256()))
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return json.dumps({
        "v": 1,
        "kind": "customer-dsse",
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": public_pem,
    })


def verify_attestation(
    raw: str,
    *,
    expected_identity: str = "",
    expected_issuer: str = "",
    expected_key_pem: str = "",
    allow_unsigned: bool = False,
    tuf_url: Optional[str] = None,
    trust_config_path: Optional[str] = None,
) -> tuple[dict, str]:
    """Return ``(statement, provenance_class)`` for a well-formed attestation.

    Raises ``AttestationError`` on anything that does not verify. Each path
    derives trust from something the reader supplied, never from the
    attestation itself:

    - Sigstore: the certificate identity must match ``expected_identity`` and
      ``expected_issuer``. Without a pinned identity any valid Sigstore
      signature from any signer would verify, which would make the check
      decorative, so an unpinned identity is refused.
    - ECDSA: the signature must verify against ``expected_key_pem``, never the
      key embedded in the attestation.
    - Unsigned: accepted only when ``allow_unsigned``, which callers set only
      where no signing identity was available at all.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AttestationError(f"Attestation is not JSON: {e}") from e

    kind = obj.get("kind", "")
    if kind == "customer-dsse":
        statement = _verify_ecdsa(obj, expected_key_pem)
        provenance = PROVENANCE_CUSTOMER_KEY
    elif kind == "unsigned":
        if not allow_unsigned:
            raise AttestationError(
                "Attestation is unsigned, but a signing identity is available "
                "here. Refusing an unsigned attestation where a signed one was "
                "expected."
            )
        statement = _decode_payload(obj.get("payload"))
        provenance = PROVENANCE_UNSIGNED
    else:
        statement = _verify_sigstore(
            raw, expected_identity, expected_issuer, tuf_url, trust_config_path,
        )
        provenance = PROVENANCE_CI_OIDC

    if statement.get("predicateType") != PREDICATE_TYPE:
        raise AttestationError(
            f"Unexpected predicateType {statement.get('predicateType')!r}; "
            f"expected {PREDICATE_TYPE}."
        )
    return statement, provenance


def _decode_payload(payload) -> dict:
    if not isinstance(payload, str) or not payload:
        raise AttestationError("Attestation carries no payload.")
    try:
        return json.loads(base64.b64decode(payload))
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation payload is unreadable: {e}") from e


def _verify_ecdsa(obj: dict, expected_key_pem: str) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from .customer_dsse_signer import compute_pae

    if not expected_key_pem:
        raise AttestationError(
            "A signed attestation was found but no public key is configured to "
            "check it against. Trusting the key carried inside the attestation "
            "would let it vouch for itself."
        )
    payload_b64 = obj.get("payload")
    statement = _decode_payload(payload_b64)
    try:
        public_key = serialization.load_pem_public_key(expected_key_pem.encode())
        public_key.verify(
            base64.b64decode(obj.get("signature", "")),
            compute_pae(base64.b64decode(payload_b64)),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as e:
        raise AttestationError(
            "Attestation signature does not verify against the configured key."
        ) from e
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation signature could not be checked: {e}") from e
    return statement


def _verify_sigstore(raw, expected_identity, expected_issuer,
                     tuf_url, trust_config_path) -> dict:
    if not expected_identity or not expected_issuer:
        raise AttestationError(
            "A Sigstore-signed attestation was found but no expected signing "
            "identity is configured. Any valid Sigstore signature would "
            "otherwise verify, whoever produced it."
        )
    from sigstore.models import Bundle
    from sigstore.verify import policy

    from .cli import _build_verifier

    try:
        bundle = Bundle.from_json(raw)
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation is not a Sigstore bundle: {e}") from e

    verifier = _build_verifier(trust_config_path, tuf_url)
    try:
        _, payload = verifier.verify_dsse(
            bundle,
            policy.Identity(identity=expected_identity, issuer=expected_issuer),
        )
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation signature does not verify: {e}") from e
    return json.loads(payload)


# ---------------------------------------------------------------------------
# Locating attestations in a checkout
# ---------------------------------------------------------------------------

def expected_ci_identity() -> tuple[str, str]:
    """The signing identity a Sigstore-signed attestation must carry here.

    Derived from the environment rather than configured, because verification
    runs in the same CI as the attestation it reads: the certificate must name
    this repository's workflow. A pinned identity is what makes the signature
    check mean anything -- without it, any valid Sigstore signature verifies,
    whoever produced it.

    Returns ``("", "")`` where no workload identity exists, which callers take
    as "this CI cannot sign keylessly".
    """
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "").strip()
    if workflow_ref:
        return (
            f"https://github.com/{workflow_ref}",
            "https://token.actions.githubusercontent.com",
        )
    gitlab_project = os.environ.get("CI_PROJECT_URL", "").strip()
    if gitlab_project and os.environ.get("CI_JOB_JWT_V2"):
        return gitlab_project, os.environ.get("CI_SERVER_URL", "").strip()
    return "", ""


def load_attestations(project_root: Path) -> list[str]:
    """Every attestation present in the checkout, unparsed.

    Returned as raw text because the serialised form is what a signature covers:
    parsing and re-serialising before verification would check a signature over
    bytes nobody signed.

    Absence is not an error here -- the caller decides what to make of it. A
    verifier treats it as a failure with a wiring pointer; it never falls back
    to running anything.
    """
    directory = project_root / ATTESTATION_DIR
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(path.read_text(encoding="utf-8"))
        except OSError:
            continue
    return out


def statement_of(raw: str) -> Optional[dict]:
    """The statement inside an attestation, without verifying it.

    For presentation only -- rendering what a run reported. Never use this to
    decide whether a claim holds.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    payload = obj.get("payload")
    if not isinstance(payload, str):
        return None
    try:
        return json.loads(base64.b64decode(payload))
    except Exception:  # noqa: BLE001
        return None


def head_commit(project_root: Path) -> str:
    """The commit under verification, from CI or the checkout.

    Read, never executed: the CI variable first, then .git/HEAD resolved by
    hand, so this does not shell out to git.
    """
    for var in ("GITHUB_SHA", "CI_COMMIT_SHA", "CIRCLE_SHA1", "BUILDKITE_COMMIT"):
        val = os.environ.get(var, "").strip()
        if val:
            return val
    head = project_root / ".git" / "HEAD"
    try:
        ref = head.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if ref.startswith("ref:"):
        target = project_root / ".git" / ref.split(" ", 1)[1].strip()
        try:
            return target.read_text(encoding="utf-8").strip()
        except OSError:
            packed = project_root / ".git" / "packed-refs"
            try:
                name = ref.split(" ", 1)[1].strip()
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.endswith(f" {name}"):
                        return line.split(" ", 1)[0].strip()
            except OSError:
                return ""
            return ""
    return ref if re.fullmatch(r"[0-9a-f]{40}", ref) else ""
