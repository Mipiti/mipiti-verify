"""BFS implementation check against the TLA+ spec at formal/audit.tla.

For every (Package, Pins) tuple drawn from the same finite state space
as the TLA+ model, this test:

    1. Computes the spec verdict via `audit_spec()` — a Python mirror
       of the TLA+ `Audit` operator.
    2. Materialises the abstract package as a JSON file (minting real
       Sigstore bundles via Fulcio + Rekor when CI OIDC is available;
       skipping bundle-present rows otherwise) and runs the actual
       `mipiti-verify audit` command.
    3. Classifies the CLI output into a Verdict label.
    4. Asserts the implementation's verdict agrees with the spec, and
       independently asserts each security invariant I1–I7 on the
       implementation's output.

The BFS is the regression gate: any change to `cli.py` that breaks
an invariant produces a failed parametrised test naming the exact
abstract (pkg, pins) tuple that violated it — the same kind of
counterexample TLC would emit.

CI Fulcio integration:
    The test detects whether the CI runner has OIDC token access
    (GitHub Actions with `id-token: write` permission, exposed via
    ACTIONS_ID_TOKEN_REQUEST_URL + _TOKEN env vars) and uses
    `sigstore.sign.SigningContext` to mint a real Fulcio-signed bundle
    once per session. Bundle-present rows of the BFS use this real
    bundle, parameterised over (results_hash binding, auditor pin
    SAN/issuer combos). Locally — or in any CI run without OIDC
    permission — bundle-present rows skip and only no-bundle rows
    execute.

State space: 4 SANs × 3 issuers × 3 fingerprints × ~6 package shapes
(no-bundle) + ~4 bundle shapes when OIDC is available. ~1800–2200
total parametrised rows. Runs in a few seconds locally, ~30s in CI
with the Fulcio mint amortised across rows.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mipiti_verify.cli import main


# --- Finite domains (mirror audit.cfg) ---------------------------------

# CI SAN URIs — two github.com SANs (registry-resolvable to GitHub
# Actions issuer) and one self-hosted SAN (no registry entry).
SAN_GH_A = "https://github.com/a/r/.github/workflows/v.yml@refs/heads/main"
SAN_GH_B = "https://github.com/b/r/.github/workflows/v.yml@refs/heads/main"
SAN_SELF = "https://gitlab.example.com/g/p//.gitlab-ci.yml@main"

ISS_GH = "https://token.actions.githubusercontent.com"
ISS_SELF = "https://gitlab.example.com"

# Model and commit identifiers for I12 / I13 coverage.
M1 = "model-bfs-1"
M2 = "model-bfs-2"
C1 = "commit-sha-1"
C2 = "commit-sha-2"

NONE = None
ABSENT = "ABSENT"

# Two ECDSA keypairs deterministically derived from constant scalars.
# Used to back the BFS's notion of "fingerprint A" and "fingerprint
# B" — concrete values both the spec and the implementation can
# verify signatures against.
#
# Deterministic derivation (rather than ec.generate_private_key()) is
# load-bearing under pytest-xdist: every xdist worker process imports
# this module independently, so per-worker fresh keys would embed
# different fingerprints into the parametrize IDs of PACKAGES — and
# xdist requires every worker to collect the *same* test IDs. Using
# a fixed scalar produces the same key every time without any private
# key material in source.
#
# The scalars are arbitrary — chosen as the SHA-256 hash of a known
# label, mod the P-256 curve order. Same approach as RFC 6979's
# deterministic ECDSA, just for keypair derivation rather than nonce
# derivation. The keys are throwaway test fixtures.
_P256_ORDER = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)


def _derive_key(label: bytes) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(hashlib.sha256(label).digest(), "big")
    # Map into the valid range [1, n-1]. The hash is uniform-random
    # over a 256-bit space; mod-(n-1) plus 1 gets us a valid scalar.
    scalar = (scalar % (_P256_ORDER - 1)) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _fp(key: ec.EllipticCurvePrivateKey) -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


KEY_A = _derive_key(b"mipiti-test-spec-invariants-key-a")
KEY_B = _derive_key(b"mipiti-test-spec-invariants-key-b")
FP_A = _fp(KEY_A)
FP_B = _fp(KEY_B)

# Customer-keyed offline DSSE path: a deterministically-derived P-256
# "customer" key. The auditor pins its fingerprint out-of-band via
# --expected-customer-key (the vendor-independence gate); a distinct
# "wrong" key models a swapped/forged customer key. Same deterministic
# derivation rationale as KEY_A/KEY_B (stable parametrize IDs under
# pytest-xdist; no private key material in source).
KEY_CUSTOMER = _derive_key(b"mipiti-test-spec-invariants-customer-dsse")
KEY_CUSTOMER_WRONG = _derive_key(b"mipiti-test-spec-invariants-customer-dsse-wrong")
FP_CUSTOMER = _fp(KEY_CUSTOMER)


# --- Customer-keyed offline DSSE bundle (no network) -------------------


# Memoize deterministic customer-DSSE bundles: identical logical inputs
# (signing/embed key identity + content_hash + predicate fields) yield a
# behaviorally identical *valid* bundle, so build + ECDSA-sign ONCE
# instead of per BFS cell (this was ~476s of CI). Pure speedup — the
# real verifier re-verifies every returned bundle, and nothing the
# spec/impl checks depends on signature byte values.
_CUSTOMER_DSSE_BUNDLE_CACHE: dict = {}


def _build_customer_dsse_bundle(
    *,
    content_hash: str,
    signing_key: ec.EllipticCurvePrivateKey,
    embed_key: ec.EllipticCurvePrivateKey | None = None,
    model_id: str = M1,
    commit_sha: str = C1,
) -> str:
    """Build a real ``customer-dsse`` bundle, fully offline.

    Reuses the production signer's Statement/PAE construction so the
    bundle is byte-identical to what the CLI's `--customer-key` sign
    path emits and what `verify_customer_dsse_bundle` consumes. The
    auditor verifies it offline against the fingerprint pinned via
    `--expected-customer-key`.

    `signing_key` produces the DSSE signature. `embed_key` (defaults to
    `signing_key`) is the PEM embedded in the bundle — pointing it at a
    different key models a swapped/forged customer key that fails the
    fingerprint-pin / signature step.
    """
    if embed_key is None:
        embed_key = signing_key
    _ck = (content_hash, id(signing_key), id(embed_key), model_id, commit_sha)
    _hit = _CUSTOMER_DSSE_BUNDLE_CACHE.get(_ck)
    if _hit is not None:
        return _hit

    from mipiti_verify.customer_dsse_signer import (
        BUNDLE_KIND,
        PAYLOAD_TYPE,
        build_statement_bytes,
        compute_pae,
    )
    payload = build_statement_bytes(
        model_id=model_id,
        tier=1,
        content_hash=content_hash,
        pipeline={"provider": "spec-invariants-bfs", "commit_sha": commit_sha},
        assertions=[],
        results=[],
    )
    pae = compute_pae(payload)
    sig = signing_key.sign(pae, ec.ECDSA(hashes.SHA256()))
    bundle = {
        "v": 1,
        "kind": BUNDLE_KIND,
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(sig).decode("ascii"),
        "public_key_pem": embed_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii"),
    }
    _out = json.dumps(bundle)
    _CUSTOMER_DSSE_BUNDLE_CACHE[_ck] = _out
    return _out


# --- Real Fulcio minting (CI only) -------------------------------------


def _have_oidc() -> bool:
    """True when the runner has a workflow OIDC token (CI with
    `id-token: write` permission). Forks don't get OIDC, so fork-PR
    runs return False and the bundle-present rows safely skip."""
    return bool(
        os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    )


def _fetch_github_oidc_token() -> str:
    """Fetch a workflow-scoped OIDC token from GitHub Actions for the
    `sigstore` audience. Same contract Fulcio expects."""
    import urllib.parse
    import urllib.request

    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}audience=sigstore"
    req = urllib.request.Request(full, headers={"Authorization": f"Bearer {tok}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body["value"]


def _mint_real_bundle(content_hash_str: str, oidc_token: str,
                       model_id: str = M1, commit_sha: str = C1):
    """Mint a real Sigstore bundle that binds to `content_hash_str`,
    with a DSSE predicate carrying the supplied `model_id` and
    `commit_sha`. The BFS uses these predicate fields to exercise
    I12 (model_id pin) and I13 (commit_sha pin) against real
    cryptography in CI.

    Returns (bundle_json: str, san: str, issuer: str).
    """
    from sigstore.dsse import StatementBuilder, Subject
    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken
    from sigstore.sign import SigningContext

    # Subject digest = sha256 of the input bytes verify_artifact gets.
    subject_digest = hashlib.sha256(content_hash_str.encode("utf-8")).hexdigest()
    statement = (
        StatementBuilder()
        .subjects([Subject(name=f"mipiti-bfs:{content_hash_str}",
                           digest={"sha256": subject_digest})])
        .predicate_type("https://mipiti.io/attestations/v1/bfs-spec-test")
        .predicate({
            "purpose": "spec invariants BFS",
            "model_id": model_id,
            "pipeline": {"commit_sha": commit_sha},
        })
        .build()
    )
    trust_config = ClientTrustConfig.production()
    signing_context = SigningContext.from_trust_config(trust_config)
    identity = IdentityToken(oidc_token)
    with signing_context.signer(identity) as signer:
        bundle = signer.sign_dsse(statement)
    bundle_json = bundle.to_json()
    # Read SAN + issuer back out of the cert so the BFS uses ground
    # truth (whatever Fulcio actually issued for this workflow).
    cert = bundle.signing_certificate
    san_uri = None
    for ext in cert.extensions:
        # SAN extension OID 2.5.29.17.
        if ext.oid.dotted_string == "2.5.29.17":
            for name in ext.value:
                # Pull the URI variant (Fulcio puts the workflow ref
                # in a UniformResourceIdentifier name).
                if hasattr(name, "value") and isinstance(name.value, str):
                    if name.value.startswith("https://"):
                        san_uri = name.value
                        break
    issuer = "https://token.actions.githubusercontent.com"  # GitHub Actions OIDC
    if san_uri is None:
        raise RuntimeError("could not extract SAN URI from minted Fulcio cert")
    return bundle_json, san_uri, issuer


# Computed canonical hashes for the BFS materialiser. h1 matches the
# canonical hash of an empty results list (so a bundle bound to h1
# verifies against an empty-results package); h2 is divergent.
_CANONICAL_H1 = (
    "sha256:" + hashlib.sha256(
        json.dumps([], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
)
_CANONICAL_H2 = "sha256:" + hashlib.sha256(b"divergent").hexdigest()


# Cache the minted bundles + real SAN once per session. Bundles are
# keyed by (bound_hash_label, model_id, commit_sha) so the BFS can
# pick a distinct bundle for each abstract (predicate_model_id,
# predicate_commit_sha) combination it enumerates. Filled lazily;
# None if OIDC isn't available.
_REAL_BUNDLES: dict[tuple[str, str, str], str] = {}
_REAL_SAN: str | None = None
_REAL_BUNDLES_INITIALISED: bool = False

# Predicate combinations the BFS exercises. Kept small to bound the
# Fulcio mint cost in CI (~2s × |bound_hash_labels| × |combos|
# = 2 × 2 × 2 = 8 mints, ~16s session setup).
_BFS_PREDICATE_COMBOS = [
    (M1, C1),
    (M2, C2),
]


def _ensure_real_bundles() -> bool:
    """Lazily mint bundles for the BFS's bound_hash × predicate
    cross-product the first time they're needed. Returns True if
    real bundles are available, False otherwise. Idempotent.
    """
    global _REAL_SAN, _REAL_BUNDLES_INITIALISED
    if _REAL_BUNDLES_INITIALISED:
        return _REAL_SAN is not None
    _REAL_BUNDLES_INITIALISED = True
    if not _have_oidc():
        return False
    try:
        token = _fetch_github_oidc_token()
        sans_seen: set[str] = set()
        for bound_label, content_hash in [("h1", _CANONICAL_H1),
                                           ("h2", _CANONICAL_H2)]:
            for mid, csha in _BFS_PREDICATE_COMBOS:
                b_json, san, _ = _mint_real_bundle(
                    content_hash, token, model_id=mid, commit_sha=csha
                )
                _REAL_BUNDLES[(bound_label, mid, csha)] = b_json
                sans_seen.add(san)
    except Exception:
        return False
    if len(sans_seen) != 1:
        # Workflow SAN should be stable across mints; if not, abort.
        return False
    _REAL_SAN = next(iter(sans_seen))
    return True


# --- Spec mirror -------------------------------------------------------


def _resolve_issuer(pins: dict) -> str | None:
    """Mirror of TLA+ ResolveIssuer.

    Explicit pin > SAN-prefix registry > NONE. Bundle's own claim is
    NEVER consulted to derive the expected issuer.
    """
    if pins["issuer_explicit"] is not None:
        return pins["issuer_explicit"]
    san = pins["san"]
    if san is None:
        return None
    if san.startswith("https://github.com/"):
        return ISS_GH
    if san.startswith("https://gitlab.com/"):
        return "https://gitlab.com"
    return None


def audit_spec(pkg: dict, pins: dict) -> str:
    """Python mirror of the TLA+ Audit operator.

    Returns one of: VERIFIED, PARTIALLY_VERIFIED, UNVERIFIED, FAILED,
    USAGE_ERROR, MODEL_ONLY. Branch order matches `cli.py` exactly so a
    divergence between this function and the implementation surfaces as
    a parametrised test failure with the offending (pkg, pins) named.

    Scenario-knob extension (gap #249 / #254 / #258 backfill): pkg may
    optionally carry `is_model_only`, `has_orphan_results`, and
    `sufficiency_state` (4-class enum) keys; pins may optionally carry
    `allow_orphan_results`. Default values mirror the cli.py default
    behaviour (no orphan results, not a model-only PDF, sufficiency
    irrelevant). The BFS rows materialised in this file all use the
    defaults; the scenario invariants are verified at the TLA+ level
    (audit_main_orphan_results_*.cfg / audit_main_model_only.cfg /
    audit_main_sufficiency.cfg). This guard keeps the spec mirror
    forward-compatible for any future BFS row that varies a scenario
    knob without forcing the existing rows to declare default fields.
    """
    # Scenario knobs — default to cli.py's nominal "no scenario" state.
    is_model_only = pkg.get("is_model_only", False)
    has_orphan_results = pkg.get("has_orphan_results", False)
    allow_orphan_results = pins.get("allow_orphan_results", False)
    sufficiency_state = pkg.get("sufficiency_state", "SUFF_NA")

    # PDF model-only short-circuit (cli.py line ~2497 / ~2522). Returns
    # BEFORE envelope dispatch, so orphan / sufficiency demotion never
    # apply on this branch.
    if is_model_only:
        pinning_requested = (
            pins["san"] is not None
            or pins["workspace_fp"] is not None
            or pins.get("model_id") is not None
            or pins.get("commit_sha") is not None
        )
        if pinning_requested:
            return "USAGE_ERROR"
        return "MODEL_ONLY"

    envelope_verdict = _audit_spec_envelope(pkg, pins)

    # Orphan demotion (cli.py line ~4055). Fires on positive-class
    # envelope verdict only; never raises a negative verdict.
    if has_orphan_results and envelope_verdict in (
        "VERIFIED", "PARTIALLY_VERIFIED", "UNVERIFIED"
    ):
        envelope_verdict = (
            "PARTIALLY_VERIFIED" if allow_orphan_results else "FAILED"
        )

    # Sufficiency demotion (cli.py line ~4115). Pending / insufficient
    # demote a flat VERIFIED to PARTIALLY_VERIFIED.
    if envelope_verdict == "VERIFIED" and sufficiency_state in (
        "SUFF_INSUFFICIENT", "SUFF_PENDING"
    ):
        envelope_verdict = "PARTIALLY_VERIFIED"

    return envelope_verdict


def _audit_spec_envelope(pkg: dict, pins: dict) -> str:
    """Envelope-dispatch portion of audit_spec — the original verdict
    function over (Package, Pins) without scenario-knob post-processing.
    Extracted so the wrapper can compose model-only / orphan /
    sufficiency demotions around a stable inner verdict.
    """
    bundle = pkg["bundle"]
    ws_sig = pkg["ws_sig"]

    # Customer-keyed offline DSSE discriminator. Mirrors audit.tla's
    # IsCustomerDsse(k): a ws_sig present and tagged customer_dsse.
    # The real CLI routes such a row entirely through the offline
    # DSSE verifier whose sole identity gate is --expected-customer-
    # key; the Sigstore-SAN pins and --expected-workspace-key do NOT
    # gate it. The materialiser builds the customer-signed DSSE
    # Statement with model_id=M1 / commit_sha=C1 and signs it with the
    # pinned customer key, so a materialised customer_dsse row has
    # dsse_predicate_model_id=M1, dsse_predicate_commit_sha=C1, and
    # customer_key_fp_match=True (the auditor always supplies the
    # matching --expected-customer-key via _customer_key_args).
    is_customer_dsse = (
        ws_sig is not ABSENT
        and ws_sig.get("key_source") == "customer_dsse"
    )
    cd_pred_model_id = M1
    cd_pred_commit_sha = C1
    cd_key_fp_match = True

    # I7: --expected-issuer alone is a usage error — key_source-
    # UNCONDITIONAL (cli.py line ~1840: issuer needs a SAN to bind to
    # regardless of key_source; --expected-customer-key does not
    # rescue a bare issuer pin).
    if pins["issuer_explicit"] is not None and pins["san"] is None:
        return "USAGE_ERROR"

    # I7-extended: predicate pins (model_id / commit_sha) without
    # SAN pin are a usage error too. Without SAN constraining whose
    # OIDC produced the bundle, an attacker minting under their own
    # OIDC can craft any predicate values matching the auditor's
    # pins — the predicate pins alone don't deliver compromised-
    # platform defense (the flag's documented purpose).
    #
    # key_source-aware carve-out for customer_dsse: --expected-
    # customer-key is the SAN-substitute for the customer-keyed
    # offline DSSE path (cli.py line ~1866), so a model_id /
    # commit_sha co-pin WITHOUT a SAN is NOT a usage error there.
    if (
        (pins.get("model_id") is not None or pins.get("commit_sha") is not None)
        and pins["san"] is None
        and not is_customer_dsse
    ):
        return "USAGE_ERROR"

    # I1: any bundle-binding pin + no bundle = FAILED. SAN, model_id,
    # commit_sha all live in the bundle's signed material; omitting
    # the bundle bypasses the pin.
    #
    # key_source-aware carve-out for customer_dsse: the dsse_bundle
    # IS the upstream evidence (cli.py line ~2750: a dsse-bearing
    # package is exempt from the no-Sigstore-bundle pin gate), so a
    # SAN / model_id / commit_sha pin + no Sigstore bundle is not
    # pin-bypass-by-omission for that key_source.
    if (
        (pins["san"] is not None
         or pins.get("model_id") is not None
         or pins.get("commit_sha") is not None)
        and bundle is ABSENT
        and not is_customer_dsse
    ):
        return "FAILED"

    # I2: workspace pin + no content_integrity = FAILED.
    if pins["workspace_fp"] is not None and ws_sig is ABSENT:
        return "FAILED"

    # ---- customer_dsse terminal dispatch -------------------------
    # Mirrors audit.tla's KS_CUSTOMER_DSSE terminal dispatch and the
    # CLI's `customer_dsse_handled` branch: identity is gated by the
    # --expected-customer-key fingerprint pin (step 3 of
    # verify_customer_dsse_bundle); --expected-model-id /
    # --expected-commit-sha are cross-checked against the CUSTOMER-
    # signed predicate; the SAN pin and --expected-workspace-key do
    # NOT gate this key_source. The key_source-independent canonical-
    # hash check still applies further below (so a tampered
    # results_hash → FAILED), reached by falling through rather than
    # short-circuiting VERIFIED here.
    if is_customer_dsse:
        if not cd_key_fp_match:
            return "FAILED"
        if (
            pins.get("model_id") is not None
            and cd_pred_model_id != pins["model_id"]
        ):
            return "FAILED"
        if (
            pins.get("commit_sha") is not None
            and cd_pred_commit_sha != pins["commit_sha"]
        ):
            return "FAILED"
        # Canonical-hash mismatch is enforced uniformly for every
        # key_source; apply it here so the customer_dsse fall-through
        # verdict matches the CLI (h2 → FAILED, h1 → VERIFIED).
        if (
            pkg["results_hash"] is not None
            and pkg["results_hash"] != pkg["results_canonical_hash"]
        ):
            return "FAILED"
        return "VERIFIED"

    # Self-hosted SAN with no resolvable issuer = FAILED (the audit
    # cannot enforce policy.Identity without an issuer).
    if (
        pins["san"] is not None
        and bundle is not ABSENT
        and _resolve_issuer(pins) is None
    ):
        return "FAILED"

    # Bundle present + pin: SAN must match.
    if (
        bundle is not ABSENT
        and pins["san"] is not None
        and bundle["san"] != pins["san"]
    ):
        return "FAILED"

    # Bundle present + pin: issuer must match resolved.
    if (
        bundle is not ABSENT
        and pins["san"] is not None
        and _resolve_issuer(pins) is not None
        and bundle["issuer"] != _resolve_issuer(pins)
    ):
        return "FAILED"

    # Bundle present but Sigstore trust chain failed.
    if bundle is not ABSENT and not bundle["valid"]:
        return "FAILED"

    # Bundle present but the envelope's explicit bundle_bind_hash is
    # missing or doesn't equal bundle.bound_hash. Mirrors the cli.py
    # branch that reads bundle_bind_hash off content_integrity and
    # compares directly to the bundle's Subject digest with no
    # canonicalisation. Older envelopes without bundle_bind_hash are
    # not supported by the post-cutover verifier.
    if bundle is not ABSENT and pkg.get("bundle_bind_hash") is None:
        return "FAILED"
    if (
        bundle is not ABSENT
        and pkg.get("bundle_bind_hash") is not None
        and bundle["bound_hash"] != pkg["bundle_bind_hash"]
    ):
        return "FAILED"

    # Bundle present + bundle_bind_signature populated and the
    # verifier could not return VALID. Two failure modes are folded
    # together by the abstract Audit operator (and by this spec
    # mirror): "INVALID" means the signature was checked against a
    # resolved key and ECDSA failed; "KEY_UNRESOLVABLE" means the
    # signature is present but no platform key was resolvable from
    # any tier (envelope public_key_pem, PDF outer-signature key,
    # or auditor-supplied --platform-pubkey). None means absent
    # (permitted); only present-and-non-VALID fails.
    if (
        bundle is not ABSENT
        and pkg.get("bundle_bind_signature") in ("INVALID", "KEY_UNRESOLVABLE")
    ):
        return "FAILED"

    # Bundle present + no results_hash = FAILED unconditionally.
    # Stricter rule: a bundle in the package implies the platform
    # produced a results_hash to go with it; absence is a malformed
    # / tampered shape. Failing regardless of pin (and regardless of
    # whether ws_sig provides fallback verification) prevents the
    # auditor from seeing "VERIFIED — content intact" while a
    # Sigstore bundle in the package was effectively ignored.
    if bundle is not ABSENT and pkg["results_hash"] is None:
        return "FAILED"

    # Bundle ↔ envelope binding is checked above against the
    # explicit `bundle_bind_hash` field. `results_hash` is
    # independently recomputed from verification_run.results and
    # verified against the platform's content-integrity signature
    # downstream; it is not part of the bundle-bind check.

    # Bundle present + model_id pin + predicate.model_id mismatch.
    if (
        bundle is not ABSENT
        and pins.get("model_id") is not None
        and bundle.get("predicate_model_id") != pins["model_id"]
    ):
        return "FAILED"

    # Bundle present + commit_sha pin + predicate.commit_sha mismatch.
    if (
        bundle is not ABSENT
        and pins.get("commit_sha") is not None
        and bundle.get("predicate_commit_sha") != pins["commit_sha"]
    ):
        return "FAILED"

    # Workspace sig: claimed_fp (when present) must match signing_key_fp.
    # Skipped for "sigstore", "customer_dsse", and "unverifiable_orphan".
    # sigstore: bundle is the trust anchor; ws_sig is the issuer's
    # redundant notarization, not a customer claim. customer_dsse: the
    # customer-signed DSSE Statement (verified offline against the
    # out-of-band-pinned fingerprint) is the trust anchor; the envelope
    # ws_sig is not re-evaluated — same trust-anchor class as sigstore.
    # orphan: signing_key_fp is by definition not in the issuer's
    # published key set; the verifier surfaces UNRESOLVED without
    # comparing claimed_fp/signing_key_fp. Mirrors the audit.tla
    # KS_SIGSTORE-class skip set {KS_SIGSTORE, KS_CUSTOMER_DSSE,
    # KS_ORPHAN}.
    ws_key_source = ws_sig.get("key_source", "legacy") if ws_sig is not ABSENT else None
    if (
        ws_sig is not ABSENT
        and ws_key_source not in ("sigstore", "customer_dsse", "unverifiable_orphan")
        and ws_sig["claimed_fp"] is not None
        and ws_sig["claimed_fp"] != ws_sig["signing_key_fp"]
    ):
        return "FAILED"

    # Workspace sig + pin: KS_ORPHAN with any workspace_fp pin =
    # FAILED unconditionally. Orphan = no resolvable public key,
    # cannot verify cryptographically; metadata-level fingerprint
    # match isn't a cryptographic guarantee. Mirrors V3 in audit.tla
    # and the implementation's orphan branch (which fails uniformly
    # on pin set).
    if (
        ws_sig is not ABSENT
        and ws_key_source == "unverifiable_orphan"
        and pins["workspace_fp"] is not None
    ):
        return "FAILED"

    # Workspace sig + pin: signing_key_fp must match pinned fp.
    if (
        ws_sig is not ABSENT
        and pins["workspace_fp"] is not None
        and ws_sig["signing_key_fp"] != pins["workspace_fp"]
    ):
        return "FAILED"

    # Workspace sig present but signature itself invalid.
    # Skipped for KS_SIGSTORE (the bundle is the trust anchor — the
    # redundant ws_sig is not re-verified), KS_CUSTOMER_DSSE (the
    # offline-verified customer-signed DSSE Statement is the trust
    # anchor — the envelope ws_sig is not re-verified; same
    # trust-anchor class as KS_SIGSTORE), and KS_ORPHAN (the row's
    # key was not in the issuer's published set, so ws_sig.valid is
    # "unknown" rather than "invalid"; verdict relies on bundle path
    # or falls to UNVERIFIED).
    if (
        ws_sig is not ABSENT
        and ws_key_source not in ("sigstore", "customer_dsse", "unverifiable_orphan")
        and not ws_sig["valid"]
    ):
        return "FAILED"

    # Hash mismatch between claimed and canonical.
    if (
        pkg["results_hash"] is not None
        and pkg["results_hash"] != pkg["results_canonical_hash"]
    ):
        return "FAILED"

    # No cryptographic verification actually ran. UNVERIFIED captures
    # both "nothing present" and "bundle present but unverifiable
    # (results_hash NONE)" — the implementation enters the bundle
    # block, finds no content_hash to bind to, and leaves
    # provenance_verified = False. Without this clause the spec would
    # diverge from the implementation in the no-pin + bundle-but-no-
    # results_hash case.
    #
    # Refined for key_source: KS_SIGSTORE-tagged and KS_ORPHAN-tagged
    # ws_sigs do not contribute to verifier confidence on their own
    # (former is sigstore-skipped, latter is unverifiable). Treat
    # them like ABSENT for this UNVERIFIED check.
    #
    # KS_CUSTOMER_DSSE is deliberately NOT in this set: unlike
    # sigstore/orphan, a customer_dsse ws_sig IS itself the trust
    # anchor (the offline-verified customer-signed DSSE Statement),
    # so it constitutes cryptographic evidence on its own and a
    # customer_dsse row does not fall through to UNVERIFIED. This
    # mirrors audit.tla, whose UNVERIFIED "no evidence" clause uses
    # {KS_SIGSTORE, KS_ORPHAN} (NOT KS_CUSTOMER_DSSE) even though the
    # claimed-fp / ws_sig.valid / I9 skip sets all include
    # KS_CUSTOMER_DSSE.
    ws_no_evidence = (
        ws_sig is ABSENT
        or ws_key_source in ("sigstore", "unverifiable_orphan")
    )
    if (bundle is ABSENT or pkg["results_hash"] is None) and ws_no_evidence:
        return "UNVERIFIED"

    return "VERIFIED"


# --- Materialisation: abstract package -> JSON file --------------------


def _materialise(tmp_path, pkg: dict) -> str:
    """Build a JSON audit package on disk matching the abstract spec.

    Workspace-signature rows always materialise. Bundle-present rows
    materialise only when real Fulcio bundles are available (CI with
    `id-token: write` permission); otherwise the test driver skips
    them. Local pytest runs and fork-PR CI runs cover only the
    no-bundle slice.
    """
    ws_sig = pkg["ws_sig"]
    bundle_abs = pkg["bundle"]

    # --- content_integrity ---
    if ws_sig is ABSENT:
        ci = None
    else:
        # Build a content_integrity block whose signature reflects the
        # abstract ws_sig.valid flag exactly.
        signing_key = KEY_A if ws_sig["signing_key_fp"] == FP_A else KEY_B
        pub_pem = signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        # results_hash claim — when the abstract package says they
        # match (pkg.results_hash == "h1"), we use the canonical
        # empty-results hash; "h2" diverges from canonical.
        stored_hash = _CANONICAL_H1 if pkg["results_hash"] == "h1" else _CANONICAL_H2
        if ws_sig["valid"]:
            sig_bytes = signing_key.sign(stored_hash.encode(), ec.ECDSA(hashes.SHA256()))
        else:
            # Sign a different message to make the signature invalid
            # against stored_hash.
            sig_bytes = signing_key.sign(b"junk", ec.ECDSA(hashes.SHA256()))
        ci = {
            "results_hash": stored_hash,
            "signature": base64.b64encode(sig_bytes).decode(),
            "key_fingerprint": ws_sig["claimed_fp"] or "",
            "public_key_pem": pub_pem,
        }
        # Pass key_source through to the envelope so the verifier
        # branches on it. Legacy rows omit the field (legacy issuer
        # builds didn't emit it); explicit values exercise V1/V2/V3.
        ks = ws_sig.get("key_source", "legacy")
        if ks != "legacy":
            ci["key_source"] = ks
        if ks == "unverifiable_orphan":
            # Orphan rows have no resolvable PEM by definition. The
            # verifier branches on this state and surfaces UNRESOLVED
            # rather than verifying against the embedded PEM.
            ci["public_key_pem"] = ""
            ci["unavailable_reason"] = "unresolved_fingerprint"
        if ks == "customer_dsse":
            # Customer-keyed offline DSSE. The trust anchor for this
            # row is the customer-signed in-toto Statement carried in
            # content_integrity.dsse_bundle (verified offline against
            # the out-of-band-pinned customer fingerprint), NOT
            # ci["signature"]. The verifier binds the Statement subject
            # to bundle_bind_hash when present, else results_hash; for
            # the no-Sigstore-bundle rows the BFS exercises here
            # bundle_bind_hash is absent, so the DSSE Statement is
            # signed over stored_hash (== ci["results_hash"]). The
            # abstract ws_sig.valid flag still varies for these rows but
            # models only the redundant envelope ws_sig (the verifier
            # ignores it on the customer_dsse path — same trust-anchor
            # class as sigstore). A real customer key signs the
            # Statement; the auditor pins its fingerprint via
            # --expected-customer-key (wired in _pin_args).
            ci["dsse_bundle"] = _build_customer_dsse_bundle(
                content_hash=stored_hash,
                signing_key=KEY_CUSTOMER,
            )

    # --- provenance (Sigstore bundle) ---
    provenance = None
    if bundle_abs is not ABSENT:
        # Bundle is the abstract dict {san, issuer, bound_hash, valid,
        # predicate_model_id, predicate_commit_sha}.
        if not _ensure_real_bundles():
            pytest.skip("Bundle row needs real Fulcio mint (CI OIDC required)")
        bound = bundle_abs["bound_hash"]
        pred_mid = bundle_abs.get("predicate_model_id", M1)
        pred_csha = bundle_abs.get("predicate_commit_sha", C1)
        bundle_key = (bound, pred_mid, pred_csha)
        if bundle_key not in _REAL_BUNDLES:
            pytest.skip(
                f"Bundle row needs predicate combo {bundle_key} not in "
                "minted set"
            )
        if bundle_abs["valid"]:
            bundle_json = _REAL_BUNDLES[bundle_key]
        else:
            # Tampered bundle — corrupt one byte of the JSON so
            # Bundle.from_json or signature verification fails.
            real = _REAL_BUNDLES[bundle_key]
            mid_idx = len(real) // 2
            bundle_json = (
                real[:mid_idx]
                + ("X" if real[mid_idx] != "X" else "Y")
                + real[mid_idx + 1:]
            )
        provenance = {"bundle": bundle_json}
        # When ci is None we still need a results_hash for the bundle
        # to bind to; carry it in a synthesised content_integrity-shaped
        # placeholder when ws_sig is absent. audit() reads
        # `content_integrity.results_hash` for the bundle bind, so we
        # populate that field even when there's no signature to
        # verify in the content_integrity block itself.
        if ci is None and pkg["results_hash"] is not None:
            ci = {
                "results_hash": (
                    _CANONICAL_H1 if pkg["results_hash"] == "h1" else _CANONICAL_H2
                ),
            }
        # Populate the explicit bundle_bind_hash / bundle_bind_signature
        # fields the post-cutover verifier reads. The bundle's Subject
        # digest is sha256(content_hash_bytes) per _mint_real_bundle;
        # the verifier compares bundle.Subject.digest.sha256 directly
        # to bundle_bind_hash with no rehashing. To exercise the
        # verifier's mismatch branch, the BFS sets bundle_bind_hash
        # from the abstract pkg.bundle_bind_hash field — which may or
        # may not equal the bundle's actual Subject digest.
        bb_token = pkg.get("bundle_bind_hash")
        if bb_token is not None and ci is not None:
            # Map the abstract token ("h1"/"h2"/"missing") to the
            # concrete sha256-of-content_hash hex the bundle was
            # minted over.
            if bb_token == "h1":
                content_hash_for_bind = _CANONICAL_H1
            elif bb_token == "h2":
                content_hash_for_bind = _CANONICAL_H2
            else:
                content_hash_for_bind = "sha256:" + ("ff" * 32)
            bind_hex = hashlib.sha256(
                content_hash_for_bind.encode("utf-8")
            ).hexdigest()
            ci["bundle_bind_hash"] = bind_hex
            # Sign with KEY_A as the platform-key abstraction. The
            # ws_sig branch above signs `stored_hash` under signing_key
            # (KEY_A or KEY_B); the bundle-bind signature is signed by
            # KEY_A throughout, modelling the platform's signing key
            # (which in production is the same key for all rows).
            #
            # The abstract `bundle_bind_signature` field carries the
            # verifier-side outcome enum, not a raw boolean:
            #
            #   "VALID"            — sign correctly; embed public_key_pem
            #                        in the envelope so the verifier can
            #                        evaluate the signature against an
            #                        envelope-resident key.
            #   "INVALID"          — sign over junk; embed public_key_pem
            #                        so the verifier reaches the ECDSA
            #                        check and fails on bad bytes.
            #   "KEY_UNRESOLVABLE" — sign correctly, but DO NOT embed
            #                        public_key_pem. Models the
            #                        production case where a row's
            #                        envelope intentionally omits the
            #                        platform key (e.g. Sigstore /
            #                        orphan key-source rows whose trust
            #                        anchor is the bundle, not an
            #                        envelope-resident PEM). The
            #                        verifier must fail-loud rather
            #                        than silently skip the check.
            #
            # No more "patch in public_key_pem if missing": the previous
            # auto-patch made the KEY_UNRESOLVABLE state unreachable in
            # BFS by construction, even though production can ship it.
            bb_sig_state = pkg.get("bundle_bind_signature")
            if bb_sig_state is not None:
                if bb_sig_state in ("VALID", "INVALID"):
                    if "public_key_pem" not in ci or not ci.get("public_key_pem"):
                        ci["public_key_pem"] = KEY_A.public_key().public_bytes(
                            serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo,
                        ).decode()
                elif bb_sig_state == "KEY_UNRESOLVABLE":
                    # Force the envelope's public_key_pem empty so the
                    # verifier's V4 branch is reachable. The abstract
                    # KEY_UNRESOLVABLE state names the production case
                    # where the row's envelope intentionally omits the
                    # platform key (Sigstore key-source rows whose
                    # trust anchor is the bundle); the ws_sig branch
                    # above may have populated public_key_pem from the
                    # workspace key, which is fine for V1/V2/V3 but
                    # would let the verifier's Tier 3 (envelope-PEM)
                    # resolution path fire and return VERIFIED — the
                    # opposite of what the abstract state pins.
                    ci["public_key_pem"] = ""
                if bb_sig_state == "VALID":
                    bb_sig = KEY_A.sign(
                        bind_hex.encode("utf-8"),
                        ec.ECDSA(hashes.SHA256()),
                    )
                elif bb_sig_state == "INVALID":
                    bb_sig = KEY_A.sign(
                        b"junk-bind-sig",
                        ec.ECDSA(hashes.SHA256()),
                    )
                else:
                    # "KEY_UNRESOLVABLE" — sign correctly so the
                    # verifier's failure is unambiguously about key
                    # resolution, not crypto. The verifier should
                    # fail before reaching the ECDSA verify call.
                    bb_sig = KEY_A.sign(
                        bind_hex.encode("utf-8"),
                        ec.ECDSA(hashes.SHA256()),
                    )
                ci["bundle_bind_signature"] = base64.b64encode(bb_sig).decode()

    payload = {
        "model": {"id": "m1", "title": "t"},
        "control_objectives": [],
        "controls": [],
        "verification_run": {"id": "r1", "results": [], "submitted_at": ""},
        "provenance": provenance,
        "content_integrity": ci,
        "generated_at": "",
        "assertions_by_control": {},
        "sufficiency": {},
    }
    p = tmp_path / "pkg.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def _classify(result) -> str:
    """Map CliRunner output → Verdict label.

    Mirrors the verdict-text logic in cli.py. The classifier deliberately
    leans on textual markers (UNVERIFIED, PARTIALLY VERIFIED, VERIFIED)
    rather than exit codes alone — exit code 1 is shared between FAILED
    and crashing-on-malformed paths, while the verdict line is the
    canonical signal.
    """
    out = result.output
    if result.exit_code == 2 or "Error" in out and "requires --expected-ci-identity" in out:
        return "USAGE_ERROR"
    if "UNVERIFIED" in out and "no cryptographic evidence" in out:
        return "UNVERIFIED"
    if "Verdict: PARTIALLY VERIFIED" in out:
        return "PARTIALLY_VERIFIED"
    if "Verdict: FAILED" in out or result.exit_code == 1:
        return "FAILED"
    if "Verdict: VERIFIED" in out:
        return "VERIFIED"
    # Unrecognised output — treat as failure so the BFS surfaces it.
    return f"UNRECOGNISED:{out[:200]}"


# --- BFS: enumerate Package × Pins -------------------------------------


def _all_packages(include_bundle_rows: bool):
    """Enumerate the slice of Package the BFS materialises.

    Without `include_bundle_rows`, only no-bundle shapes are returned
    (workspace-sig combinations). With it, real-Fulcio-bundle shapes
    are added: bundle bound to h1 vs h2, valid vs tampered.
    """
    pkgs = []
    # No-evidence package (UNVERIFIED candidate).
    pkgs.append({
        "bundle": ABSENT,
        "ws_sig": ABSENT,
        "results_hash": NONE,
        "results_canonical_hash": "h1",
        "bundle_bind_hash": None,
        "bundle_bind_signature": None,
    })
    # Workspace-signed packages with each (signing_key_fp, claimed_fp,
    # valid) combination. key_source = "legacy" preserves the
    # pre-discriminator semantics (ws_sig.valid required for VERIFIED)
    # so the existing 7,200-row BFS coverage of I1-I13 is unchanged.
    for signing_fp in [FP_A, FP_B]:
        for claimed_fp in [NONE, FP_A, FP_B]:
            for valid in [True, False]:
                for results_hash in ["h1", "h2"]:
                    pkgs.append({
                        "bundle": ABSENT,
                        "ws_sig": {
                            "signing_key_fp": signing_fp,
                            "claimed_fp": claimed_fp,
                            "message_hash": results_hash,
                            "valid": valid,
                            "key_source": "legacy",
                        },
                        "results_hash": results_hash,
                        "results_canonical_hash": "h1",
                        "bundle_bind_hash": None,
                        "bundle_bind_signature": None,
                    })
    # Customer-keyed offline DSSE rows (key_source = "customer_dsse").
    # No Sigstore bundle by construction — this path exists precisely
    # for air-gapped / non-Sigstore CI that structurally cannot mint a
    # Fulcio bundle, so these rows are always materialised (not gated
    # on CI OIDC) and exercise the new trust-anchor class even on a
    # local run. The customer-signed DSSE Statement carried in
    # content_integrity.dsse_bundle is the trust anchor; the auditor
    # pins the customer key fingerprint out-of-band
    # (--expected-customer-key, wired in _customer_key_args). These
    # rows faithfully exercise the KS_SIGSTORE-class skip sets the
    # spec added customer_dsse to:
    #   - claimed_fp != signing_key_fp (claimed_fp=FP_B vs
    #     signing_key_fp=FP_A): would FAIL the metadata-fp branch if
    #     customer_dsse were NOT in the claimed-fp skip set. Because
    #     it IS in the skip set, the row still reaches VERIFIED — a
    #     non-vacuous exercise of that skip.
    #   - the ws_sig.valid skip and the I9 refinement are exercised
    #     structurally: the row reaches VERIFIED through the
    #     customer_dsse-aware branches without the generic
    #     ws_sig.valid gate firing (the verifier never consults
    #     ci["signature"] on this path — the customer-signed DSSE
    #     Statement is the anchor).
    # results_hash h1/h2 still drives the (key_source-independent)
    # canonical-hash mismatch branch (h1 → VERIFIED, h2 → FAILED).
    #
    # ws_sig.valid is pinned True: a customer_dsse row's trust anchor
    # is the customer-signed DSSE Statement, and KeySourceResolver R12
    # emits the customer_dsse classification ONLY when that bundle
    # re-verifies (DSSE_VALID). So a customer_dsse row with an invalid
    # anchor is producer-impossible — exactly analogous to audit.tla's
    # InitBase pin that makes (bundle.valid=FALSE,
    # key_source=KS_SIGSTORE) unreachable. Enumerating valid=False
    # here would explore a state the issuer cannot emit (and would
    # spuriously trip audit.tla's I5, which is written over
    # pkg.ws_sig.valid). Pinning True imports the producer constraint,
    # matching the end-to-end composition the deployed pipeline
    # guarantees.
    for claimed_fp in [NONE, FP_A, FP_B]:
        for results_hash in ["h1", "h2"]:
            pkgs.append({
                "bundle": ABSENT,
                "ws_sig": {
                    "signing_key_fp": FP_A,
                    "claimed_fp": claimed_fp,
                    "message_hash": results_hash,
                    "valid": True,
                    "key_source": "customer_dsse",
                },
                "results_hash": results_hash,
                "results_canonical_hash": "h1",
                "bundle_bind_hash": None,
                "bundle_bind_signature": None,
            })

    # Real-Fulcio-bundle packages (only enumerated when CI provides
    # OIDC; otherwise these rows aren't generated). The bundle's SAN
    # and issuer are filled in lazily at materialisation time using
    # the workflow's actual Fulcio cert — see _bundle_san() / _bundle_issuer().
    if include_bundle_rows:
        # Bundle bound to a hash + package claims same hash (matched).
        # Predicate fields (model_id, commit_sha) are enumerated so I12
        # and I13 are exercised against real Fulcio bundles. Each
        # (bound_hash, model_id, commit_sha) combo must be present in
        # _REAL_BUNDLES (minted by _ensure_real_bundles).
        # Default for existing rows: bundle_bind_hash matches
        # bundle.bound_hash and bundle_bind_signature is valid (True).
        # I14-specific variations are added as a separate row block
        # below to keep the I1–I13 coverage unchanged.
        for bound_hash in ["h1", "h2"]:
            for pred_mid, pred_csha in _BFS_PREDICATE_COMBOS:
                for valid in [True, False]:
                    pkgs.append({
                        "bundle": {
                            "san": "<real_san>",  # filled at runtime
                            "issuer": ISS_GH,
                            "bound_hash": bound_hash,
                            "predicate_model_id": pred_mid,
                            "predicate_commit_sha": pred_csha,
                            "valid": valid,
                        },
                        "ws_sig": ABSENT,
                        "results_hash": bound_hash,
                        "results_canonical_hash": "h1",
                        "bundle_bind_hash": bound_hash,
                        "bundle_bind_signature": "VALID",
                    })
        # I8 / step-#8 coverage: bundle bound to one hash, package
        # claims another. Sigstore's verify_artifact fails because
        # the Subject digest doesn't match the input bytes; spec says
        # FAILED via step #8 (bound_hash mismatch), implementation
        # propagates the verify exception → has_failure → FAILED.
        # results_canonical_hash is always "h1" because the
        # materialiser uses an empty `results` list, whose canonical
        # JSON ("[]") hashes to _CANONICAL_H1. The point of these
        # rows is to exercise the bundle-binding mismatch path, which
        # both spec and impl detect — though sometimes via different
        # branches (verify_artifact failure vs explicit step #8).
        for bound_hash, claimed_hash in [("h1", "h2"), ("h2", "h1")]:
            for valid in [True, False]:
                pkgs.append({
                    "bundle": {
                        "san": "<real_san>",
                        "issuer": ISS_GH,
                        "bound_hash": bound_hash,
                        "predicate_model_id": M1,
                        "predicate_commit_sha": C1,
                        "valid": valid,
                    },
                    "ws_sig": ABSENT,
                    "results_hash": claimed_hash,
                    "results_canonical_hash": "h1",
                    "bundle_bind_hash": bound_hash,
                    "bundle_bind_signature": "VALID",
                })
        # I10 corner case: bundle present but results_hash is NONE.
        for valid in [True, False]:
            pkgs.append({
                "bundle": {
                    "san": "<real_san>",
                    "issuer": ISS_GH,
                    "bound_hash": "h1",  # arbitrary; never reached
                    "predicate_model_id": M1,
                    "predicate_commit_sha": C1,
                    "valid": valid,
                },
                "ws_sig": ABSENT,
                "results_hash": NONE,
                "results_canonical_hash": "h1",
                "bundle_bind_hash": "h1",
                "bundle_bind_signature": "VALID",
            })

        # V1 / V2 / V3 coverage: rows where ws_sig.key_source is
        # KS_SIGSTORE or KS_ORPHAN AND a real Sigstore bundle is
        # present. These exercise the new key_source-aware Audit
        # branches that admit ws_sig.valid=False (sigstore-skipped
        # or orphan-unknown) when bundle drives the verdict.
        for ks in ["sigstore", "unverifiable_orphan"]:
            for ws_valid in [True, False]:
                pkgs.append({
                    "bundle": {
                        "san": "<real_san>",
                        "issuer": ISS_GH,
                        "bound_hash": "h1",
                        "predicate_model_id": M1,
                        "predicate_commit_sha": C1,
                        "valid": True,
                    },
                    "ws_sig": {
                        "signing_key_fp": FP_A,
                        "claimed_fp": NONE,
                        "message_hash": "h1",
                        "valid": ws_valid,
                        "key_source": ks,
                    },
                    "results_hash": "h1",
                    "results_canonical_hash": "h1",
                    "bundle_bind_hash": "h1",
                    "bundle_bind_signature": "VALID",
                })

        # I14 — explicit bundle_bind variations. Each row has a valid
        # Sigstore bundle bound to h1 and matching results_hash; only
        # the envelope's bundle_bind_hash / bundle_bind_signature
        # fields vary. The verifier's branch order guarantees the
        # bundle-bind check fires before signature, results_hash, and
        # ws_sig branches, so these rows isolate the I14 property.
        # Mismatching bundle_bind_hash is modelled as the abstract
        # token "h2" (the materialiser maps it to a digest the bundle
        # was NOT signed over). Missing bundle_bind_hash is modelled
        # by setting the field to None; missing signature by setting
        # bundle_bind_signature to None (NOT "INVALID", which means
        # present-but-invalid).
        for bb_hash, bb_sig in [
            ("h2", "VALID"),    # mismatched hash, valid sig over the
                                # mismatched value: hash check fires first.
            (None, "VALID"),    # missing hash on a bundle-bearing
                                # envelope: hard fail.
            (None, None),       # missing both (legacy envelope shape):
                                # hard fail under the post-cutover rule.
            ("h1", "INVALID"),  # matching hash, invalid signature:
                                # signature check fires.
            ("h1", None),       # matching hash, no signature: VERIFIED
                                # is permitted (sig is optional).
        ]:
            pkgs.append({
                "bundle": {
                    "san": "<real_san>",
                    "issuer": ISS_GH,
                    "bound_hash": "h1",
                    "predicate_model_id": M1,
                    "predicate_commit_sha": C1,
                    "valid": True,
                },
                "ws_sig": ABSENT,
                "results_hash": "h1",
                "results_canonical_hash": "h1",
                "bundle_bind_hash": bb_hash,
                "bundle_bind_signature": bb_sig,
            })

        # V4 — bundle_bind_signature is present but the envelope has no
        # platform key for the verifier to evaluate it against. This
        # state is reachable in production for envelope rows whose
        # public_key_pem is intentionally empty (e.g. Sigstore-keyed
        # rows whose trust anchor is the bundle, not an envelope-
        # resident PEM). The previous BFS materialiser auto-patched
        # public_key_pem in whenever bundle_bind_signature was
        # populated, making the gap state impossible-by-construction;
        # the materialiser no longer does that, and this row exercises
        # the V4 "fail-loud on KEY_UNRESOLVABLE" branch.
        #
        # The row is wired through ws_sig.key_source = "sigstore" so
        # the materialiser leaves public_key_pem empty (the production
        # invariant for Sigstore-keyed rows), and the verifier's V4
        # branch fires when the envelope has no key in scope and no
        # PDF outer-signature key (BFS calls audit() against a JSON
        # archive, not a PDF) and no --platform-pubkey was supplied.
        pkgs.append({
            "bundle": {
                "san": "<real_san>",
                "issuer": ISS_GH,
                "bound_hash": "h1",
                "predicate_model_id": M1,
                "predicate_commit_sha": C1,
                "valid": True,
            },
            "ws_sig": {
                "signing_key_fp": FP_A,
                "claimed_fp": NONE,
                "message_hash": "h1",
                "valid": True,
                "key_source": "sigstore",
            },
            "results_hash": "h1",
            "results_canonical_hash": "h1",
            "bundle_bind_hash": "h1",
            "bundle_bind_signature": "KEY_UNRESOLVABLE",
        })

        # V4 — same gap state via the orphan key-source row. Orphan
        # rows have empty public_key_pem in production (the issuer
        # could not resolve the fingerprint to a published key). When
        # the row also carries a populated bundle_bind_signature, the
        # verifier hits the same V4 branch — no key in envelope, no
        # PDF outer signature in scope, no --platform-pubkey: FAILED.
        pkgs.append({
            "bundle": {
                "san": "<real_san>",
                "issuer": ISS_GH,
                "bound_hash": "h1",
                "predicate_model_id": M1,
                "predicate_commit_sha": C1,
                "valid": True,
            },
            "ws_sig": {
                "signing_key_fp": FP_A,
                "claimed_fp": NONE,
                "message_hash": "h1",
                "valid": True,
                "key_source": "unverifiable_orphan",
            },
            "results_hash": "h1",
            "results_canonical_hash": "h1",
            "bundle_bind_hash": "h1",
            "bundle_bind_signature": "KEY_UNRESOLVABLE",
        })
    return pkgs


def _all_pins():
    """Full Pins cross-product over all five dimensions: SAN, issuer,
    workspace fingerprint, model_id, commit_sha. Expansion with
    model_id and commit_sha exercises I12 and I13 for every package
    shape (in particular, the no-bundle / no-results_hash / matched
    bundle rows). Local BFS row count is ~8000, runs in ~80s.

    The "<real_san>" placeholder represents the workflow SAN of the
    runtime CI run (resolved by `_resolve_pins_san()` at test-execution
    time). Including it as a constant placeholder — rather than
    inserting `_REAL_SAN` directly — keeps test-collection deterministic
    across pytest-xdist workers (each worker may see a different
    `_REAL_SAN` value or no value at all under transient mint failures;
    using a placeholder de-couples collection from the network call).
    Tests requiring the real SAN skip via `_resolve_pins_san()` when
    `_REAL_SAN` is None at runtime.
    """
    sans = [NONE, SAN_GH_A, SAN_GH_B, SAN_SELF, "<real_san>"]
    pins_list = []
    for san in sans:
        for iss in [NONE, ISS_GH, ISS_SELF]:
            for ws in [NONE, FP_A, FP_B]:
                # Pin domain {NONE, M1} × {NONE, C1} keeps the BFS
                # row count to ~7200 locally. Mismatch is still
                # exercised: bundle predicate enumerates {M1, M2} and
                # {C1, C2}, so (pin=M1, predicate=M2) and (pin=C1,
                # predicate=C2) cover the mismatch path. Adding M2/C2
                # to the pin domain would 2.25× the BFS without
                # buying extra falsification power for I12/I13.
                for mid in [NONE, M1]:
                    for csha in [NONE, C1]:
                        pins_list.append({
                            "san": san,
                            "issuer_explicit": iss,
                            "workspace_fp": ws,
                            "model_id": mid,
                            "commit_sha": csha,
                        })
    return pins_list


# PACKAGES enumeration is *deterministic* — always includes bundle
# rows regardless of whether real Fulcio bundles are available at
# this moment. The runtime materialiser at _materialise() handles
# the no-OIDC case via pytest.skip, so non-CI runs and fork-PR runs
# emit the same test IDs but skip the bundle-row tests at execution
# time.
#
# Critical for pytest-xdist correctness: every worker process imports
# this module independently, and pytest-xdist requires every worker
# to collect IDENTICAL test IDs. If the collection were gated by
# `_ensure_real_bundles()` (which makes a network call to Fulcio
# that can succeed for some workers and fail for others under
# transient conditions or rate limits), workers would disagree on
# PACKAGES and xdist would refuse to run with "Different tests were
# collected between gw1 and gw2."
#
# `_REAL_SAN` is also computed pre-collection, but `_all_pins()`
# tolerates None (it just doesn't add the real-SAN pin variant —
# again, no test-ID divergence).
_ensure_real_bundles()  # populate _REAL_SAN / _REAL_BUNDLES if available
PACKAGES = _all_packages(include_bundle_rows=True)
PINS_LIST = _all_pins()


def _resolve_pins_san(pins: dict) -> dict:
    """Replace the placeholder pin SAN with the real workflow SAN.

    Returns the original pins dict if no resolution is needed. Skips
    the test (via pytest.skip) if the placeholder is set but no real
    SAN was minted — same skip-pattern as `_materialise()` uses for
    bundle-present rows.
    """
    if pins.get("san") != "<real_san>":
        return pins
    if _REAL_SAN is None:
        pytest.skip("Real-SAN pin needs Fulcio mint (CI OIDC required)")
    return {**pins, "san": _REAL_SAN}


def _resolve_bundle_san(pkg: dict) -> dict:
    """Replace the placeholder bundle.san with the real workflow SAN."""
    if pkg["bundle"] is ABSENT:
        return pkg
    if pkg["bundle"]["san"] == "<real_san>":
        new_bundle = dict(pkg["bundle"])
        new_bundle["san"] = _REAL_SAN
        return {**pkg, "bundle": new_bundle}
    return pkg


def _pin_args(pins: dict) -> list[str]:
    args = []
    if pins["san"]:
        args += ["--expected-ci-identity", pins["san"]]
    if pins["issuer_explicit"]:
        args += ["--expected-issuer", pins["issuer_explicit"]]
    if pins["workspace_fp"]:
        args += ["--expected-workspace-key", pins["workspace_fp"]]
    if pins.get("model_id"):
        args += ["--expected-model-id", pins["model_id"]]
    if pins.get("commit_sha"):
        args += ["--expected-commit-sha", pins["commit_sha"]]
    return args


def _customer_key_args(tmp_path, pkg: dict) -> list[str]:
    """Audit-side `--expected-customer-key` arg for customer_dsse rows.

    The customer-DSSE path's entire trust basis is the auditor pinning
    the customer's public-key fingerprint out-of-band; the CLI fails
    closed without `--expected-customer-key`, so every materialised
    customer_dsse row must supply it. Unlike SAN/issuer/workspace pins,
    this is a property of the package's signing path (not the abstract
    Pins cross-product), so it's derived from `pkg` here rather than
    from the Pins enumeration. Writes the pinned customer PUBLIC key
    PEM to a temp file and returns the CLI flag pointing at it.

    Returns an empty list for non-customer_dsse rows.
    """
    ws = pkg.get("ws_sig")
    if ws is ABSENT or ws is None:
        return []
    if ws.get("key_source") != "customer_dsse":
        return []
    pem = KEY_CUSTOMER.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_path = tmp_path / "expected_customer_key.pem"
    key_path.write_bytes(pem)
    return ["--expected-customer-key", str(key_path)]


def _pkg_id(pkg: dict) -> str:
    if pkg["bundle"] is ABSENT:
        bundle = "no-bnd"
    else:
        b = pkg["bundle"]
        pmid = b.get("predicate_model_id", "?")[-2:]
        pcsha = b.get("predicate_commit_sha", "?")[-2:]
        bundle = (
            f"bnd(bh={b['bound_hash']},pm={pmid},pc={pcsha},"
            f"v={int(b['valid'])})"
        )
    if pkg["ws_sig"] is ABSENT:
        ws = "no-ws"
    else:
        w = pkg["ws_sig"]
        # Short key_source tag keeps parametrize IDs unique: the
        # customer_dsse no-bundle rows would otherwise collide with the
        # legacy no-bundle rows (same fp/claimed/valid/rh/bb), which
        # pytest rejects. legacy→"lg", sigstore→"ss",
        # customer_dsse→"cd", unverifiable_orphan→"or".
        _ks_tag = {
            "legacy": "lg",
            "sigstore": "ss",
            "customer_dsse": "cd",
            "unverifiable_orphan": "or",
        }.get(w.get("key_source", "legacy"), w.get("key_source", "legacy"))
        ws = (
            f"ws({w['signing_key_fp'][:4]},"
            f"c={w['claimed_fp'][:4] if w['claimed_fp'] else 'N'},"
            f"v={int(w['valid'])},k={_ks_tag})"
        )
    bb_hash = pkg.get("bundle_bind_hash")
    bb_sig = pkg.get("bundle_bind_signature")
    bb_hash_id = "N" if bb_hash is None else bb_hash
    if bb_sig is None:
        bb_sig_id = "N"
    elif bb_sig == "VALID":
        bb_sig_id = "V"
    elif bb_sig == "INVALID":
        bb_sig_id = "X"
    else:  # "KEY_UNRESOLVABLE"
        bb_sig_id = "U"
    return (
        f"{bundle}:{ws}:rh={pkg['results_hash'] or 'N'}:"
        f"bb={bb_hash_id}/{bb_sig_id}"
    )


def _pins_id(pins: dict) -> str:
    if pins["san"] is None:
        san = "N"
    elif _REAL_SAN and pins["san"] == _REAL_SAN:
        san = "real"
    else:
        san = pins["san"][8:14]
    iss = "N" if pins["issuer_explicit"] is None else pins["issuer_explicit"][:6]
    ws = "N" if pins["workspace_fp"] is None else pins["workspace_fp"][:4]
    mid = "N" if pins.get("model_id") is None else pins["model_id"][-2:]
    csha = "N" if pins.get("commit_sha") is None else pins["commit_sha"][-2:]
    return f"san={san},iss={iss},ws={ws},mid={mid},csha={csha}"


def _skip_outside_modeled_domain(pkg: dict, pins: dict) -> None:
    """No-op: customer_dsse is now fully modeled under every pin.

    Previously this skipped pinned customer_dsse rows: the earlier
    `audit.tla` modeled KS_CUSTOMER_DSSE only via the three
    workspace-signature skip sets (claimed-fp, ws_sig.valid, I9) and
    left its pin clauses (I1 / I7 / the SAN identity pin / the
    --expected-workspace-key pin) key_source-UNCONDITIONAL, so the
    spec over-broadly disagreed with the real CLI on the pinned
    customer_dsse path (the CLI gates customer-DSSE identity solely on
    --expected-customer-key). That public proof-vs-code gap is now
    CLOSED: `audit.tla` was refined so the identity-pin invariants are
    key_source-aware —

      - I1 / I7's predicate co-pin / the SAN-match branch / the
        --expected-workspace-key branch are scoped OUT of
        customer_dsse (additively: every other key_source's behaviour
        is unchanged);
      - the new V5a/V5b/V5c invariants positively state the
        customer_dsse pinned property — an --expected-customer-key
        fingerprint mismatch FAILS; a match + producer-valid
        customer-signed DSSE row + intact canonical hash + matching
        predicate pins VERIFIES; the Sigstore-SAN pins do not gate
        customer_dsse.

    `audit_spec()` mirrors the refined operator (the customer_dsse
    terminal dispatch + the carve-outs), so the pinned customer_dsse
    cells now EXECUTE against the spec rather than skip — exercising
    the pin-driven customer_dsse path non-vacuously. The function is
    retained (still called by both test bodies) so the call sites
    stay stable; it now intentionally does nothing.
    """
    return


# --- Tests --------------------------------------------------------------


@pytest.mark.parametrize(
    "pkg",
    PACKAGES,
    ids=[_pkg_id(p) for p in PACKAGES],
)
@pytest.mark.parametrize(
    "pins",
    PINS_LIST,
    ids=[_pins_id(p) for p in PINS_LIST],
)
def test_implementation_matches_spec(tmp_path, pkg, pins):
    """For every (Package, Pins), spec_verdict == real_verdict.

    This is the implementation conformance check: any divergence
    between the TLA+-mirror `audit_spec()` and the actual Python
    `audit()` Click command is a regression. Pytest reports the
    offending (pkg, pins) ID in the test name so it's actionable.
    """
    pkg_resolved = _resolve_bundle_san(pkg)
    pins_resolved = _resolve_pins_san(pins)
    _skip_outside_modeled_domain(pkg_resolved, pins_resolved)
    expected = audit_spec(pkg_resolved, pins_resolved)
    path = _materialise(tmp_path, pkg_resolved)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", path]
        + _pin_args(pins_resolved)
        + _customer_key_args(tmp_path, pkg_resolved),
    )
    actual = _classify(result)
    assert actual == expected, (
        f"Spec/impl divergence:\n"
        f"  pkg = {pkg_resolved}\n"
        f"  pins = {pins_resolved}\n"
        f"  spec verdict = {expected}\n"
        f"  impl verdict = {actual}\n"
        f"  output:\n{result.output}"
    )


@pytest.mark.parametrize("pins", PINS_LIST, ids=[_pins_id(p) for p in PINS_LIST])
@pytest.mark.parametrize("pkg", PACKAGES, ids=[_pkg_id(p) for p in PACKAGES])
def test_invariants_on_implementation(tmp_path, pkg, pins):
    """Each of I1–I7 holds on the actual Python implementation.

    Same enumeration as test_implementation_matches_spec but each
    assertion is the invariant in its raw form. A failure here pins
    down which specific invariant the implementation violated, even
    if test_implementation_matches_spec also fails for the same row.
    """
    pkg_resolved = _resolve_bundle_san(pkg)
    pins = _resolve_pins_san(pins)
    _skip_outside_modeled_domain(pkg_resolved, pins)
    path = _materialise(tmp_path, pkg_resolved)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", path]
        + _pin_args(pins)
        + _customer_key_args(tmp_path, pkg_resolved),
    )
    verdict = _classify(result)

    # Customer-keyed offline DSSE discriminator (mirrors audit.tla's
    # IsCustomerDsse). The identity-pin invariants below are
    # key_source-AWARE: the SAN / predicate-co-pin / workspace-fp pin
    # clauses are scoped OUT of customer_dsse (the CLI's customer-DSSE
    # path gates identity solely on --expected-customer-key); the
    # corresponding positive properties are asserted as V5a/V5b. The
    # issuer-explicit-alone clause stays key_source-unconditional.
    ws_cd = pkg_resolved.get("ws_sig")
    is_cd = (
        ws_cd is not ABSENT
        and ws_cd is not None
        and ws_cd.get("key_source") == "customer_dsse"
    )

    # I7 — issuer-explicit-alone (no SAN) is a usage error for EVERY
    # key_source (cli.py line ~1840). The model_id / commit_sha
    # co-pin clause is a usage error too, EXCEPT for customer_dsse,
    # whose --expected-customer-key is the SAN-substitute (cli.py
    # line ~1866).
    if pins["san"] is None and (
        pins["issuer_explicit"] is not None
        or (
            (pins.get("model_id") is not None
             or pins.get("commit_sha") is not None)
            and not is_cd
        )
    ):
        assert verdict == "USAGE_ERROR", (
            f"I7 violated: pins={pins}, verdict={verdict}\n{result.output}"
        )
        return  # I7 fires first — other invariants don't apply.

    # I1 — SAN pin + no bundle ⇒ FAILED. Scoped out of customer_dsse:
    # the dsse_bundle is its own upstream evidence (cli.py line
    # ~2750), so a SAN / predicate pin + no Sigstore bundle is not
    # pin-bypass-by-omission for that key_source — see V5b.
    if (
        pins["san"] is not None
        and pkg_resolved["bundle"] is ABSENT
        and not is_cd
    ):
        assert verdict == "FAILED", (
            f"I1 violated: pins={pins}, pkg={pkg_resolved}, verdict={verdict}\n"
            f"{result.output}"
        )

    # I2 — workspace pin + no ws_sig ⇒ FAILED. (customer_dsse always
    # carries a ws_sig, so this is vacuous there — left unscoped.)
    if pins["workspace_fp"] is not None and pkg_resolved["ws_sig"] is ABSENT:
        assert verdict == "FAILED", (
            f"I2 violated: pins={pins}, pkg={pkg_resolved}, verdict={verdict}\n"
            f"{result.output}"
        )

    # V5a/V5b — the customer_dsse pinned property, asserted positively
    # against the real CLI. The materialiser always supplies the
    # matching --expected-customer-key (via _customer_key_args) and
    # signs the customer DSSE Statement with model_id=M1 / commit_sha
    # =C1, so a materialised customer_dsse row has a matched key and a
    # predicate that matches the {NONE, M1} × {NONE, C1} pin domain.
    # The verdict is therefore VERIFIED when the canonical hash is
    # intact (results_hash == canonical) and FAILED when it is not —
    # INDEPENDENT of any SAN / issuer / workspace-fp pin set, proving
    # those pins do not gate customer_dsse (V5c). --expected-issuer
    # alone is excluded (key_source-independent USAGE_ERROR handled
    # by the I7 return above).
    if is_cd:
        hash_intact = (
            pkg_resolved["results_hash"]
            == pkg_resolved["results_canonical_hash"]
        )
        expected_cd = "VERIFIED" if hash_intact else "FAILED"
        assert verdict == expected_cd, (
            f"V5 violated: customer_dsse pinned verdict\n"
            f"  pkg={pkg_resolved}, pins={pins}\n"
            f"  expected={expected_cd}, got={verdict}\n{result.output}"
        )

    # I3 — bundle present + pin SAN matches but bundle's actual issuer
    # differs from resolved expected: must FAIL. (For real Fulcio
    # bundles, the actual issuer is always GitHub Actions, so this
    # invariant fires when the auditor pinned a non-GitHub explicit
    # issuer alongside the real GitHub SAN.)
    if (
        pkg_resolved["bundle"] is not ABSENT
        and pins["san"] is not None
        and pkg_resolved["bundle"]["san"] == pins["san"]
        and _resolve_issuer(pins) is not None
        and pkg_resolved["bundle"]["issuer"] != _resolve_issuer(pins)
    ):
        assert verdict == "FAILED", (
            f"I3 violated: bundle issuer ≠ resolved expected, but pass\n"
            f"  pkg={pkg_resolved}, pins={pins}, verdict={verdict}\n"
            f"  resolved={_resolve_issuer(pins)}\n{result.output}"
        )

    # I4 — workspace pin + signing_key_fp ≠ pinned ⇒ FAILED. Scoped
    # out of customer_dsse: the customer-DSSE CLI path never consults
    # --expected-workspace-key; its identity binding is the
    # --expected-customer-key fingerprint pin (asserted via V5
    # above).
    if (
        pins["workspace_fp"] is not None
        and pkg_resolved["ws_sig"] is not ABSENT
        and not is_cd
        and pkg_resolved["ws_sig"]["signing_key_fp"] != pins["workspace_fp"]
    ):
        assert verdict == "FAILED", (
            f"I4 violated: pins={pins}, pkg={pkg_resolved}, verdict={verdict}\n"
            f"{result.output}"
        )

    # I5 — VERIFIED ⇒ at least one valid signature was checked.
    if verdict == "VERIFIED":
        has_valid_bundle = (
            pkg_resolved["bundle"] is not ABSENT and pkg_resolved["bundle"]["valid"]
        )
        has_valid_ws = (
            pkg_resolved["ws_sig"] is not ABSENT and pkg_resolved["ws_sig"]["valid"]
        )
        assert has_valid_bundle or has_valid_ws, (
            f"I5 violated: VERIFIED with no valid evidence\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )

    # I6 — VERIFIED|PARTIALLY ⇒ results_hash matches canonical (when
    # results_hash is set).
    if (
        verdict in {"VERIFIED", "PARTIALLY_VERIFIED"}
        and pkg_resolved["results_hash"] is not None
    ):
        assert pkg_resolved["results_hash"] == pkg_resolved["results_canonical_hash"], (
            f"I6 violated: positive verdict with hash mismatch\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )

    # I8 — VERIFIED|PARTIALLY with bundle ⇒ bundle_bind_hash present
    # and bundle.bound_hash matches it. Defense-in-depth check beyond
    # Sigstore's verify_artifact: the envelope's explicit
    # bundle_bind_hash is the value the bundle's in-toto Subject digest
    # binds to. results_hash is independently recomputed downstream
    # against the platform's content-integrity signature; it is not
    # part of the bundle-bind check.
    if (
        verdict in {"VERIFIED", "PARTIALLY_VERIFIED"}
        and pkg_resolved["bundle"] is not ABSENT
    ):
        assert pkg_resolved.get("bundle_bind_hash") is not None, (
            f"I8 violated: positive verdict with bundle but no bundle_bind_hash\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )
        assert (
            pkg_resolved["bundle"]["bound_hash"] == pkg_resolved["bundle_bind_hash"]
        ), (
            f"I8 violated: positive verdict with bundle.bound_hash != bundle_bind_hash\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )

    # I9 (refined) — VERIFIED ⇒ every present signature is valid,
    # EXCEPT when the ws_sig carries key_source ∈ {sigstore,
    # customer_dsse, unverifiable_orphan}. Sigstore-tagged ws_sig is
    # the issuer's redundant notarization (bundle is the trust anchor;
    # the ws_sig signature is intentionally not re-verified).
    # customer_dsse-tagged ws_sig: the offline-verified customer-signed
    # DSSE Statement is the trust anchor — same trust-anchor class as
    # sigstore; the envelope ws_sig is not re-verified. Orphan-tagged
    # ws_sig has signing_key_fp by definition not in the issuer's
    # published key set; ws_sig.valid is "unknown" rather than
    # "invalid". For all three, ws_sig.valid is not part of the
    # VERIFIED preconditions. Mirrors the audit.tla
    # I9_AllPresentSignaturesValid refinement (skip set
    # {KS_SIGSTORE, KS_CUSTOMER_DSSE, KS_ORPHAN}).
    if verdict == "VERIFIED":
        if pkg_resolved["bundle"] is not ABSENT:
            assert pkg_resolved["bundle"]["valid"], (
                f"I9 violated: VERIFIED with invalid bundle present\n"
                f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
            )
        if pkg_resolved["ws_sig"] is not ABSENT:
            ws_ks = pkg_resolved["ws_sig"].get("key_source", "legacy")
            if ws_ks not in ("sigstore", "customer_dsse", "unverifiable_orphan"):
                assert pkg_resolved["ws_sig"]["valid"], (
                    f"I9 violated: VERIFIED with invalid ws_sig present "
                    f"(key_source={ws_ks!r})\n"
                    f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
                )

    # I10 — bundle present + results_hash = NONE ⇒ not VERIFIED. The
    # bundle has no artifact to bind to and Sigstore verify_artifact
    # cannot run; the implementation must emit UNVERIFIED or FAILED.
    if (
        pkg_resolved["bundle"] is not ABSENT
        and pkg_resolved["results_hash"] is None
    ):
        assert verdict in {"UNVERIFIED", "FAILED"}, (
            f"I10 violated: VERIFIED with unbindable bundle\n"
            f"  pkg={pkg_resolved}, pins={pins}, verdict={verdict}\n"
            f"{result.output}"
        )

    # I11 — VERIFIED with bundle + SAN pin ⇒ bundle.san = pin.san.
    # Defense-in-depth on top of policy.Identity's SAN check.
    if (
        verdict == "VERIFIED"
        and pkg_resolved["bundle"] is not ABSENT
        and pins["san"] is not None
    ):
        assert pkg_resolved["bundle"]["san"] == pins["san"], (
            f"I11 violated: VERIFIED with bundle.san != pin.san\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )

    # I12 — VERIFIED + bundle + model_id pin ⇒
    # bundle.predicate_model_id = pin.model_id. Defends against
    # cross-model substitution.
    if (
        verdict == "VERIFIED"
        and pkg_resolved["bundle"] is not ABSENT
        and pins.get("model_id") is not None
    ):
        assert (
            pkg_resolved["bundle"].get("predicate_model_id") == pins["model_id"]
        ), (
            f"I12 violated: VERIFIED with predicate.model_id != pin.model_id\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )

    # I13 — VERIFIED + bundle + commit_sha pin ⇒
    # bundle.predicate_commit_sha = pin.commit_sha. Defends against
    # replay of an older verification run.
    if (
        verdict == "VERIFIED"
        and pkg_resolved["bundle"] is not ABSENT
        and pins.get("commit_sha") is not None
    ):
        assert (
            pkg_resolved["bundle"].get("predicate_commit_sha")
            == pins["commit_sha"]
        ), (
            f"I13 violated: VERIFIED with predicate.commit_sha != "
            f"pin.commit_sha\n  pkg={pkg_resolved}, pins={pins}\n"
            f"{result.output}"
        )

    # I14 — VERIFIED + bundle present ⇒ bundle_bind_hash equals the
    # bundle's Subject digest AND, when bundle_bind_signature is
    # populated, the signature is valid. The verifier reads
    # bundle_bind_hash off the envelope and compares directly with no
    # canonicalisation; older envelopes that omit the field cannot
    # earn VERIFIED.
    if (
        verdict == "VERIFIED"
        and pkg_resolved["bundle"] is not ABSENT
    ):
        assert pkg_resolved.get("bundle_bind_hash") is not None, (
            f"I14 violated: VERIFIED with bundle but no bundle_bind_hash\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )
        assert (
            pkg_resolved["bundle"]["bound_hash"]
            == pkg_resolved["bundle_bind_hash"]
        ), (
            f"I14 violated: VERIFIED with bundle.bound_hash != "
            f"bundle_bind_hash\n  pkg={pkg_resolved}, pins={pins}\n"
            f"{result.output}"
        )
        assert pkg_resolved.get("bundle_bind_signature") not in (
            "INVALID", "KEY_UNRESOLVABLE"
        ), (
            f"I14 violated: VERIFIED with non-VALID bundle_bind_signature\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )


# --- Scenario-knob invariants (V6..V12) -------------------------------
#
# Targeted unit-level coverage for the new audit_spec post-processing
# layers added 2026-05-27 (gap #254 / #258 backfill). The TLA+ spec
# verifies the abstract operator's behaviour exhaustively over the
# pinned-envelope state space; these tests verify the spec mirror in
# `audit_spec` matches that behaviour on representative inputs.
#
# The model-only (V10/V11/V12) and orphan-results (V8/V9) and
# sufficiency (V6/V7) branches all post-process the envelope verdict
# via local enum/boolean knobs — no Sigstore minting required, no
# real-code invocation needed (cli.py-side coverage lives in
# tests/test_cli.py). These are spec-mirror sanity checks.

_DEFAULT_PINS_NONE = {
    "san": None,
    "issuer_explicit": None,
    "workspace_fp": None,
    "model_id": None,
    "commit_sha": None,
}


def _envelope_unverified():
    """Canonical no-evidence envelope: spec mirror returns UNVERIFIED."""
    return {
        "bundle": ABSENT,
        "ws_sig": ABSENT,
        "results_hash": None,
        "results_canonical_hash": "h1",
        "bundle_bind_hash": None,
        "bundle_bind_signature": None,
    }


def test_v10_model_only_emits_model_only():
    pkg = dict(_envelope_unverified(), is_model_only=True)
    assert audit_spec(pkg, _DEFAULT_PINS_NONE) == "MODEL_ONLY"


def test_v11_model_only_with_pinning_is_usage_error():
    pkg = dict(_envelope_unverified(), is_model_only=True)
    for pin_field in ("san", "workspace_fp", "model_id", "commit_sha"):
        pins = dict(
            _DEFAULT_PINS_NONE,
            **{pin_field: "san_gh_a" if pin_field == "san" else "x"},
        )
        assert audit_spec(pkg, pins) == "USAGE_ERROR", pin_field


def test_v12_model_only_only_emitted_on_model_only_input():
    # An envelope with is_model_only=FALSE never emits MODEL_ONLY,
    # regardless of pin / sufficiency / orphan state.
    for orphan in (False, True):
        for allow in (False, True):
            for suff in ("SUFF_ALL", "SUFF_INSUFFICIENT",
                          "SUFF_PENDING", "SUFF_NA"):
                pkg = dict(
                    _envelope_unverified(),
                    has_orphan_results=orphan,
                    sufficiency_state=suff,
                )
                pins = dict(_DEFAULT_PINS_NONE, allow_orphan_results=allow)
                assert audit_spec(pkg, pins) != "MODEL_ONLY", (
                    f"MODEL_ONLY leaked into envelope branch: "
                    f"orphan={orphan}, allow={allow}, suff={suff}"
                )


def test_v8_orphan_results_fail_close_default():
    # Envelope verdict UNVERIFIED (no evidence) + orphan + allow=False
    # demotes to FAILED.
    pkg = dict(_envelope_unverified(), has_orphan_results=True)
    pins = dict(_DEFAULT_PINS_NONE, allow_orphan_results=False)
    assert audit_spec(pkg, pins) == "FAILED"


def test_v9_allow_orphan_results_demotes_to_partial():
    pkg = dict(_envelope_unverified(), has_orphan_results=True)
    pins = dict(_DEFAULT_PINS_NONE, allow_orphan_results=True)
    assert audit_spec(pkg, pins) == "PARTIALLY_VERIFIED"


def test_v6_pending_sufficiency_demotes_verified():
    # Build a customer_dsse VERIFIED envelope (audit_spec returns
    # VERIFIED on the customer_dsse terminal dispatch with matched
    # predicate / fingerprint and canonical hash intact). Then add
    # sufficiency_state = SUFF_PENDING — verdict must drop to
    # PARTIALLY_VERIFIED.
    pkg = {
        "bundle": ABSENT,
        "ws_sig": {
            "key_source": "customer_dsse",
            "signing_key_fp": "fp_a",
            "claimed_fp": None,
            "valid": True,
            "message_hash": "h1",
        },
        "results_hash": "h1",
        "results_canonical_hash": "h1",
        "bundle_bind_hash": None,
        "bundle_bind_signature": None,
    }
    # Without sufficiency knob → VERIFIED.
    assert audit_spec(pkg, _DEFAULT_PINS_NONE) == "VERIFIED"
    # With SUFF_PENDING → PARTIALLY_VERIFIED.
    pkg_pending = dict(pkg, sufficiency_state="SUFF_PENDING")
    assert audit_spec(pkg_pending, _DEFAULT_PINS_NONE) == "PARTIALLY_VERIFIED"


def test_v7_insufficient_sufficiency_demotes_verified():
    pkg = {
        "bundle": ABSENT,
        "ws_sig": {
            "key_source": "customer_dsse",
            "signing_key_fp": "fp_a",
            "claimed_fp": None,
            "valid": True,
            "message_hash": "h1",
        },
        "results_hash": "h1",
        "results_canonical_hash": "h1",
        "bundle_bind_hash": None,
        "bundle_bind_signature": None,
        "sufficiency_state": "SUFF_INSUFFICIENT",
    }
    assert audit_spec(pkg, _DEFAULT_PINS_NONE) == "PARTIALLY_VERIFIED"


def test_orphan_demotion_never_overrides_failed():
    # A FAILED envelope verdict + orphan + allow=True should NOT
    # promote to PARTIALLY_VERIFIED. The orphan demotion fires only
    # on positive-class verdicts.
    pkg = {
        # workspace_fp pin + no ws_sig = I2 FAILED.
        "bundle": ABSENT,
        "ws_sig": ABSENT,
        "results_hash": None,
        "results_canonical_hash": "h1",
        "bundle_bind_hash": None,
        "bundle_bind_signature": None,
        "has_orphan_results": True,
    }
    pins = dict(_DEFAULT_PINS_NONE, workspace_fp="fp_a",
                 allow_orphan_results=True)
    assert audit_spec(pkg, pins) == "FAILED"
