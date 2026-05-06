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

# Two real ECDSA keypairs — fingerprints are computed canonically
# (SHA-256 of DER SubjectPublicKeyInfo), the same way the platform
# and the audit verifier compute them.
def _genkey() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _fp(key: ec.EllipticCurvePrivateKey) -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


KEY_A = _genkey()
KEY_B = _genkey()
FP_A = _fp(KEY_A)
FP_B = _fp(KEY_B)


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
    USAGE_ERROR. Branch order matches `cli.py` exactly so a divergence
    between this function and the implementation surfaces as a
    parametrised test failure with the offending (pkg, pins) named.
    """
    bundle = pkg["bundle"]
    ws_sig = pkg["ws_sig"]

    # I7: --expected-issuer alone is a usage error.
    if pins["issuer_explicit"] is not None and pins["san"] is None:
        return "USAGE_ERROR"

    # I7-extended: predicate pins (model_id / commit_sha) without
    # SAN pin are a usage error too. Without SAN constraining whose
    # OIDC produced the bundle, an attacker minting under their own
    # OIDC can craft any predicate values matching the auditor's
    # pins — the predicate pins alone don't deliver compromised-
    # platform defense (the flag's documented purpose).
    if (
        (pins.get("model_id") is not None or pins.get("commit_sha") is not None)
        and pins["san"] is None
    ):
        return "USAGE_ERROR"

    # I1: any bundle-binding pin + no bundle = FAILED. SAN, model_id,
    # commit_sha all live in the bundle's signed material; omitting
    # the bundle bypasses the pin.
    if (
        (pins["san"] is not None
         or pins.get("model_id") is not None
         or pins.get("commit_sha") is not None)
        and bundle is ABSENT
    ):
        return "FAILED"

    # I2: workspace pin + no content_integrity = FAILED.
    if pins["workspace_fp"] is not None and ws_sig is ABSENT:
        return "FAILED"

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

    # Bundle present but doesn't bind to claimed results_hash.
    # NB: in the BFS materialiser, pkg.results_hash carries the SAME
    # token ("h1"/"h2") as bundle.bound_hash, so this check is a pure
    # equality on the abstract token. The actual implementation
    # checks the same property at the bytes level (bundle binds to
    # content_integrity.results_hash via Subject digest).
    if (
        bundle is not ABSENT
        and pkg["results_hash"] is not None
        and bundle["bound_hash"] != pkg["results_hash"]
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
    # Skipped for KS_SIGSTORE — sigstore is the trust anchor, ws_sig
    # is the issuer's redundant notarization, not a customer claim.
    ws_key_source = ws_sig.get("key_source", "legacy") if ws_sig is not ABSENT else None
    if (
        ws_sig is not ABSENT
        and ws_key_source != "sigstore"
        and ws_sig["claimed_fp"] is not None
        and ws_sig["claimed_fp"] != ws_sig["signing_key_fp"]
    ):
        return "FAILED"

    # Workspace sig + pin: signing_key_fp must match pinned fp.
    # KS_ORPHAN rows have signing_key_fp not in published key set —
    # workspace_fp pin against an orphan row falls through here when
    # the fingerprint comparison fails (which it always will for
    # orphan rows, since orphan_fp != any registered workspace_fp).
    if (
        ws_sig is not ABSENT
        and pins["workspace_fp"] is not None
        and ws_sig["signing_key_fp"] != pins["workspace_fp"]
    ):
        return "FAILED"

    # Workspace sig present but signature itself invalid.
    # Skipped for KS_SIGSTORE (the bundle is the trust anchor — the
    # redundant ws_sig is not re-verified) and for KS_ORPHAN (the
    # row's key was not in the issuer's published set, so
    # ws_sig.valid is "unknown" rather than "invalid"; verdict
    # relies on bundle path or falls to UNVERIFIED).
    if (
        ws_sig is not ABSENT
        and ws_key_source not in ("sigstore", "unverifiable_orphan")
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
                })
    return pkgs


def _all_pins(real_san: str | None):
    """Full Pins cross-product over all five dimensions: SAN, issuer,
    workspace fingerprint, model_id, commit_sha. Expansion with
    model_id and commit_sha exercises I12 and I13 for every package
    shape (in particular, the no-bundle / no-results_hash / matched
    bundle rows). Local BFS row count is ~8000, runs in ~80s.
    """
    sans = [NONE, SAN_GH_A, SAN_GH_B, SAN_SELF]
    if real_san:
        sans.append(real_san)
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


# Lazily resolve the real SAN at module import. _ensure_real_bundles()
# is what actually mints; if it succeeds, _REAL_SAN is populated.
# We call it eagerly here so PACKAGES / PINS_LIST sizes are stable
# across the test session (parametrised IDs are computed at collection
# time and must not change between runs).
_HAS_REAL_BUNDLES = _ensure_real_bundles()
PACKAGES = _all_packages(include_bundle_rows=_HAS_REAL_BUNDLES)
PINS_LIST = _all_pins(_REAL_SAN)


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
        ws = f"ws({w['signing_key_fp'][:4]},c={w['claimed_fp'][:4] if w['claimed_fp'] else 'N'},v={int(w['valid'])})"
    return f"{bundle}:{ws}:rh={pkg['results_hash'] or 'N'}"


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
    expected = audit_spec(pkg_resolved, pins)
    path = _materialise(tmp_path, pkg_resolved)
    runner = CliRunner()
    result = runner.invoke(main, ["audit", path] + _pin_args(pins))
    actual = _classify(result)
    assert actual == expected, (
        f"Spec/impl divergence:\n"
        f"  pkg = {pkg_resolved}\n"
        f"  pins = {pins}\n"
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
    path = _materialise(tmp_path, pkg_resolved)
    runner = CliRunner()
    result = runner.invoke(main, ["audit", path] + _pin_args(pins))
    verdict = _classify(result)

    # I7 — any co-pin (issuer, model_id, commit_sha) without SAN is
    # a usage error.
    if pins["san"] is None and (
        pins["issuer_explicit"] is not None
        or pins.get("model_id") is not None
        or pins.get("commit_sha") is not None
    ):
        assert verdict == "USAGE_ERROR", (
            f"I7 violated: pins={pins}, verdict={verdict}\n{result.output}"
        )
        return  # I7 fires first — other invariants don't apply.

    # I1 — SAN pin + no bundle ⇒ FAILED.
    if pins["san"] is not None and pkg_resolved["bundle"] is ABSENT:
        assert verdict == "FAILED", (
            f"I1 violated: pins={pins}, pkg={pkg_resolved}, verdict={verdict}\n"
            f"{result.output}"
        )

    # I2 — workspace pin + no ws_sig ⇒ FAILED.
    if pins["workspace_fp"] is not None and pkg_resolved["ws_sig"] is ABSENT:
        assert verdict == "FAILED", (
            f"I2 violated: pins={pins}, pkg={pkg_resolved}, verdict={verdict}\n"
            f"{result.output}"
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

    # I4 — workspace pin + signing_key_fp ≠ pinned ⇒ FAILED.
    if (
        pins["workspace_fp"] is not None
        and pkg_resolved["ws_sig"] is not ABSENT
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

    # I8 — VERIFIED|PARTIALLY with bundle ⇒ results_hash present and
    # bundle.bound_hash matches it. Defense-in-depth check beyond
    # Sigstore's verify_artifact.
    if (
        verdict in {"VERIFIED", "PARTIALLY_VERIFIED"}
        and pkg_resolved["bundle"] is not ABSENT
    ):
        assert pkg_resolved["results_hash"] is not None, (
            f"I8 violated: positive verdict with bundle but no results_hash\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )
        assert (
            pkg_resolved["bundle"]["bound_hash"] == pkg_resolved["results_hash"]
        ), (
            f"I8 violated: positive verdict with bundle.bound_hash != results_hash\n"
            f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
        )

    # I9 — VERIFIED ⇒ every present signature is valid. Stronger than
    # I5 (which only requires at least one valid). The implementation
    # fails when any present signature fails; I9 captures that.
    if verdict == "VERIFIED":
        if pkg_resolved["bundle"] is not ABSENT:
            assert pkg_resolved["bundle"]["valid"], (
                f"I9 violated: VERIFIED with invalid bundle present\n"
                f"  pkg={pkg_resolved}, pins={pins}\n{result.output}"
            )
        if pkg_resolved["ws_sig"] is not ABSENT:
            assert pkg_resolved["ws_sig"]["valid"], (
                f"I9 violated: VERIFIED with invalid ws_sig present\n"
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
