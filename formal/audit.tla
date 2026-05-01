---- MODULE audit ----
(***************************************************************************)
(* TLA+ specification of the security invariants of `mipiti-verify audit`. *)
(*                                                                         *)
(* The audit verifier is modeled as a pure function from (Package, Pins)   *)
(* to Verdict, with cryptographic primitives (Sigstore trust chain, ECDSA  *)
(* verify, fingerprint canonicalisation) abstracted as oracles. The        *)
(* invariants encode the security properties the verifier MUST maintain to *)
(* defend against the compromised-platform threat model.                   *)
(*                                                                         *)
(* The corresponding implementation lives in                               *)
(* `verify/src/mipiti_verify/cli.py` (the `audit` Click command).          *)
(*                                                                         *)
(* A separate Python BFS test                                              *)
(* (`verify/tests/test_spec_invariants.py`) runs the actual                *)
(* implementation against an exhaustive enumeration of the same finite     *)
(* state space and asserts the invariants hold there too. The TLA+ spec    *)
(* is the source of truth for "what the property is"; the BFS is the       *)
(* regression gate for "what the code actually does."                      *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Identities,            \* finite set of possible CI SAN URIs
    Issuers,               \* finite set of possible OIDC issuer URLs
    Fingerprints,          \* finite set of possible workspace key fingerprints
    Hashes,                \* finite set of possible content hashes
    ModelIds,              \* finite set of possible model IDs
    CommitShas,            \* finite set of possible commit SHAs
    SAN_PREFIX_REGISTRY,   \* function: Identities -> Issuers (partial)
    NONE,                  \* sentinel for "not present"
    ABSENT                 \* sentinel for "evidence omitted from package"

VARIABLES pkg, pins

vars == <<pkg, pins>>

(***************************************************************************)
(* Domain definitions.                                                     *)
(*                                                                         *)
(* Bundle abstracts what Fulcio actually attested to:                      *)
(*   - san: the SAN URI in the cert (NONE if missing)                      *)
(*   - issuer: the OIDC issuer extension value (NONE if missing)           *)
(*   - bound_hash: the artifact hash the bundle was signed over            *)
(*   - valid: did Sigstore's trust chain (Fulcio root + Rekor proof)       *)
(*     verify against the package's results_hash?                          *)
(*                                                                         *)
(* WSSig abstracts a workspace ECDSA submission signature:                 *)
(*   - signing_key_fp: canonical fingerprint of the key actually used      *)
(*     to compute the signature (recomputed from public_key_pem)           *)
(*   - claimed_fp: the fingerprint declared in the package's metadata      *)
(*     (may diverge from signing_key_fp in a forged package)               *)
(*   - message_hash: the hash the signature commits to                     *)
(*   - valid: does the signature verify against the public key embedded    *)
(*     in the package?                                                     *)
(***************************************************************************)

Bundle == [
    san                    : Identities \cup {NONE},
    issuer                 : Issuers \cup {NONE},
    bound_hash             : Hashes,
    \* DSSE predicate fields (signed inside the bundle's in-toto
    \* Statement). NONE means the predicate omitted the field — a
    \* malformed bundle that the auditor can still pin against.
    predicate_model_id     : ModelIds \cup {NONE},
    predicate_commit_sha   : CommitShas \cup {NONE},
    valid                  : BOOLEAN
]

WSSig == [
    signing_key_fp : Fingerprints,
    claimed_fp     : Fingerprints \cup {NONE},
    message_hash   : Hashes,
    valid          : BOOLEAN
]

Package == [
    bundle                 : (Bundle \cup {ABSENT}),
    ws_sig                 : (WSSig \cup {ABSENT}),
    results_hash           : (Hashes \cup {NONE}),
    results_canonical_hash : Hashes
]

Pins == [
    san             : Identities \cup {NONE},
    issuer_explicit : Issuers \cup {NONE},
    workspace_fp    : Fingerprints \cup {NONE},
    model_id        : ModelIds \cup {NONE},
    commit_sha      : CommitShas \cup {NONE}
]

Verdict == {"VERIFIED", "PARTIALLY_VERIFIED", "UNVERIFIED",
            "FAILED", "USAGE_ERROR"}

(***************************************************************************)
(* Issuer resolution: explicit pin > SAN-prefix registry > NONE.           *)
(* The bundle's own claim about its issuer is NEVER consulted to derive    *)
(* the expected issuer; doing so would let a forged bundle self-attest.    *)
(***************************************************************************)
ResolveIssuer(p) ==
    IF p.issuer_explicit # NONE
    THEN p.issuer_explicit
    ELSE IF p.san # NONE /\ p.san \in DOMAIN SAN_PREFIX_REGISTRY
         THEN SAN_PREFIX_REGISTRY[p.san]
         ELSE NONE

(***************************************************************************)
(* Audit: the abstract specification of what the verifier should compute.  *)
(* The actual Python implementation is checked against this in the BFS     *)
(* test. The cases are listed in the same order as the implementation      *)
(* evaluates them.                                                         *)
(***************************************************************************)
Audit(k, q) ==
    \* I7 case: pinning issuer alone, or predicate pins (model_id /
    \* commit_sha) without a SAN pin, is a usage error. The predicate
    \* pins are signed by Fulcio, but Fulcio signs whatever predicate
    \* the OIDC-token-holder supplies; without a SAN pin constraining
    \* whose OIDC was used, the predicate pins offer no compromised-
    \* platform defense (the flag's documented purpose).
    IF q.san = NONE
       /\ (q.issuer_explicit # NONE
           \/ q.model_id # NONE
           \/ q.commit_sha # NONE)
    THEN "USAGE_ERROR"

    \* I1 case: SAN pin + no Sigstore bundle = FAILED (pin-bypass-by-omission).
    \* Generalised to all bundle-binding pins: model_id and commit_sha
    \* live in the bundle's signed predicate, so omitting the bundle
    \* bypasses those pins too.
    ELSE IF (q.san # NONE \/ q.model_id # NONE \/ q.commit_sha # NONE)
         /\ k.bundle = ABSENT
    THEN "FAILED"

    \* I2 case: workspace pin + no content_integrity = FAILED.
    ELSE IF q.workspace_fp # NONE /\ k.ws_sig = ABSENT
    THEN "FAILED"

    \* Self-hosted SAN with no resolvable issuer = FAILED.
    ELSE IF q.san # NONE /\ k.bundle # ABSENT /\ ResolveIssuer(q) = NONE
    THEN "FAILED"

    \* Bundle present + pin requires SAN match.
    ELSE IF k.bundle # ABSENT /\ q.san # NONE /\ k.bundle.san # q.san
    THEN "FAILED"

    \* Bundle present + pin requires issuer match (resolved per pins).
    ELSE IF k.bundle # ABSENT /\ q.san # NONE
         /\ ResolveIssuer(q) # NONE
         /\ k.bundle.issuer # ResolveIssuer(q)
    THEN "FAILED"

    \* Bundle present but trust chain failed.
    ELSE IF k.bundle # ABSENT /\ ~k.bundle.valid
    THEN "FAILED"

    \* Bundle present but doesn't bind to package's claimed results_hash.
    ELSE IF k.bundle # ABSENT /\ k.results_hash # NONE
         /\ k.bundle.bound_hash # k.results_hash
    THEN "FAILED"

    \* Bundle present but no results_hash to bind to (and a bundle-
    \* binding pin is set). Without verify_artifact's binding check
    \* running, neither the SAN/issuer policy nor the predicate-field
    \* pins (model_id, commit_sha) can be enforced.
    ELSE IF k.bundle # ABSENT /\ k.results_hash = NONE
         /\ (q.san # NONE \/ q.model_id # NONE \/ q.commit_sha # NONE)
    THEN "FAILED"

    \* Bundle present + model_id pin + bundle predicate doesn't match.
    ELSE IF k.bundle # ABSENT /\ q.model_id # NONE
         /\ k.bundle.predicate_model_id # q.model_id
    THEN "FAILED"

    \* Bundle present + commit_sha pin + bundle predicate doesn't match.
    ELSE IF k.bundle # ABSENT /\ q.commit_sha # NONE
         /\ k.bundle.predicate_commit_sha # q.commit_sha
    THEN "FAILED"

    \* Workspace sig: claimed_fp (if present) must match signing_key_fp.
    ELSE IF k.ws_sig # ABSENT /\ k.ws_sig.claimed_fp # NONE
         /\ k.ws_sig.claimed_fp # k.ws_sig.signing_key_fp
    THEN "FAILED"

    \* Workspace sig: pin requires recomputed signing_key_fp match.
    ELSE IF k.ws_sig # ABSENT /\ q.workspace_fp # NONE
         /\ k.ws_sig.signing_key_fp # q.workspace_fp
    THEN "FAILED"

    \* Workspace sig present but invalid.
    ELSE IF k.ws_sig # ABSENT /\ ~k.ws_sig.valid
    THEN "FAILED"

    \* Hash mismatch: results_hash claim doesn't match canonical hash.
    ELSE IF k.results_hash # NONE
         /\ k.results_hash # k.results_canonical_hash
    THEN "FAILED"

    \* No cryptographic verification actually ran:
    \*   - the bundle is absent OR the bundle has no results_hash to
    \*     bind to (so verify_artifact never executed), AND
    \*   - the workspace signature is absent.
    \* This prevents the corner case where a package carries an
    \* unverifiable bundle (results_hash = NONE) but no pin is set —
    \* the implementation correctly emits UNVERIFIED in that case.
    ELSE IF (k.bundle = ABSENT \/ k.results_hash = NONE)
         /\ k.ws_sig = ABSENT
    THEN "UNVERIFIED"

    \* Otherwise: VERIFIED.
    ELSE "VERIFIED"

(***************************************************************************)
(* State machine: TLC enumerates every (pkg, pins) by allowing the next-   *)
(* step relation to pick any combination. This makes every reachable state *)
(* a (pkg, pins) pair; checking an invariant on every reachable state is   *)
(* equivalent to checking it on every (pkg, pins) in the cross-product.    *)
(***************************************************************************)
Init == /\ pkg \in Package
        /\ pins \in Pins

Next == /\ pkg' \in Package
        /\ pins' \in Pins

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Security invariants. Each is a property the implementation must hold    *)
(* for every input. TLC checks these are universally true on the abstract  *)
(* Audit operator; the Python BFS checks them on the real implementation.  *)
(***************************************************************************)

\* I1 — any bundle-binding pin (SAN, model_id, commit_sha) requires
\* Sigstore evidence. A compromised platform must not be able to
\* bypass the pin by omitting the bundle. All three pins reduce to
\* the same property: the bundle's signed material is what's pinned
\* against, so omitting the bundle defeats the pin.
I1_SanPinIsBinding ==
    ((pins.san # NONE \/ pins.model_id # NONE \/ pins.commit_sha # NONE)
     /\ pkg.bundle = ABSENT)
    => Audit(pkg, pins) = "FAILED"

\* I2 — workspace pin requires content_integrity evidence.
I2_WorkspacePinIsBinding ==
    (pins.workspace_fp # NONE /\ pkg.ws_sig = ABSENT)
    => Audit(pkg, pins) = "FAILED"

\* I3 — issuer is never sourced from the bundle's own claim. When a
\* bundle is present and the auditor's expected issuer (resolved from
\* pins) differs from the bundle's claim, the audit must FAIL. (The
\* contrapositive: VERIFIED with bundle present implies bundle.issuer
\* equals the auditor's expected issuer, not the bundle's self-claim.)
I3_IssuerNeverSelfAttested ==
    (pins.san # NONE
     /\ pkg.bundle # ABSENT
     /\ ResolveIssuer(pins) # NONE
     /\ pkg.bundle.issuer # ResolveIssuer(pins))
    => Audit(pkg, pins) = "FAILED"

\* I4 — workspace fingerprint must equal the canonical fingerprint of
\* the public key actually used for verification (signing_key_fp), not
\* the package's claim. Forged-key attacks must FAIL.
I4_WorkspaceFpBound ==
    (pins.workspace_fp # NONE
     /\ pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.signing_key_fp # pins.workspace_fp)
    => Audit(pkg, pins) = "FAILED"

\* I5 — VERIFIED implies actual cryptographic verification ran. A
\* package with no signatures cannot earn the green VERIFIED verdict.
I5_VerifiedImpliesEvidence ==
    (Audit(pkg, pins) = "VERIFIED")
    => \/ (pkg.bundle # ABSENT /\ pkg.bundle.valid)
       \/ (pkg.ws_sig # ABSENT /\ pkg.ws_sig.valid)

\* I6 — content hash binds to actual results when verdict is positive.
I6_ContentHashBoundToResults ==
    (Audit(pkg, pins) \in {"VERIFIED", "PARTIALLY_VERIFIED"}
     /\ pkg.results_hash # NONE)
    => pkg.results_hash = pkg.results_canonical_hash

\* I7 — any pin whose enforcement requires the SAN pin (issuer
\* explicit, model_id, commit_sha) without a SAN pin is a usage
\* error. policy.Identity needs both SAN+issuer; predicate pins
\* without SAN deliver no compromised-platform defense because an
\* attacker minting under their own OIDC controls the predicate.
I7_SanRequiredForCoPins ==
    (pins.san = NONE
     /\ (pins.issuer_explicit # NONE
         \/ pins.model_id # NONE
         \/ pins.commit_sha # NONE))
    => Audit(pkg, pins) = "USAGE_ERROR"

\* I8 — bundle bound_hash matches the package's claimed results_hash
\* on any positive verdict. Defense-in-depth on top of Sigstore's
\* verify_artifact (which raises when the bundle's Subject digest
\* doesn't equal sha256(input_)) — explicitly stating this as an
\* invariant catches future flow changes that bypass verify_artifact
\* or pass the wrong artifact bytes to it.
I8_BundleBoundToResultsHash ==
    (Audit(pkg, pins) \in {"VERIFIED", "PARTIALLY_VERIFIED"}
     /\ pkg.bundle # ABSENT)
    => /\ pkg.results_hash # NONE
       /\ pkg.bundle.bound_hash = pkg.results_hash

\* I9 — VERIFIED requires every present signature to verify, not just
\* one. I5 alone is too weak: it allows VERIFIED when ANY signature
\* is valid, even if a co-located other signature is invalid. The
\* implementation correctly fails when any present signature fails;
\* I9 captures that property explicitly.
I9_AllPresentSignaturesValid ==
    (Audit(pkg, pins) = "VERIFIED")
    => /\ (pkg.bundle = ABSENT \/ pkg.bundle.valid)
       /\ (pkg.ws_sig = ABSENT \/ pkg.ws_sig.valid)

\* I10 — a bundle present without a results_hash to bind to cannot
\* yield VERIFIED. The bundle is structurally unverifiable in this
\* shape (Sigstore's verify_artifact has no artifact bytes to check
\* against), so the verdict must be either UNVERIFIED (no pin set)
\* or FAILED (pin set — see step #9 of Audit). The contrapositive:
\* VERIFIED with a bundle implies the bundle was actually checked
\* against a hash.
I10_UnboundBundleNotVerified ==
    (pkg.bundle # ABSENT /\ pkg.results_hash = NONE)
    => Audit(pkg, pins) \in {"FAILED", "UNVERIFIED"}

\* I11 — VERIFIED with bundle present and SAN pin set implies the
\* bundle's SAN equals the pin. Symmetric counterpart of I3 for SAN:
\* I3 ensures issuer matches; I11 ensures SAN matches. Defense-in-
\* depth on top of policy.Identity's SAN check.
I11_BundleSanMatchesPin ==
    (Audit(pkg, pins) = "VERIFIED"
     /\ pkg.bundle # ABSENT
     /\ pins.san # NONE)
    => pkg.bundle.san = pins.san

\* I12 — VERIFIED with bundle present and model_id pin set implies
\* the bundle's predicate model_id equals the pin. Defends against
\* cross-model substitution: a real, cryptographically-valid audit
\* package for a different model cannot be passed off as the
\* auditor's intended model. Pin-bypass-by-omission (no bundle while
\* model_id pin set) is enforced by the generalised I1 / step #2.
I12_BundleModelIdMatchesPin ==
    (Audit(pkg, pins) = "VERIFIED"
     /\ pkg.bundle # ABSENT
     /\ pins.model_id # NONE)
    => pkg.bundle.predicate_model_id = pins.model_id

\* I13 — VERIFIED with bundle present and commit_sha pin set implies
\* the bundle's predicate commit_sha equals the pin. Defends against
\* replay: a real, cryptographically-valid audit package from an
\* older verification run (different commit) cannot be passed off as
\* an audit of the release the auditor is certifying.
I13_BundleCommitShaMatchesPin ==
    (Audit(pkg, pins) = "VERIFIED"
     /\ pkg.bundle # ABSENT
     /\ pins.commit_sha # NONE)
    => pkg.bundle.predicate_commit_sha = pins.commit_sha

\* Conjunction of all invariants — the property TLC checks.
SecurityInvariants ==
    /\ I1_SanPinIsBinding
    /\ I2_WorkspacePinIsBinding
    /\ I3_IssuerNeverSelfAttested
    /\ I4_WorkspaceFpBound
    /\ I5_VerifiedImpliesEvidence
    /\ I6_ContentHashBoundToResults
    /\ I7_SanRequiredForCoPins
    /\ I8_BundleBoundToResultsHash
    /\ I9_AllPresentSignaturesValid
    /\ I10_UnboundBundleNotVerified
    /\ I11_BundleSanMatchesPin
    /\ I12_BundleModelIdMatchesPin
    /\ I13_BundleCommitShaMatchesPin

(***************************************************************************)
(* Type invariant: every reachable state has well-typed pkg and pins.      *)
(***************************************************************************)
TypeOK ==
    /\ pkg \in Package
    /\ pins \in Pins

====
