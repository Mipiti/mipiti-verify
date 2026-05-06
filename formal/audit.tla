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
    ABSENT,                \* sentinel for "evidence omitted from package"

    \* Audit-envelope key_source discriminator (added 2026-05-05).
    \* Tells the verifier how to consume the content_integrity block.
    \* See KeySourceResolver.tla in this directory for the issuer-side
    \* contract producing these values.
    KS_SIGSTORE,           \* Sigstore provenance is the trust anchor;
                           \* ws_sig (if present) is redundant notarization
                           \* and skipped during verification.
    KS_PLATFORM,           \* server-notarized; ws_sig.valid required.
    KS_WORKSPACE,          \* customer-uploaded ECDSA; ws_sig.valid required.
    KS_ORPHAN,             \* fingerprint did not resolve in issuer's
                           \* published key set; ws_sig.valid is unknown.
    KS_LEGACY              \* envelope without key_source field
                           \* (older issuer build) — ws_sig.valid required
                           \* per pre-discriminator semantics.

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

KeySources == {KS_SIGSTORE, KS_PLATFORM, KS_WORKSPACE, KS_ORPHAN, KS_LEGACY}

WSSig == [
    signing_key_fp : Fingerprints,
    claimed_fp     : Fingerprints \cup {NONE},
    message_hash   : Hashes,
    valid          : BOOLEAN,
    \* Issuer's key_source classification for this row. KS_LEGACY
    \* models the existing envelope shape (no key_source field) so
    \* the pre-discriminator BFS rows continue to validate against
    \* the existing 13 invariants unchanged. KS_SIGSTORE and
    \* KS_ORPHAN unlock the V1/V2/V3 invariants below.
    key_source     : KeySources
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
\* Concrete instantiation of SAN_PREFIX_REGISTRY for TLC. The
\* CONSTANT declaration above keeps the spec parameterised, but
\* TLC's .cfg parser rejects inline function/record literals in
\* CONSTANT assignments — so the .cfg uses the `<-` operator-bind
\* syntax to replace SAN_PREFIX_REGISTRY with this default at
\* model-check time. Encodes the same SAN-prefix → issuer mapping
\* the Python implementation hard-codes (github.com / gitlab.com).
SAN_PREFIX_REGISTRY_DEFAULT ==
    [s \in {"san_gh_a"} |-> "iss_gh"]

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

    \* Bundle present but no results_hash to bind to. The platform
    \* produces bundles together with content_integrity.results_hash;
    \* a bundle without the corresponding hash is a malformed /
    \* tampered package shape. Fail unconditionally — a workspace-
    \* ECDSA fallback path that would otherwise yield VERIFIED is
    \* not allowed when a Sigstore bundle is also in the package
    \* but cannot be verified.
    ELSE IF k.bundle # ABSENT /\ k.results_hash = NONE
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
    \* Skipped for KS_SIGSTORE (Sigstore is the trust anchor; ws_sig
    \* is the issuer's redundant notarization, not a customer claim).
    ELSE IF k.ws_sig # ABSENT
         /\ k.ws_sig.key_source # KS_SIGSTORE
         /\ k.ws_sig.claimed_fp # NONE
         /\ k.ws_sig.claimed_fp # k.ws_sig.signing_key_fp
    THEN "FAILED"

    \* Workspace sig: pin requires recomputed signing_key_fp match.
    \* For KS_ORPHAN, the row's signing_key_fp is by definition not
    \* in the issuer's published set, so a workspace-fp pin against
    \* it cannot be satisfied — fall through to FAILED.
    ELSE IF k.ws_sig # ABSENT /\ q.workspace_fp # NONE
         /\ k.ws_sig.signing_key_fp # q.workspace_fp
    THEN "FAILED"

    \* Workspace sig present but invalid.
    \* Skipped for KS_SIGSTORE (the bundle path is the trust anchor —
    \* the redundant ws_sig signature is not re-verified) and for
    \* KS_ORPHAN (the row's key was not in the issuer's published
    \* set, so ws_sig.valid is "unknown" rather than "invalid";
    \* verdict relies on bundle path or falls to UNVERIFIED).
    ELSE IF k.ws_sig # ABSENT
         /\ k.ws_sig.key_source \notin {KS_SIGSTORE, KS_ORPHAN}
         /\ ~k.ws_sig.valid
    THEN "FAILED"

    \* Hash mismatch: results_hash claim doesn't match canonical hash.
    ELSE IF k.results_hash # NONE
         /\ k.results_hash # k.results_canonical_hash
    THEN "FAILED"

    \* No cryptographic verification actually ran:
    \*   - the bundle is absent OR the bundle has no results_hash to
    \*     bind to (so verify_artifact never executed), AND
    \*   - the workspace signature is absent OR is sigstore-skipped /
    \*     orphan-unknown (neither contributes to verifier confidence
    \*     on its own).
    \* This prevents the corner case where a package carries an
    \* unverifiable bundle (results_hash = NONE) but no pin is set —
    \* the implementation correctly emits UNVERIFIED in that case.
    ELSE IF (k.bundle = ABSENT \/ k.results_hash = NONE)
         /\ (k.ws_sig = ABSENT
             \/ k.ws_sig.key_source \in {KS_SIGSTORE, KS_ORPHAN})
    THEN "UNVERIFIED"

    \* Otherwise: VERIFIED.
    ELSE "VERIFIED"

(***************************************************************************)
(* State machine: TLC enumerates every (pkg, pins) at Init (21M tuples on  *)
(* the configured constants), then `Next == UNCHANGED vars` makes each      *)
(* state self-loop. TLC checks invariants on every initial state and       *)
(* finishes — the state graph is a million self-loops, no transitions to   *)
(* explore. The original `Next == pkg' \in Package /\ pins' \in Pins`      *)
(* allowed every state to transition to every other, forcing TLC to do     *)
(* O(states²) successor-fingerprint operations (~10^14 evaluations on a    *)
(* 21M state space) and exceeded one hour of runtime in CI without          *)
(* finishing.                                                              *)
(***************************************************************************)
Init == /\ pkg \in Package
        /\ pins \in Pins

Next == UNCHANGED vars

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
\*
\* The conclusion allows USAGE_ERROR alongside FAILED because I7
\* (predicate-pin-without-SAN, issuer-without-SAN) returns
\* USAGE_ERROR before I1's FAILED branch fires. Both verdicts are
\* non-positive — the safety property is preserved either way.
I1_SanPinIsBinding ==
    ((pins.san # NONE \/ pins.model_id # NONE \/ pins.commit_sha # NONE)
     /\ pkg.bundle = ABSENT)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

\* I2 — workspace pin requires content_integrity evidence.
\* Same I7-co-occurrence allowance as I1: when the auditor also has
\* a co-pin without SAN, USAGE_ERROR fires before the workspace
\* check; conclusion widens to admit it.
I2_WorkspacePinIsBinding ==
    (pins.workspace_fp # NONE /\ pkg.ws_sig = ABSENT)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

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
\* Allows USAGE_ERROR for the same reason as I1/I2 (I7 fires first
\* when a co-pin is set without SAN).
I4_WorkspaceFpBound ==
    (pins.workspace_fp # NONE
     /\ pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.signing_key_fp # pins.workspace_fp)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

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

\* I8 — bundle present + positive verdict ⇒ bundle's bound_hash
\* equals the package's claimed results_hash. Defense-in-depth on
\* top of Sigstore's verify_artifact, which raises when the bundle's
\* Subject digest doesn't equal sha256(input_). With the malformed-
\* bundle (no results_hash) case now an unconditional FAILED in the
\* Audit operator, this invariant holds without an ws_sig=ABSENT
\* exception.
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
\*
\* Refined for the key_source discriminator: when the issuer marks
\* a ws_sig as KS_SIGSTORE (its validity is redundant — Sigstore is
\* the trust anchor) or KS_ORPHAN (its validity is not decidable —
\* the key is not in the issuer's published set), ws_sig.valid is
\* not part of the VERIFIED preconditions. For KS_PLATFORM,
\* KS_WORKSPACE, and KS_LEGACY (older envelopes), ws_sig.valid
\* IS required as before — preserving the original property's
\* strength on every input shape it covered before.
I9_AllPresentSignaturesValid ==
    (Audit(pkg, pins) = "VERIFIED")
    => /\ (pkg.bundle = ABSENT \/ pkg.bundle.valid)
       /\ (pkg.ws_sig = ABSENT
           \/ pkg.ws_sig.key_source = KS_SIGSTORE
           \/ pkg.ws_sig.key_source = KS_ORPHAN
           \/ pkg.ws_sig.valid)

\* I10 — a bundle present without a results_hash to bind to cannot
\* yield a positive verdict. With the strict malformed-bundle rule,
\* the Audit operator returns FAILED unconditionally for this case
\* — even when ws_sig is present and would otherwise verify. A
\* bundle in the package without its corresponding results_hash is
\* a malformed / tampered shape; refusing it ensures the auditor
\* doesn't see a "VERIFIED — content intact" verdict on a package
\* whose bundle was effectively ignored. USAGE_ERROR can still
\* preempt FAILED when an issuer-alone or predicate-pin-without-SAN
\* configuration is set.
I10_UnboundBundleNotVerified ==
    (pkg.bundle # ABSENT /\ pkg.results_hash = NONE)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

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

\* V1 — Sigstore-skip soundness. When the issuer marks a row's
\* ws_sig with key_source = KS_SIGSTORE, the verifier MUST NOT FAIL
\* the audit on ws_sig.valid alone (the sigstore bundle path is the
\* trust anchor; the ws_sig is the issuer's redundant notarization
\* and is intentionally skipped). VERIFIED in this case requires
\* the bundle path to succeed, captured by I9's refined conjunction.
\* The property captured here: if the only failing signature is a
\* sigstore-tagged ws_sig, the audit DOES NOT FAIL.
V1_SigstoreSkipSoundness ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_SIGSTORE
     /\ ~pkg.ws_sig.valid
     /\ pkg.bundle # ABSENT
     /\ pkg.bundle.valid
     /\ pkg.results_hash # NONE
     /\ pkg.bundle.bound_hash = pkg.results_hash
     /\ pkg.results_hash = pkg.results_canonical_hash
     /\ pins.san = NONE
     /\ pins.issuer_explicit = NONE
     /\ pins.workspace_fp = NONE
     /\ pins.model_id = NONE
     /\ pins.commit_sha = NONE)
    => Audit(pkg, pins) = "VERIFIED"

\* V2 — Orphan-with-bundle still verifiable. When the issuer marks a
\* row's ws_sig with key_source = KS_ORPHAN (fingerprint not in
\* published key set) and a Sigstore bundle is also present and
\* validly bound to the results, the verifier MUST still produce
\* VERIFIED via the bundle path. The orphan ws_sig's validity is
\* not consulted (mirrors V1's logic, but for the orphan case).
V2_OrphanWithBundleVerified ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_ORPHAN
     /\ pkg.bundle # ABSENT
     /\ pkg.bundle.valid
     /\ pkg.results_hash # NONE
     /\ pkg.bundle.bound_hash = pkg.results_hash
     /\ pkg.results_hash = pkg.results_canonical_hash
     /\ pins.san = NONE
     /\ pins.issuer_explicit = NONE
     /\ pins.workspace_fp = NONE
     /\ pins.model_id = NONE
     /\ pins.commit_sha = NONE)
    => Audit(pkg, pins) = "VERIFIED"

\* V3 — Orphan + workspace pin = FAILED. When the issuer marks a
\* row's ws_sig with key_source = KS_ORPHAN, a workspace_fp pin
\* CANNOT be satisfied (the row's signing_key_fp is by definition
\* not in the issuer's published key set, and the pin is checked
\* against a fingerprint the verifier expects to find in that set).
\* The audit MUST FAIL. Generalises I2 (workspace pin requires
\* ws_sig present) to also reject ws_sig present-but-orphan when
\* the pin's intent (workspace-keyed submission) cannot be served.
V3_OrphanWithWorkspacePinFails ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_ORPHAN
     /\ pkg.ws_sig.signing_key_fp # pins.workspace_fp
     /\ pins.workspace_fp # NONE
     /\ pins.san = NONE
     /\ pins.model_id = NONE
     /\ pins.commit_sha = NONE)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

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
    /\ V1_SigstoreSkipSoundness
    /\ V2_OrphanWithBundleVerified
    /\ V3_OrphanWithWorkspacePinFails

(***************************************************************************)
(* Type invariant: every reachable state has well-typed pkg and pins.      *)
(***************************************************************************)
TypeOK ==
    /\ pkg \in Package
    /\ pins \in Pins

====
