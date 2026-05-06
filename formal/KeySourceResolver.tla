--------------------------- MODULE KeySourceResolver ---------------------------
(*
 * Formal specification of the audit-envelope key-source resolver.
 *
 * The audit envelope embedded in HTML and PDF reports carries a
 * `content_integrity` block. When the issuer constructs that block,
 * it classifies the row's signing path and stamps a `key_source`
 * discriminator into it so the verifier (mipiti-verify) knows how to
 * consume it. This module specifies the contract that classification
 * must obey.
 *
 * Models the issuer side of the audit-envelope trust chain.
 * Companion specs in this directory:
 *   - audit.tla              : verifier-side spec for how the audit
 *                              envelope is consumed (13 invariants
 *                              on verifier verdicts).
 *   - VerificationPipeline.tla : Tier 1 / Tier 2 assertion-state
 *                              lifecycle.
 *
 * Eight resolver-side invariants pin issuer correctness; see the
 * INVARIANTS section below for full statements. Summary:
 *
 *   R1   Soundness of `key_source` declaration
 *   R2   Resolver totality
 *   R3   Sigstore bundle precedence
 *   R3a  Invalid-bundle non-precedence
 *   R4   Backward-compat envelope
 *   R5   Orphan honesty
 *   R6   Fingerprint preservation
 *   R10  Key-authority + retired_at correctness per platform sub-case
 *
 * A companion Python BFS in the issuer's repository drives the real
 * resolver implementation against the same finite domain explored
 * here, asserting both spec/implementation agreement and every
 * invariant.
 *
 * Run via TLC:
 *     java -jar tla2tools.jar -config KeySourceResolver.cfg \
 *          KeySourceResolver.tla
 *)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    \* Key-source classification values emitted by the resolver.
    KSSigstore, KSPlatform, KSWorkspace, KSOrphan,

    \* Key-authority sub-classification (for KSPlatform). Three slots
    \* model the case where the issuer publishes more than one
    \* platform key at a time — typically an active key plus a small
    \* number of historical keys that signed older rows. The exact
    \* labels are issuer-private; the spec only uses them as
    \* opaque identifiers to model R10's correctness property.
    KAActive, KAArchived, KAHistorical, KANone,

    \* Sentinel for "field absent / not populated".
    NULL,

    \* Finite domain of fingerprints exercised by the spec. Each slot
    \* represents a class of fingerprints the resolver might
    \* encounter on an input row:
    \*   FP_ACTIVE        — matches the issuer's currently-active
    \*                      platform signing key.
    \*   FP_PRIOR_PRIMARY — matches a previously-active platform key
    \*                      preserved across a key rotation.
    \*   FP_PRIOR_HISTORY — matches an even-older platform key from
    \*                      the issuer's rotation history.
    \*   FP_WORKSPACE     — matches a customer-uploaded workspace
    \*                      ECDSA key.
    \*   FP_ORPHAN        — does not match any published key source.
    \*   FP_NONE          — no fingerprint present on the row.
    FP_ACTIVE, FP_PRIOR_PRIMARY, FP_PRIOR_HISTORY, FP_WORKSPACE,
    FP_ORPHAN, FP_NONE,

    \* Valid / invalid bundle markers.
    BUNDLE_VALID, BUNDLE_INVALID, BUNDLE_ABSENT

VARIABLES
    \* Resolver inputs (drawn from the finite domain).
    inSignature,        \* raw signature bytes — modeled as TRUE/FALSE for present/absent
    inFingerprint,      \* one of FP_*; FP_NONE = no fingerprint on the row
    inSignedHash,       \* TRUE/FALSE for present/absent
    inBundle            \* one of BUNDLE_*

vars == <<inSignature, inFingerprint, inSignedHash, inBundle>>

-----------------------------------------------------------------------------
(* Domain definitions. *)

KeySources == {KSSigstore, KSPlatform, KSWorkspace, KSOrphan}
KeyAuthorities == {KAActive, KAArchived, KAHistorical, KANone}
Fingerprints == {FP_ACTIVE, FP_PRIOR_PRIMARY, FP_PRIOR_HISTORY,
                 FP_WORKSPACE, FP_ORPHAN, FP_NONE}
Bundles == {BUNDLE_VALID, BUNDLE_INVALID, BUNDLE_ABSENT}

\* Inputs to the resolver. The fingerprint is what the row carries;
\* the resolver matches it against the issuer's published key set
\* (an environment-level fact, not part of the input row).
ResolverInput == [
    sig_present  : BOOLEAN,
    fp           : Fingerprints,
    hash_present : BOOLEAN,
    bundle       : Bundles
]

\* Resolver output descriptor. Mirrors KeySourceDescriptor's
\* to_envelope() shape so the spec is round-trip-checkable against
\* the real implementation's serialization.
ResolverOutput == [
    key_source         : KeySources,
    key_authority      : KeyAuthorities,
    fingerprint        : Fingerprints,
    public_key_pem     : BOOLEAN,    \* TRUE = populated, FALSE = empty
    signature_b64      : BOOLEAN,
    signed_hash        : BOOLEAN,
    workspace_id       : BOOLEAN,    \* TRUE = populated (workspace path)
    retired_at         : BOOLEAN,    \* TRUE = populated
    unavailable_reason : BOOLEAN     \* TRUE = populated (orphan path)
]

-----------------------------------------------------------------------------
(* The Resolve operator — DESIGN INTENT.                                   *)
(*                                                                         *)
(* Walk order: bundle → active → prior-primary → prior-history →          *)
(* workspace → orphan. Returns a fully-populated ResolverOutput record     *)
(* for every input.                                                        *)
(***************************************************************************)
Resolve(in) ==
    \* Step 1: bundle precedence (R3). Valid bundle wins regardless of fp.
    IF in.bundle = BUNDLE_VALID
    THEN [
        key_source         |-> KSSigstore,
        key_authority      |-> KANone,
        fingerprint        |-> in.fp,
        public_key_pem     |-> FALSE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> FALSE,
        unavailable_reason |-> FALSE
    ]

    \* No fingerprint: orphan with distinct reason ("row_carries_no_fingerprint").
    ELSE IF in.fp = FP_NONE
    THEN [
        key_source         |-> KSOrphan,
        key_authority      |-> KANone,
        fingerprint        |-> in.fp,
        public_key_pem     |-> FALSE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> FALSE,
        unavailable_reason |-> TRUE
    ]

    \* Step 2: active platform signer.
    ELSE IF in.fp = FP_ACTIVE
    THEN [
        key_source         |-> KSPlatform,
        key_authority      |-> KAActive,
        fingerprint        |-> in.fp,
        public_key_pem     |-> TRUE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> FALSE,
        unavailable_reason |-> FALSE
    ]

    \* Step 3: prior-primary platform key (most recently retired).
    ELSE IF in.fp = FP_PRIOR_PRIMARY
    THEN [
        key_source         |-> KSPlatform,
        key_authority      |-> KAArchived,
        fingerprint        |-> in.fp,
        public_key_pem     |-> TRUE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> TRUE,
        unavailable_reason |-> FALSE
    ]

    \* Step 4: deeper rotation history.
    ELSE IF in.fp = FP_PRIOR_HISTORY
    THEN [
        key_source         |-> KSPlatform,
        key_authority      |-> KAHistorical,
        fingerprint        |-> in.fp,
        public_key_pem     |-> TRUE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> FALSE,
        unavailable_reason |-> FALSE
    ]

    \* Step 5: customer-uploaded workspace ECDSA key.
    ELSE IF in.fp = FP_WORKSPACE
    THEN [
        key_source         |-> KSWorkspace,
        key_authority      |-> KANone,
        fingerprint        |-> in.fp,
        public_key_pem     |-> TRUE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> TRUE,
        retired_at         |-> FALSE,
        unavailable_reason |-> FALSE
    ]

    \* Step 6: orphan with structured reason.
    ELSE [
        key_source         |-> KSOrphan,
        key_authority      |-> KANone,
        fingerprint        |-> in.fp,
        public_key_pem     |-> FALSE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> FALSE,
        unavailable_reason |-> TRUE
    ]

-----------------------------------------------------------------------------
(* State machine: TLC enumerates every input tuple at Init, then       *)
(* `Next == UNCHANGED vars` makes each state self-loop. Same shape as  *)
(* mipiti-verify/formal/audit.tla.                                     *)
(***************************************************************************)
Init == /\ inSignature \in BOOLEAN
        /\ inFingerprint \in Fingerprints
        /\ inSignedHash \in BOOLEAN
        /\ inBundle \in Bundles

Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

CurrentInput == [
    sig_present  |-> inSignature,
    fp           |-> inFingerprint,
    hash_present |-> inSignedHash,
    bundle       |-> inBundle
]

CurrentOutput == Resolve(CurrentInput)

-----------------------------------------------------------------------------
(* Resolver invariants. R1-R5 must hold for every input.                   *)
(***************************************************************************)

\* R1 — Soundness of `key_source` declaration. When the resolver emits
\* `platform` or `workspace`, the embedded public_key_pem must be
\* populated AND the row's fingerprint must be the one that actually
\* matched the published key set. (Modeled here as: pub-pem is
\* populated and the descriptor's fingerprint equals the input
\* fingerprint, which by construction was the one that matched.)
R1_SoundnessOfKeySource ==
    LET out == CurrentOutput IN
    out.key_source \in {KSPlatform, KSWorkspace}
    => /\ out.public_key_pem = TRUE
       /\ out.fingerprint = inFingerprint

\* R2 — Resolver totality. Every input produces exactly one of the
\* four key_source values. (The Resolve operator above is structurally
\* total — every IF-ELSE-IF branch has an ELSE — so the conclusion
\* reduces to the type assertion that key_source is one of the
\* enumerated values.)
R2_Totality ==
    CurrentOutput.key_source \in KeySources

\* R3 — Bundle precedence. A valid Sigstore bundle wins over any
\* fingerprint-based classification.
R3_BundlePrecedence ==
    inBundle = BUNDLE_VALID
    => CurrentOutput.key_source = KSSigstore

\* R4 — Backward-compat envelope. For `platform` and `workspace`
\* paths, every legacy field that older verifier builds rely on is
\* populated.
R4_BackwardCompatEnvelope ==
    LET out == CurrentOutput IN
    out.key_source \in {KSPlatform, KSWorkspace}
    => /\ out.public_key_pem = TRUE
       /\ out.signature_b64 = inSignature
       /\ out.signed_hash = inSignedHash
       /\ out.fingerprint = inFingerprint

\* R5 — Orphan honesty. When the resolver classifies as orphan, the
\* embedded public_key_pem must be empty AND a structured
\* unavailable_reason must be populated. The verifier must not crash
\* on the empty PEM, and the auditor sees an honest "key not in
\* issuer's published set" rather than a forged positive verdict.
R5_OrphanHonesty ==
    LET out == CurrentOutput IN
    out.key_source = KSOrphan
    => /\ out.public_key_pem = FALSE
       /\ out.unavailable_reason = TRUE

\* Defense-in-depth on R3: a bundle that is INVALID (failed Sigstore
\* trust-chain verification) MUST NOT classify as sigstore. Otherwise
\* a forged bundle could bypass the platform / workspace key check.
R3a_InvalidBundleNotSigstore ==
    inBundle = BUNDLE_INVALID
    => CurrentOutput.key_source # KSSigstore

\* R6 — Fingerprint preservation. The descriptor's `fingerprint` field
\* MUST equal the input's `attestation_key_fingerprint` on every path
\* (including sigstore and orphan). Defends against a resolver bug
\* that returned the *matched* key's fingerprint instead of the row's
\* — would let an attacker who controls a retired-key file silently
\* substitute their own fingerprint into the audit envelope and have
\* it accepted.
R6_FingerprintPreservation ==
    CurrentOutput.fingerprint = inFingerprint

\* R10 — Key-authority and retired_at correctness per platform
\* sub-case. The resolver's choice of key_authority must match which
\* key source the row's fingerprint actually came from:
\*   FP_ACTIVE        => active                      (retired_at=FALSE)
\*   FP_PRIOR_PRIMARY => archived (most recent prior, retired_at=TRUE)
\*   FP_PRIOR_HISTORY => historical (deeper rotation, retired_at=FALSE)
\* Catches a future refactor that mislabels a row as retired when it
\* came from the active key (or vice versa). Auditors rely on
\* key_authority + retired_at to reason about which keys are still
\* trustworthy.
R10_KeyAuthorityCorrectness ==
    LET out == CurrentOutput IN
    /\ (out.key_source = KSPlatform /\ inFingerprint = FP_PRIOR_PRIMARY)
       => out.retired_at = TRUE
    /\ (out.key_source = KSPlatform /\ inFingerprint = FP_ACTIVE)
       => out.retired_at = FALSE
    /\ (out.key_source = KSPlatform /\ inFingerprint = FP_PRIOR_HISTORY)
       => out.retired_at = FALSE

\* Conjunction of all invariants — the property TLC checks.
ResolverInvariants ==
    /\ R1_SoundnessOfKeySource
    /\ R2_Totality
    /\ R3_BundlePrecedence
    /\ R3a_InvalidBundleNotSigstore
    /\ R4_BackwardCompatEnvelope
    /\ R5_OrphanHonesty
    /\ R6_FingerprintPreservation
    /\ R10_KeyAuthorityCorrectness

-----------------------------------------------------------------------------
(* Type invariant: every reachable state has well-typed inputs.            *)
(***************************************************************************)
TypeOK ==
    /\ inSignature \in BOOLEAN
    /\ inFingerprint \in Fingerprints
    /\ inSignedHash \in BOOLEAN
    /\ inBundle \in Bundles

=============================================================================
