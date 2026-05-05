--------------------------- MODULE KeySourceResolver ---------------------------
(*
 * Formal specification of the audit-envelope key-source resolver.
 *
 * Models `services.signing_key_resolver.resolve_key_source` — the
 * single function that, given a verification_run row's
 * (attestation_signature, attestation_key_fingerprint,
 * attestation_signed_hash, attestation, workspace_repo) inputs,
 * classifies the row's signing path and produces the descriptor that
 * `assertions_service.get_audit_package` and
 * `get_verification_audit` embed in the audit envelope's
 * `content_integrity` block.
 *
 * Models the issuer side of the trust chain. Companion specs:
 *   - mipiti-verify/formal/audit.tla : verifier-side spec for how the
 *     audit envelope is consumed (13 invariants on verifier verdicts).
 *   - mipiti-verify/formal/VerificationPipeline.tla : Tier 1 / Tier 2
 *     assertion-state lifecycle.
 *
 * Five resolver-side invariants pin issuer correctness:
 *
 *   R1 (Soundness of `key_source` declaration) — when the resolver
 *      emits `key_source = "platform" | "workspace"`, the embedded
 *      public_key_pem's fingerprint must equal the row's
 *      `attestation_key_fingerprint`. The verifier recomputes this
 *      and rejects mismatches; the issuer must not produce them.
 *
 *   R2 (Resolver totality + uniqueness) — for every input tuple,
 *      exactly one `key_source` value is emitted. No fall-through
 *      gaps, no double-classification.
 *
 *   R3 (Bundle precedence) — when the row carries a valid Sigstore
 *      bundle, `key_source = "sigstore"` regardless of fingerprint
 *      resolution against the platform / workspace key sets. The
 *      bundle is the publicly-verifiable transparency-log path; it
 *      beats any server-side key lookup.
 *
 *   R4 (Backward-compat envelope) — for `key_source IN {"platform",
 *      "workspace"}`, the legacy fields (public_key_pem, signature,
 *      key_fingerprint, signed_hash) are populated so older
 *      mipiti-verify builds (without `key_source` awareness)
 *      continue to verify unchanged.
 *
 *   R5 (Orphan honesty) — `key_source = "unverifiable_orphan"`
 *      implies public_key_pem is empty AND unavailable_reason is
 *      populated with a public-safe enum value. The verifier must
 *      not crash on the empty PEM, and the auditor sees an honest
 *      "key not in issuer's published set" rather than a forged
 *      green verdict.
 *
 * The companion Python checker (check_key_source_resolver.py)
 * verifies that the real resolve_key_source() function matches this
 * spec for every input in the finite domain.
 *
 * Run via TLC:
 *     java -jar tla2tools.jar -config KeySourceResolver.cfg \
 *          KeySourceResolver.tla
 *
 * Run via Python (also cross-checks against the real implementation):
 *     python formal/check_key_source_resolver.py
 *)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    \* Key-source classification values emitted by the resolver.
    KSSigstore, KSPlatform, KSWorkspace, KSOrphan,

    \* Key-authority sub-classification (for KSPlatform).
    KAActive, KALegacyLocal, KALegacyRetired, KANone,

    \* Sentinel for "field absent / not populated".
    NULL,

    \* Finite domain of fingerprints; one per key source plus an
    \* orphan that matches none.
    FP_ACTIVE, FP_LEGACY_CARRY, FP_RETIRED_DIR, FP_WORKSPACE,
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
KeyAuthorities == {KAActive, KALegacyLocal, KALegacyRetired, KANone}
Fingerprints == {FP_ACTIVE, FP_LEGACY_CARRY, FP_RETIRED_DIR,
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
(* Walk order matches services/signing_key_resolver.py. Returns a          *)
(* fully-populated ResolverOutput record for every input.                  *)
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

    \* Step 3: KMS-cutover legacy carry-forward.
    ELSE IF in.fp = FP_LEGACY_CARRY
    THEN [
        key_source         |-> KSPlatform,
        key_authority      |-> KALegacyLocal,
        fingerprint        |-> in.fp,
        public_key_pem     |-> TRUE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> TRUE,
        unavailable_reason |-> FALSE
    ]

    \* Step 4: on-disk retired-keys directory.
    ELSE IF in.fp = FP_RETIRED_DIR
    THEN [
        key_source         |-> KSPlatform,
        key_authority      |-> KALegacyRetired,
        fingerprint        |-> in.fp,
        public_key_pem     |-> TRUE,
        signature_b64      |-> in.sig_present,
        signed_hash        |-> in.hash_present,
        workspace_id       |-> FALSE,
        retired_at         |-> FALSE,
        unavailable_reason |-> FALSE
    ]

    \* Step 5: per-org workspace_verification_keys.
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
\*   FP_ACTIVE        => active key                  (retired_at=FALSE)
\*   FP_LEGACY_CARRY  => legacy-local-pem carry-fwd  (retired_at=TRUE)
\*   FP_RETIRED_DIR   => legacy-retired-pem (history)(retired_at=FALSE)
\* Catches a future refactor that mislabels a row as retired when it
\* came from the active key (or vice versa) — auditors rely on
\* key_authority + retired_at to reason about which keys are still
\* trustworthy.
R10_KeyAuthorityCorrectness ==
    LET out == CurrentOutput IN
    /\ (out.key_source = KSPlatform /\ inFingerprint = FP_LEGACY_CARRY)
       => out.retired_at = TRUE
    /\ (out.key_source = KSPlatform /\ inFingerprint = FP_ACTIVE)
       => out.retired_at = FALSE
    /\ (out.key_source = KSPlatform /\ inFingerprint = FP_RETIRED_DIR)
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
