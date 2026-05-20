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
    KS_CUSTOMER_DSSE,      \* customer-keyed offline DSSE attestation. The
                           \* customer-signed in-toto Statement (verified
                           \* offline against an out-of-band-pinned
                           \* fingerprint) is the trust anchor; the
                           \* envelope ws_sig is NOT re-evaluated — same
                           \* trust-anchor class as KS_SIGSTORE. See
                           \* KeySourceResolver.tla (KSCustomerDsse / R12)
                           \* for the issuer-side contract.
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

KeySources == {KS_SIGSTORE, KS_PLATFORM, KS_WORKSPACE, KS_CUSTOMER_DSSE,
               KS_ORPHAN, KS_LEGACY}

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
    key_source     : KeySources,
    \* --- KS_CUSTOMER_DSSE fields ---------------------------------
    \* The customer-keyed offline DSSE path has NO Sigstore bundle by
    \* construction (it exists precisely for air-gapped / non-Sigstore
    \* CI). The customer-signed in-toto Statement carried in the
    \* envelope's content_integrity.dsse_bundle is the trust anchor;
    \* the auditor binds it out-of-band via --expected-customer-key.
    \* These fields model the Statement + the auditor's customer-key
    \* fingerprint pin so the spec can state the pinned property
    \* positively. They are observable ONLY when
    \* key_source = KS_CUSTOMER_DSSE; for every other key_source they
    \* are pinned to canonical sentinels in InitBase (dead fields, no
    \* enumeration cost).
    \*
    \* dsse_predicate_model_id / dsse_predicate_commit_sha: the
    \* model_id / commit_sha signed inside the customer's DSSE
    \* predicate. The verifier cross-checks --expected-model-id /
    \* --expected-commit-sha against THESE (cli.py customer_dsse
    \* branch), not against a Sigstore bundle predicate.
    dsse_predicate_model_id   : ModelIds \cup {NONE},
    dsse_predicate_commit_sha : CommitShas \cup {NONE},
    \* customer_key_fp_match: did the key that actually signed the DSSE
    \* bundle (recomputed SHA-256 DER-SPKI fingerprint) equal the
    \* auditor's out-of-band --expected-customer-key fingerprint?
    \* This is step 3 of verify_customer_dsse_bundle — THE
    \* vendor-independence gate and the sole identity binding for this
    \* key_source. The CLI fails closed when --expected-customer-key
    \* is absent, so a customer_dsse row is always evaluated against
    \* this pin; FALSE models a swapped / vendor-substituted key.
    customer_key_fp_match     : BOOLEAN
]

\* bundle_bind_signature outcomes — the verifier-side resolution and
\* signature check, modeled as a discriminated outcome rather than a
\* single BOOLEAN. The previous BOOLEAN form's comment claimed the
\* platform public key was "already embedded in the envelope"; that
\* precondition was asserted by the abstraction rather than checked,
\* and conflated two distinct verifier code paths into one bit:
\*
\*   1. signature was checked against a resolved key, ECDSA failed;
\*   2. signature could not be checked because no key was resolvable.
\*
\* Both produced the same FAILED verdict, but the second path is real
\* in production for envelope rows whose embedded public_key_pem is
\* intentionally empty (e.g. Sigstore key-source rows whose trust
\* anchor is the bundle, not an envelope-resident PEM). The verifier
\* now resolves the platform key from up to three sources, in order:
\* an explicit auditor-supplied --platform-pubkey; the platform key
\* already resolved by the PDF outer-signature path; the envelope's
\* own public_key_pem. KEY_UNRESOLVABLE captures the case where none
\* of the three apply — the signature is present but the verifier
\* has no key to evaluate it against, and FAILS rather than silently
\* skipping the check.
BundleBindSigOutcomes == {"VALID", "INVALID", "KEY_UNRESOLVABLE"}

Package == [
    bundle                 : (Bundle \cup {ABSENT}),
    ws_sig                 : (WSSig \cup {ABSENT}),
    results_hash           : (Hashes \cup {NONE}),
    results_canonical_hash : Hashes,
    \* bundle_bind_hash: the explicit envelope-level hash the verifier
    \* compares to bundle.bound_hash (the bundle's in-toto Subject
    \* digest). The verifier does NOT canonicalise or rehash either
    \* side; equality is checked directly. NONE means the envelope
    \* omitted the field — accepted only when the envelope carries no
    \* bundle (post-cutover envelopes always pair the two).
    \*
    \* bundle_bind_signature: discriminated outcome of the verifier's
    \* bundle-bind-signature check (VALID / INVALID / KEY_UNRESOLVABLE)
    \* or NONE when the envelope omitted the signature entirely. See
    \* BundleBindSigOutcomes above for the meaning of each value.
    bundle_bind_hash       : (Hashes \cup {NONE}),
    bundle_bind_signature  : (BundleBindSigOutcomes \cup {NONE})
]

\* ---- Generation-time customer_dsse pruning for Config 2 -----------
\* PackageGen(gen) is the set TLC ENUMERATES at Init. With gen = TRUE
\* it is exactly `Package` (Config 1 / audit.cfg — byte-equivalent,
\* customer_dsse fully generated). With gen = FALSE (Config 2) the
\* WSSig generator drops KS_CUSTOMER_DSSE from `key_source` and pins
\* the three customer_dsse-ONLY fields to their canonical sentinels —
\* so TLC's `\in` enumerator generates ~18x fewer WSSig records
\* (3 * 3 * 2 collapsed to 1 * 1 * 1, KeySources 6 -> 5). This is a
\* genuine generation-domain restriction (membership in a smaller
\* set), NOT a post-`\in` filter — TLC never materialises the
\* customer_dsse sub-product.
\*
\* Lossless (COMPOSITION.md "Config-2 customer_dsse exclusion"):
\* every invariant Config 2 checks (I8/I14/V1/V2/V4, + TypeOK)
\* requires pkg.bundle # ABSENT in its premise, and a customer_dsse
\* row has bundle = ABSENT (KeySourceResolver R12, imported in
\* InitBase), so every dropped customer_dsse state is vacuously-true
\* for all Config-2 invariants and contributes zero coverage. The
\* dropped customer_dsse-only field values are likewise unobserved on
\* the surviving non-customer_dsse rows (the pre-existing InitBase
\* dead-field pin already canonicalises them there). Config 1
\* (Init_main) uses gen = TRUE and keeps customer_dsse — V5a/V5b/V5c
\* live in its partition and need it.
\* Set-parameterized row generators. Take an explicit set of allowed
\* `key_source` values so each Config-1 sub-config (audit_main_*.cfg)
\* can pin enumeration to its own key_source class — the bulk of the
\* Config-1 sub-split speedup. customer_dsse-specific fields are
\* dead-field-pinned when KS_CUSTOMER_DSSE is excluded from
\* allowedKS, identical semantics to the legacy boolean form's
\* pinning when gen=FALSE.
WSSigGenFor(allowedKS) ==
    [ signing_key_fp : Fingerprints,
      claimed_fp     : Fingerprints \cup {NONE},
      message_hash   : Hashes,
      valid          : BOOLEAN,
      key_source     : allowedKS,
      dsse_predicate_model_id   : IF KS_CUSTOMER_DSSE \in allowedKS
                                  THEN ModelIds \cup {NONE}
                                  ELSE {NONE},
      dsse_predicate_commit_sha : IF KS_CUSTOMER_DSSE \in allowedKS
                                  THEN CommitShas \cup {NONE}
                                  ELSE {NONE},
      customer_key_fp_match     : IF KS_CUSTOMER_DSSE \in allowedKS
                                  THEN BOOLEAN
                                  ELSE {TRUE} ]

PackageGenFor(allowedKS) ==
    [ bundle                 : (Bundle \cup {ABSENT}),
      ws_sig                 : (WSSigGenFor(allowedKS) \cup {ABSENT}),
      results_hash           : (Hashes \cup {NONE}),
      results_canonical_hash : Hashes,
      bundle_bind_hash       : (Hashes \cup {NONE}),
      bundle_bind_signature  : (BundleBindSigOutcomes \cup {NONE}) ]

\* Legacy boolean wrappers — preserved byte-equivalently so Init /
\* Init_bind callers continue to work unchanged. gen=TRUE → all 6
\* key_source values; gen=FALSE → all except KS_CUSTOMER_DSSE.
WSSigGen(gen) ==
    WSSigGenFor(IF gen THEN KeySources ELSE KeySources \ {KS_CUSTOMER_DSSE})

PackageGen(gen) ==
    PackageGenFor(IF gen THEN KeySources ELSE KeySources \ {KS_CUSTOMER_DSSE})

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
(* Symmetry — TLC state-space reduction.                                   *)
(*                                                                         *)
(* The invariants are *structural*: they reference fingerprints, hashes,   *)
(* model_ids and commit_shas by relationships ("matches", "differs"),      *)
(* never by name. So any permutation of the inhabitants of those finite    *)
(* sets produces a state TLC has already explored under a different        *)
(* labelling. Telling TLC that lets it quotient the state graph by these   *)
(* permutations.                                                           *)
(*                                                                         *)
(* Identities and Issuers are EXCLUDED from the symmetry set: the          *)
(* SAN_PREFIX_REGISTRY operator is asymmetric (san_gh_a maps to iss_gh,    *)
(* san_self maps to nothing), so permuting Identities or Issuers would     *)
(* produce semantically distinct states under ResolveIssuer().             *)
(*                                                                         *)
(* Precision-preserving: an invariant V holds on every reachable state    *)
(* iff it holds on every equivalence-class representative, because V is   *)
(* invariant under the same permutations.                                  *)
(***************************************************************************)
Symmetry ==
    Permutations(Hashes)
    \cup Permutations(Fingerprints)
    \cup Permutations(ModelIds)
    \cup Permutations(CommitShas)

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
(* Customer-keyed offline DSSE: key_source-aware predicate.                 *)
(*                                                                          *)
(* IsCustomerDsse(k) is TRUE iff the package's content_integrity row is     *)
(* the customer-keyed offline DSSE shape: a ws_sig present and tagged       *)
(* KS_CUSTOMER_DSSE. The real CLI routes such a row entirely through the    *)
(* offline DSSE verifier (cli.py `customer_dsse` branch +                   *)
(* customer_dsse_verifier.py):                                              *)
(*                                                                          *)
(*   - Identity is gated SOLELY by the auditor's --expected-customer-key    *)
(*     fingerprint pin (step 3 of verify_customer_dsse_bundle). The         *)
(*     Sigstore-SAN identity pins (I1/I7's SAN clauses, the SAN-match       *)
(*     branch) and the --expected-workspace-key fingerprint pin do NOT      *)
(*     gate this key_source — there is no Sigstore bundle to bind a SAN     *)
(*     to, and the customer-DSSE path never consults the workspace-key      *)
(*     pin.                                                                 *)
(*   - The predicate pins --expected-model-id / --expected-commit-sha       *)
(*     ARE enforced, but against the CUSTOMER-signed DSSE predicate         *)
(*     (the dsse_predicate fields), not a Sigstore bundle predicate.        *)
(*   - --expected-customer-key satisfies the same SAN-substitute role for   *)
(*     the SAN-less-co-pin usage error: model_id / commit_sha co-pins       *)
(*     WITHOUT a SAN are NOT a usage error for customer_dsse (cli.py        *)
(*     line ~1866), because the customer-key fingerprint pin binds          *)
(*     verification to a specific key. --expected-issuer alone IS still a   *)
(*     usage error regardless of key_source (cli.py line ~1840).            *)
(*                                                                          *)
(* The customer-DSSE path has no Sigstore bundle by construction; a         *)
(* KS_CUSTOMER_DSSE row therefore always has bundle = ABSENT. This is the   *)
(* producer contract from KeySourceResolver.tla R12 (the class fires only   *)
(* when NO valid Sigstore bundle is present and a valid customer-signed     *)
(* DSSE bundle re-verifies against the resolved fingerprint); InitBase      *)
(* imports it so the consumer spec does not explore producer-impossible     *)
(* states.                                                                  *)
(***************************************************************************)
IsCustomerDsse(k) ==
    k.ws_sig # ABSENT /\ k.ws_sig.key_source = KS_CUSTOMER_DSSE

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
    \*
    \* key_source-aware carve-out for KS_CUSTOMER_DSSE: the customer-
    \* keyed offline DSSE path binds verification to a specific key via
    \* the auditor's --expected-customer-key fingerprint pin, which is
    \* the SAN-substitute for this key_source (cli.py line ~1866). So a
    \* model_id / commit_sha co-pin WITHOUT a SAN is NOT a usage error
    \* for customer_dsse — the predicate is signed by the customer's
    \* own pinned key, so the predicate pins are meaningful. But
    \* --expected-issuer alone is STILL a usage error regardless of
    \* key_source (cli.py line ~1840: issuer needs a SAN to bind to;
    \* customer-key does not rescue a bare issuer pin).
    IF q.san = NONE /\ q.issuer_explicit # NONE
    THEN "USAGE_ERROR"

    ELSE IF q.san = NONE
       /\ (q.model_id # NONE \/ q.commit_sha # NONE)
       /\ ~IsCustomerDsse(k)
    THEN "USAGE_ERROR"

    \* I1 case: SAN pin + no Sigstore bundle = FAILED (pin-bypass-by-omission).
    \* Generalised to all bundle-binding pins: model_id and commit_sha
    \* live in the bundle's signed predicate, so omitting the bundle
    \* bypasses those pins too.
    \*
    \* key_source-aware carve-out for KS_CUSTOMER_DSSE: a customer-keyed
    \* offline DSSE envelope carries its OWN independent upstream
    \* evidence (the customer-signed in-toto Statement in
    \* content_integrity.dsse_bundle, with model_id / commit_sha in its
    \* signed predicate). The CLI exempts a dsse-bundle-bearing package
    \* from the no-Sigstore-bundle pin gate (cli.py line ~2750:
    \* `not _has_dsse`) and instead enforces the predicate pins against
    \* the customer-signed Statement in the customer_dsse branch below.
    \* So a SAN / model_id / commit_sha pin + no Sigstore bundle is NOT
    \* pin-bypass-by-omission for customer_dsse — the evidence is the
    \* DSSE bundle, not a Fulcio bundle.
    ELSE IF (q.san # NONE \/ q.model_id # NONE \/ q.commit_sha # NONE)
         /\ k.bundle = ABSENT
         /\ ~IsCustomerDsse(k)
    THEN "FAILED"

    \* I2 case: workspace pin + no content_integrity = FAILED.
    ELSE IF q.workspace_fp # NONE /\ k.ws_sig = ABSENT
    THEN "FAILED"

    \* ---- KS_CUSTOMER_DSSE terminal dispatch -----------------------
    \* The customer-keyed offline DSSE path is resolved here in full,
    \* mirroring the CLI's `customer_dsse_handled` branch which routes
    \* the row entirely through customer_dsse_verifier.py and then
    \* skips the generic content_integrity / Sigstore dispatch. By
    \* this point the SAN-less issuer-alone usage error (above) and the
    \* workspace-pin-without-ws_sig fail (I2, above) have been applied;
    \* the I1 / SAN-less-co-pin branches were carved out for
    \* customer_dsse. What remains is the customer-DSSE contract:
    \*
    \*   1. Identity gate: the auditor's --expected-customer-key
    \*      fingerprint pin must match the key that signed the DSSE
    \*      bundle (verify_customer_dsse_bundle step 3 — the
    \*      vendor-independence gate). Mismatch ⇒ FAILED. This is the
    \*      SOLE identity binding for this key_source; the Sigstore-SAN
    \*      pins and the workspace-fp pin do NOT gate it.
    \*   2. Predicate pins: --expected-model-id / --expected-commit-sha
    \*      are cross-checked against the CUSTOMER-signed DSSE
    \*      predicate (dsse_predicate_*), not a Sigstore bundle.
    \*      Mismatch ⇒ FAILED.
    \*   3. Otherwise, with the offline-verified customer-signed
    \*      Statement as the trust anchor and the canonical content
    \*      hash intact, the row is VERIFIED. The key_source-independent
    \*      results_hash canonical-hash check still applies (a tampered
    \*      results_hash ⇒ FAILED) — it is enforced uniformly further
    \*      below, so customer_dsse falls through to it rather than
    \*      short-circuiting VERIFIED here.
    ELSE IF IsCustomerDsse(k) /\ ~k.ws_sig.customer_key_fp_match
    THEN "FAILED"

    ELSE IF IsCustomerDsse(k) /\ q.model_id # NONE
         /\ k.ws_sig.dsse_predicate_model_id # q.model_id
    THEN "FAILED"

    ELSE IF IsCustomerDsse(k) /\ q.commit_sha # NONE
         /\ k.ws_sig.dsse_predicate_commit_sha # q.commit_sha
    THEN "FAILED"

    \* Self-hosted SAN with no resolvable issuer = FAILED.
    \* customer_dsse is exempt: there is no Sigstore bundle and the
    \* SAN pin does not gate this key_source (the customer-key
    \* fingerprint pin, checked above, is its identity binding).
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

    \* Bundle present but the envelope's explicit binding hash is
    \* missing or doesn't equal the bundle's Subject digest. The
    \* verifier reads bundle_bind_hash directly off the envelope and
    \* compares to bundle.bound_hash with no rehashing on either
    \* side; absence of bundle_bind_hash on a bundle-bearing envelope
    \* is a hard fail (older envelopes that omitted the field are
    \* not supported).
    ELSE IF k.bundle # ABSENT /\ k.bundle_bind_hash = NONE
    THEN "FAILED"

    ELSE IF k.bundle # ABSENT
         /\ k.bundle_bind_hash # NONE
         /\ k.bundle.bound_hash # k.bundle_bind_hash
    THEN "FAILED"

    \* Bundle present + bundle_bind_signature populated and either
    \* cryptographically invalid OR not evaluable because no platform
    \* public key was resolvable. The platform signature over
    \* bundle_bind_hash gives the auditor tamper-evidence on the
    \* binding claim itself; an invalid signature is a hard fail, and
    \* a present-but-unverifiable signature is also a hard fail
    \* (silent skip would let an attacker drop the bind by spoofing
    \* the empty-key state). NONE means the envelope omitted the
    \* signature — that's permitted; only present-and-non-VALID fails.
    ELSE IF k.bundle # ABSENT
         /\ k.bundle_bind_signature \in {"INVALID", "KEY_UNRESOLVABLE"}
    THEN "FAILED"

    \* Bundle present but no results_hash to bind the canonical hash
    \* check to. The issuer pairs each bundle with a results_hash for
    \* canonical-hash content-integrity; a bundle without it is a
    \* malformed / tampered envelope shape. Fail unconditionally — a
    \* workspace-ECDSA fallback path that would otherwise yield
    \* VERIFIED is not allowed when a Sigstore bundle is also in the
    \* package but cannot be verified.
    ELSE IF k.bundle # ABSENT /\ k.results_hash = NONE
    THEN "FAILED"

    \* Bundle ↔ envelope binding is checked above against the
    \* explicit bundle_bind_hash field. results_hash is independently
    \* recomputed downstream against the platform's content-integrity
    \* signature; it is not part of the bundle-bind check.

    \* Bundle present + model_id pin + bundle predicate doesn't match.
    ELSE IF k.bundle # ABSENT /\ q.model_id # NONE
         /\ k.bundle.predicate_model_id # q.model_id
    THEN "FAILED"

    \* Bundle present + commit_sha pin + bundle predicate doesn't match.
    ELSE IF k.bundle # ABSENT /\ q.commit_sha # NONE
         /\ k.bundle.predicate_commit_sha # q.commit_sha
    THEN "FAILED"

    \* Workspace sig: claimed_fp (if present) must match signing_key_fp.
    \* Skipped for KS_SIGSTORE, KS_CUSTOMER_DSSE, and KS_ORPHAN.
    \* KS_SIGSTORE: bundle is the trust anchor; ws_sig is the issuer's
    \* redundant notarization, not a customer claim. KS_CUSTOMER_DSSE:
    \* the customer-signed DSSE Statement (verified offline against the
    \* out-of-band-pinned fingerprint) is the trust anchor; the
    \* envelope ws_sig is not re-evaluated — same trust-anchor class as
    \* KS_SIGSTORE. KS_ORPHAN: the row's signing_key_fp is by
    \* definition not in the issuer's published key set; the verifier
    \* surfaces this via the UNRESOLVED branch without comparing
    \* claimed_fp / signing_key_fp metadata. The workspace_fp pin check
    \* below still catches orphan + pin (V3).
    ELSE IF k.ws_sig # ABSENT
         /\ k.ws_sig.key_source \notin
              {KS_SIGSTORE, KS_CUSTOMER_DSSE, KS_ORPHAN}
         /\ k.ws_sig.claimed_fp # NONE
         /\ k.ws_sig.claimed_fp # k.ws_sig.signing_key_fp
    THEN "FAILED"

    \* Workspace sig: --expected-workspace-key pinned against an
    \* orphan-tagged row = FAILED unconditionally, regardless of
    \* whether the envelope's claimed signing_key_fp happens to match
    \* the pin. Orphan means the verifier has no resolvable public
    \* key to verify the signature cryptographically; a metadata-
    \* level fingerprint match is not a cryptographic guarantee, so
    \* admitting it as "pin satisfied" would give the auditor a false
    \* sense of verification. The implementation's orphan branch
    \* fails uniformly on pin set; this branch keeps the spec aligned.
    ELSE IF k.ws_sig # ABSENT /\ q.workspace_fp # NONE
         /\ k.ws_sig.key_source = KS_ORPHAN
    THEN "FAILED"

    \* Workspace sig: pin requires recomputed signing_key_fp match.
    \* key_source-aware carve-out for KS_CUSTOMER_DSSE: the customer-
    \* keyed offline DSSE path never consults --expected-workspace-key
    \* (cli.py routes the row through the offline DSSE verifier whose
    \* sole identity gate is --expected-customer-key, applied above).
    \* A workspace-fp pin therefore does not gate a customer_dsse row;
    \* its identity binding is the customer-key fingerprint pin already
    \* enforced in the terminal dispatch.
    ELSE IF k.ws_sig # ABSENT /\ q.workspace_fp # NONE
         /\ k.ws_sig.key_source # KS_CUSTOMER_DSSE
         /\ k.ws_sig.signing_key_fp # q.workspace_fp
    THEN "FAILED"

    \* Workspace sig present but invalid.
    \* Skipped for KS_SIGSTORE (the bundle path is the trust anchor —
    \* the redundant ws_sig signature is not re-verified),
    \* KS_CUSTOMER_DSSE (the offline-verified customer-signed DSSE
    \* Statement is the trust anchor — the envelope ws_sig is not
    \* re-verified), and KS_ORPHAN (the row's key was not in the
    \* issuer's published set, so ws_sig.valid is "unknown" rather
    \* than "invalid"; verdict relies on bundle path or falls to
    \* UNVERIFIED).
    ELSE IF k.ws_sig # ABSENT
         /\ k.ws_sig.key_source \notin
              {KS_SIGSTORE, KS_CUSTOMER_DSSE, KS_ORPHAN}
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
\* Base shape: every (pkg, pins) tuple from the typed records, with
\* the same precision-preserving "vacuous fields when bundle absent"
\* and "dead signature when bind FAILED" pruning the original spec
\* enforced. Compositional split refines this into two narrower init
\* predicates below; each .cfg picks one Spec.
\* InitBase(genCustomerDsse) — shared init skeleton, parameterised on
\* whether customer_dsse rows are GENERATED.
\*
\*   - genCustomerDsse = TRUE  (Config 1 / audit.cfg): customer_dsse
\*     rows are generated; the R12 producer constraint and the
\*     relation-class canonicalisation apply (V5a/V5b/V5c need them).
\*   - genCustomerDsse = FALSE (Config 2 / audit_bundle_bind.cfg):
\*     customer_dsse is excluded at GENERATION time via PackageGen
\*     (FALSE): the enumerated WSSig set drops KS_CUSTOMER_DSSE and
\*     pins the three customer_dsse-only fields to singletons, so
\*     TLC's `\in` enumerator never materialises the customer_dsse
\*     sub-product (true domain restriction, not a post-filter). This
\*     is the lossless Config-2 customer_dsse exclusion
\*     (COMPOSITION.md): every invariant Config 2 checks
\*     (I8/I14/V1/V2/V4) requires pkg.bundle # ABSENT, and a
\*     customer_dsse row has bundle = ABSENT (R12), so every excluded
\*     state is vacuously-true for all Config-2 invariants.
\* Set-parameterized init — the underlying implementation. Takes an
\* explicit set of allowed `key_source` values; the per-class Config-1
\* sub-config Inits below call this with singletons / small subsets
\* to prune InitBase enumeration by key_source at generation time
\* (the bulk of the sub-split speedup). Every producer-side
\* constraint below is per-(pkg,pins)-row, so restricting allowedKS
\* simply enumerates a subset of rows — every constraint still holds
\* on each restricted row.
InitBaseFor(allowedKS) ==
    /\ pkg \in PackageGenFor(allowedKS)
    /\ pins \in Pins
    \* When the envelope carries no bundle, bundle_bind_hash and
    \* bundle_bind_signature describe the bundle-bind relationship
    \* for an absent bundle and have no observable behaviour — the
    \* Audit operator never reads them when bundle = ABSENT. Pin
    \* them to canonical "absent" sentinels so TLC does not
    \* enumerate equivalent-output duplicates.
    /\ (pkg.bundle = ABSENT
        => /\ pkg.bundle_bind_hash = NONE
           /\ pkg.bundle_bind_signature = NONE)
    \* Producer-side classification constraint (R3a in the issuer's
    \* KeySourceResolver BFS): a row whose Sigstore bundle failed
    \* trust-chain validation is NEVER classified as
    \* `key_source = KS_SIGSTORE` by the issuer — invalid bundles
    \* fall through to the next resolver step and end up as platform
    \* / workspace / orphan, never sigstore. The audit operator's
    \* type system independently allows the tuple
    \* `(bundle.valid = FALSE, ws_sig.key_source = KS_SIGSTORE)`,
    \* so without this Init pin the BFS would explore states the
    \* producer cannot emit — wasting state-space budget and
    \* obscuring real coverage. Pinning here imports the producer's
    \* constraint into the consumer-side spec; matches the
    \* end-to-end composition the deployed pipeline guarantees.
    /\ (pkg.bundle # ABSENT /\ ~pkg.bundle.valid /\ pkg.ws_sig # ABSENT
        => pkg.ws_sig.key_source # KS_SIGSTORE)
    \* When the bundle-bind branch will FAIL early — either because
    \* bundle_bind_hash is NONE (malformed envelope) or because it
    \* doesn't equal bundle.bound_hash (mismatched bind) — the
    \* Audit operator returns FAILED before evaluating the
    \* bundle_bind_signature check. The signature is dead on those
    \* states; pin it to NONE.
    /\ ((pkg.bundle # ABSENT
         /\ (\/ pkg.bundle_bind_hash = NONE
             \/ pkg.bundle.bound_hash # pkg.bundle_bind_hash))
        => pkg.bundle_bind_signature = NONE)
    \* ---- KS_CUSTOMER_DSSE producer constraints + dead-field pin ---
    \* Producer-side classification constraint (KeySourceResolver.tla
    \* R12): the issuer emits key_source = KS_CUSTOMER_DSSE ONLY when
    \* (a) no valid Sigstore bundle is present — the customer-DSSE
    \* path exists precisely for non-Sigstore CI, and Sigstore still
    \* wins by precedence — and (b) a valid customer-signed DSSE
    \* bundle re-verifies against the resolved fingerprint, so the
    \* envelope row is a well-formed signed row. Import both into the
    \* consumer spec so the BFS does not explore producer-impossible
    \* states (analogous to the R3a sigstore pin above): a
    \* customer_dsse row has bundle = ABSENT and the envelope ws_sig
    \* itself is well-formed (valid = TRUE — its validity is never
    \* re-evaluated by the verifier on this path; KeySourceResolver
    \* R12 only emits the class when the row is producer-valid).
    \* customer_key_fp_match is DELIBERATELY left free: it is the
    \* auditor's independent out-of-band --expected-customer-key pin
    \* (not a producer property), so both match (VERIFIED) and
    \* mismatch (a swapped / vendor-substituted key ⇒ FAILED) must be
    \* explored to exercise the customer-DSSE identity property
    \* non-vacuously.
    /\ (pkg.ws_sig # ABSENT /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
        => /\ pkg.bundle = ABSENT
           /\ pkg.ws_sig.valid = TRUE)
    \* Dead-field pruning: the customer-DSSE Statement fields
    \* (dsse_predicate_model_id / dsse_predicate_commit_sha) and the
    \* customer-key fingerprint-pin outcome (customer_key_fp_match)
    \* are read by the Audit operator ONLY on the KS_CUSTOMER_DSSE
    \* terminal-dispatch branch. For every other key_source (and for
    \* an absent ws_sig) they have no observable behaviour; pin them
    \* to canonical sentinels (NONE / NONE / TRUE) so TLC does not
    \* enumerate equivalent-output duplicates.
    /\ (~(pkg.ws_sig # ABSENT /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE)
        => (pkg.ws_sig = ABSENT \/
            (/\ pkg.ws_sig.dsse_predicate_model_id = NONE
             /\ pkg.ws_sig.dsse_predicate_commit_sha = NONE
             /\ pkg.ws_sig.customer_key_fp_match = TRUE)))
    \* Customer-DSSE relation-class canonicalisation (generation-time
    \* twin of the AuditView reduction). A TLC `VIEW` collapses the
    \* *seen/queue* set but TLC still *generates* every raw InitBase
    \* tuple — and the customer_dsse predicate × pin cross-product is
    \* the residual generation blow-up. By the SAME faithfulness
    \* property the AuditView VIEW relies on (machine-proven by
    \* formal/check_audit_view_faithful.py): every invariant —
    \* transitively through Audit — observes dsse_predicate_model_id /
    \* dsse_predicate_commit_sha ONLY via (in)equality against
    \* pins.model_id / pins.commit_sha, so a customer_dsse row's
    \* verdict is a function of the 3-valued relation token
    \*   Rel3(dsse_predicate_*, pins.*) ∈ {q_none, match, mismatch}
    \* alone, NOT of the predicate's identity. It therefore suffices
    \* to GENERATE one canonical representative of each reachable
    \* relation class instead of the full predicate domain:
    \*   - pins.* = NONE  ⇒ relation is `q_none` for every predicate
    \*     value ⇒ pin the predicate to NONE (1 rep, was 3).
    \*   - pins.* # NONE   ⇒ only `match` (predicate = pin) and
    \*     `mismatch` are reachable; NONE is a canonical mismatch
    \*     witness (NONE # any non-NONE pin), so the predicate ranges
    \*     over {pins.*, NONE} — exactly the two classes, 2 reps
    \*     (was 3). Any other mismatch value is relation-equivalent to
    \*     the NONE witness and, by the proven faithfulness, yields an
    \*     identical verdict on every invariant — so dropping it from
    \*     *generation* is lossless, not merely dedup-equivalent.
    \* This is the standard canonical-representative InitBase pruning
    \* (same pattern as the dead-field pins above), certified lossless
    \* by the AuditView AST proof rather than asserted. The VIEW is
    \* retained: it is the formal lossless artifact under review and
    \* still collapses the residual successor/seen-set space.
    /\ (pkg.ws_sig # ABSENT /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
        => /\ (pins.model_id = NONE
               => pkg.ws_sig.dsse_predicate_model_id = NONE)
           /\ (pins.model_id # NONE
               => pkg.ws_sig.dsse_predicate_model_id
                    \in {pins.model_id, NONE})
           /\ (pins.commit_sha = NONE
               => pkg.ws_sig.dsse_predicate_commit_sha = NONE)
           /\ (pins.commit_sha # NONE
               => pkg.ws_sig.dsse_predicate_commit_sha
                    \in {pins.commit_sha, NONE}))
    \* Sigstore/bundle relation-class canonicalisation — the
    \* generation-time twin of AuditView's NEW two-sided (ELSE,
    \* bundle-present) collapse, exactly symmetric to the
    \* customer_dsse twin above but for the Sigstore *bundle*
    \* predicate. This is the residual *generation* blow-up that
    \* dominated Config 1 (~3·3·3·3 raw `bundle.predicate_* × pins.*`
    \* cross-product on every bundle-present non-customer_dsse row;
    \* TLC enumerates raw InitBase tuples single-threaded BEFORE the
    \* VIEW applies, so the seen-set collapse alone left Config 1 at
    \* ~1 h). By the SAME machine-proven faithfulness property
    \* (check_audit_view_faithful.py — `predicate_model_id` /
    \* `predicate_commit_sha` are observed ONLY via `=`/`#`/`/=`
    \* against pins.model_id / pins.commit_sha or NONE, in Audit
    \* (q ≡ pins) and I12/I13), every bundle-present row's verdict
    \* is a function of
    \*   Rel3(bundle.predicate_*, pins.*) ∈ {q_none, match, mismatch}
    \* alone, NOT of the predicate's identity — so generating one
    \* canonical representative of each reachable relation class is
    \* lossless, not merely dedup-equivalent:
    \*   - pins.* = NONE  ⇒ q_none for every predicate value ⇒ pin
    \*     the bundle predicate to NONE (1 rep, was 3).
    \*   - pins.* # NONE   ⇒ only `match` (predicate = pin) and
    \*     `mismatch` are reachable; NONE is a canonical mismatch
    \*     witness (NONE # any non-NONE pin), so the predicate ranges
    \*     over {pins.*, NONE} — exactly the two classes (2 reps,
    \*     was 3). Any other mismatch value is relation-equivalent
    \*     to the NONE witness and yields an identical verdict on
    \*     every invariant by the proven faithfulness.
    \* A customer_dsse row has bundle = ABSENT (R12), so the
    \* `pkg.bundle # ABSENT` guard excludes it — the two twins are
    \* disjoint and compose. The VIEW is retained as the formal
    \* lossless artifact; this twin only restores GENERATION
    \* tractability the VIEW cannot (it acts post-generation).
    /\ (pkg.bundle # ABSENT
        => /\ (pins.model_id = NONE
               => pkg.bundle.predicate_model_id = NONE)
           /\ (pins.model_id # NONE
               => pkg.bundle.predicate_model_id
                    \in {pins.model_id, NONE})
           /\ (pins.commit_sha = NONE
               => pkg.bundle.predicate_commit_sha = NONE)
           /\ (pins.commit_sha # NONE
               => pkg.bundle.predicate_commit_sha
                    \in {pins.commit_sha, NONE}))

\* Legacy boolean wrapper. Preserves the original InitBase(genCustomerDsse)
\* API byte-equivalently so Init / Init_bind (which call InitBase(TRUE)
\* / InitBase(FALSE)) continue to work unchanged. New per-class
\* Config-1 sub-config Inits below call InitBaseFor directly.
InitBase(genCustomerDsse) ==
    InitBaseFor(IF genCustomerDsse THEN KeySources
                                   ELSE KeySources \ {KS_CUSTOMER_DSSE})

\* Init_bind — init for audit_bundle_bind.cfg, the **Config 2** half
\* of the compositional split (bundle_bind cross-product explored, vs
\* Config 1's bundle_bind-pinned half realized as the 5 per-key_source
\* sub-configs audit_main_*.cfg). "Config 2" is a conceptual label for
\* the bundle_bind-explored partition, not a sibling cfg filename.
\*
\* Full bundle_bind cross-product preserved (this is what Config 2
\* exists to verify) and full ws_sig variation preserved (V1/V2
\* preconditions require ws_sig present with specific key_source
\* values). Pins are pinned to NONE since V1/V2's premises require
\* all pins NONE, and I8/I14 are independent of pins.
\*
\* Lossless customer_dsse exclusion (see formal/COMPOSITION.md
\* "Config-2 customer_dsse exclusion"). Every invariant Config 2
\* checks — I8, I14, V1, V2, V4 (and TypeOK) — has a premise conjunct
\* requiring `pkg.bundle # ABSENT`. A customer_dsse row has
\* `pkg.bundle = ABSENT` (KeySourceResolver R12 producer constraint,
\* imported in InitBase lines ~601-603), so on every customer_dsse
\* state all five Config-2 invariant premises are vacuously false and
\* the invariants hold trivially — customer_dsse states contribute
\* zero coverage to Config 2. None of I8/I14/V1/V2/V4 reference
\* KS_CUSTOMER_DSSE / dsse_predicate_* / customer_key_fp_match /
\* IsCustomerDsse in their own bodies (only the shared, invariant-
\* agnostic Audit/WSSig/KeySources infrastructure does). Excluding
\* customer_dsse rows from generation is therefore lossless for
\* Config 2 — it drops only states on which every checked invariant
\* is vacuously true — and collapses Config 2 back to its
\* pre-customer_dsse magnitude. Config 1 (Init_main) legitimately
\* keeps customer_dsse: V5a/V5b/V5c live in its partition and need it.
\*
\* The exclusion is enforced at *generation* time, not as a
\* post-filter. InitBase(FALSE) enumerates `pkg \in PackageGen(FALSE)`
\* (defined next to Package), whose WSSig generator already DROPS
\* KS_CUSTOMER_DSSE from `key_source` and pins the three
\* customer_dsse-only fields to singletons — so TLC's `\in`
\* enumerator generates ~18x fewer WSSig records and never
\* materialises the customer_dsse sub-product. A bare conjunctive
\* `key_source # KS_CUSTOMER_DSSE` AFTER an unparameterised
\* `pkg \in Package` would NOT prune generation (TLC still iterates
\* the full record product, then discards) — empirically the
\* init-generation blow-up the AuditView / InitBase-canon work
\* documents. PackageGen(FALSE) ⊆ Package, so TypeOK still holds on
\* every Config-2 state. Measured: Config 2 completes in ~3.5 min /
\* 142,743 distinct states (was multi-hour / non-terminating).
Init_bind ==
    /\ InitBase(FALSE)
    /\ pins.san = NONE
    /\ pins.issuer_explicit = NONE
    /\ pins.workspace_fp = NONE
    /\ pins.model_id = NONE
    /\ pins.commit_sha = NONE

Next == UNCHANGED vars

\* Spec_bind — selected by audit_bundle_bind.cfg's SPECIFICATION.
\* Config-1's Spec_main_<class> operators are defined below in the
\* per-key_source sub-split block.
Spec_bind == Init_bind /\ [][Next]_vars

(*--------------------------------------------------------------------*)
(* Config 1 per-key_source sub-split — Init / Spec operators.        *)
(*                                                                    *)
(* Splits the original Init_main key_source enumeration (all 6 KS    *)
(* values) into per-class sub-configs whose union covers KeySources  *)
(* exactly once. Because every invariant in ConfigMainInvariants is  *)
(* a per-(pkg, pins)-row predicate and key_source is a property of  *)
(* the row, partitioning by pkg.ws_sig.key_source is lossless by    *)
(* construction: every row is enumerated in exactly one sub-config, *)
(* every invariant whose premise can fire on a row's class is       *)
(* checked there, and invariants whose premise excludes a class are *)
(* vacuously true on that sub-config's states.                      *)
(*                                                                    *)
(* Bundle-bind pinning is preserved (matching, valid representative *)
(* — same as Init_main) so each sub-config exercises the same       *)
(* bundle_bind-pinned slice of the original Config-1 space. Each    *)
(* sub-config also inherits the orphan/legacy slot of the partition *)
(* where appropriate.                                                *)
(*                                                                    *)
(* See formal/COMPOSITION.md for the per-invariant × per-sub-config *)
(* coverage matrix and the totality proof                            *)
(* (formal/check_audit_partition_total.py).                          *)
(*--------------------------------------------------------------------*)

Init_main_sigstore ==
    /\ InitBaseFor({KS_SIGSTORE})
    /\ (pkg.bundle # ABSENT
        => /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
           /\ pkg.bundle_bind_signature = "VALID")

Init_main_platform ==
    /\ InitBaseFor({KS_PLATFORM})
    /\ (pkg.bundle # ABSENT
        => /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
           /\ pkg.bundle_bind_signature = "VALID")

Init_main_workspace ==
    /\ InitBaseFor({KS_WORKSPACE})
    /\ (pkg.bundle # ABSENT
        => /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
           /\ pkg.bundle_bind_signature = "VALID")

Init_main_cdsse ==
    /\ InitBaseFor({KS_CUSTOMER_DSSE})
    /\ (pkg.bundle # ABSENT
        => /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
           /\ pkg.bundle_bind_signature = "VALID")

\* Orphan + legacy grouped: both are no-canonical-bundle-path terminal
\* classes (per KeySourceResolver) and share invariant structure
\* (V3 fires on orphan-with-workspace-pin; legacy keeps the
\* pre-discriminator universe). Combined here so the 5 sub-configs
\* (vs 6 individual) keep CI matrix fan-out modest.
Init_main_orphan_legacy ==
    /\ InitBaseFor({KS_ORPHAN, KS_LEGACY})
    /\ (pkg.bundle # ABSENT
        => /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
           /\ pkg.bundle_bind_signature = "VALID")

Spec_main_sigstore       == Init_main_sigstore       /\ [][Next]_vars
Spec_main_platform       == Init_main_platform       /\ [][Next]_vars
Spec_main_workspace      == Init_main_workspace      /\ [][Next]_vars
Spec_main_cdsse          == Init_main_cdsse          /\ [][Next]_vars
Spec_main_orphan_legacy  == Init_main_orphan_legacy  /\ [][Next]_vars

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
\*
\* key_source scoping: this invariant governs the key_sources whose
\* pinned material lives in a SIGSTORE bundle (sigstore / platform /
\* workspace / orphan / legacy). KS_CUSTOMER_DSSE is excluded — it
\* carries its OWN upstream evidence (the customer-signed in-toto
\* Statement) and has no Sigstore bundle by construction, so
\* "omitting the bundle" is not pin-bypass for that key_source. The
\* corresponding positive property for customer_dsse — that its
\* identity binding is the --expected-customer-key fingerprint pin,
\* not a SAN / predicate-without-key pin — is stated by V5a/V5b. The
\* exclusion is additive: I1's strength on every key_source it
\* governed before is unchanged.
I1_SanPinIsBinding ==
    ((pins.san # NONE \/ pins.model_id # NONE \/ pins.commit_sha # NONE)
     /\ pkg.bundle = ABSENT
     /\ ~(pkg.ws_sig # ABSENT
          /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE))
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
\*
\* key_source scoping: --expected-workspace-key governs the ECDSA
\* workspace-signature path (platform / workspace / legacy) and the
\* orphan case (V3). KS_CUSTOMER_DSSE is excluded — the customer-DSSE
\* CLI path never consults --expected-workspace-key; its identity
\* binding is the --expected-customer-key fingerprint pin (V5a/V5b).
\* Pinning workspace_fp on a customer_dsse row is a no-op for that
\* pin, not a forged-key signal, so the FAILED conclusion does not
\* apply. The exclusion is additive: I4's strength on every
\* key_source it governed before is unchanged.
I4_WorkspaceFpBound ==
    (pins.workspace_fp # NONE
     /\ pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source # KS_CUSTOMER_DSSE
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
\*
\* key_source scoping for the predicate co-pins: --expected-model-id
\* / --expected-commit-sha without a SAN pin is a usage error for
\* the Sigstore-bundle key_sources, but NOT for KS_CUSTOMER_DSSE —
\* --expected-customer-key is the SAN-substitute for the customer-
\* keyed offline DSSE path (cli.py line ~1866): the predicate is
\* signed by the customer's own pinned key, so the predicate pins
\* ARE meaningful there. The issuer-explicit-alone clause stays
\* key_source-UNCONDITIONAL: --expected-issuer needs a SAN to bind
\* to regardless of key_source (cli.py line ~1840), so a bare issuer
\* pin is a usage error even for customer_dsse. V5b states the
\* corresponding positive property (customer_dsse with matched
\* predicate pins and a matched customer key VERIFIES). The scoping
\* is additive: I7's strength on every key_source it governed before
\* is unchanged for the issuer clause, and unchanged for the
\* predicate clause on every key_source except the one the CLI
\* explicitly carves out.
I7_SanRequiredForCoPins ==
    (pins.san = NONE
     /\ (pins.issuer_explicit # NONE
         \/ ((pins.model_id # NONE \/ pins.commit_sha # NONE)
             /\ ~(pkg.ws_sig # ABSENT
                  /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE))))
    => Audit(pkg, pins) = "USAGE_ERROR"

\* I8 — bundle present + positive verdict ⇒ bundle's bound_hash
\* equals the explicit envelope bundle_bind_hash field. results_hash
\* is independently recomputed downstream against the platform's
\* content-integrity signature; it is not part of the bundle-bind
\* check. A malformed envelope where a bundle is present without a
\* bundle_bind_hash is unconditionally FAILED by the Audit operator.
I8_BundleBoundToBundleBindHash ==
    (Audit(pkg, pins) \in {"VERIFIED", "PARTIALLY_VERIFIED"}
     /\ pkg.bundle # ABSENT)
    => /\ pkg.bundle_bind_hash # NONE
       /\ pkg.bundle.bound_hash = pkg.bundle_bind_hash

\* I9 — VERIFIED requires every present signature to verify, not just
\* one. I5 alone is too weak: it allows VERIFIED when ANY signature
\* is valid, even if a co-located other signature is invalid. The
\* implementation correctly fails when any present signature fails;
\* I9 captures that property explicitly.
\*
\* Refined for the key_source discriminator: when the issuer marks
\* a ws_sig as KS_SIGSTORE (its validity is redundant — Sigstore is
\* the trust anchor), KS_CUSTOMER_DSSE (the offline-verified
\* customer-signed DSSE Statement is the trust anchor — same
\* trust-anchor class as KS_SIGSTORE), or KS_ORPHAN (its validity is
\* not decidable — the key is not in the issuer's published set),
\* ws_sig.valid is not part of the VERIFIED preconditions. For
\* KS_PLATFORM, KS_WORKSPACE, and KS_LEGACY (older envelopes),
\* ws_sig.valid IS required as before — preserving the original
\* property's strength on every input shape it covered before.
I9_AllPresentSignaturesValid ==
    (Audit(pkg, pins) = "VERIFIED")
    => /\ (pkg.bundle = ABSENT \/ pkg.bundle.valid)
       /\ (pkg.ws_sig = ABSENT
           \/ pkg.ws_sig.key_source = KS_SIGSTORE
           \/ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
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

\* I14 — VERIFIED with bundle present implies the envelope's explicit
\* bundle_bind_hash is populated AND equals the bundle's in-toto
\* Subject digest (bundle.bound_hash). When bundle_bind_signature is
\* present, it must be valid. The verifier compares both values
\* directly with no canonicalisation, no rehashing — the contract is
\* "envelope says X, bundle was signed over X." Defends against:
\*   - issuer-side regressions where the binding value is computed
\*     differently on signing vs verifying sides;
\*   - silent acceptance of a bundle whose Subject digest doesn't
\*     match anything the envelope explicitly commits to;
\*   - tampered bundle_bind_hash (caught by signature check when the
\*     issuer populated bundle_bind_signature).
I14_BundleBindExplicit ==
    (Audit(pkg, pins) = "VERIFIED"
     /\ pkg.bundle # ABSENT)
    => /\ pkg.bundle_bind_hash # NONE
       /\ pkg.bundle.bound_hash = pkg.bundle_bind_hash
       /\ pkg.bundle_bind_signature \notin {"INVALID", "KEY_UNRESOLVABLE"}

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
     /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
     /\ pkg.bundle_bind_signature \notin {"INVALID", "KEY_UNRESOLVABLE"}
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
     /\ pkg.bundle_bind_hash = pkg.bundle.bound_hash
     /\ pkg.bundle_bind_signature \notin {"INVALID", "KEY_UNRESOLVABLE"}
     /\ pkg.results_hash = pkg.results_canonical_hash
     /\ pins.san = NONE
     /\ pins.issuer_explicit = NONE
     /\ pins.workspace_fp = NONE
     /\ pins.model_id = NONE
     /\ pins.commit_sha = NONE)
    => Audit(pkg, pins) = "VERIFIED"

\* V3 — Orphan + workspace pin = FAILED, unconditionally. When the
\* issuer marks a row's ws_sig with key_source = KS_ORPHAN, the
\* verifier has no resolvable public key to verify the signature
\* against. A metadata-level fingerprint match between the
\* envelope's claimed signing_key_fp and the auditor's pin is NOT
\* a cryptographic guarantee — admitting it as "pin satisfied"
\* would let a forger set claimed_fp = customer's pinned fp without
\* actually signing with the customer's key. So the audit MUST FAIL
\* whenever the auditor pinned workspace_fp on an orphan row,
\* regardless of fingerprint match. Generalises I2 (workspace pin
\* requires ws_sig present) to also reject ws_sig present-but-
\* orphan when the pin's intent (cryptographic verification against
\* a known workspace key) cannot be served.
V3_OrphanWithWorkspacePinFails ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_ORPHAN
     /\ pins.workspace_fp # NONE
     /\ pins.san = NONE
     /\ pins.model_id = NONE
     /\ pins.commit_sha = NONE)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

\* V4 — Bundle-bind-signature key resolution must be explicit.
\*
\* When the envelope carries a bundle and the bundle-bind signature
\* is present, the verifier MUST evaluate the signature against a
\* resolved platform public key. If no key is resolvable from any
\* tier (auditor-supplied --platform-pubkey, PDF outer-signature
\* pubkey, or envelope-embedded public_key_pem), the verifier MUST
\* fail the audit rather than silently skipping the check.
\*
\* This invariant exists to close a class of bug where a previous
\* BOOLEAN abstraction of bundle_bind_signature conflated "the
\* signature failed crypto" with "the verifier had no key to check
\* against." Both produced the same FAILED verdict in Audit, but the
\* implementation could enter the second state at runtime and either
\* silently skip the check or crash with a confusing error. The
\* discriminated outcome (KEY_UNRESOLVABLE) makes the gap state
\* observable to TLC and to the BFS bridge, and pins the verifier
\* to fail-loud with a remediation message.
V4_BundleBindSigKeyResolutionExplicit ==
    (pkg.bundle # ABSENT
     /\ pkg.bundle_bind_signature = "KEY_UNRESOLVABLE")
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

\* V5 — Customer-keyed offline DSSE: the identity binding under a pin
\* is the customer-key fingerprint pin, NOT the Sigstore-SAN pin nor
\* the workspace-fp pin. This is the positive statement of the
\* property the implementation correctly enforces (cli.py
\* `customer_dsse` branch + customer_dsse_verifier.py step 3); the
\* spec must model it rather than over-constrain customer_dsse with
\* the Sigstore-identity pins it does not engage.
\*
\* V5a — --expected-customer-key pin MISMATCH must FAIL. The
\* fingerprint pin is the entire trust basis for this key_source
\* (the vendor-independence gate); a swapped / vendor-substituted
\* customer key cannot earn a positive verdict, regardless of any
\* SAN / issuer / workspace-fp / predicate pin the auditor set.
V5a_CustomerDssePinMismatchFails ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
     /\ ~pkg.ws_sig.customer_key_fp_match)
    => Audit(pkg, pins) \in {"FAILED", "USAGE_ERROR"}

\* V5b — a matching --expected-customer-key pin, a producer-valid
\* customer-signed DSSE row (R12), the canonical content hash intact,
\* and any predicate pins (model_id / commit_sha) matching the
\* customer-signed predicate ⇒ VERIFIED. Crucially, the verdict is
\* positive EVEN WHEN a Sigstore-SAN pin or a workspace-fp pin is
\* set: those pins do not gate customer_dsse, so they must neither
\* vacuously over-constrain it nor wrongly reject it. (--expected-
\* issuer alone is excluded because that is a key_source-independent
\* usage error per cli.py line ~1840.)
V5b_CustomerDsseKeyMatchVerifies ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
     /\ pkg.bundle = ABSENT
     /\ pkg.ws_sig.customer_key_fp_match
     /\ pkg.results_hash # NONE
     /\ pkg.results_hash = pkg.results_canonical_hash
     /\ ~(pins.san = NONE /\ pins.issuer_explicit # NONE)
     /\ (pins.model_id # NONE
         => pkg.ws_sig.dsse_predicate_model_id = pins.model_id)
     /\ (pins.commit_sha # NONE
         => pkg.ws_sig.dsse_predicate_commit_sha = pins.commit_sha))
    => Audit(pkg, pins) = "VERIFIED"

\* V5c — the Sigstore-identity pins (SAN, resolved issuer) do NOT
\* gate customer_dsse. Concretely: a customer_dsse row's verdict is
\* invariant under the SAN pin — substituting any SAN pin value
\* yields the same verdict as with no SAN pin. This positively states
\* that I1/I7's SAN clauses and the SAN-match branch are correctly
\* scoped out of customer_dsse (they govern only the key_sources that
\* actually carry a Sigstore bundle). The issuer-alone usage error is
\* key_source-independent, so SAN is varied with issuer_explicit held
\* at NONE to isolate the SAN dimension.
V5c_CustomerDsseSanPinDoesNotGate ==
    (pkg.ws_sig # ABSENT
     /\ pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
     /\ pins.issuer_explicit = NONE)
    => \A alt_san \in (Identities \cup {NONE}) :
         Audit(pkg, [pins EXCEPT !.san = alt_san])
           = Audit(pkg, [pins EXCEPT !.san = NONE])

\* C1 — Composition lemma for Config 1.
\*
\* Asserts that, on every state in Config 1's pinned domain, Audit's
\* verdict is INDEPENDENT of the bundle_bind dimension. Operationally:
\* substitute every alternative bundle_bind value into the state, and
\* compare Audit's verdict on the substituted state to Audit's verdict
\* on the canonical (matching) representative — they must produce the
\* same verdict for invariants Config 1 cares about.
\*
\* This is the Flavor 1 composition check: TLC mechanically verifies
\* that pinning bundle_bind to "matching, valid" in Config 1 is
\* precision-preserving for the invariants in Config 1.
\*
\* The verdict equivalence allows for one structural difference: a
\* state with bundle_bind = mismatch produces Audit = FAILED via the
\* bundle-bind branch, while the canonical-matching representative
\* may produce a positive verdict. Config 1's invariants are
\* structured as "X => positive" or "X => negative" with X
\* independent of bundle_bind, so the verdict CLASS (positive vs
\* negative) is what matters — not the exact verdict value. We
\* check class equivalence on the canonical representative against
\* the canonical representative itself (trivially equal); the
\* meaningful work is checking that the alternative substitutions
\* land in the negative class via the bundle-bind branch.
ConfigMainCompositionLemma ==
    \* Only meaningful when bundle is present; bundle-absent states
    \* have bundle_bind already pinned to NONE/NONE in InitBase.
    pkg.bundle # ABSENT =>
      \A bb_hash \in (Hashes \cup {NONE}) :
        \A bb_sig \in (BundleBindSigOutcomes \cup {NONE}) :
          LET pkg_alt == [pkg EXCEPT
                            !.bundle_bind_hash = bb_hash,
                            !.bundle_bind_signature = bb_sig]
          IN  \* Either the substituted state lands in negative
              \* class via the bundle-bind branch (proving Config 1's
              \* pinning loses no positive-class violations), OR the
              \* substituted state has the same verdict as the
              \* canonical (proving bundle_bind is dead on this
              \* state's verdict class).
              \/ Audit(pkg_alt, pins) \in {"FAILED", "USAGE_ERROR"}
              \/ Audit(pkg_alt, pins) = Audit(pkg, pins)

\* Conjunction of all invariants — the property TLC checks.
SecurityInvariants ==
    /\ I1_SanPinIsBinding
    /\ I2_WorkspacePinIsBinding
    /\ I3_IssuerNeverSelfAttested
    /\ I4_WorkspaceFpBound
    /\ I5_VerifiedImpliesEvidence
    /\ I6_ContentHashBoundToResults
    /\ I7_SanRequiredForCoPins
    /\ I8_BundleBoundToBundleBindHash
    /\ I9_AllPresentSignaturesValid
    /\ I10_UnboundBundleNotVerified
    /\ I11_BundleSanMatchesPin
    /\ I12_BundleModelIdMatchesPin
    /\ I13_BundleCommitShaMatchesPin
    /\ I14_BundleBindExplicit
    /\ V1_SigstoreSkipSoundness
    /\ V2_OrphanWithBundleVerified
    /\ V3_OrphanWithWorkspacePinFails
    /\ V4_BundleBindSigKeyResolutionExplicit
    /\ V5a_CustomerDssePinMismatchFails
    /\ V5b_CustomerDsseKeyMatchVerifies
    /\ V5c_CustomerDsseSanPinDoesNotGate

\* Config 1's invariant set: the subset of SecurityInvariants whose
\* truth value is independent of bundle_bind on the pinned-matching
\* representative. Config 1 (audit_main.cfg) checks this PLUS the
\* composition lemma that proves the bundle_bind independence.
ConfigMainInvariants ==
    /\ I1_SanPinIsBinding
    /\ I2_WorkspacePinIsBinding
    /\ I3_IssuerNeverSelfAttested
    /\ I4_WorkspaceFpBound
    /\ I5_VerifiedImpliesEvidence
    /\ I6_ContentHashBoundToResults
    /\ I7_SanRequiredForCoPins
    /\ I9_AllPresentSignaturesValid
    /\ I10_UnboundBundleNotVerified
    /\ I11_BundleSanMatchesPin
    /\ I12_BundleModelIdMatchesPin
    /\ I13_BundleCommitShaMatchesPin
    /\ V3_OrphanWithWorkspacePinFails
    \* V5a/V5b/V5c — customer_dsse pinned property. customer_dsse
    \* rows have bundle = ABSENT (R12 producer constraint imported in
    \* InitBase), so bundle_bind is pinned NONE/NONE and these
    \* invariants are bundle_bind-independent — Config 1's partition.
    \* ConfigMainCompositionLemma is vacuous on customer_dsse rows
    \* (its premise is pkg.bundle # ABSENT), so the partition
    \* argument is unaffected.
    /\ V5a_CustomerDssePinMismatchFails
    /\ V5b_CustomerDsseKeyMatchVerifies
    /\ V5c_CustomerDsseSanPinDoesNotGate
    /\ ConfigMainCompositionLemma

\* Config 2's invariant set: the bundle-bind-specific invariants
\* (I8, I14) plus the V1/V2 cases that have bundle_bind in their
\* preconditions. Config 2 (audit_bundle_bind.cfg) explores the
\* full bundle_bind cross-product with ws_sig/pins minimised.
ConfigBindInvariants ==
    /\ I8_BundleBoundToBundleBindHash
    /\ I14_BundleBindExplicit
    /\ V1_SigstoreSkipSoundness
    /\ V2_OrphanWithBundleVerified
    /\ V4_BundleBindSigKeyResolutionExplicit

(***************************************************************************)
(* Type invariant: every reachable state has well-typed pkg and pins.      *)
(***************************************************************************)
TypeOK ==
    /\ pkg \in Package
    /\ pins \in Pins

(***************************************************************************)
(* AuditView — a provably lossless TLC VIEW that collapses the             *)
(* customer_dsse-specific identity cross-product.                          *)
(*                                                                          *)
(* Problem. The customer_dsse modeling added three WSSig fields —           *)
(* `customer_key_fp_match`, `dsse_predicate_model_id`,                      *)
(* `dsse_predicate_commit_sha`. On a customer_dsse row the auditor's        *)
(* model_id / commit_sha pins are cross-checked against the                 *)
(* customer-signed DSSE predicate (the dsse_predicate_* fields), so the     *)
(* state space carries the FULL product                                     *)
(* (dsse_predicate_model_id × pins.model_id) ×                              *)
(* (dsse_predicate_commit_sha × pins.commit_sha) × customer_key_fp_match    *)
(* = 3·3 · 3·3 · 2 = 162 raw combinations on the configured constants,      *)
(* multiplied into the rest of the audit space. TLC explodes.               *)
(*                                                                          *)
(* Key observation (soundness basis). Every invariant in both .cfgs'        *)
(* INVARIANTS list — and the `Audit` operator itself — observes these       *)
(* collapsed fields ONLY through (in)equality relations, never through      *)
(* their identities:                                                        *)
(*                                                                          *)
(*   * `customer_key_fp_match` is a BOOLEAN used as a boolean (the          *)
(*     terminal-dispatch `~customer_key_fp_match ⇒ FAILED` clause;          *)
(*     V5a's `~customer_key_fp_match`; V5b's `customer_key_fp_match`).      *)
(*   * `dsse_predicate_model_id` is read ONLY as                            *)
(*     `dsse_predicate_model_id # q.model_id` (Audit's customer_dsse        *)
(*     model-id branch) and `dsse_predicate_model_id = pins.model_id`       *)
(*     (V5b). Both are equality tests against `q.model_id`, themselves      *)
(*     guarded by `q.model_id # NONE`. The verdict therefore depends only   *)
(*     on which of three classes the pair (dsse_predicate_model_id,         *)
(*     q.model_id) falls in: q_none / match / mismatch.                     *)
(*   * `dsse_predicate_commit_sha` — symmetric, same three classes.         *)
(*                                                                          *)
(* So a customer_dsse row's contribution to every invariant FACTORS         *)
(* THROUGH the tuple                                                        *)
(*   <customer_key_fp_match,                                                 *)
(*    Rel3(dsse_predicate_model_id,  q.model_id),                           *)
(*    Rel3(dsse_predicate_commit_sha, q.commit_sha)>                        *)
(* — 2·3·3 = 18 observable classes instead of 162. `check_audit_view_*`     *)
(* mechanically PROVES the "factors through" claim by an AST walk over      *)
(* the cfg invariants' operator-call graph (every collapsed-field           *)
(* reference must be inside `=` / `#` / `/=` or be a boolean-as-boolean).   *)
(*                                                                          *)
(* Two-sided Rel3 collapse (extended). The SAME factor-through        *)
(* argument holds on the NON-customer_dsse / Sigstore-bundle class.    *)
(* When `bundle # ABSENT`, the auditor's model_id / commit_sha pins    *)
(* are cross-checked against the *Sigstore bundle* predicate           *)
(* (`pkg.bundle.predicate_model_id / predicate_commit_sha`) — and      *)
(* across the Audit operator and EVERY cfg invariant those four        *)
(* quantities (the two bundle predicate fields and pins.model_id /     *)
(* pins.commit_sha) are observed ONLY through `=` / `#` / `/=`         *)
(* against each other or the NONE sentinel:                            *)
(*                                                                          *)
(*   * `bundle.predicate_model_id` is read ONLY as                     *)
(*     `bundle.predicate_model_id # q.model_id` (Audit:481-482, with   *)
(*     q ≡ pins — every cfg invocation is `Audit(pkg, pins)`) and      *)
(*     `bundle.predicate_model_id = pins.model_id` (I12). Both are     *)
(*     guarded by `pins.model_id # NONE`.                              *)
(*   * `bundle.predicate_commit_sha` — symmetric (Audit:486-487, I13). *)
(*   * `pins.model_id` / `pins.commit_sha` are otherwise observed only *)
(*     via `# NONE` / `= NONE` (I1/I7/V3 …) — a relation the Rel3      *)
(*     token's `q_none` class preserves exactly.                       *)
(*                                                                          *)
(* So a bundle-present non-customer_dsse row's contribution FACTORS    *)
(* THROUGH                                                             *)
(*   <Rel3(bundle.predicate_model_id,  pins.model_id),                 *)
(*    Rel3(bundle.predicate_commit_sha, pins.commit_sha)>              *)
(* — 9 observable classes per pair instead of the 3·3·3·3 raw          *)
(* cross-product — and the view drops those four identities and keeps  *)
(* every other field verbatim. check_audit_view_faithful.py adds       *)
(* `predicate_model_id` / `predicate_commit_sha` to the collapsed set  *)
(* and mechanically PROVES this by the SAME AST walk.                  *)
(*                                                                          *)
(* Bundle-ABSENT subcase (soundness-critical). On a non-customer_dsse  *)
(* row with `bundle = ABSENT` the view is the IDENTITY, bit-for-bit    *)
(* unchanged from the pre-extension view:                              *)
(*                                                                          *)
(*   * There is NO bundle predicate; every bundle-predicate / I12 /    *)
(*     I13 read is guarded by `bundle # ABSENT` and is vacuous.        *)
(*   * `pins.model_id` / `pins.commit_sha` are observed by the         *)
(*     surviving non-bundle pin invariants only via `# NONE` /         *)
(*     `= NONE`, but with no predicate to fold them into there is no   *)
(*     token to project onto — keeping them verbatim is the only       *)
(*     sound choice and preserves behaviour exactly.                   *)
(*   * `dsse_predicate_*` / `customer_key_fp_match` are pinned to      *)
(*     canonical dead-field sentinels for every non-customer_dsse row  *)
(*     by InitBase; the view keeps them verbatim so the proof          *)
(*     obligation is local.                                            *)
(*                                                                          *)
(* Net: AuditView now collapses the customer_dsse-specific redundancy  *)
(* (THEN branch) AND the symmetric Sigstore/bundle-predicate           *)
(* redundancy (ELSE, bundle present), and is the literal identity      *)
(* only on the bundle-ABSENT non-customer_dsse subcase. Two states     *)
(* with the same AuditView agree on every cfg invariant (the AST       *)
(* proof) ⇒ the VIEW is lossless by construction; the mutation test    *)
(* corroborates empirically.                                          *)
(***************************************************************************)

\* Three-valued relation token for an (envelope-predicate, auditor-pin)
\* pair. q = NONE means the pin is unset (the pin-guarded branches are
\* vacuous); otherwise the only thing any invariant or the Audit
\* operator observes is whether the predicate equals the pin.
Rel3(predicate_val, pin_val) ==
    IF pin_val = NONE THEN "q_none"
    ELSE IF predicate_val = pin_val THEN "match"
    ELSE "mismatch"

AuditView ==
    IF IsCustomerDsse(pkg)
    THEN \* Customer_dsse row: project the model_id / commit_sha
         \* identities to their observable 3-valued relation classes
         \* and the fp-match flag verbatim; keep EVERY other
         \* observable field of pkg/pins verbatim. `pkg.bundle` is
         \* ABSENT here (R12 / InitBase), so bundle_bind_* and the
         \* bundle record are already at canonical sentinels.
         << \* --- pkg with the two dsse predicate identities + the
            \*     two collapsed pin identities replaced by tokens ---
            [ bundle                 |-> pkg.bundle,
              results_hash           |-> pkg.results_hash,
              results_canonical_hash |-> pkg.results_canonical_hash,
              bundle_bind_hash       |-> pkg.bundle_bind_hash,
              bundle_bind_signature  |-> pkg.bundle_bind_signature,
              ws_sig_signing_key_fp  |-> pkg.ws_sig.signing_key_fp,
              ws_sig_claimed_fp      |-> pkg.ws_sig.claimed_fp,
              ws_sig_message_hash    |-> pkg.ws_sig.message_hash,
              ws_sig_valid           |-> pkg.ws_sig.valid,
              ws_sig_key_source      |-> pkg.ws_sig.key_source,
              \* collapsed: boolean kept verbatim
              customer_key_fp_match  |-> pkg.ws_sig.customer_key_fp_match,
              \* collapsed: (dsse predicate, pin) -> 3-valued token
              model_id_rel    |-> Rel3(pkg.ws_sig.dsse_predicate_model_id,
                                       pins.model_id),
              commit_sha_rel  |-> Rel3(pkg.ws_sig.dsse_predicate_commit_sha,
                                       pins.commit_sha) ],
            \* --- pins with the two collapsed identities dropped
            \*     (folded into the tokens above); the rest verbatim ---
            [ san             |-> pins.san,
              issuer_explicit |-> pins.issuer_explicit,
              workspace_fp    |-> pins.workspace_fp ] >>
    ELSE IF pkg.bundle = ABSENT
    THEN \* Non-customer_dsse AND bundle ABSENT (incl. ws_sig = ABSENT).
         \* No bundle predicate exists; every bundle-predicate /
         \* I12 / I13 read is guarded by `bundle # ABSENT` and is
         \* vacuous here. pins.model_id / pins.commit_sha are observed
         \* by the surviving non-bundle pin invariants ONLY via
         \* `# NONE` / `= NONE` — but with no predicate to fold them
         \* into, keep the state verbatim: the IDENTITY, bit-for-bit
         \* unchanged from the pre-extension view on this subcase.
         << pkg, pins >>
    ELSE \* Non-customer_dsse AND bundle PRESENT: the Sigstore /
         \* bundle class. Symmetric to the customer_dsse THEN branch,
         \* but the predicate lives in `pkg.bundle` (not ws_sig).
         \*
         \* Soundness basis (machine-proven by
         \* formal/check_audit_view_faithful.py, F1): across the Audit
         \* operator and EVERY cfg invariant (transitively through the
         \* full operator-call graph) the four quantities
         \*   pkg.bundle.predicate_model_id / predicate_commit_sha and
         \*   pins.model_id / pins.commit_sha
         \* are observed ONLY through `=` / `#` / `/=` against each
         \* other or the NONE sentinel — Audit:481-482/486-487
         \* (`bundle.predicate_* # q.*`, q ≡ pins) and I12/I13
         \* (`bundle.predicate_* = pins.*`). Every such read is
         \* guarded by `q.* # NONE` / `pins.* # NONE`. So a
         \* bundle-present non-customer_dsse row's contribution to
         \* every invariant FACTORS THROUGH the pair
         \*   <Rel3(bundle.predicate_model_id,  pins.model_id),
         \*    Rel3(bundle.predicate_commit_sha, pins.commit_sha)>
         \* (q_none captures pin = NONE, which is the only other way
         \* these fields are observed) — 9 observable classes per
         \* field-pair instead of the 3·3·3·3 raw cross-product. The
         \* projection drops the four identities and keeps EVERY other
         \* field of pkg/bundle/pins verbatim, so any state two
         \* AuditView-equal rows could disagree on is unobservable.
         << \* --- pkg with the bundle record's two predicate
            \*     identities replaced by tokens; every other pkg /
            \*     bundle field kept verbatim ---
            [ bundle_san             |-> pkg.bundle.san,
              bundle_issuer          |-> pkg.bundle.issuer,
              bundle_bound_hash      |-> pkg.bundle.bound_hash,
              bundle_valid           |-> pkg.bundle.valid,
              results_hash           |-> pkg.results_hash,
              results_canonical_hash |-> pkg.results_canonical_hash,
              bundle_bind_hash       |-> pkg.bundle_bind_hash,
              bundle_bind_signature  |-> pkg.bundle_bind_signature,
              ws_sig                 |-> pkg.ws_sig,
              \* collapsed: (bundle predicate, pin) -> 3-valued token
              model_id_rel    |-> Rel3(pkg.bundle.predicate_model_id,
                                       pins.model_id),
              commit_sha_rel  |-> Rel3(pkg.bundle.predicate_commit_sha,
                                       pins.commit_sha) ],
            \* --- pins with the two collapsed identities dropped
            \*     (folded into the tokens above); the rest verbatim;
            \*     pkg.ws_sig kept whole (customer_dsse fields are at
            \*     canonical InitBase sentinels for non-customer_dsse
            \*     rows, so no extra collapse is needed here) ---
            [ san             |-> pins.san,
              issuer_explicit |-> pins.issuer_explicit,
              workspace_fp    |-> pins.workspace_fp ] >>

====
