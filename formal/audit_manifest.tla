--------------------------- MODULE audit_manifest ---------------------------
(*
 * Formal specification of the audit-pack manifest signature path
 * (Option β; see docs/audit-pack-signing.md in the parent repo).
 *
 * The legacy inline ECDSA signature in `content_integrity` covered
 * exactly one hash: `results_hash = sha256(canonical_json(
 * verification_run.results))`. The rest of the pack body (model
 * definition, controls, assumptions, assertions, composition section)
 * was not signature-bound — a party with write access to the pack
 * between issuer-signing and auditor-receipt could substitute any
 * non-results section without breaking the inline signature.
 *
 * The manifest path closes that gap. `content_integrity` now carries:
 *
 *   manifest                : { sections : section_name -> hash }
 *   manifest_hash           : sha256(canonical_json(manifest))
 *   manifest_signature      : ECDSA(manifest_hash) signed by the
 *                             platform / workspace key
 *   manifest_key_fingerprint: fingerprint of the signing key
 *
 * The verifier:
 *   1. Recomputes the canonical hash of the manifest object and
 *      compares to `manifest_hash`.
 *   2. Recomputes the fingerprint of the embedded public key and
 *      compares to `manifest_key_fingerprint`.
 *   3. Verifies the ECDSA signature over `manifest_hash` bytes using
 *      the public key.
 *   4. For each section in the manifest, recomputes the section's
 *      canonical hash from the pack's top-level key and compares
 *      to the manifest entry.
 *
 * Any single-byte tampering of a section, the manifest, the embedded
 * PEM, or the signature must reach a FAIL verdict.
 *
 * This is a separate spec module from `audit.tla` because the manifest
 * verification protocol is independent of the legacy results-hash
 * verification protocol: a pack either carries a manifest (new path)
 * or falls through to the legacy path (which `audit.tla` already
 * models). The two paths share the same key-source resolver
 * (`KeySourceResolver.tla`); they verify different scopes.
 *
 * Run via TLC:
 *     java -jar tla2tools.jar -config audit_manifest_platform.cfg \
 *          audit_manifest.tla
 *     java -jar tla2tools.jar -config audit_manifest_workspace.cfg \
 *          audit_manifest.tla
 *
 * Companion files:
 *   audit_manifest_platform.cfg  : key_source = KS_PLATFORM slice
 *   audit_manifest_workspace.cfg : key_source = KS_WORKSPACE slice
 *)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Sections,             \* finite set of section names in the pack
    Contents,             \* finite set of abstract section-content values
    Hashes,               \* finite set of abstract hash values
    Keys,                 \* finite set of signing-key identities
    Fingerprints,         \* finite set of public-key fingerprints

    \* The injective oracles below model the cryptographic primitives.
    \* They are CONSTANTS so each .cfg pins them to a concrete instance
    \* (chosen so different abstract inputs map to different abstract
    \* hashes / fingerprints — the property a real SHA-256 / KMS-signer
    \* exhibits with overwhelming probability). The spec then proves
    \* the verifier reaches FAIL on any input that violates the
    \* equality the verifier reads from the pack.
    H_CONTENT,            \* Contents -> Hashes — section content hash
    H_MANIFEST,           \* (Sections -> Hashes) -> Hashes — manifest hash
    FP_OF,                \* Keys -> Fingerprints — fingerprint of a key

    \* Key_source for the signer of the manifest signature. The
    \* manifest path piggy-backs on the same PLATFORM_SIGNER chain
    \* `audit.tla` models — Sigstore and customer-DSSE paths cover
    \* the whole body via DSSE and don't need the manifest. So the
    \* manifest spec is parameterised over the two key_source values
    \* where the manifest path is *the* trust anchor: KS_PLATFORM
    \* (platform-signed) and KS_WORKSPACE (workspace-signed).
    KS_PLATFORM,
    KS_WORKSPACE,

    \* Sentinels for "field absent from the pack" and "no value".
    NONE,
    ABSENT

VARIABLES
    \* The pack as it reaches the verifier. The attacker (see Next /
    \* Tamper actions) may rewrite any field between issuer-signing
    \* and auditor-receipt, EXCEPT the issuer's private signing key.
    \* So the attacker cannot forge a new signature over a chosen
    \* hash; they can only attempt to substitute or alter sections /
    \* manifest / signature / fingerprint / embedded PEM.
    pack

vars == <<pack>>

(***************************************************************************)
(* Domain definitions.                                                     *)
(*                                                                         *)
(* The pack carries:                                                       *)
(*   - sections      : the per-section content as it appears in the pack   *)
(*                     (e.g., pack["model"], pack["controls"]). The        *)
(*                     verifier hashes the canonical JSON of each.         *)
(*   - manifest      : the signed manifest claiming per-section hashes.    *)
(*   - manifest_hash : the hash the signature is supposedly over           *)
(*                     (as stored in the pack — may be tampered).          *)
(*   - sig_message   : the hash actually committed to by the ECDSA         *)
(*                     signature (oracle-level — what the issuer's         *)
(*                     private key signed; not directly readable from      *)
(*                     the pack).                                          *)
(*   - sig_key       : the abstract key identity that produced the         *)
(*                     signature (oracle-level).                           *)
(*   - embedded_key  : the public key embedded in the pack's               *)
(*                     content_integrity.public_key_pem. The verifier      *)
(*                     reads the fingerprint from this and runs the        *)
(*                     ECDSA verify against this key.                      *)
(*   - claimed_fp    : the fingerprint claimed in                          *)
(*                     content_integrity.manifest_key_fingerprint.         *)
(*   - key_source    : the issuer's key_source classification              *)
(*                     (KS_PLATFORM or KS_WORKSPACE for this spec).        *)
(*                                                                         *)
(* `ABSENT` for `manifest` / `manifest_hash` / `sig_message` models a      *)
(* pack the issuer emitted in legacy-only form (no manifest block). The   *)
(* verifier falls through to the legacy path, which `audit.tla` models.  *)
(* This spec asserts the manifest-path-specific verdict is OK_LEGACY in   *)
(* that case (Invariant B5, BackwardCompat).                              *)
(***************************************************************************)

\* The "section_hashes" map: which abstract hash the issuer claims for
\* each section in the signed manifest. Modeled as a function over
\* Sections; the abstract manifest object equals this function.
ManifestObj == [Sections -> Hashes]

Pack == [
    \* Per-section content as it appears in the pack body.
    sections      : [Sections -> Contents],

    \* Manifest object (may be ABSENT for legacy-only packs).
    manifest      : ManifestObj \cup {ABSENT},

    \* manifest_hash stored in the pack (may diverge from the actual
    \* hash of `manifest` after a tampering action).
    manifest_hash : Hashes \cup {ABSENT},

    \* Oracle-level fields: what the issuer's private key actually
    \* committed to. The attacker cannot change these without
    \* possessing the private key. These are observable only by the
    \* signature-verify oracle (modeled as a comparison below).
    sig_message   : Hashes \cup {ABSENT},
    sig_key       : Keys \cup {ABSENT},

    \* The embedded public key the verifier reads from the pack's
    \* public_key_pem. The attacker can swap this for a different
    \* key (they can publish any public key — that's not secret).
    embedded_key  : Keys \cup {ABSENT},

    \* The fingerprint claimed in manifest_key_fingerprint.
    claimed_fp    : Fingerprints \cup {ABSENT},

    \* Issuer's key_source classification.
    key_source    : {KS_PLATFORM, KS_WORKSPACE}
]

(***************************************************************************)
(* Verdict — the audit-manifest verifier's terminal output.                *)
(*                                                                         *)
(* OK_MANIFEST      : manifest signature verified, fingerprint matched,    *)
(*                    manifest_hash matched the recomputed canonical hash, *)
(*                    AND every section's recomputed hash matched its      *)
(*                    manifest entry.                                      *)
(* OK_LEGACY        : pack has no manifest block; verifier falls through   *)
(*                    to the legacy path (modeled by audit.tla). This      *)
(*                    spec treats OK_LEGACY as a backward-compatibility    *)
(*                    pass-through and does NOT claim it implies any       *)
(*                    integrity property beyond what audit.tla proves.    *)
(* FAIL_*           : terminal failure values, one per detectable          *)
(*                    tampering class. Distinct values let invariants     *)
(*                    pin WHICH class detected the tamper, which is      *)
(*                    stronger than collapsing them all to one FAIL.     *)
(***************************************************************************)
Verdict == {"OK_MANIFEST", "OK_LEGACY",
            "FAIL_MANIFEST_HASH_MISMATCH",
            "FAIL_FINGERPRINT_MISMATCH",
            "FAIL_SIGNATURE_INVALID",
            "FAIL_SECTION_MISMATCH"}

(***************************************************************************)
(* Cryptographic oracles.                                                  *)
(*                                                                         *)
(* HashContent(c)        : abstract SHA-256 of a section's canonical JSON. *)
(* HashManifest(m)       : abstract SHA-256 of a manifest object's        *)
(*                         canonical JSON.                                 *)
(* Fingerprint(k)        : abstract SHA-256 of a key's DER-SPKI.           *)
(* SigVerify(k, msg, sig): does the abstract ECDSA-verify call return     *)
(*                         success? The signature is modeled as the       *)
(*                         (key, message) pair the issuer signed; the     *)
(*                         verifier passes the pack's claimed              *)
(*                         manifest_hash as the message and the embedded  *)
(*                         public key as k. Success iff k = sig_key       *)
(*                         AND msg = sig_message — i.e., the same key     *)
(*                         actually signed that same hash.                 *)
(***************************************************************************)
HashContent(c)  == H_CONTENT[c]
HashManifest(m) == H_MANIFEST[m]
Fingerprint(k)  == FP_OF[k]

\* Signature verification: real ECDSA returns success iff the signature
\* was produced over `msg` by the private key matching public key `k`.
\* The attacker holds neither private key (KS_PLATFORM and KS_WORKSPACE
\* private keys are out of reach by assumption), so they cannot forge
\* a (k, msg) pair where SigVerify holds for a fresh msg. The model
\* enforces this by storing the issuer's (sig_key, sig_message) pair
\* in the pack and checking the verifier's claimed key/message against
\* it.
SigVerify(k, msg, p) ==
    /\ p.sig_key     # ABSENT
    /\ p.sig_message # ABSENT
    /\ k   = p.sig_key
    /\ msg = p.sig_message

(***************************************************************************)
(* AuditManifest — the abstract verifier specification.                    *)
(*                                                                         *)
(* This is the pure function the implementation must compute. The Python  *)
(* implementation lives in `verify/src/mipiti_verify/cli.py`               *)
(* (`_verify_audit_pack_manifest`); a Python BFS may later cross-check    *)
(* it against this spec the same way `audit.tla` is cross-checked by     *)
(* `tests/test_spec_invariants.py`.                                       *)
(*                                                                         *)
(* The cases are listed in the order the implementation evaluates them.   *)
(* The legacy-fallthrough case (B5) must come first so an absent          *)
(* manifest never triggers a spurious FAIL on a downstream check.         *)
(***************************************************************************)
AuditManifest(p) ==
    \* Backward-compat: no manifest in the pack → fall through to the
    \* legacy path. The legacy path's verdict is modeled by audit.tla;
    \* this spec only asserts the fall-through happens.
    IF p.manifest = ABSENT
    THEN "OK_LEGACY"

    \* Step 1: recompute canonical hash of the manifest object and
    \* compare to manifest_hash. Tampered manifest content with the
    \* original manifest_hash retained → detected here.
    ELSE IF HashManifest(p.manifest) # p.manifest_hash
    THEN "FAIL_MANIFEST_HASH_MISMATCH"

    \* Step 2: recompute fingerprint of the embedded public key and
    \* compare to manifest_key_fingerprint. An attacker who swaps the
    \* embedded PEM for an attacker-keyed PEM (so the next ECDSA check
    \* passes against the attacker's key) is detected here unless they
    \* also rewrite manifest_key_fingerprint to match — but that's
    \* defended by Step 3 below.
    ELSE IF p.embedded_key = ABSENT
       \/ Fingerprint(p.embedded_key) # p.claimed_fp
    THEN "FAIL_FINGERPRINT_MISMATCH"

    \* Step 3: ECDSA-verify the manifest_signature over manifest_hash
    \* using the embedded public key. An attacker without the issuer's
    \* private key cannot mint a (key, hash) pair satisfying this.
    ELSE IF ~SigVerify(p.embedded_key, p.manifest_hash, p)
    THEN "FAIL_SIGNATURE_INVALID"

    \* Step 4: for each section the manifest claims, recompute its
    \* canonical hash from the pack's top-level key and compare to
    \* the manifest entry. A section substituted for tampered content
    \* (keeping the manifest intact) is detected here.
    ELSE IF \E s \in Sections :
              HashContent(p.sections[s]) # p.manifest[s]
    THEN "FAIL_SECTION_MISMATCH"

    \* All checks pass → manifest path verifies the whole pack body.
    ELSE "OK_MANIFEST"

(***************************************************************************)
(* Symmetry — TLC state-space reduction.                                   *)
(*                                                                         *)
(* The H_CONTENT / H_MANIFEST / FP_OF oracles are concrete bijections      *)
(* the .cfg pins by name — they reference their domain elements as TLA+   *)
(* strings (e.g., "c1" -> "h_c1"). TLC's symmetry mechanism rejects        *)
(* string-typed CONSTANTS in the Permutations() operator (only opaque     *)
(* model values can be permuted), so we declare no symmetry on the        *)
(* string-typed sets — the .cfg's pinned bijection IS the canonical       *)
(* representative.                                                         *)
(*                                                                         *)
(* The state space remains small enough for unrestricted TLC enumeration: *)
(* 2 sections × 2 contents × 3 keys × 8 hashes × 3 fingerprints, plus the *)
(* attacker tampers. No symmetry reduction needed.                         *)
(***************************************************************************)
Symmetry == {}

(***************************************************************************)
(* Init — the issuer's honest pack, BEFORE attacker tampering.            *)
(*                                                                         *)
(* The honest pack:                                                       *)
(*   - sections[s] is whatever content the issuer emitted for section s; *)
(*   - manifest[s] = HashContent(sections[s]) for every s;                *)
(*   - manifest_hash = HashManifest(manifest);                            *)
(*   - sig_message = manifest_hash;                                       *)
(*   - sig_key = the issuer's key for this row's key_source;              *)
(*   - embedded_key = the same key;                                       *)
(*   - claimed_fp = Fingerprint(embedded_key);                            *)
(*   - key_source ∈ {KS_PLATFORM, KS_WORKSPACE}.                          *)
(*                                                                         *)
(* TLC enumerates the issuer-key choice over Keys × {KS_PLATFORM,        *)
(* KS_WORKSPACE} (the .cfg pins one key per source for the partition;    *)
(* either covers both paths through the matrix).                          *)
(*                                                                         *)
(* Init also enumerates a legacy-only state where manifest = ABSENT     *)
(* (the backward-compatibility branch of the verifier).                  *)
(***************************************************************************)
HonestPack(sectionContents, k, ks) ==
    LET m == [s \in Sections |-> HashContent(sectionContents[s])]
    IN  [ sections      |-> sectionContents,
          manifest      |-> m,
          manifest_hash |-> HashManifest(m),
          sig_message   |-> HashManifest(m),
          sig_key       |-> k,
          embedded_key  |-> k,
          claimed_fp    |-> Fingerprint(k),
          key_source    |-> ks ]

LegacyOnlyPack(sectionContents, ks) ==
    [ sections      |-> sectionContents,
      manifest      |-> ABSENT,
      manifest_hash |-> ABSENT,
      sig_message   |-> ABSENT,
      sig_key       |-> ABSENT,
      embedded_key  |-> ABSENT,
      claimed_fp    |-> ABSENT,
      key_source    |-> ks ]

\* Initial state: pick any honest pack (or a legacy-only one) over the
\* finite domain. The Next actions below model the attacker's
\* tampering choices.
Init ==
    \E sc \in [Sections -> Contents], k \in Keys,
       ks \in {KS_PLATFORM, KS_WORKSPACE} :
       \/ pack = HonestPack(sc, k, ks)
       \/ pack = LegacyOnlyPack(sc, ks)

(***************************************************************************)
(* Next — the attacker actions.                                            *)
(*                                                                         *)
(* The attacker can rewrite any byte of the pack between issuer-signing   *)
(* and auditor-receipt EXCEPT the issuer's private signing key. So they  *)
(* cannot mint a fresh (sig_key, sig_message) pair — those oracle fields *)
(* are immutable under Next. They CAN swap the embedded_key for an       *)
(* attacker-keyed PEM, rewrite manifest_key_fingerprint, alter            *)
(* manifest_hash, alter manifest content, or substitute section content. *)
(*                                                                         *)
(* Each Tamper* action models one atomic tamper class. UNCHANGED on the  *)
(* immutable fields enforces "attacker cannot forge a signature".         *)
(***************************************************************************)

\* Tamper a single section's content. The manifest's claimed hash for
\* that section is NOT updated (the attacker would need to re-sign to
\* update it). The verifier should detect via FAIL_SECTION_MISMATCH.
TamperSection ==
    \E s \in Sections, c \in Contents :
        /\ pack.manifest # ABSENT
        /\ c # pack.sections[s]
        /\ pack' = [pack EXCEPT !.sections[s] = c]

\* Tamper the manifest object directly (e.g., flip a section's claimed
\* hash). The stored manifest_hash is NOT updated; FAIL_MANIFEST_HASH_MISMATCH.
TamperManifest ==
    \E s \in Sections, h \in Hashes :
        /\ pack.manifest # ABSENT
        /\ h # pack.manifest[s]
        /\ pack' = [pack EXCEPT !.manifest[s] = h]

\* Tamper the stored manifest_hash. The signature was over the old hash;
\* SigVerify fails against the new claimed message → FAIL_SIGNATURE_INVALID.
\* (Or, if the attacker leaves manifest_hash equal to the old sig_message
\* but rewrites the manifest content, the manifest-hash check catches it
\* via FAIL_MANIFEST_HASH_MISMATCH — TamperManifest above.)
TamperManifestHash ==
    \E h \in Hashes :
        /\ pack.manifest # ABSENT
        /\ h # pack.manifest_hash
        /\ pack' = [pack EXCEPT !.manifest_hash = h]

\* Swap the embedded public key for an attacker-keyed one. The
\* fingerprint check (Step 2) catches this unless the attacker also
\* rewrites claimed_fp. If they do, Step 3 catches it (SigVerify fails
\* because the attacker's key was not the issuer's key over sig_message).
TamperEmbeddedKey ==
    \E k \in Keys :
        /\ pack.manifest # ABSENT
        /\ k # pack.embedded_key
        /\ pack' = [pack EXCEPT !.embedded_key = k]

\* Rewrite the claimed_fp field. Combined with TamperEmbeddedKey this is
\* the "swap to attacker key + rewrite fingerprint" attack — defended
\* by Step 3 (signature verify) since the attacker's key didn't sign
\* sig_message.
TamperClaimedFingerprint ==
    \E f \in Fingerprints :
        /\ pack.manifest # ABSENT
        /\ f # pack.claimed_fp
        /\ pack' = [pack EXCEPT !.claimed_fp = f]

\* Tamper the section content of a legacy-only pack. Backward-compat:
\* verifier verdict stays OK_LEGACY regardless — this spec does not
\* claim the legacy path detects body tampering (it doesn't, by
\* design; that's the whole reason the manifest path exists). The
\* legacy path's invariants are modeled by audit.tla.
TamperLegacySection ==
    \E s \in Sections, c \in Contents :
        /\ pack.manifest = ABSENT
        /\ c # pack.sections[s]
        /\ pack' = [pack EXCEPT !.sections[s] = c]

\* Stutter — the pack reaches the verifier untampered. Modeled
\* explicitly because TLC's `[Next]_vars` stutter would not generate a
\* "tampered-zero" reachable state otherwise; with TamperSection /
\* TamperManifest etc. as the only Next actions, every reachable state
\* would have at least one tamper applied to it (except Init itself).
\* StutterStep keeps the honest pack reachable post-Init.
StutterStep == UNCHANGED vars

Next ==
    \/ TamperSection
    \/ TamperManifest
    \/ TamperManifestHash
    \/ TamperEmbeddedKey
    \/ TamperClaimedFingerprint
    \/ TamperLegacySection
    \/ StutterStep

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* TypeOK — the state-space type invariant. Pinned by every cfg.           *)
(***************************************************************************)
TypeOK == pack \in Pack

(***************************************************************************)
(* Invariants.                                                             *)
(*                                                                         *)
(* B1 (Authenticity). Whenever AuditManifest(pack) = OK_MANIFEST, the     *)
(*    pack's per-section content hashes equal the manifest's claimed     *)
(*    hashes AND the manifest's stored hash equals the canonical hash    *)
(*    of the manifest object AND the signature verifies. I.e., OK only   *)
(*    on a fully-authentic pack.                                          *)
(*                                                                         *)
(* B2 (Per-section integrity). On OK_MANIFEST, every section's content   *)
(*    hash matches its manifest entry. (Strong corollary of B1; kept     *)
(*    separate so a counterexample naming a section is more readable.)   *)
(*                                                                         *)
(* B3 (Tamper detection — section). After TamperSection, the verdict is  *)
(*    never OK_MANIFEST. (Negative invariant: ¬(verdict = OK_MANIFEST    *)
(*    ∧ ∃s : HashContent(sections[s]) ≠ manifest[s]).)                    *)
(*                                                                         *)
(* B4 (Tamper detection — manifest / hash / key). After any of the       *)
(*    other tamper actions on a manifest-bearing pack, the verdict is   *)
(*    never OK_MANIFEST. Covered by the negation in B1.                  *)
(*                                                                         *)
(* B5 (Backward compatibility). A pack without a manifest yields        *)
(*    OK_LEGACY (the legacy fall-through), never OK_MANIFEST or any     *)
(*    FAIL_*. This is the invariant that lets the manifest path ship as *)
(*    additive — old packs the issuer emitted before this feature do    *)
(*    not regress.                                                        *)
(*                                                                         *)
(* B6 (Selective disclosure soundness). For every section s, the         *)
(*    triple (sections[s], manifest, manifest_hash, manifest_signature) *)
(*    is sufficient to authenticate s in isolation: the manifest +      *)
(*    signature establish the signed map, and HashContent(sections[s])  *)
(*    = manifest[s] establishes s's binding. Stated as: OK_MANIFEST     *)
(*    implies that for every s, an independent re-check of just s's     *)
(*    binding succeeds. (Together with B1, this is the formal statement *)
(*    of the per-section extraction protocol.)                           *)
(*                                                                         *)
(* B7 (No false positive from forged-key swap). The attacker cannot     *)
(*    swap embedded_key + claimed_fp to an attacker-controlled (key,    *)
(*    fingerprint) pair and reach OK_MANIFEST. The signature check     *)
(*    catches it. Formally: OK_MANIFEST ⇒ embedded_key = sig_key       *)
(*    (the embedded key is the same key that actually signed).          *)
(***************************************************************************)

B1_Authenticity ==
    AuditManifest(pack) = "OK_MANIFEST" =>
        /\ pack.manifest # ABSENT
        /\ HashManifest(pack.manifest) = pack.manifest_hash
        /\ pack.embedded_key # ABSENT
        /\ Fingerprint(pack.embedded_key) = pack.claimed_fp
        /\ SigVerify(pack.embedded_key, pack.manifest_hash, pack)
        /\ \A s \in Sections :
              HashContent(pack.sections[s]) = pack.manifest[s]

B2_PerSection ==
    AuditManifest(pack) = "OK_MANIFEST" =>
        \A s \in Sections :
            HashContent(pack.sections[s]) = pack.manifest[s]

B3_TamperDetection_Section ==
    (   pack.manifest # ABSENT
     /\ \E s \in Sections : HashContent(pack.sections[s]) # pack.manifest[s]
    ) => AuditManifest(pack) # "OK_MANIFEST"

B4_TamperDetection_Manifest ==
    (   pack.manifest # ABSENT
     /\ \/ HashManifest(pack.manifest) # pack.manifest_hash
        \/ pack.embedded_key = ABSENT
        \/ Fingerprint(pack.embedded_key) # pack.claimed_fp
        \/ ~SigVerify(pack.embedded_key, pack.manifest_hash, pack)
    ) => AuditManifest(pack) # "OK_MANIFEST"

B5_BackwardCompat ==
    pack.manifest = ABSENT => AuditManifest(pack) = "OK_LEGACY"

\* Selective disclosure: extracting one section s and the manifest +
\* signature is sufficient to authenticate s. Modeled as: on OK_MANIFEST,
\* for every s, the per-section extraction predicate holds. The
\* extraction predicate is exactly the conjunction the recipient checks:
\* (a) manifest_hash equals the recomputed hash of the manifest;
\* (b) signature verifies over manifest_hash; (c) the section's
\* recomputed content hash equals its manifest entry.
ExtractionVerifies(s) ==
    /\ pack.manifest # ABSENT
    /\ HashManifest(pack.manifest) = pack.manifest_hash
    /\ pack.embedded_key # ABSENT
    /\ SigVerify(pack.embedded_key, pack.manifest_hash, pack)
    /\ HashContent(pack.sections[s]) = pack.manifest[s]

B6_SelectiveDisclosureSound ==
    AuditManifest(pack) = "OK_MANIFEST" =>
        \A s \in Sections : ExtractionVerifies(s)

\* Selective-disclosure converse: if the recipient receives a section
\* with content that differs from what the manifest claims, the
\* extraction predicate FAILS for that section — i.e., the recipient
\* detects the substitution. Formally: ¬ExtractionVerifies(s) when the
\* section's content hash differs from its manifest entry (manifest +
\* signature otherwise intact).
B6b_SelectiveDisclosure_DetectsTamper ==
    (   pack.manifest # ABSENT
     /\ HashManifest(pack.manifest) = pack.manifest_hash
     /\ pack.embedded_key # ABSENT
     /\ SigVerify(pack.embedded_key, pack.manifest_hash, pack)
     /\ \E s \in Sections :
           HashContent(pack.sections[s]) # pack.manifest[s]
    ) => \E s \in Sections : ~ExtractionVerifies(s)

B7_NoForgedKeySwap ==
    AuditManifest(pack) = "OK_MANIFEST" =>
        /\ pack.embedded_key # ABSENT
        /\ pack.sig_key     # ABSENT
        /\ pack.embedded_key = pack.sig_key

\* Aggregate invariant set referenced by both cfgs. Listing them
\* individually here keeps TLC's per-invariant diagnostic intact: a
\* counterexample names the specific B* clause that failed.
ManifestInvariants ==
    /\ TypeOK
    /\ B1_Authenticity
    /\ B2_PerSection
    /\ B3_TamperDetection_Section
    /\ B4_TamperDetection_Manifest
    /\ B5_BackwardCompat
    /\ B6_SelectiveDisclosureSound
    /\ B6b_SelectiveDisclosure_DetectsTamper
    /\ B7_NoForgedKeySwap

(***************************************************************************)
(* Concrete oracle instantiations for the .cfg files.                      *)
(*                                                                         *)
(* TLC's .cfg parser rejects inline function/record literals in CONSTANT  *)
(* assignments, so the .cfg uses the `<-` operator-bind syntax to replace *)
(* H_CONTENT / H_MANIFEST / FP_OF with the defaults below. These mirror   *)
(* the SAN_PREFIX_REGISTRY_DEFAULT pattern audit.tla uses for its         *)
(* registry oracle.                                                       *)
(*                                                                         *)
(* The defaults are concrete bijections over the .cfg's pinned finite     *)
(* domains. SHA-256 is collision-resistant in practice, so modeling each *)
(* oracle as a bijection is the right finite abstraction: any "collision *)
(* between two distinct inputs" the attacker would need to exploit does  *)
(* not exist in the model, matching the real-world cryptographic         *)
(* assumption.                                                             *)
(*                                                                         *)
(* Each oracle is parameterised on the .cfg's CONSTANT sets (c1/c2 for    *)
(* Contents, h1/h2 for Hashes, k_a/k_b/k_atk for Keys, etc.). The        *)
(* H_MANIFEST default uses a deterministic but distinguishing hash of    *)
(* the manifest function — modeled as a tagged sum of its entries — so   *)
(* two manifests differing in any one section map to different hashes.    *)
(***************************************************************************)

\* Hash-domain layout pinned by the .cfg:
\*
\*   Hashes = {h_c1, h_c2,                  -- co-domain of H_CONTENT
\*             h_m_aa, h_m_ab,              -- co-domain of H_MANIFEST
\*             h_m_ba, h_m_bb,
\*             h_atk}                        -- attacker-chosen value
\*                                              never equal to any
\*                                              honest hash above (so
\*                                              TamperManifestHash to
\*                                              h_atk can never
\*                                              accidentally pass the
\*                                              signature check by
\*                                              colliding with
\*                                              sig_message).
\*
\* Both H_CONTENT and H_MANIFEST map into Hashes, with disjoint ranges
\* (modeling collision-resistance: a real SHA-256 of a section's
\* canonical JSON has overwhelming probability of differing from the
\* hash of any manifest object). H_CONTENT is a bijection over the
\* pinned Contents = {c1, c2}.
H_CONTENT_DEFAULT ==
    ("c1" :> "h_c1") @@ ("c2" :> "h_c2")

\* H_MANIFEST default: distinguishing hash of the manifest object.
\* The pinned domain Sections = {s1, s2}, the H_CONTENT range = {h_c1,
\* h_c2}, so the honest manifests TLC can construct in Init range over
\* the 2^2 = 4 maps [{s1, s2} -> {h_c1, h_c2}]. We assign each to a
\* distinct manifest-hash co-domain element so any tamper of the
\* manifest object (TamperManifest, which writes a new entry from
\* Hashes) maps to a different hash, ensuring FAIL_MANIFEST_HASH_MISMATCH
\* fires deterministically.
\*
\* For tampered manifests where an entry was rewritten to an attacker-
\* chosen Hash value not in H_CONTENT's range (e.g., h_atk, or one of
\* the manifest-hash dedicated values), H_MANIFEST defaults to h_m_aa
\* (an arbitrary but consistent value). The verifier still detects
\* the tamper because the original manifest_hash field was over the
\* honest manifest's hash, so the recomputed hash of the tampered
\* manifest is in {h_m_aa, h_m_ab, h_m_ba, h_m_bb} ≠ original
\* manifest_hash (when those four are distinct from each other on the
\* honest input).
H_MANIFEST_DEFAULT ==
    [m \in [{"s1", "s2"} -> {"h_c1", "h_c2", "h_m_aa", "h_m_ab",
                              "h_m_ba", "h_m_bb", "h_tampered",
                              "h_atk"}] |->
        IF m["s1"] = "h_c1" /\ m["s2"] = "h_c1" THEN "h_m_aa"
        ELSE IF m["s1"] = "h_c1" /\ m["s2"] = "h_c2" THEN "h_m_ab"
        ELSE IF m["s1"] = "h_c2" /\ m["s2"] = "h_c1" THEN "h_m_ba"
        ELSE IF m["s1"] = "h_c2" /\ m["s2"] = "h_c2" THEN "h_m_bb"
        \* Any tampered manifest mapping outside H_CONTENT's range
        \* gets a distinct hash (h_tampered). Distinct from every
        \* honest-manifest hash, so it never collides with the
        \* signature's committed message.
        ELSE "h_tampered"]

\* FP_OF default: each key maps to a distinct fingerprint. Pinned
\* domain in the .cfg: Keys = {k_a, k_b, k_atk}, Fingerprints =
\* {fp_a, fp_b, fp_atk}. k_a -> fp_a, k_b -> fp_b, k_atk -> fp_atk
\* (bijection — no two real public keys hash to the same fingerprint
\* under SHA-256).
FP_OF_DEFAULT ==
    ("k_a" :> "fp_a") @@ ("k_b" :> "fp_b") @@ ("k_atk" :> "fp_atk")

(***************************************************************************)
(* Per-key_source spec partitions.                                         *)
(*                                                                         *)
(* The .cfg files instantiate Spec_platform or Spec_workspace to pin TLC  *)
(* enumeration to one key_source class. Same pattern as audit.tla's       *)
(* Spec_main_<class> sub-split. The union of the two sub-configs covers   *)
(* the full key_source space {KS_PLATFORM, KS_WORKSPACE}.                  *)
(***************************************************************************)

InitFor(allowedKS) ==
    \E sc \in [Sections -> Contents], k \in Keys, ks \in allowedKS :
       \/ pack = HonestPack(sc, k, ks)
       \/ pack = LegacyOnlyPack(sc, ks)

Init_platform   == InitFor({KS_PLATFORM})
Init_workspace  == InitFor({KS_WORKSPACE})

Spec_platform   == Init_platform   /\ [][Next]_vars
Spec_workspace  == Init_workspace  /\ [][Next]_vars

==============================================================================
