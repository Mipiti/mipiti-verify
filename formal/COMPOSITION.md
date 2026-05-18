# Compositional Verification of `audit.tla`

The audit-envelope verifier's correctness is verified compositionally
across two TLC configurations:

- **`audit_main.cfg`** — pins `bundle_bind_hash` and `bundle_bind_signature`
  to their canonical "matching, valid" representative (`bundle_bind_hash =
  bundle.bound_hash`, `bundle_bind_signature = TRUE`). Verifies invariants
  whose truth value is independent of `bundle_bind_*` on that
  representative: I1–I7, I9–I13, V3.
- **`audit_bundle_bind.cfg`** — explores the full `bundle_bind_*` cross-
  product AND the full `ws_sig` variation (V1/V2's preconditions
  require `ws_sig` present with specific `key_source` values). Pins
  all auditor pins to `NONE`, since V1/V2's premises require this and
  I8/I14 are pin-independent. Verifies I8, I14, V1, V2.

The conjunction of both configs' invariants is logically equivalent to
the un-split `audit.cfg`'s `SecurityInvariants`, *if* the partition
argument below holds. The partition argument is itself
machine-checked: `audit_main.cfg` includes a `ConfigMainCompositionLemma`
that mechanically validates the pinning is precision-preserving for
each invariant in Config 1.

## Why split

The full-domain TLC enumeration runs on `~95M` distinct states
post-symmetry. Each new field on `Package` multiplies the state space.
After explicit `bundle_bind_hash` and `bundle_bind_signature` were
added, single-config TLC takes ~23 minutes per CI run.

State-space cost is multiplicative, but invariants only depend on
subsets of the dimensions. Splitting turns a multiplication into a
sum:

```
Single config:  bundle × ws_sig × pins × bundle_bind ≈ 95M states
Config 1:       bundle × ws_sig × pins × {pinned}    ≈ 10M states
Config 2:       bundle × {pinned} × {pinned} × bundle_bind ≈ 30K states
Total split:    ~10M states (roughly 10× reduction)
```

## Partition argument

Each invariant in `audit.tla` has a **dependency footprint** — the set
of fields its premise and conclusion reference, transitively through
`Audit`. The partition is sound iff every invariant lives in a config
whose state-space exploration covers its dependency footprint.

### Invariants in Config 1 (pinned `bundle_bind`)

These invariants are bundle_bind-independent under the canonical-
matching pinning:

| Invariant | Why bundle_bind doesn't affect its truth value |
|---|---|
| `I1_SanPinIsBinding` | Premise references `pins.san`/`model_id`/`commit_sha` and `bundle = ABSENT`. Conclusion: `Audit ∈ {FAILED, USAGE_ERROR}`. Bundle-absent states have `bundle_bind` already pinned to `NONE/NONE` in `InitBase`. Bundle-present states satisfy the premise vacuously (`bundle ≠ ABSENT`), so the implication holds trivially. |
| `I2_WorkspacePinIsBinding` | Premise: `pins.workspace_fp ≠ NONE` AND `ws_sig = ABSENT`. Conclusion: `Audit ∈ {FAILED, USAGE_ERROR}`. Independent of `bundle_bind`: the workspace-pin-without-ws_sig case fires `Audit = FAILED` via the I2 branch in `Audit`, not the bundle-bind branches. |
| `I3_IssuerNeverSelfAttested` | Premise references `pins.san`, `bundle ≠ ABSENT`, `ResolveIssuer(pins) ≠ NONE`, `bundle.issuer ≠ ResolveIssuer`. Conclusion: `Audit = FAILED`. The bundle-issuer-mismatch branch fires before the bundle-bind branches in `Audit`'s ordering, so `bundle_bind` is irrelevant. |
| `I4_WorkspaceFpBound` | Premise: `pins.workspace_fp ≠ NONE` AND `ws_sig ≠ ABSENT` AND `ws_sig.signing_key_fp ≠ pins.workspace_fp`. Conclusion: `Audit ∈ {FAILED, USAGE_ERROR}`. The workspace-fp-mismatch branch in `Audit` is independent of `bundle_bind`. |
| `I5_VerifiedImpliesEvidence` | Premise: `Audit = VERIFIED`. For `Audit = VERIFIED`, the bundle-bind branches must NOT have fired (else FAILED), so `bundle_bind` is in the canonical-matching state. Pinning to that state in Config 1 covers all `Audit = VERIFIED` reachable states. |
| `I6_ContentHashBoundToResults` | Premise: `Audit ∈ {VERIFIED, PARTIALLY_VERIFIED}` and `results_hash ≠ NONE`. Same `Audit = positive ⇒ bundle_bind matching` argument as I5. |
| `I7_SanRequiredForCoPins` | Premise: `pins.san = NONE` AND co-pin set. Conclusion: `Audit = USAGE_ERROR`. The USAGE_ERROR branch fires first in `Audit` (before any bundle-bind logic), so `bundle_bind` is irrelevant. |
| `I9_AllPresentSignaturesValid` | Premise: `Audit = VERIFIED`. Same `Audit = VERIFIED ⇒ bundle_bind matching` argument as I5. |
| `I10_UnboundBundleNotVerified` | Premise: `bundle ≠ ABSENT` AND `results_hash = NONE`. Conclusion: `Audit ∈ {UNVERIFIED, FAILED, USAGE_ERROR}`. The bundle-without-results_hash branch in `Audit` is structurally orthogonal to `bundle_bind` (it fires before the bind check). |
| `I11_BundleSanMatchesPin` | Premise: `Audit = VERIFIED` AND `bundle ≠ ABSENT` AND `pins.san ≠ NONE`. Same `Audit = VERIFIED ⇒ bundle_bind matching` argument. |
| `I12_BundleModelIdMatchesPin` | Same `Audit = VERIFIED ⇒ bundle_bind matching` argument. |
| `I13_BundleCommitShaMatchesPin` | Same `Audit = VERIFIED ⇒ bundle_bind matching` argument. |
| `V3_OrphanWithWorkspacePinFails` | Premise: `ws_sig.key_source = KS_ORPHAN` AND `pins.workspace_fp ≠ NONE` (no other pins set). Conclusion: `Audit ∈ {FAILED, USAGE_ERROR}`. The orphan + workspace-pin branch in `Audit` is independent of `bundle_bind` — fires before the bundle-bind check on bundle-present states; on bundle-absent states `bundle_bind` is already NONE. |

### Invariants in Config 2 (full `bundle_bind` cross-product)

These invariants explicitly reference `bundle_bind_hash` and/or
`bundle_bind_signature` in their premise or conclusion:

| Invariant | Reason |
|---|---|
| `I8_BundleBoundToBundleBindHash` | Conclusion: `bundle.bound_hash = bundle_bind_hash`. Must explore states where they differ. |
| `I14_BundleBindExplicit` | Conclusion: `bundle_bind_hash ≠ NONE` AND `bundle.bound_hash = bundle_bind_hash`. Same. |
| `V1_SigstoreSkipSoundness` | Premise: `bundle ≠ ABSENT` AND `bundle_bind_hash = bundle.bound_hash` AND `bundle_bind_signature ∉ {INVALID, KEY_UNRESOLVABLE}`. Must explore the full domain to confirm the conclusion holds on all premise-satisfying states. |
| `V2_OrphanWithBundleVerified` | Same as V1 with `KS_ORPHAN`. |
| `V4_BundleBindSigKeyResolutionExplicit` | Premise: `bundle ≠ ABSENT` AND `bundle_bind_signature = KEY_UNRESOLVABLE`. Conclusion: `Audit ∈ {FAILED, USAGE_ERROR}`. Directly references the `bundle_bind_signature` domain. |

Config 2 pins all auditor pins (`pins.san`, `issuer_explicit`,
`workspace_fp`, `model_id`, `commit_sha`) to `NONE`. Reason: V1/V2's
premises explicitly require all pins NONE; I8/I14's premise/conclusion
don't reference pins. Pinning is precision-preserving for these four
invariants.

`ws_sig` varies fully in Config 2 — V1's premise requires `ws_sig`
present with `key_source = KS_SIGSTORE`, V2's with `key_source =
KS_ORPHAN`. Without `ws_sig` variation Config 2 cannot exercise those
preconditions.

## Machine-checked composition lemma

`audit_main.cfg` includes `ConfigMainCompositionLemma` (defined in
`audit.tla`):

```tla
ConfigMainCompositionLemma ==
    pkg.bundle # ABSENT =>
      \A bb_hash \in (Hashes \cup {NONE}) :
        \A bb_sig \in (BOOLEAN \cup {NONE}) :
          LET pkg_alt == [pkg EXCEPT
                            !.bundle_bind_hash = bb_hash,
                            !.bundle_bind_signature = bb_sig]
          IN  \/ Audit(pkg_alt, pins) \in {"FAILED", "USAGE_ERROR"}
              \/ Audit(pkg_alt, pins) = Audit(pkg, pins)
```

For every state Config 1 explores, this asserts that altering
`bundle_bind` either (a) lands in the negative verdict class via the
bundle-bind branch, or (b) preserves `Audit`'s verdict. Together with
the pinning, this mechanically validates that Config 1's enumeration
loses no invariant violations to the bundle_bind dimension.

If TLC reports "Model checking completed. No error has been found"
on `audit_main.cfg`, both:

1. Config 1's invariants hold on every state in the pinned domain,
   AND
2. The pinning is compositionally sound — no full-domain violation
   could exist that Config 1's enumeration missed.

## Equivalence claim

If TLC accepts both `audit_main.cfg` and `audit_bundle_bind.cfg`,
then the conjunction of all invariants in `SecurityInvariants` holds
on `audit.tla`'s reachable state space.

The original `audit.cfg` is retained for backward compatibility and
periodic soundness verification (manual or scheduled run); it is not
required on every CI tick.

## Config-2 customer_dsse exclusion (lossless)

`Init_bind` (Config 2's init operator, selected by
`audit_bundle_bind.cfg` via `SPECIFICATION Spec_bind`) calls the
parameterised `InitBase(genCustomerDsse)` with `genCustomerDsse =
FALSE`. `InitBase(FALSE)` enumerates `pkg \in PackageGen(FALSE)`,
whose `WSSigGen(FALSE)` generator **drops `KS_CUSTOMER_DSSE` from the
`key_source` domain and pins the three customer_dsse-only WSSig
fields to singletons**:

```tla
key_source                : KeySources \ {KS_CUSTOMER_DSSE}
dsse_predicate_model_id   : {NONE}
dsse_predicate_commit_sha : {NONE}
customer_key_fp_match     : {TRUE}
```

i.e. **Config 2 never generates a customer_dsse row** — and, because
this is a smaller *enumerated set* (not a post-`\in` filter), TLC's
init-state generator never materialises the customer_dsse
sub-product (~18× fewer WSSig records: `3·3·2` collapsed to `1·1·1`,
`KeySources` 6→5). `Init_main` (Config 1) and the legacy `Init` call
`InitBase(TRUE)`, where `PackageGen(TRUE)` is byte-equivalent to the
original `Package` (customer_dsse fully generated). Note
`PackageGen(FALSE) ⊆ Package`, so `TypeOK == pkg \in Package` still
holds on every Config-2 state. A *bare conjunctive* exclusion
(`… /\ pkg.ws_sig.key_source # KS_CUSTOMER_DSSE`) layered after an
unparameterised `pkg \in Package` was measured **not** to prune
generation — TLC iterates the full record product first and only
then discards — which is the init-generation blow-up the AuditView /
InitBase-canon work documents; the generator-set restriction is what
actually prunes.

This is *lossless* — it removes only states on which every invariant
Config 2 checks is vacuously true:

- The exact invariant set Config 2 verifies is
  `ConfigBindInvariants` = **`I8`, `I14`, `V1`, `V2`, `V4`** (plus
  `TypeOK`). This is the machine-checked list — `audit.tla`'s
  `ConfigBindInvariants` body — not a prose restatement.
- **Every one of `I8`, `I14`, `V1`, `V2`, `V4` has a premise conjunct
  requiring `pkg.bundle # ABSENT`** (I8: `… /\ pkg.bundle # ABSENT`;
  I14: `Audit = VERIFIED /\ pkg.bundle # ABSENT`; V1/V2:
  `… /\ pkg.bundle # ABSENT /\ pkg.bundle.valid …`; V4:
  `pkg.bundle # ABSENT /\ bundle_bind_signature = KEY_UNRESOLVABLE`).
  `TypeOK` is a pure type predicate that holds on every well-typed
  state regardless.
- A customer_dsse row has **`pkg.bundle = ABSENT`** — the
  KeySourceResolver `R12` producer constraint imported into
  `InitBase` (the clause `pkg.ws_sig.key_source = KS_CUSTOMER_DSSE
  => pkg.bundle = ABSENT /\ pkg.ws_sig.valid = TRUE`).
- Therefore on **every** customer_dsse state, all five Config-2
  invariant premises are vacuously false ⇒ each invariant holds
  trivially. Customer_dsse states contribute **zero** invariant
  coverage to Config 2.

This is the *same* partition argument that already places the
customer_dsse positive properties (`V5a`/`V5b`/`V5c`) in **Config
1's** partition: customer_dsse rows are bundle-absent, hence
`bundle_bind`-pinned `NONE/NONE`, hence Config-1 territory.
`Init_main` (Config 1) is **unchanged** and still generates
customer_dsse — `V5a`/`V5b`/`V5c` legitimately need it, and Config
1's sound full run stands.

**Soundness gate (verified before adopting the exclusion).** The
transitive operator closure of `ConfigBindInvariants`/`TypeOK` (the
same call-graph the AST proof in `check_audit_view_faithful.py`
walks) reaches `KS_CUSTOMER_DSSE` / `dsse_predicate_*` /
`customer_key_fp_match` / `IsCustomerDsse` **only** through the
shared, invariant-agnostic `Audit` / `WSSig` / `KeySources`
infrastructure. **No Config-2 invariant body itself** references any
customer_dsse symbol, nor does any Config-2 invariant observe the
customer_dsse `Audit` terminal-dispatch outcome (each requires
`bundle # ABSENT`, which customer_dsse — being bundle-absent — can
never satisfy, so the customer_dsse branch of `Audit` is unreachable
on any state where a Config-2 premise is non-vacuous). The exclusion
is sound.

Effect (measured, `eclipse-temurin:21-jre`, `-Xmx8g -workers auto`,
TLC 2.19): Config 2 (`audit_bundle_bind.cfg`) **completes** —
`Model checking completed. No error has been found.` — in
**3 min 37 s**, **142,743 distinct states** (1,272,102 generated).
Before this change Config 2 did not terminate (stuck in init-state
generation past 2 h with the customer_dsse cross-product
materialised). Config 1 (`audit_main.cfg`) is byte-unchanged and its
prior sound ~1 h run stands (its spec call `InitBase(TRUE)` is
provably a no-op refactor: `PackageGen(TRUE) ≡ Package`).

The reduction is orthogonal to (and composes with) the `AuditView`
VIEW and the `InitBase` relation-class canonicalisation: those make
the *retained* customer_dsse states tractable for Config 1; this
exclusion removes the *vacuous* ones from Config 2 entirely.

## CI job split

The audit-spec TLC work runs in a **dedicated `audit-tlc` job** in
`.github/workflows/ci.yml`, parallel to `test` and
`test-spec-invariants`:

- `audit-tlc` owns the `check_audit_view_faithful.py` AST-proof gate
  (it certifies the lossless `AuditView` reduction these two configs
  depend on), the TLC download, and the two `audit.tla` configs
  (`audit_main.cfg` Config 1 + `audit_bundle_bind.cfg` Config 2),
  both with `-workers auto`.
- `test` keeps the Python BFS cross-check and the
  `VerificationPipeline` / `KeySourceResolver` TLC runs.

Rationale: a long-but-correct audit TLC run no longer sits on the
critical path of the fast unit/BFS suite. No gate is weakened — every
job (`test`, `audit-tlc`, `test-spec-invariants`) remains a required
status check; the AST proof still fails closed; `-workers auto` and
the JVM tuning are unchanged.

## Companion: resolver-side invariant index

The issuer-side `KeySourceResolver.tla` carries its own invariant set
(`R1`–`R6`, `R10`, `R12` + `R3a`), indexed in that module's header.
The `customer_dsse` key-source classification adds **`R12` —
Customer-DSSE binding integrity**: the `customer_dsse` class fires iff
a stored workspace key resolves the fingerprint AND a valid
customer-signed DSSE bundle re-verifies against it (and no valid
Sigstore bundle is present, which still wins by precedence); it must
carry the dsse_bundle, stored public key, and workspace id and must
not be an orphan, while the bare-key `workspace` class must never
carry a dsse_bundle. This is a resolver invariant, not part of the
`audit.tla` `bundle_bind` partition above — it is checked by
`KeySourceResolver.cfg` (and the companion Python BFS), independently
of the two audit configs.

On the verifier side, `audit.tla` adds `KS_CUSTOMER_DSSE` to
`KeySources` in the same trust-anchor class as `KS_SIGSTORE` (the
customer-signed DSSE Statement, verified offline against an
out-of-band-pinned fingerprint, is the anchor — the envelope ws_sig
is not re-evaluated). It is added to the `KS_SIGSTORE`-style ws_sig
skip sets and to `I9`'s skip set.

### Customer-DSSE identity-pin scoping

The customer-keyed offline DSSE path gates identity **solely** on the
auditor's `--expected-customer-key` fingerprint pin (the
vendor-independence gate, `customer_dsse_verifier.py` step 3). It does
**not** engage the Sigstore-SAN identity pins (`--expected-ci-identity`
/ the resolved-issuer pin) nor the `--expected-workspace-key` pin —
there is no Sigstore bundle to bind a SAN to, and the customer-DSSE
CLI branch never consults the workspace-key pin. The model_id /
commit_sha predicate pins ARE enforced, but against the
customer-signed DSSE predicate, not a Sigstore bundle.

`audit.tla` models this with a key_source-aware refinement that is
**additive** (no behaviour change for sigstore / platform / workspace
/ orphan / legacy):

- A `KS_CUSTOMER_DSSE` *terminal dispatch* in the `Audit` operator
  (placed after the `I2` workspace-pin fail, mirroring the CLI's
  `customer_dsse_handled` branch): an `--expected-customer-key`
  fingerprint mismatch ⇒ `FAILED`; a model_id / commit_sha pin not
  matching the customer-signed predicate ⇒ `FAILED`; otherwise the
  key_source-independent canonical-hash check decides
  (`VERIFIED` / `FAILED`).
- The Sigstore-identity pin clauses are scoped out of customer_dsse:
  `I1` (bundle-binding-pin-is-binding) and `I7`'s predicate-co-pin
  clause carve out customer_dsse; `I4` (workspace-fp bound) carves it
  out; the `Audit` operator's SAN-less-co-pin / I1-omission /
  SAN-match / workspace-fp branches all gain `~IsCustomerDsse(k)`
  guards. `I7`'s **issuer-explicit-alone** clause stays
  key_source-unconditional (a bare `--expected-issuer` is a usage
  error regardless of key_source).
- Three new invariants positively state the customer_dsse pinned
  property: **`V5a`** (a customer-key fingerprint-pin mismatch must
  FAIL), **`V5b`** (a match + a producer-valid customer-signed DSSE
  row + intact canonical hash + matching predicate pins ⇒ VERIFIED,
  *even when* a SAN or workspace-fp pin is set), and **`V5c`** (a
  customer_dsse row's verdict is invariant under the SAN pin — the
  Sigstore-identity pins provably do not gate it).

The `KS_CUSTOMER_DSSE` producer contract from `KeySourceResolver.tla`
`R12` (the class fires only when no valid Sigstore bundle is present
and a valid customer-signed DSSE bundle re-verifies) is imported into
`InitBase`: a customer_dsse row has `bundle = ABSENT` and a
producer-valid envelope ws_sig (`valid = TRUE`). Because
`bundle = ABSENT`, `bundle_bind` is pinned `NONE/NONE` and the
customer_dsse invariants are `bundle_bind`-independent — they live in
Config 1's partition, and `ConfigMainCompositionLemma` (premise
`pkg.bundle # ABSENT`) is vacuous on customer_dsse rows. The
refinement therefore introduces no new `bundle_bind`-dependent premise
or conclusion, so the partition argument and
`ConfigMainCompositionLemma` above remain sound unchanged.

## `AuditView` — lossless customer_dsse state-space reduction

The `customer_dsse` modeling added three `WSSig` fields —
`customer_key_fp_match : BOOLEAN`,
`dsse_predicate_model_id : ModelIds ∪ {NONE}`,
`dsse_predicate_commit_sha : CommitShas ∪ {NONE}`. On a customer_dsse
row the auditor's `model_id` / `commit_sha` pins are cross-checked
against the customer-signed DSSE predicate (the `dsse_predicate_*`
fields), so the reachable state space carries the **full
cross-product**

```
(dsse_predicate_model_id × pins.model_id)
  × (dsse_predicate_commit_sha × pins.commit_sha)
  × customer_key_fp_match
= 3·3 · 3·3 · 2 = 162 raw combinations
```

multiplied into the rest of the audit space, on top of the already
symmetry-reduced graph. With this product present, TLC on
`audit_main.cfg` / `audit_bundle_bind.cfg` ran 2h+ with no progress
checkpoint (effectively non-terminating in CI).

### The reduction

`AuditView` (defined in `audit.tla`, wired via `VIEW AuditView` in
both cfgs) is a **key-source-conditional** TLC view:

- **On a `customer_dsse` row** (`IsCustomerDsse(pkg)`): it projects
  the pair `(dsse_predicate_model_id, pins.model_id)` to a 3-valued
  relation token via `Rel3` — `q_none` (pin unset) / `match` /
  `mismatch` — does the same for `(dsse_predicate_commit_sha,
  pins.commit_sha)`, keeps `customer_key_fp_match` verbatim (a
  boolean), and keeps **every other observable field of `pkg`/`pins`
  verbatim**. The 162-way raw product collapses to
  `2·3·3 = 18` observable classes.
- **On every NON-customer_dsse state** (and when `ws_sig = ABSENT`):
  the view is the **identity** `<<pkg, pins>>`.

### Why identity off the customer_dsse path (soundness)

Collapsing `pins.model_id` / `pins.commit_sha` *globally* would be
**unsound**: `I12` / `I13` assert
`bundle.predicate_model_id = pins.model_id` (resp. commit_sha) and
`Audit`'s Sigstore bundle-predicate branches compare the *bundle*
predicate to `q.model_id` *by identity*. A global collapse would
conflate states those Sigstore-pin invariants distinguish, hiding
real violations. `AuditView` therefore collapses
`pins.model_id`/`commit_sha` **only on a customer_dsse row**, where
`bundle = ABSENT` (KeySourceResolver `R12`, imported in `InitBase`)
makes every bundle-predicate branch vacuous — so the collapse is
observationally inert for the Sigstore-pin invariants. On every
Sigstore / platform / workspace / orphan / legacy state `AuditView`
is the literal identity, so I1–I14 / V1–V4 and their Sigstore-pin
identity uses see the unreduced state exactly as before.

### Lossless by construction — the AST proof

A TLC `VIEW` is lossless iff every checked invariant *factors
through* the view (two states with the same view agree on every
invariant). `formal/check_audit_view_faithful.py` **proves** this by
a stdlib-only structural analysis of `audit.tla`:

1. Parse every top-level operator; resolve the operator-call graph
   transitively from the `INVARIANTS` roots of both cfgs (an
   invariant calling a helper that touches a collapsed field counts).
2. For every reference to a collapsed field
   (`dsse_predicate_model_id`, `dsse_predicate_commit_sha`,
   `customer_key_fp_match`, and the `.model_id` / `.commit_sha`
   pins) inside any invariant-reachable operator body, classify its
   immediate syntactic context and **assert** it is an operand of an
   (in)equality operator (`=`, `#`, `/=`) or — for the boolean —
   used as a boolean. Arithmetic, ordering (`<`,`>`,`<=`,`>=`),
   function application exposing identity, and identity-distinguishing
   set membership all FAIL. Any reference not *positively* provable
   safe FAILS (sound over-approximation: unprovable ⇒ unsafe).

Because every invariant observes the collapsed quantities **only via
(in)equality / boolean-as-boolean**, each invariant's truth value is
a function of the 3-valued relation token and the kept boolean —
i.e. it factors through `AuditView`. The reduction therefore loses
no invariant violation: it is **lossless by construction**, and the
script is the machine-checked proof. The AST analyzer is a sound
over-approximation (it never passes a reference it cannot prove
safe) and is non-vacuous (a negative self-test confirms it flags an
injected arithmetic/ordering use of a collapsed field).

### Generation-time twin: the InitBase relation-class canonicalisation

A TLC `VIEW` collapses the *seen / state-queue* set but TLC still
**generates** every raw `InitBase` tuple before applying the view —
so the customer_dsse predicate × pin cross-product remained the
residual *generation* blow-up (init-state enumeration never reached
the BFS phase where the view's benefit applies). `InitBase`
therefore also pins the customer_dsse predicate fields to a
**canonical representative of each reachable relation class**, by the
*same* faithfulness property the AST proof establishes:

- `pins.model_id = NONE` ⇒ the relation is `q_none` for every
  predicate value ⇒ `dsse_predicate_model_id = NONE` (1 generated
  rep, was 3).
- `pins.model_id # NONE` ⇒ only `match`
  (`dsse_predicate_model_id = pins.model_id`) and `mismatch` are
  reachable; `NONE` is a canonical mismatch witness
  (`NONE # any non-NONE pin`), so the predicate ranges over
  `{pins.model_id, NONE}` — exactly the two classes (2 reps, was 3).
- Symmetric for `commit_sha`.

This is **lossless, not merely dedup-equivalent**: because every
invariant's verdict is a proven function of
`Rel3(dsse_predicate_*, pins.*)` alone (the AST proof), every dropped
predicate value is relation-equivalent to a retained representative
and yields an identical verdict on every invariant — so omitting it
from *generation* changes no checked property. It is the standard
canonical-representative `InitBase` pruning (same pattern as the
pre-existing dead-field pins), certified by
`check_audit_view_faithful.py` rather than asserted. The `VIEW`
is retained — it is the formal lossless artifact under review and
still collapses the residual successor/seen-set space; the
`InitBase` canonicalisation is its generation-time twin so TLC
actually terminates in tractable time.

### Corroborated by a mutation test

As an independent empirical check that the view does not mask
regressions: a customer_dsse invariant is deliberately broken (the
`Audit` terminal-dispatch clause `~customer_key_fp_match ⇒ FAILED`
weakened so a mismatched customer key no longer fails) and TLC is
re-run **with the view active**. TLC still reports an invariant
violation (`V5a_CustomerDssePinMismatchFails` counterexample),
proving the view did not hide the regression. Reverting the mutation
restores a clean run. See the final-report record of the
before/after TLC output.

### Residual soundness assumption

The faithfulness proof reasons over `audit.tla`'s source structure:
it assumes the spec uses the standard TLA+ operators it tokenizes
(`=`, `#`, `/=`, `\/`, `/\`, `~`, `=>`, `\in`, etc.) and does not
hide an identity-exposing observation of a collapsed field behind a
construct the tokenizer does not model (e.g. a user-defined operator
that returns one of the collapsed fields unequal-tested). The
call-graph closure and the conservative "unprovable ⇒ unsafe" rule
bound this: a new helper that touched a collapsed field unsafely
would have to do so via one of the classified syntactic shapes (and
fail) or via an unmodeled construct (and the analyzer, being
conservative on unknown contexts, fails closed). The mutation test
provides orthogonal empirical assurance.
