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
| `V1_SigstoreSkipSoundness` | Premise: `bundle_bind_hash = bundle.bound_hash` AND `bundle_bind_signature ≠ FALSE`. Must explore the full domain to confirm the conclusion holds on all premise-satisfying states. |
| `V2_OrphanWithBundleVerified` | Same as V1 with `KS_ORPHAN`. |

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
skip sets and to `I9`'s skip set; it introduces no new
`bundle_bind`-dependent premise or conclusion, so the partition
argument and `ConfigMainCompositionLemma` above remain sound
unchanged.
