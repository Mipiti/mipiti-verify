# `mipiti-verify audit` — formal spec

This directory contains a TLA+ specification of the security
invariants of the `audit` command (compromised-platform threat
model) and a Python BFS test that checks the actual implementation
against the same invariants. It complements the `VerificationPipeline`
spec in this directory which covers the verification pipeline's
fail-closed properties.

The bundle-binding contract (I14) is observable purely from the
envelope: the `content_integrity` block carries `bundle_bind_hash`
(and optionally `bundle_bind_signature`); the verifier compares
the value against the bundle's in-toto Subject digest directly,
with no canonicalisation. This verifier version requires
post-cutover envelopes — older envelopes that omit
`bundle_bind_hash` are rejected when a Sigstore bundle is
present.

## Files

- `audit.tla` — TLA+ module. Models the verifier as a pure function
  `Audit(Package, Pins) → Verdict` with cryptographic primitives
  abstracted as oracles. Invariants `I1`–`I14` encode the security
  properties of the **legacy** `results_hash`-scoped inline signature
  path.
- `audit_main_*.cfg` / `audit_bundle_bind.cfg` — TLC configs for the
  6-way compositional split of the legacy path (see
  `COMPOSITION.md`).
- `audit_manifest.tla` — TLA+ module for the **manifest signature
  path** (Option β; `docs/audit-pack-signing.md` in the parent
  repo). Models the verifier as a pure function
  `AuditManifest(Pack) → Verdict` over packs carrying the new
  `content_integrity.manifest` block. Invariants `B1`–`B7` encode
  authenticity, per-section integrity, tamper detection, backward
  compatibility, and selective-disclosure soundness.
- `audit_manifest_platform.cfg` / `audit_manifest_workspace.cfg` —
  TLC configs for the per-key_source slices of the manifest path
  (KS_PLATFORM / KS_WORKSPACE — the two classes where the manifest
  signature is the trust anchor; Sigstore and customer_dsse cover
  the whole body via DSSE and don't need the manifest).
- `../tests/test_spec_invariants.py` — Python BFS. Enumerates the
  same finite cross-product `Package × Pins`, runs the actual
  Python `audit()` Click command on each materialised package, and
  asserts the same invariants on the real verdict. In CI (with
  `id-token: write` permission) bundle-present rows mint real
  Sigstore bundles via Fulcio; locally and in fork-PR runs, those
  rows skip and only the no-bundle slice executes.

## Running TLC

Requires the TLA+ Toolbox or the `tla2tools.jar` distribution
(`https://github.com/tlaplus/tlaplus/releases`). With `tla2tools.jar`
on the classpath:

```bash
# Legacy results_hash path (one per key_source class):
java -cp tla2tools.jar tlc2.TLC -config audit_main_platform.cfg audit.tla
# Manifest signature path (one per key_source class):
java -cp tla2tools.jar tlc2.TLC -config audit_manifest_platform.cfg audit_manifest.tla
java -cp tla2tools.jar tlc2.TLC -config audit_manifest_workspace.cfg audit_manifest.tla
```

State spaces are small to medium (manifest sub-configs ~221K
distinct states each, ~1-2 s of TLC time; legacy sub-configs
1-9 min). A successful run reports `Model checking completed.
No error has been found.` and one or more states with each
invariant satisfied.

If an invariant fails, TLC emits a counterexample trace — a
specific `(pkg, pins)` value violating the invariant. That value
should be added as a regression test in
`test_spec_invariants.py` and then fixed in `cli.py`.

## Running the Python BFS

```bash
cd verify
py -m pytest tests/test_spec_invariants.py -v
```

The BFS does *not* require TLC. It is a self-contained pytest
file. The TLA+ spec exists as documentation of the
invariants and as a separate, mechanically-checkable artefact.

## Threat model and assumptions

**Primary threat**: a compromised Mipiti platform (i.e., the platform's
report-signing key is in attacker hands) attempts to ship a fabricated
audit package. The auditor uses pin flags (`--expected-ci-identity` /
`--expected-model-id` / `--expected-commit-sha` /
`--expected-workspace-key`) to bind the audit to upstream evidence the
platform cannot forge.

**In scope** (covered by invariants `I1`–`I13`):
- Pin-bypass by omitting upstream evidence.
- Forged Sigstore bundle from an attacker-controlled CI identity.
- Forged workspace-ECDSA submission from an attacker-held key.
- Cross-model substitution (real audit for a different model).
- Replay (real audit from an older verification run / different commit).
- Issuer self-attestation (bundle declaring its own issuer to bypass the pin).
- Tampered results (canonical hash mismatch) regardless of signature presence.
- Bundle bound to a different artifact than the package's claimed `results_hash`.

**Out of scope (assumed)**:

- *Auditor environment is trustworthy*. If the machine running
  `mipiti-verify audit` is compromised, the attacker can rewrite the
  pin values themselves; no client-side check defends against that.
- *Sigstore's trust root is honest*. The TUF root, Fulcio CA, and Rekor
  signing keys are taken on faith. For air-gapped or paranoid
  verification, pin a frozen trust config with `--sigstore-trust-config`
  so audit time has no outbound dependency.
- *Customer's CI / workspace key is confidential*. The pin's structural
  defense rests on "only the customer can produce evidence binding to
  the customer's identity." If the attacker holds the customer's GitHub
  Actions OIDC or the workspace ECDSA private key, they can produce
  evidence that legitimately matches every pin. **Customers MUST**:
  - Generate the workspace ECDSA private key on a trusted machine and
    keep it in a secrets manager (cloud KMS, GitHub Actions repository
    secrets, Vault, etc.) — never on a developer laptop or shared drive.
  - Restrict CI workflows that can mint Sigstore bundles to protected
    branches and the necessary `permissions: id-token: write` scope.
- *The `mipiti-verify` binary itself is not downgraded*. Pin
  `mipiti-verify` to a specific version digest in CI:
  - GitHub Action users: pin by commit SHA, e.g.
    `uses: mipiti/mipiti-verify-action@<40-char-sha>`, not `@v0.34` or
    `@main`.
  - pip users: install from a hash-locked requirements file with
    `pip install --require-hashes -r requirements.lock`. PyPI
    publishing uses Trusted Publishing + Sigstore attestations, so
    the version pin chains back to the same Sigstore trust root the
    audit verifier itself uses.

**Pin layering — what each pin defends against**:

| Pin | Standalone use | Requires `--expected-ci-identity`? |
|---|---|---|
| `--expected-ci-identity` (+ `--expected-issuer`) | ✓ | — |
| `--expected-workspace-key` | ✓ | — |
| `--expected-issuer` | usage error | yes (policy.Identity needs both SAN and issuer) |
| `--expected-model-id` | usage error | yes (predicate pins need SAN to be effective against compromised platform) |
| `--expected-commit-sha` | usage error | yes (same reason as model_id) |

The reason model_id and commit_sha cannot stand alone: the bundle's
predicate is signed by Fulcio, but Fulcio signs whatever predicate
the OIDC-token-holder supplies. An attacker who can mint *any*
Fulcio bundle (under their own CI's OIDC) can craft predicate
values matching any auditor pin. The SAN pin is what constrains
*whose* OIDC was used. Since the flag's advertised purpose is
compromised-platform defense, the audit fails closed (exit 2) when
a predicate pin is set without a SAN pin — same precedent as
`--expected-issuer` alone, which has zero effect (`policy.UnsafeNoOp`
is chosen instead). Auditors with the narrower "I just want a
cross-model sanity check" use case can perform that check by
inspecting the audit's printed `predicate.model_id` line manually,
or by reading the bundle's predicate out-of-band.

**Operational hardening**:

- *Input size cap*. The audit refuses to load files larger than 64 MB
  to prevent a malicious gigabyte-sized package from OOMing the
  auditor's CI runner. Real audit packages are a few MB at most.
- *HTML report + identity pin = usage error*. HTML reports don't
  carry the upstream evidence (Sigstore bundles, workspace-ECDSA
  signatures) that identity pins bind to. Passing a pin flag with an
  HTML report fails closed (exit 2) rather than silently exiting 0
  with the pin dropped — same fail-closed reasoning as
  `--expected-issuer` alone.
- *Custom Sigstore trust root, no silent fallback*. When the auditor
  passes `--sigstore-tuf-url` or `--sigstore-trust-config` and the
  installed sigstore-python version doesn't expose the trust-config
  API, the audit fails loudly with a clear error rather than
  silently using the public Sigstore (which would replace the
  auditor's chosen security guarantee).
- *Strict malformed-bundle rule*. A package containing a Sigstore
  bundle but no `content_integrity.results_hash` for it to bind to
  fails the audit unconditionally — regardless of pins or
  workspace-ECDSA fallback. Without this, the audit could otherwise
  return "VERIFIED — content intact" via the workspace path while a
  Sigstore bundle visible in the package was effectively ignored,
  which would mislead the auditor about what was actually verified.

**Naturally mitigated**:
- *Malicious customer presenting a forged audit to a third party*. The
  third party runs `mipiti-verify audit` themselves with pins they
  derived from the customer's public infrastructure (GitHub repo
  workflow file, customer's published workspace public key). The audit
  binds the package to those pins regardless of what the customer
  claims, so a forged package fails the third party's verification.
- *Replay across commits*. The audit binds to a commit SHA via the
  bundle's signed predicate. With `--expected-commit-sha`, the auditor
  rejects any package whose embedded commit SHA differs from the
  release they're certifying. Without the flag, the auditor would need
  to manually inspect the bundle predicate — error-prone but not
  insecure if performed.

## What the abstraction covers and does not cover

**Covered**:
- Pin-bypass-by-omission for SAN, model_id, commit_sha, and workspace
  key (`I1`, `I2`).
- Issuer never self-attested by the bundle (`I3`).
- Workspace fingerprint bound to the actual signing key (`I4`).
- VERIFIED verdict requires actual cryptographic verification (`I5`).
- Content hash binds to actual results, regardless of signature
  presence (`I6`). The BFS surfaced an early version of `cli.py`
  that gated this check on `content_integrity.signature` being
  present — a forged package could ship a real Sigstore bundle
  bound to one hash and tampered `verification_run.results` and
  the audit would not catch the discrepancy. The canonical-hash
  check is now hoisted to run whenever `results_hash` is claimed.
- Usage error for pinning issuer alone (`I7`).
- Bundle bound_hash matches the envelope's `bundle_bind_hash` on
  positive verdict (`I8`) — defense-in-depth on top of Sigstore's
  verify_artifact.
- All present signatures must be valid, not just one (`I9`).
  Strengthens `I5`: a VERIFIED package with a valid bundle and an
  invalid co-located workspace signature is not VERIFIED.
- Unbindable bundle (no results_hash) cannot yield VERIFIED (`I10`).
  A bundle present without the results_hash it was minted to bind
  to is structurally malformed; the audit emits UNVERIFIED rather
  than letting the bundle quietly drop from verification.
- Bundle SAN matches the auditor pin on VERIFIED (`I11`) —
  symmetric counterpart of `I3` for SAN.
- Bundle predicate `model_id` matches the auditor pin (`I12`) —
  defends against cross-model substitution. The model_id is read
  from the bundle's signed in-toto predicate, never from the
  package's outer (unsigned) metadata.
- Bundle predicate `pipeline.commit_sha` matches the auditor pin
  (`I13`) — defends against replay of an older verification run
  for a different commit. Same source: signed predicate, not outer
  metadata.
- Bundle bind via explicit envelope hash (`I14`). The envelope
  carries a `bundle_bind_hash` field that the verifier compares
  *directly* to the bundle's in-toto Subject digest — no
  canonicalisation, no rehashing on either side. When the envelope
  also carries `bundle_bind_signature`, the verifier checks it
  against the platform public key embedded alongside it. A
  Sigstore bundle present in the envelope without `bundle_bind_hash`
  is rejected: an envelope-side binding is required to verify that
  the bundle is bound to the package the auditor was handed. Defends against:
    - issuer-side regressions where the binding value is computed
      one way at signing and another way at verifying;
    - silent acceptance of a bundle whose Subject digest doesn't
      match anything the envelope explicitly commits to;
    - tampered `bundle_bind_hash` (caught by the platform
      signature when populated).

**Abstracted away (oracles)**:
- The Sigstore trust chain (Fulcio CA + Rekor inclusion proof + SCT)
  is modelled as a single boolean `bundle.valid`. The TLA+ spec
  cannot prove ECDSA is sound; it can only check that the *call
  structure* uses the primitive correctly.
- ECDSA signature verification is `ws_sig.valid`.
- Canonical fingerprint computation is the identity on the abstract
  `signing_key_fp` field.

**Out of scope**:
- Sigstore TUF root freshness, Rekor witness scheme.
- Attacker compromising Fulcio's signing key.
- Implementation bugs unrelated to the invariants (regex parsing,
  exception ordering). These are caught by the per-feature pytest
  suite, not the BFS spec test.

## When to update the spec

If the threat model changes — for example, a new pin flag is added,
or the verdict logic acquires a new exit path — update `audit.tla`
first to express the new invariant, then run TLC, then update
`cli.py` to satisfy it, then verify the BFS passes. The spec leads;
the implementation follows.
