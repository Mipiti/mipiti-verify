# Changelog

All notable changes to `mipiti-verify` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The `audit` command's default output is now an auditor-first
  workpaper summary instead of the exhaustive evidence listing. Order:
  verdict line first, trust contract, contributing runs (one line per
  run, remediation detail kept for non-`VERIFIED` runs), the
  producer-disclosure cross-check outcome, an itemized Caveats section
  (producer warnings and auditor-side warnings, each with its
  remediation hint), per-control assertion counts with sufficiency
  status, condensed composition aggregates (entity table plus a single
  coverage line), and the compact cryptographic evidence blocks
  (provenance, content integrity, manifest). Detail auto-expands only
  on failure or degradation: a failed assertion prints its full row, a
  hash mismatch prints expected vs. recomputed hashes, an
  unresolvable or unverifiable run keeps its explanation and
  remediation lines. Exit codes are unchanged in both modes — scripted
  consumers should rely on exit codes (or opt into `--full`).

### Added

- `audit --full` flag restoring the previous exhaustive output in
  verification order: per-assertion result detail, the full
  composition/coverage enumeration with per-CO contributing controls,
  the inheritance-binding rows, and the producer's provenance-health
  panel.

### Fixed

- The sigstore library's "unsafe (no-op) verification policy used! no
  verification performed!" notice no longer leaks into `audit` output
  when no `--expected-ci-identity` is pinned. The notice contradicted
  the CLI's own accurate explanation (the cryptographic chain is
  verified; only the identity match is skipped) and is now filtered —
  targeted to that one message, only around the verification call.

- Run-level provenance verification for the `audit` command. Newer
  audit envelopes carry two additive top-level keys:
  `contributing_runs` (one entry per status-determining CI run, each
  carrying the exact canonical results text whose hash was signed,
  its own hash + signature + key material, the assertion ids that run
  determines, and optionally a per-run Sigstore bundle) and
  `provenance_health` (the producer's own coverage disclosure,
  rendered as a summary panel). Each run is verified independently —
  hash recomputed over the exact canonical bytes, signature over the
  hash, bundle when present — and reported as `VERIFIED`,
  `UNRESOLVED KEY`, `UNVERIFIABLE SERIALIZATION`, `TAMPER-MISMATCH`,
  or `UNSIGNED`. The verified runs reconstruct the report's
  verification state; assertions with no embedded determining run are
  reported as manifest-only provenance and cross-checked against the
  producer disclosure. A run declaring `unverifiable_serialization`
  (signed bytes can no longer be re-derived; predates canonical
  freezing) is a coverage limitation, distinct from a hash mismatch,
  and never fails the verdict; a genuine mismatch over present
  canonical text fails as tampering. Older envelopes without these
  keys verify unchanged, with run-level coverage reported as unknown.
- Remediation hints on audit failure lines. Every failure class
  (document signature invalid, run hash mismatch, unverifiable
  serialization, unresolved/orphaned signing key, missing Sigstore
  provenance, manifest-only assertions) now carries a one-line,
  auditor-audience remediation sentence rendered subordinate to the
  failure line.

- Seven RTL/Verilog assertion types: `module_exists`,
  `module_instantiated`, `port_exists`, `parameter_defined`,
  `signal_exists`, `sva_assertion_present`, and `register_reset`.
  Tier-1 verification runs deterministic RE2-based checks over
  Verilog/SystemVerilog source — module/primitive/program
  declarations, direct instantiations within a module body, ANSI and
  non-ANSI port declarations (optionally direction-qualified),
  parameter/localparam declarations (optionally value-matched against
  an RE2 pattern and scoped to a module), net/variable declarations
  (optionally kind-qualified), named SVA properties/assertions, and
  registers assigned inside reset-referencing always blocks. Each
  type also ships a tier-2 semantic template so the AI pass can
  reject comment-only matches, vacuous assertions, and reset branches
  that don't actually clear the register.
- Runner-side rendering for tier-2 semantic verification. The runner
  now carries one Jinja2 instruction template per supported assertion
  type (21 templates total) and renders the LLM input locally with a
  freshly-minted per-call boundary token. Instructions are the
  runner's published code (trusted, outside the boundary); assertion
  params and source-code excerpts are wrapped via the `| untrusted`
  Jinja filter (inside the boundary). The boundary token is generated
  via `secrets.token_hex(12)` at the call site, used once, and
  discarded — it never crosses the network and is never persisted.
- Vendored `_prompt_renderer` module with the boundary-token render
  framework, kept synchronized with the Mipiti backend's copy.
- `Tier2RunnerSide.tla` formal model with five invariants (T1 token
  freshness, T2 token secrecy, T3 instruction authenticity, T4 data
  isolation, T5 no-confusion with legacy backend fields). Wired into
  CI alongside the existing TLC checks.

### Changed

- `Tier2Provider.evaluate` now takes `assertion_type` and
  `assertion_params` keyword arguments instead of a pre-rendered
  prompt + backend-supplied boundary token. The runner constructs the
  LLM input from the structured wire payload; the backend no longer
  controls the prompt body.
- `Runner._verify_tier2` requires the backend payload to ship the
  structured `type` + `params` fields. A payload missing these
  surfaces a clear "Backend payload missing required `type` /
  `params` fields" error so operators can act, rather than degrading
  to a less-defended path. Coordinated release: requires the matching
  backend version that drops `tier2_prompt` + `tier2_boundary_token`
  from the wire payload. Customers running mismatched versions need
  to upgrade their CLI.
- New runtime dependency: `jinja2>=3.1` (used by the vendored
  template renderer).

### Fixed

- Per-run Sigstore bundle binding uses the run entry's
  `bundle_bind_hash`, matching the top-level bundle-bind check. The
  bundle's in-toto Subject digest is minted over the bundle-bind
  value, a different hash domain from `results_hash` (which binds the
  run's frozen `results_canonical` bytes); comparing the Subject
  digest against `results_hash` mismatches on every well-formed
  bundle, so every Sigstore-attested contributing run false-failed as
  `TAMPER-MISMATCH`. A genuine Subject-digest vs `bundle_bind_hash`
  mismatch remains the tamper signal; a per-run bundle with no
  `bundle_bind_hash` to bind against is reported as unbindable
  (warning-grade, `sigstore: unbound`) and the run's hash + signature
  path carries its verification.
- The top-level Sigstore block no longer prints `Certificate: (none)`
  for Fulcio-issued certificates, whose X.509 subject is empty by
  design (the identity lives in the SAN extension). The subject is
  printed when populated, the SAN URIs otherwise, and the line is
  omitted when neither is available.
- The provenance-health cross-check now uses the producer's coverage
  semantics: an assertion counts as run-covered only when its
  status-determining run passed the auditor-side verification (hash +
  resolved signature, or a verified Sigstore bundle). Previously the
  cross-check counted mere embedding — a report whose embedded runs
  all failed key resolution was reported as a false "Producer
  disclosure disagreement" against a correct
  `assertions_manifest_only` disclosure. Genuine disagreements
  (producer claiming coverage the auditor cannot verify) are still
  flagged.
- The "assertions determined by embedded runs that could not be fully
  verified" summary now sums determinations across ALL non-verified
  embedded runs; previously it was intersected with the report's
  accumulated assertion records, undercounting when several runs
  failed verification.
- The deprecated top-level results-hash pair no longer produces
  tamper-shaped output when the envelope embeds contributing runs.
  With run-level provenance present, the accumulated
  `verification_run.results` view is earned across multiple runs
  (each carrying its own independently verified hash + signature), so
  a divergence on the legacy pair is a deprecation artefact: it is
  now rendered as `NOT SCORED` (informational, no remediation line)
  and tamper conclusions come solely from the per-run checks.
  Envelopes without `contributing_runs` keep the strict behavior —
  there the legacy pair is the only content binding available.
- Audit-pack manifest section hashes are recomputed generically for
  any section name the manifest claims. Section hashes are, by
  contract, SHA-256 over the canonical JSON of the section exactly as
  present in the package, so the verifier needs no section-specific
  knowledge — `functional_tests`, `assertions_by_functional_test`,
  `contributing_runs`, `provenance_health`, and any future section
  now verify instead of being skipped with an unknown-section
  warning. A section named in the manifest but absent from the
  package is now a failure for every section name (previously only
  for names the verifier recognized).
- The provenance-health panel displays the additive disclosure fields
  `verified_as_of`, `attestations_near_expiry`, and
  `attestations_expired` when present; unrecognized disclosure keys
  never break rendering.
- Audit-pack manifest verification no longer requires the
  verification run's `public_key_pem`. The manifest is signed by the
  issuer's platform key, which is not necessarily the run's key; the
  manifest signing key is now resolved by `manifest_key_fingerprint`
  — via the embedded `manifest_public_key_pem` (offline), the
  envelope key or an in-scope platform key on fingerprint match, or a
  JWKS lookup — so packs whose run key is orphaned or
  workspace-signed verify their manifest correctly instead of failing
  with a missing-key error.
- `--output github` annotations and per-assertion text output now
  carry the threat model context (`[<title> <id8>]` prefix on every
  `::warning::` / `::error::` / `::notice::` title and group header).
  Previously the GitHub UI Annotations panel surfaced verification
  failures without model attribution, making it impossible to tell
  which model an `asrt_NNN` belonged to when running verification
  across multiple models in one CI step.

#### Tier-2 verification hardening (scope + fail-closed + source-loading)

Five layered fixes that close a false-positive INJECTION_DETECTED
class of failure and the deeper false-pass risk it accidentally
masked. The runner now refuses any assertion whose `repo` field
does not equal its auto-detected `self.repo` (sentinel `no_repo`
and the absent-`repo` legacy case excepted); when `self.repo`
cannot be auto-detected and was not supplied, the runner exits
non-zero rather than evaluating an unbounded set. Tier-2's
source-loading now resolves `params["pattern"]` for `test_exists`
/ `test_passes` types — previously tier-2 looked for `params["file"]`
and silently received empty source content while tier-1's pattern
glob succeeded; the keys-mismatch produced empty SOURCE_CODE that
the LLM either interpreted as an injection attempt (immediate
boundary close, returning INJECTION_DETECTED) or, under a
permissive prompt, could have evaluated as YES from the assertion
description alone. A pre-LLM guard now fails-closed at the runner
level if the source-code is unexpectedly empty for a type that
requires it, without invoking the LLM at all — the conservative
default `_EMPTY_SOURCE_OK_TYPES` is the empty frozenset, meaning
every type requires source-code evidence. The tier-2 templates
gain a universal fail-closed clause instructing the LLM that lack
of visible evidence is NEVER a YES verdict and that the assertion's
`description` is a CLAIM, not evidence — the LLM-side safety net
is now explicit rather than implicit.

### Deprecated

- The legacy `content_integrity.signature` over `content_integrity.results_hash`
  verification path is now flagged as deprecated. When an audit pack is
  verified via the legacy path only (no signed audit-pack manifest present),
  the CLI emits a yellow advisory naming the narrowed verification scope: the
  legacy path binds only `verification_run.results`, leaving the model
  definition, controls, assumptions, assertions, and composition section
  unsigned. The advisory recommends the pack issuer update Mipiti to a release
  that emits the manifest path. The legacy verification still produces a
  VERIFIED result for what it covers — exit code is unchanged (0 when the
  signature is valid). When both the manifest and legacy fields are present,
  the trust-contract line acknowledges that the legacy fields were ignored as
  deprecated. The legacy fields will be removed in a future release after a
  soak period.
