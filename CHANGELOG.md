# Changelog

All notable changes to `mipiti-verify` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
