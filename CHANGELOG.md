# Changelog

All notable changes to `mipiti-verify` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
