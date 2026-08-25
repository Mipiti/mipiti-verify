# Changelog

All notable changes to `mipiti-verify` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The signed attestation payload now carries each assertion's content
  (id, type, params, description), binding (control / assumption /
  functional-test / node ids, repo) and provenance (origin, inherited-from
  model, author, creation time) instead of the full pulled record. The
  platform's stored verdict state from earlier runs (tier statuses,
  reviewer prose, verification timestamps, coherence results, supersession
  and deletion flags) is left out: CI did not verify it, and the run's own
  verdicts travel in `results`. The content hash is unchanged.
- RTL verifiers (`module_exists`, `module_instantiated`, `port_exists`,
  `parameter_defined`, `signal_exists`, `sva_assertion_present`,
  `register_reset`) read repository files only. Their subject is an RTL
  source by definition, so a `target` param is refused with a clear message
  instead of being resolved to platform-held content. The set of assertion
  types that accept a target is now exactly the set whose verifier reads
  through the shared file-or-target resolver.

- Tier 1 for `function_exists`, `class_exists`, `import_present`,
  `decorator_present` and `function_calls` now requires the shape of the thing
  being asserted, not an occurrence of a name. Each of these types answers a
  question about how a file is written — is this symbol defined here, is this
  module imported here, is this decorator applied to this function, does this
  function call that one — and each previously answered it from a pattern that
  ordinary English also produces: for a function, the name followed by an open
  paren; for a type, a declaration keyword followed by the name; for an import,
  one of the words `import`, `from` or `use` followed by the module name; for a
  decorator, the decorator's name followed somewhere below by the function's;
  for a call, the callee's name followed by a paren anywhere in the text after
  the caller. None of those shapes is peculiar to code. A sentence, a comment,
  a docstring, a string literal, a JSON value or a markdown heading produces
  them as readily as a source file does, so an assertion could report a
  mechanical pass against a file that merely mentions the subject. A pass now
  means the construct is written in the file.

  This matters because the mechanical tier is where these questions are
  decided. Each of these types states a structural fact about how a file is
  written, and the rest of the pipeline builds on that answer rather than
  re-deriving it, so the mechanical answer has to be exact.

  For a function, the definition starts its own line, preceded only by
  indentation, modifiers and a return type, and its parameter list is followed
  by a body or by a declaration terminator — an opening brace, a complete
  one-line body, or a semicolon closing the line. A modifier keyword ahead of
  the name is not enough on its own; any modifier prefix is matched against a
  fixed set of keywords rather than against an arbitrary word. Coverage of real
  definitions is unchanged or wider. The forms the previous general pattern
  reached are still reached — Go functions and methods with a receiver, C and
  C++ functions, prototypes and out-of-line members, Java and C# methods,
  Kotlin, Swift, JS/TS class methods, object-literal shorthand, getters and
  generators — across wrapped signatures and parameter lists containing
  parentheses. Functions bound to a name rather than declared are now
  recognised at the definition itself: arrow functions and class-property
  arrows, `var f = function`, Go `var f = func`, and Python `f = lambda`. Two
  forms are deliberately out of scope because nothing distinguishes them from
  running text: a Go interface method, which carries no terminator at all, and
  a definition placed mid-line inside a single-line object literal.

  For a type, the declaration starts its own line, preceded only by indentation
  and modifiers drawn from a fixed set — `public`, `private`, `protected`,
  `internal`, `abstract`, `final`, `sealed`, `static`, `partial`, `export`,
  `export default`, `declare`, `open`, `data`, `case`, `typedef`, `pub` and its
  scoped forms — and it is followed by something that opens or terminates a
  declaration: a body brace at the end of the line or on the next one, a Python
  colon with a structured base list, a semicolon closing a forward declaration
  or a unit or tuple struct, or a complete one-line body. A base list may wrap
  across lines the way a formatter writes a long one, and only a clause that
  actually began may wrap. Covered: Python classes, bare and with bases,
  decorated, nested, and with PEP 695 type parameters; Java and C# classes,
  annotation types, generic declarations and the Allman brace; TypeScript and
  JavaScript classes and interfaces, exported and default-exported, with
  wrapped `extends` lists; Rust structs — unit, tuple, generic and
  `where`-bounded — and enums; Go `type X struct` and `type X interface`,
  generic and inside a `type (…)` block; C and C++ structs, enums, scoped
  enums, forward declarations and `typedef`s; and Kotlin, Scala and Swift
  declarations that carry a body.

  Two type forms are deliberately out of scope, because a line carrying neither
  a body nor a terminator is indistinguishable from a line of documentation:
  Ruby's `class Foo` and `class Foo < Base`, and the Kotlin, Scala or Swift
  declaration whose primary constructor is the whole of it. TypeScript `type X
  = …` aliases are still not recognised, as they were not before.

  For an import, the statement occupies its own line and ends where a statement
  ends — at a semicolon, at the end of the line, or at a quoted module path —
  or it is a call whose argument is the quoted path. Covered: Python `import`
  and `from … import`, dotted, aliased, relative, comma-separated and wrapped
  in parentheses; JavaScript and TypeScript ES modules, default, named,
  namespace, type-only and side-effect, re-exports, `require` and dynamic
  `import`, with the specifier list or the specifier itself wrapped across
  lines; Go single imports and import blocks, aliased or not; Rust `use`,
  including grouped, aliased, `pub` and scoped-`pub` forms, and `extern crate`;
  Java and Kotlin imports, static and wildcard; C# `using`, static and aliased;
  the C, C++ and Objective-C preprocessor include; Ruby `require` and
  `require_relative`; PHP `use`; and the SystemVerilog package import. A module
  path covers itself and everything under it, so importing a submodule
  satisfies an assertion naming its package; the reverse does not hold, since
  naming the submodule claims strictly more than importing the package. Two
  forms are out of scope: a Rust brace-grouped `use` satisfies an assertion
  naming the path before the brace but not one naming a member inside it, and a
  specifier assembled at run time from a variable names no module to check.

  For a decorator, the decorator has to sit against a definition of the named
  function, by the same standard the existence types apply, with only further
  annotations, comments and blank lines between the two. Arguments may wrap
  across lines, which the previous single-line tail handled only by accident,
  and so may other annotations in the same stack. The decorator's name is
  matched against its full dotted path or its final segment — the leading path
  is how the decorator was reached rather than part of its identity — and on
  whole segments, so a decorator whose name merely begins with the one asserted
  no longer satisfies it. Python's decorator spelling in a file that is not a
  Python source is read as a quotation of code rather than as code; the
  annotation forms of the other languages are available to every source.

  For a call, the caller has to be found by the definition shape rather than by
  a keyword and a name, so a caller named in running text no longer hands the
  search whatever follows it as if it were a body; and the search runs over a
  copy of the source with comment and string-literal interiors blanked, so a
  callee named in a comment or quoted in a message is not a call. Blanking
  preserves every position and every newline, so line numbers and the
  indentation the body slice reads are the file's own. It knows the languages'
  comment and string forms, not their grammars, and it fails toward missing a
  call rather than inventing one: it never removes anything that is not a
  comment or a literal's interior, and it leaves preprocessor directives,
  private-member syntax and template-literal interpolations intact.

  Python is now decided by the parser rather than by a pattern, for all five
  types. A `.py` or `.pyi` source is parsed and the question answered against
  the tree — a definition node with that name at any depth, an import node, the
  decorator list held against the definition it belongs to, a call inside the
  caller's body — so formatting the patterns do not anticipate cannot produce a
  miss, and a comment, a docstring or a string literal cannot produce a pass,
  since none of them can produce a node. A dynamic import with a literal module
  name counts as an import. A source that will not parse falls back to the
  patterns, which remain the only path for every other language.

  An assertion that passed only because its subject was mentioned now fails,
  and has to be restated against a file where the construct is actually
  written.

- A `target` param, which points an assertion at the model's feature
  description instead of a repository file, is now accepted by exactly two
  assertion types: `pattern_matches` and `pattern_absent`. Both decide tier 1
  with a caller-supplied regex over arbitrary text, and both state their
  tier-2 criterion over the matched text itself, so a prose description is a
  subject they are defined for. Every other type states its criterion over
  source-language structure (a definition, an import, a decorator, a call, a
  registration, a configuration reference) or over the role the scanned
  artifact plays in the running system, which a description does not carry.
  Those types now read repository files only and refuse a `target` with a
  clear message: the code-structure types (`function_exists`, `class_exists`,
  `decorator_present`, `function_calls`, `import_present`), the semantic types
  (`parameter_validated`, `error_handled`, `middleware_registered`,
  `http_header_set`), `env_var_referenced`, `no_plaintext_secret`, and the RTL
  types (`module_exists`, `module_instantiated`, `port_exists`,
  `parameter_defined`, `signal_exists`, `sva_assertion_present`,
  `register_reset`). A claim about the design text that was previously
  expressed through one of those types is expressed as `pattern_matches` or
  `pattern_absent` against the same `target`, with no loss of coverage.

- Tier-2 semantic verification now states its criterion in the terms of the
  subject it is reading. When an assertion names a platform target — the
  model's feature description — the `pattern_matches` and `pattern_absent`
  templates state their criterion against a design specification rather than
  against source code, and name that subject to the reviewer, so the semantic
  tier is no longer asked whether a passage of prose is a correct
  implementation. Every other template is unchanged, and so is the rendering
  of an assertion verified against a repository file: an assertion that names
  no target produces the prompt it produced before, byte for byte. The
  description text is also no longer repeated inside the params shown
  alongside it — it is already the payload under review, and rendering it
  twice under two labels doubled the prompt for a long specification. Only
  the prompt changes: what tier 1 evaluated, the stored params, and any hash
  taken over them are untouched. Assertions of this shape are not new, so an
  existing one is reviewed on different terms after upgrading and its tier-2
  verdict can move.

- Tier-2 semantic verification of `function_exists` / `class_exists`
  assertions now reviews the isolated definition block instead of the
  enclosing file. Existence is decided by the structural tier; the semantic
  tier judges only the body, so it is no longer asked to locate the symbol
  before judging it. Python definitions are cut by `ast` (decorators
  included); other languages use a line-based block heuristic (matching
  brace, or indentation). When the block cannot be isolated the reviewer
  receives the enclosing file as before.

### Security

- A pattern assertion must now be capable of failing. `pattern_matches` and
  `pattern_absent` reject a regex the subject has no way to refute: for
  `pattern_matches`, a regex the empty subject already satisfies, and for
  `pattern_absent`, a regex no subject can satisfy. In either shape the outcome
  is a property of the regex rather than of the content, so it establishes
  nothing about what was scanned. `pattern_matches` also rejects a match that
  consumed no character of the subject, on the same principle: the proof has to
  be witnessed by the content. The rejection is a tier-1 FAIL whose detail
  names the reason, so an assertion built on such a regex that passed before
  this release now fails, and has to be restated as a regex its subject can
  refute. The check is applied to the pattern the mechanical tier evaluates,
  inline flag modifiers included, and is deliberately one-sided — anything it
  cannot read unambiguously proceeds as before, and a pattern the engine cannot
  compile keeps reporting itself as one.

- Tier-2 semantic verification now defers to the deterministic structural check
  for symbol existence on `function_exists` and `class_exists` assertions.
  Whether a symbol exists is a structural fact, decided by the mechanical tier;
  the semantic tier assesses the quality of a symbol that exists and is no
  longer a source of truth for existence itself. Before consulting the model,
  the runner re-runs the structural check on the full file (the same check the
  mechanical tier applies) and skips the semantic pass when the symbol is
  absent, so tier 2 can only ever downgrade a result, never establish one. A
  symbol that is genuinely present still proceeds to the quality check
  unchanged.
- Raised the `cryptography` floor to `>=50.0.0` (from `>=48.0.1`) to clear
  advisory PYSEC-2026-3552. The three hash-pinned lockfiles are regenerated
  accordingly (`cryptography` 49.0.0 → 50.0.0, and its dependent `pyopenssl`
  26.3.0 → 26.4.0); no other resolved versions change.

### Added

- The `audit` command now renders the audit pack's `findings` section — the
  full dispositioned finding set (open, remediated, and dismissed), grouped by
  disposition with a per-bucket summary. Each finding shows its kind, control,
  severity, and title; dismissed and remediated findings additionally show who
  disposed of them and why, so an auditor sees not only the live gaps but the
  decisions that closed or accepted the rest. Finding kinds are displayed
  directly from the pack data (never matched against a fixed list), so kinds
  introduced later still render. The section is additive: packs without it
  render nothing, and the render is informational (it never changes the audit
  verdict). Signed packs that include the section already verify unchanged —
  manifest verification hashes every section the manifest enumerates.

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
