# Changelog

All notable changes to `mipiti-verify` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Two assertion types whose pass is a statement about EVERY site in a declared
  scope rather than about one place. `sink_default_deny`: over every source
  file in `scope`, every site of a declared sink receives, at each guarded
  position, only a form the declared `safe_forms` vocabulary accepts, or is an
  allowlisted site with a reviewed reason. `typed_boundary`: every guarded sink
  position receives a value built through a declared constructor of
  `boundary_type`, and every construction site of that type takes only literal
  or named-constant arguments. A sink is a call, a constructor, a macro
  invocation, a store to a named target or a module instantiation, so a
  hardware description is read by the same rules as a software source
  (Verilog, SystemVerilog and VHDL alongside Python, JavaScript, TypeScript,
  Go, Rust, Java, Kotlin, C, C++, C#, Ruby, PHP and Swift).

  What makes the verdict worth something is what the check refuses. A pass is
  returned only when every site in the declared scope was examined and each
  one proved safe, so everything that leaves a part of the scope unexamined is
  a refusal: a scope that matches nothing; a file it cannot read, whose
  extension names no language, that the parser rejects, or in a language this
  install has no parser for (reading a language other than Python needs the
  `ast` extra; the refusal names it); a link anywhere in the region an entry
  searches, matched or not, since a pattern walk does not descend through a
  linked directory and a linked file names content under a path the tree does
  not own; a scope over 5,000 files, over 2 MiB in one file, or over 16 MiB in
  total, all of which arrive as "narrow it" rather than as a job the machine
  killed; and a chain of functions forwarding into a sink deeper than 12 hops,
  where the sink set had not closed when the budget ran out. Every site it
  could not classify counts as a violation, as does reflection, dynamic
  evaluation, a macro body naming a sink, a shell invocation built from a
  variable, and a sink handed on as a value. Import and assignment aliases,
  and in-scope wrappers that forward a parameter into a guarded position, are
  sinks themselves, closed to a fixpoint. An allowlist entry must name a file,
  a site, a callee, a reason and a reviewer and must match a site the check
  actually flagged; a stale entry fails the run, the allowlist content sits
  inside the evidence hash so editing it reopens review, and no entry
  suppresses a scope or parse refusal. An exception excepts a site the run
  examined, so the list cannot be longer than the sites in scope, and a run
  whose every flagged site is an exception -- with nothing anywhere in the
  scope admitted by form -- has decided nothing mechanically and is refused
  as vacuous. A safe form is decided from the value and never from where it
  sits: `parameter_binding` names a data structure written at the site every
  element of which is itself an admitted form, so a structure holding an
  interpolation, a name that is not a constant, a call or another structure
  is a violation, and so is one no element could be read from. What a callee
  does with a value it accepts is a property of the callee and is not read,
  so a sink taking bound values in a later argument is declared by naming the
  statement position in `positions`, which leaves the data positions
  unguarded. The one residual -- a
  sink reached under a name in neither `sinks` nor `wrappers` -- is stated in
  the result and is what the semantic tier reviews, over the inventory the
  mechanical tier built rather than by re-scanning.

  A verdict's details carry the counts, the refusal reasons and a per-parser
  file count, and stay inside the size a result may be submitted at whatever
  the submission holds: a per-site listing beyond that budget is dropped with
  a line saying how many were left out, a refusal states its first reasons
  and then how many it did not list, and the whole string is cut to the bound
  as a last resort, so one oversized row can never reject the batch it
  travels in. The counts stay complete. Paths in a verdict are
  repository-relative, so a filesystem error contributes its reason and never
  the checkout's location on the machine that ran it. Within one invocation a
  scope is read and parsed once for both the verdict and the inventory the
  semantic tier is shown.

- `attest-construction` and `attest-allowlist-review`: two signed statements
  for the facts a repository cannot settle on its own. The first compiles
  probes that build a boundary type from something that is not a literal and
  records the ones the toolchain refused (a probe that compiles writes
  nothing and exits non-zero; probes are compiled, never run). The second
  records the reviewed exceptions and who stands behind them at this commit.
  A probe the toolchain never answered on -- no tool installed, no project
  file above the source, a command that would not start or ran out of time --
  is reported as an absent answer and signs nothing, since only the
  toolchain's own rejection of a probe is evidence about the type.
  Neither changes a verdict; each replaces "on the author's word" with "in a
  signed statement" in the facts a reader sees. Both kinds are declared in
  `schemas/test-result-v1.schema.json`, and neither evidences that a test ran.

- Every assertion type now declares the CLASS of fact its verdict reports --
  `presence`, `under_approximating_scan`, `existential_witness`,
  `sound_over_approximation` or `by_construction` -- at the one place the type
  is registered, so no reader infers strength from a type's name, its
  parameters or a file path. A test file existing, and a symbol inside one,
  are `presence`: they prove something exists, never that it ran. The
  vocabulary and the per-type class are held equal to the assertion-type
  catalogue by `formal/check_types.py` (T5, T7), which also holds the sink
  vocabulary equal across the two declarations (T8: the safe forms and the
  sink kinds, each put through the engine's own params reader), and
  `formal/check_sound.py` proves over a grammar of programs that the sound
  engine's flagged set contains every unsafe site, self-validating that each
  of its enumeration features is load-bearing and naming the programs it
  refuses on purpose -- those whose safety would rest on a fact about the
  callee -- so a build that started passing one would fail the checker.

- A `mechanism_found` fact on a `test_attested` result, and in the facts block
  the semantic tier is shown: whether the named mechanism resolves to a
  definition in the checkout. A mechanism that cannot be located leaves every
  claim about it unresolvable, which now reads as a stated fact rather than as
  two unexplained unknowns.

- Tier-2 self-consistency and evidence-keyed verdict reuse, so a nondeterministic judge cannot flicker a control's verified status between runs. Each fresh evidence is judged N times (N=3 default; `--tier2-consistency-n` / `tier2-consistency-n` input / `MIPITI_TIER2_CONSISTENCY_N`) and the spread decides: a PASS requires every judgment to agree, a unanimous fail is a confident fail, an all-inconclusive vote is skipped, and anything else is a split — reported not verified and deliberately not cached, so a borderline verdict is never frozen into a lucky green. Each verdict is keyed by a hash of exactly what the judge is shown (assertion type, params, assembled source, subject kind, the per-type template bytes, provider and model); when the platform returns a stored verdict for an unchanged hash the runner reuses it with no judge call. A confident assertion converges to a cached pass over a run or two; a genuinely borderline one never caches green.

### Fixed

- The semantic judge is no longer asked to locate what the mechanical tier
  already located. A `test_attested` assertion whose mechanism is imported
  rather than defined (a framework middleware class, say) showed the judge
  a mechanism section reading "not found", and the judge answered in kind;
  it now shows the sites in the file that reference and configure the
  symbol. Every presence-type prompt ends with the mechanical tier's own
  finding ("defined at line 131", "pattern found"). When a not-found
  refusal is still set aside, the recorded details carry the structural
  finding and the judge's reasoning, so the cause is readable instead of
  a bare "unanswered".

### Fixed

- An absence assertion (`pattern_absent`, `no_plaintext_secret`) can pass
  tier 2. Its templates asked the presence question ("lack of visible
  evidence is never YES") and offered a `NOT_FOUND` reason that, for a
  target expected to be absent, restated the structural result; the
  runner then set the verdict aside as a contradiction and the assertion
  stayed pending, so a control whose clause is provable only by an
  absence could never reach verified. The templates now ask whether the
  confirmed absence proves the aspect (the regex could be too narrow, the
  behaviour reachable another way, the file the wrong place), offer only
  a `QUALITY` reason, and say the scan covered the whole subject when the
  judge sees an excerpt. Absence types are exempt from the not-found
  discard, so a stray one is a plain refusal rather than a permanent skip.
- The `test_attested` template says outright that an unmeasured fact
  ("reached mechanism: unknown") is never a ground for NO.

### Changed

- Formal checks in CI take a third of the time. `audit_bundle_bind.cfg`
  and `audit_main_orphan_legacy.cfg` are split per `key_source` class
  (`audit_bind_*.cfg`, `audit_main_orphan.cfg`, `audit_main_legacy.cfg`),
  each its own matrix job, since TLC enumerates a spec's initial states
  on one thread; the partition checker asserts the Config-2 split is total
  and disjoint. The audit-spec implementation sweep runs its rows across a
  fork pool and hands every row a pinned Sigstore trust root instead of
  refreshing it per row.

### Fixed

- A dependence pair that recorded no outcome now says why in the verifier's
  details (`fails without mechanism: not established (<reason>)`), and the
  refusal outside a git checkout names the alternatives (`--strategy hook`;
  runtime disabling for Python and JavaScript). The README states the git
  requirement of source mutation.
- `run --all` reports on the models bound to the repository it runs in. A
  model whose description provenance names another repository is skipped
  with one notice. One that names this repository has every coverage gap
  reported, evidence or not. One that names none, and has no assertion
  bound to this repository, gets a single line saying so instead of one
  warning per control; the report carries `repo_bound_assertions`.
- `MIPITI_ATTESTATION_DIR` names where attestations are written and read
  (default `.mipiti/attestations` under the project root). The action sets
  it to a directory of its own when the checkout is not writable by the
  container's user, so no `chmod` of the workspace is needed.
- `formal/check_adapters.py` without the parser extra: the properties that
  need a parser (mutation confinement, the drive for the compile and
  clean-tree gates, the parser-versus-fallback comparison) are reported
  not established instead of failing or aborting; the runtime's refusal to
  mutate what it cannot isolate is unchanged.

### Added

- A source mutation runs only on a definition the language layer isolates
  exactly (`scope: symbol`, from a parser or the HDL keyword scanner). A
  span the line heuristic can only offer as a `block` may be a different
  definition, and a mutation of the wrong block can still compile, so the
  pair is `error` with reason `definition not isolated exactly (install
  mipiti-verify[ast] or nominate a unique symbol)`. Formal property A8 in
  `formal/check_adapters.py`.

- Command output (test runs, suite runs, coverage runs, compile checks) is
  streamed to a temporary file and only its last 64 KiB read back for a
  reason string, so memory stays bounded whatever a harness prints.

- The end-to-end runner tests that wrap a toolchain in `sh -c` skip on a
  runner without a POSIX shell.

- Property-based checks (`hypothesis`, in the `dev` extra) over the
  definition locators and the coverage readers: `locate` never raises on
  arbitrary text and every span it returns is the file's own lines
  carrying the name; `hash_of` ignores line endings and trailing blanks and
  nothing else; the HDL keyword scanner never raises and its blocks nest;
  `read_coverage` returns a report or its own error on any bytes, with only
  positive line numbers under normalised repository-relative paths;
  `parse_junit` returns a summary or its own error. Three findings fixed
  along the way: a deeply nested Python file no longer escapes as
  `MemoryError` from the parser, a coverage path with a `..` segment is
  folded (and dropped when it climbs out of the root) instead of kept
  verbatim, and a negative line number in a coverage.py export is ignored
  like a zero.

- `attest-reach --suite-cmd "<command>" --coverage-file <report>` (action:
  `suite-cmd` with `reach-pairs`): reach for a harness that cannot run one
  test alone. The suite runs once under coverage and every nominated test
  records what the suite executed in its mechanism's file as
  `suite_reached`, with `predicate.reach_scope = "suite"` (schema: optional
  `reach_scope`, `test` | `suite`; per-test records now carry `test`).
  Stated for what it is: per-test reach is undefined for such a harness,
  so a suite-scope record is information and never yields `reached`. The
  verifier's details line and the tier-2 facts block read
  `reached mechanism: unknown (suite-level coverage only)` when that is
  all there is. `formal/check_evidence_records.py` gains a suite-scope
  reach axis (8 axes, 15120 combinations) showing R3 never sets the fact
  from it.

- `attest-dependence` stubs a Verilog / SystemVerilog `module` declared in
  the non-ANSI style (`module m(a, y); input a; output y; ...`): the
  header is kept, the body's port declarations are re-emitted verbatim
  (directions, `wire` / `reg` / `logic`, packed ranges, `signed`, comma
  lists), every `output` is driven to `x` (`assign` for a net, an
  `always_comb` / `always @*` block for a variable), and the stub ends
  with `endmodule`. The declarations are read with the grammar when the
  `[ast]` extra is installed and by the keyword scanner otherwise. A port
  the header names without a declaration in the body, or a declaration
  naming a port the header does not list, is `error` with the reason.

- `no_plaintext_secret` refuses an empty or omitted `patterns` list: an
  absence check names what it checked for, or it establishes nothing.

- Formal checks over every verifier, every assertion type, the composition
  of test-evidence records, and every runner adapter
  (`formal/check_verifiers.py`, `formal/check_types.py`,
  `formal/check_evidence_records.py`, `formal/check_adapters.py`), each exhaustive over its space and
  cross-checked against an independent oracle: a structural verifier passes
  only when its condition holds and fails closed otherwise; a type is stated
  consistently across the catalogue, its verifier's parameter reads, its
  tier-2 template and its evidence class; a mutated source file is restored
  byte-for-byte, changed only within the named definition, compile-checked
  before the test runs, and refused when the working tree is dirty; a
  `test_attested` pass comes only from a test-result record at the commit,
  and the reach and dependence facts only from a record that was actually
  run at that commit for that mechanism. Each
  runs as an ordinary test, so CI runs them on every push. The verifier
  registry now states each type's evidence class (`presence` or
  `behavioral`) via `EVIDENCE_CLASS` / `evidence_class()`.
- Test-result attestations carry each test's definition: `attest-tests`
  locates every recorded test in the checkout and records its `file` and a
  `definition_sha256` over the definition block (or the file, marked
  `definition_scope: "file"`, when the block cannot be isolated). The
  `test_attested` result reports it as `evidence_hash`, so the platform can
  bind acceptance to the test as written.
- `attest-tests --coverage <coverage.py JSON with contexts>` records, per
  test, the files and lines it reached. When a `test_attested` assertion names
  a `mechanism` (`<file>::<symbol>`), the result reports `reached: true|false`
  from that record.
- `attest-dependence`, a new opt-in command for the job that already runs
  tests: each `(test, mechanism)` pair is run once with the mechanism replaced
  by a stub and the outcome is signed into a dependence attestation
  (`predicate.kind = "dependence"`). The `test_attested` result reports
  `depends: true|false` when such a record names the test and mechanism at
  the commit under verification. This command runs tests; `run` still
  executes nothing. Pairs come from `--pair` or `--from-model`.
- Tier-2 review of a `test_attested` assertion reads the test's definition
  from the checkout, the named mechanism's definition, and a facts block
  (definition hash match, reached, fails without); the criterion answers NO
  when the facts show the test never reached, or does not depend on, the
  mechanism.
- Test-backed assertions (`test_attested`, `test_exists`, and
  `function_exists` / `class_exists` on a test file) are always verified under
  `--changed-files`: a test's subject is the code it exercises, not its own
  file.
- The predicate schema gains the optional per-test fields `file`,
  `definition_sha256`, `definition_scope`, `reached`, `fails_without` and the
  optional `kind`. No version bump; absence means "not recorded".
- Definition location for every supported language. `attest-tests` cuts a
  test's definition with Python's `ast`, with tree-sitter for JavaScript,
  TypeScript, Go, Rust, Java, Kotlin, C, C++, C#, Ruby, PHP, Swift, Verilog,
  SystemVerilog and VHDL when the new optional extra `mipiti-verify[ast]`
  (`tree-sitter-language-pack`, also in `[all]`) is installed, with a
  keyword-pair block scanner for the HDLs when it is not, and with the brace
  / indentation block otherwise. Each test entry now always records
  `definition_scope` (`symbol`, `block` or `file`) and, unless the scope is
  the file, `parser` (`ast`, `tree-sitter`, `keyword`, `lines`), so a reader
  knows what the hash covers and how the span was found.
- The `mechanism` of a `test_attested` assertion may name its kind:
  `<file>::<kind>:<name>` (`rtl/alu.sv::module:alu`,
  `rtl/fsm.sv::always:seq_logic`); a bare name is tried as a function, then a
  class, then each HDL kind in a fixed order. Reach is computed against the
  span the file's language resolves. The kinds are one vocabulary
  (`languages.definitions.MECHANISM_KINDS`, equal to the catalogue's), read by
  the locator, the disable adapters and the verifier alike; `struct` and
  `impl` locate as `class`.
- `attest-tests --coverage` reads LCOV (`.info` / `.lcov`, including
  `verilator_coverage --write-info` output), Cobertura XML and JaCoCo XML in
  addition to coverage.py JSON, detected from content, and accepts a
  directory of one report per test (`<test id>.<ext>`, `::` spelled `__`).
  A report that attributes lines to tests records `reached` per test; an
  aggregate report (any format, or coverage.py without contexts) is no longer
  refused: it records `suite_reached` per test and leaves `reached` absent,
  because a suite-wide report cannot say what one test executed.
- The predicate schema gains the optional per-test `parser` and
  `suite_reached`; `definition_scope` accepts `symbol` and `block`.
- Action inputs `coverage-report` and `dependence-pairs`.
- Runner adapters (`languages/adapters/`) behind `attest-dependence` and the
  new `attest-reach`: pytest (also cocotb suites driven by pytest), jest,
  vitest, mocha, `go test -run`, `cargo test`, Maven (`-Dtest=`), Gradle
  (`--tests`), `dotnet test --filter`, rspec, phpunit, and a command runner
  (`--run-cmd "make sim TEST={test}"`, `--coverage-cmd`, `--coverage-file`)
  for simulators and custom harnesses. Detected from the project's files,
  the mechanisms' language breaking a polyglot tie; `--runner` overrides.
  Every adapter selects exactly one test, maps the runner's exit status so a
  run that selected nothing, failed to build, could not start or timed out is
  `error` with a reason (never `failed`), and runs the test under the
  language's coverage tool.
- Dependence for every supported language. A JavaScript or TypeScript
  mechanism is disabled by a setup file registered for the run (jest
  `--setupFilesAfterEnv`, a temporary vitest config extending the project's
  with a `setupFiles` entry, mocha `--require`) that mocks the module by its
  resolved path and replaces the export (`default`, a function, or
  `Class.method` on the prototype) with a function that throws. Go, Rust,
  Java, Kotlin, C, C++, C#, Swift, Verilog, SystemVerilog and VHDL mechanisms
  are disabled by source mutation: the definition's body is replaced by one
  that aborts (a Verilog `module` by a stub with the same ANSI header whose
  outputs are driven to `x`, a `function`/`task` by `$fatal`, a labelled
  block, `property`, `sequence` or `assert` removed; a VHDL `architecture`
  emptied, a `process` removed, a `function`/`procedure` by `assert false`),
  the tree is compile- or lint-checked first with the language's toolchain,
  the file is refused when it has uncommitted changes, and the original
  bytes are restored afterwards and verified by hash. A compile failure, a
  refused file or a mechanism that cannot be disabled records `error` with
  the reason in `fails_without[].reason`, which the verifier reads as
  unknown.
- `attest-reach`: runs each nominated test alone under coverage through the
  runner adapter and signs the lines it executed in the mechanism's file
  into a `predicate.kind = "reach"` attestation (`-reach` suffix), in the
  same per-test `reached: [{file, lines}]` shape `attest-tests --coverage`
  records. Only the mechanism's file is kept. Same pair sources
  (`--pair`, `--from-model`), same `--timeout` / `--total-timeout` budget
  (unrun pairs recorded as `error` with a reason), same signing ladder as
  `attest-dependence`. Go `-coverprofile`, SimpleCov `.resultset.json` and
  Clover XML are converted to LCOV; JaCoCo and Cobertura are read as they
  are.
- Action inputs `reach-pairs`, `runner`, `run-cmd`, `coverage-cmd` and
  `coverage-file`; `dependence-pairs` is no longer Python-only.
- `--strategy hook` on `attest-dependence` and `attest-reach` (default stays
  `mutation`): a second dependence strategy for compiled codebases that
  build once. The repository places a tripwire inside each mechanism's own
  body, gated out of production by a build flag (Go tag / Rust feature
  `mipiti_hooks`, C/C++ and Swift `MIPITI_HOOKS`, Verilog `` `MIPITI_HOOKS ``,
  a VHDL generic; Java/Kotlin compiled always, inert), that aborts with
  `mipiti-hook <file>::<symbol> at <file>:<line>` only when
  `MIPITI_DISABLE_MECHANISM` equals its own id. The go runner builds one
  test binary per package with `go test -c -tags mipiti_hooks`, cargo with
  `cargo test --no-run --features mipiti_hooks`, the command runner with a
  new `--build-cmd`, then each pair runs with its mechanism named; no
  source is rewritten and the tree need not be clean. Two mandatory checks
  are recorded: the location proof (dependence is credited only when the
  marker for this mechanism lies inside its exactly located definition,
  recorded as `fails_without[].hook_location`; a failure without the marker
  or with one outside the span is `error` with the reason) and a control
  run (every nominated test once with a value no hook answers to, recorded
  as `control_run`; any failure records `error` for every pair and stops).
  The record carries `strategy: "hook"`. pytest, jest, vitest and mocha
  refuse the strategy with a reason pointing at their runtime disable.
  Action inputs `strategy` and `build-cmd`.
- `attest-dependence --suite-cmd "<command>" --suite-junit <report>`:
  dependence from a whole-suite run, for simulators and any harness that
  cannot select one test. Pairs are grouped by mechanism; each mechanism is
  disabled in turn through the runner's strategy (same compile/lint gate,
  same byte-exact restore), the suite command runs once, and the JUnit
  report it wrote gives every nominated test its outcome. A skipped test
  records `error` with reason `skipped under mutation`, an absent one
  `not in report`, a run that wrote no report `no report`, and a failed
  gate its reason, for every pair on that mechanism. `--timeout` applies
  per suite run and `--total-timeout` across mechanisms. Same
  `kind: "dependence"` attestation. Action inputs `suite-cmd` and
  `suite-junit`. The pytest disable plugin also loads through
  `PYTEST_PLUGINS`, so a pytest suite command needs no extra flag.
- `attest-dependence --total-timeout` (default 1800s, also
  `MIPITI_DEPENDENCE_TOTAL_TIMEOUT`) bounds the whole run; a pair that would
  start after the budget is spent is recorded as not run, with a `reason`,
  and reads as unknown rather than as an outcome.
- `run --test-file-pattern` (also `MIPITI_TEST_FILE_PATTERN`) marks
  additional paths as test files for the `--changed-files` rule, for
  repositories whose tests live outside the conventional layouts.
- Each `test_attested` result submitted to the platform carries the signing
  class of the attestation it was checked against (`ci_oidc`, `customer_key`
  or `unsigned`) in a `provenance` field, as data rather than inside the
  details prose, so the audit envelope and the platform can weigh it.
- The test-result predicate schema is published at
  `schemas/test-result-v1.schema.json`, so a producer other than this CLI can
  emit a conforming attestation.
- GitLab keyless signing recognises the `id_tokens` job keyword (token
  exposed as `SIGSTORE_ID_TOKEN`) in addition to the retired `CI_JOB_JWT_V2`,
  and the pinned identity is the workflow SAN (`project//config@ref`) rather
  than the bare project URL.
- README covers the predicate, provenance, running tests and verification in
  separate jobs, and GitLab setup.

### Changed

- **`test_passes` is replaced by `test_attested`.** Verification is a read-only
  operation: it reads evidence your project already produced and runs nothing.
  `test_passes` was the one type that did not fit that rule, so it is removed.

  A test result now reaches verification as a statement your CI signed about a
  run your own workflow performed. Have your test step write a JUnit report and
  point the action at it:

  ```yaml
  - run: pytest --junitxml=report.xml
  - uses: Mipiti/mipiti-verify@<version>
    with:
      all: true
      junit-report: report.xml
  ```

  No extra step, nothing to install, and no secret: the attestation is signed
  keylessly with the run's own OIDC identity, the same way verification runs
  are already signed. The certificate binds the repository, ref and workflow,
  so the result carries where it came from. CI with no workload identity signs
  with `attestation-signing-key` (ECDSA P-256) instead, and CI with neither
  records the result as self-declared.

  Outside GitHub Actions the equivalent is `mipiti-verify attest-tests --junit
  report.xml`, run after your tests. Either way the report is read, never
  produced -- the step that runs your tests is yours.

  Verification pins the signing identity it expects: for a keyless signature,
  the workflow of the repository being verified; for a key, one the reader
  configured, never the key carried inside the attestation. Verification then
  checks the signature, that the attestation covers the commit under
  verification, that the run selected tests and that they passed, and that the
  test the assertion names passed in that run.

  The attestation records each test's own outcome, and the named one must be
  `passed`. Being present in the run says only that the test was collected: a
  skipped test appears exactly like one that ran, and skipping leaves the
  failure and error counts at zero, so every aggregate still reads green. The
  name is matched exactly, so an assertion about `test_auth` is not satisfied
  by `test_auth_disabled`. A run that selected nothing, or in which everything
  was skipped, is likewise rejected rather than treated as a pass.

  An attestation can also record the configuration its run ran under, and an
  assertion can require it:

  ```yaml
  - uses: Mipiti/mipiti-verify@<version>
    with:
      junit-report: report.xml
      attestation-env: FEATURE_AUTH ENFORCE_TLS
  ```

  A suite can pass with the control it exercises switched off, and assertions
  over files in the tree describe the configuration a repository *declares*
  rather than the one a run *had*. Naming the keys records their values in the
  signed statement, so `test_attested` can carry an `env` requirement and hold
  the run to it. Only the names given are recorded, never the whole
  environment; a nominated key that was unset is recorded as unset, so an
  assertion can require that a flag was absent; and credential-looking names
  are refused rather than redacted, since a signed artifact is distributed. A
  run that recorded nothing cannot satisfy an environment requirement.

  An attestation that names no commit is refused, as is one read where the
  commit under verification cannot be determined. The binding is what stops a
  result being replayed against a different tree, and a binding that lapsed
  whenever either side was missing would not be one.

  An attestation without a signature is accepted and recorded as self-declared
  only where no verification key is configured. Where one is, an unsigned
  attestation is refused, so removing a signature cannot lower the bar a result
  is held to.

  With this change no assertion type executes anything.

### Fixed

- The workflow example in the README pinned `actions/checkout` at v4.3.1, which
  runs on a Node.js version GitHub now forces onto a newer runtime and has
  announced for removal. Anyone who copied the snippet inherited the warning on
  every run. Now pinned to v6.0.2, matching the pin this project's own workflows
  already use.

- A semantic verdict that arrives with no explanation now records no reason,
  instead of echoing the verdict token back as one.

  When a response carried nothing after its verdict line, the parser used the
  whole response as the reasoning — so a bare `YES` was stored as the
  justification for itself. Downstream that is indistinguishable from a real
  explanation, and worse than storing nothing: a consumer can render an absent
  reason honestly, but cannot detect a fabricated one.

  The verdict itself is unaffected; only the recorded reason changes, and only
  when there was never a reason to record.

### Changed

- The GitHub Action emits a `::warning::` annotation when a run is about to
  submit unsigned — no OIDC token in the job and no signing key configured.
  Nothing else changes: the run still submits, and `require-attestation`
  still defaults to `false`. The README now documents
  `require-attestation: true` as the recommended setting for CI gates whose
  results are audited.

- The action passes the `tier2-api-key` value only to the SDK of the
  provider named in `tier2-provider`, instead of exposing it under both the
  OpenAI and Anthropic variable names.

- The container image is published under its version tag only; the floating
  `latest` tag is no longer pushed. `action.yml` pins the image by digest and
  the README's `uses:` snippet is pinned by commit, so nothing resolves
  through `latest`. Each published image now carries a build-provenance
  attestation in the registry, verifiable with
  `gh attestation verify oci://ghcr.io/mipiti/mipiti-verify@<digest> --owner Mipiti`.


### Fixed

- The boundary between the two verification tiers is now enforced in both
  directions, and across every declaration type rather than two symbol types.

  Whether a criterion holds structurally — a symbol defined, a file present, an
  import declared, a pattern matched, a dependency pinned — is settled by the
  structural tier. The semantic tier is a quality gate layered on that fact: it
  may judge a present target insufficient, and it may not decide the fact
  itself.

  Previously that was enforced only on entry: the semantic tier was refused
  when the structural check did not hold. It could still DECLINE a target the
  structural check had confirmed, on the ground that it could not locate it,
  which contradicts a settled fact rather than judging quality. Such a verdict
  is now discarded and the result reported as inconclusive, never converted
  into a pass — affirming would be the same boundary violation reversed.

  To make this decidable rather than inferred, a refusal now declares its
  reason (`REASON: QUALITY` or `REASON: NOT_FOUND`) on the line after the
  verdict. The check reads that declaration and never interprets prose, so a
  quality refusal that happens to describe something as absent is untouched,
  and a provider that emits no declaration has its verdicts left as they are.

  The entry check also widens from two symbol types to every declaration type.
  It stays scoped to verifiers that are pure and cheap, since it re-runs them:
  types whose verifier executes the code under test are excluded, as running a
  test suite as a side effect of a semantic check would duplicate work the
  structural tier already did. Assertions judged against supplied content
  rather than a repository file are likewise exempt.


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
