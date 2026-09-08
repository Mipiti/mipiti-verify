# Formal Verification

This directory contains two formal-verification artefacts, each anchored
on its own TLA+ spec + Python BFS implementation check:

| Artefact | Specifies | Detailed README |
|---|---|---|
| **Assertion verification pipeline** (`VerificationPipeline.tla`) | The lifecycle of an assertion through Tier 1 (mechanical) and Tier 2 (semantic/LLM) checks, plus reverify-mode semantics. | This README. |
| **Tier-2 runner-side rendering** (`Tier2RunnerSide.tla`) | The single-path tier-2 prompt-injection defense: per-call boundary token freshness + secrecy, trusted instruction placement outside the boundary, data-isolation of attacker-controlled inputs inside the boundary, and the absence of any legacy tier2_prompt / tier2_boundary_token wire fields. Five invariants T1–T5. | This README. |
| **Audit verifier** (`audit.tla`) | The compromised-platform threat model for `mipiti-verify audit`: identity pinning, predicate pinning, fail-closed validations, and 13 invariants over the verifier's verdict function. | [`audit-README.md`](./audit-README.md) |

The rest of this README covers the assertion-verification-pipeline
artefact. mipiti-verify's verification pipeline is formally verified
using TLA+ specifications with independent model checking, exhaustive
state exploration, and cross-checks against the real code.

## Why formal verification?

mipiti-verify runs in customer CI pipelines with access to source code, secrets, and deployment credentials. If the verification pipeline has a bug — for example, if an LLM response could override a mechanical check, or if a network error could silently produce a PASS — the consequences are severe: controls would appear verified when they aren't.

Traditional testing catches specific scenarios. Formal verification proves properties hold in **every possible state** the system can reach. The difference: tests say "these 50 scenarios work," formal verification says "no scenario exists where this property fails."

## What is verified

The TLA+ specification (`VerificationPipeline.tla`) models the lifecycle of an assertion through Tier 1 (mechanical) and Tier 2 (semantic/LLM) verification. Six security-critical invariants are proven to hold in every reachable state:

| Invariant | Property | Why it matters |
|-----------|----------|---------------|
| **I1** | Tier 2 never overrides Tier 1 failure | An LLM saying "looks good" can never override a mechanical check that says the code doesn't match. The non-LLM gate ensures deterministic verification can't be subverted by probabilistic AI. |
| **I2** | All error paths fail-closed | A network glitch, malformed response, or verifier crash produces FAIL, never PASS. No error can silently mark a control as verified. |
| **I3** | PASS requires Tier 1 pass | A control can only be verified if the mechanical check actually found the evidence. No shortcut to PASS. |
| **I4** | Submitted results were evaluated | Results are never submitted to the platform without both tiers completing. No unevaluated assertions slip through. |
| **I5** | Tier 2 only runs after Tier 1 | The semantic check never starts before mechanical verification completes. The pipeline always evaluates Tier 1 first, ensuring deterministic results are available before LLM evaluation. |
| **I6a** | Tier 1 failure skips Tier 2 (default mode) | Without `--reverify`, a mechanical check failure automatically skips Tier 2. No LLM resources wasted on already-failed assertions. |
| **I6b** | All assertions get Tier 2 evaluated (reverify mode) | With `--reverify`, every assertion gets a fresh Tier 2 result — including Tier 1 failures. No stale data. The platform requires both tiers to pass, so Tier 2 alone can never promote a Tier 1 failure to PASS (guaranteed by I1). |

## How it works

The verification uses a three-layer approach:

### Layer 1: Design verification (TLA+ / TLC)

`VerificationPipeline.tla` defines the pipeline as a state machine:
- **States**: each assertion has a Tier 1 result (pending/pass/fail), Tier 2 result (pending/pass/fail/skipped), error status, and submitted flag
- **Actions**: RunTier1Pass, RunTier1Fail, RunTier2Pass, RunTier2Fail, SkipTier2, HandleError, SubmitResults
- **Invariants**: the six properties above

TLC (the TLA+ model checker, developed by Leslie Lamport) independently explores every reachable state and verifies every invariant holds. TLC runs on both configurations (default and reverify) using separate `.cfg` files. TLC is a completely independent tool — if the Python checker has a bug, TLC still catches design flaws.

### Layer 2: Exhaustive state exploration (Python BFS)

`check_pipeline.py` implements breadth-first search over all reachable states for both modes: default (130 states, 193 transitions) and reverify (306 states, 501 transitions). At each state, it checks all invariants appropriate to the mode. This is the same exhaustive approach used for the Mipiti platform's assurance engine.

### Layer 3: Implementation cross-check (real code, real files)

The formal checker doesn't just verify its own model — it calls the **real** verifier functions with **real** files on a **real** filesystem:

- **Model-based testing**: for each of the 130 reachable states, creates temporary files, calls the real `_verify_tier1` and `_verify_tier2` functions, and verifies the invariants hold on the real results. No mocks.
- **Cross-checks** (22 configs): verifies fail-closed behavior (path traversal, bad regex, missing files), determinism (same inputs → same outputs), evidence requirement (PASS only with actual evidence), and assertion isolation (verifying one assertion doesn't affect another).
- **AST structural proofs** (6 properties): analyzes the source code structure to prove properties hold for ALL inputs — `_verify_tier1` catches all exceptions, `_verify_tier2` returns skipped without a provider, `safe_resolve_path` rejects path traversal, `safe_regex_search` uses RE2, symlinks are rejected, and regex has timeout enforcement.

## What this guarantees

If all three layers pass (which CI enforces on every commit):

1. **The design is correct**: no sequence of actions can violate the six invariants (TLC proves this)
2. **The code matches the design**: the real verifier functions produce the same results as the formal spec for every reachable state (model-based testing proves this)
3. **Safety properties hold structurally**: error handling, path confinement, and regex safety are enforced by code structure, not by testing specific cases (AST proofs prove this)

Together: **the verification pipeline is provably correct** — not just tested, proven.

## Running the verification

```bash
# Python BFS + cross-checks + model-based testing + AST proofs
python formal/check_pipeline.py

# TLC independent verification (requires Java)
curl -sL https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar -o formal/tla2tools.jar
java -jar formal/tla2tools.jar -config VerificationPipeline.cfg -workers auto VerificationPipeline.tla
```

Both run automatically in CI on every commit (see `.github/workflows/ci.yml`).

## Exhaustive checks over the verifiers, the types and the adapters

Four further checkers close the gap between "the pipeline is correct" and
"every part the pipeline is built from is correct". Each is exhaustive
over a finite space rather than sampled, cross-checks the real code against
an independent oracle, and prints one `VERIFIED` line per property. Each
also runs as an ordinary test (`tests/test_formal_verifiers.py`,
`tests/test_formal_types.py`, `tests/test_formal_evidence_records.py`,
`tests/test_formal_adapters.py`, `tests/test_formal_sound.py`), so CI runs
them on every push without a separate step.

| Checker | Proves | Space |
|---|---|---|
| `check_verifiers.py` | Every registered structural verifier passes only when its condition holds, fails when it does not, fails closed on a path that leaves the project root or a pattern the linear-time engine rejects, and fails on a missing input. The verdict of every equivalence class is computed by an independent specification and compared with the verifier's. `test_attested` is enumerated over the facts that decide it (attestation present, commit bound, run outcome, selection non-empty, something passed, the named test's own status, recorded environment, whether a signature was possible) against a fact-derived oracle. A verifier registered without classes fails the run. The two sound witnesses are covered by the ground-truth programs of `check_sound.py`, run from here so registry coverage is exhaustive. Structural proofs over the source (no PASS on an error path, safe file access, safe regex) hold for all inputs. | 30 verifiers, 173 classes, 62 structural checks |
| `check_types.py` | T1 every catalogue type has a structural verifier (or an explicit, reasoned exemption). T2 the parameters each verifier reads, found with `ast` through the helpers it hands `params` to, are the parameters the catalogue declares: a key the verifier requires is catalogue-required, every catalogue-required key is read by the verifier or (for tier-2-only inputs) by the runner, and every optional read is declared or in an allowance that is itself checked against the code. T3 templates and registered types are in bijection and every template uses only the variables the runner supplies (read from the runner's render call). T4 every template, rendered for every subject, carries the fail-closed clause and the injection-refusal clause. T5 every registered type has exactly one evidence class, stated in the registry, and it is one of the declared vocabulary. T6 one mechanism-kind vocabulary across the catalogue, the verifier and the adapters. T7 the soundness class the registry states for a type is the class the catalogue declares for it, and the two vocabularies are the same set. | 30 types x 7 properties |
| `check_evidence_records.py` | How the three signed records compose into one `test_attested` verdict, over every combination of their states through the real verifier: R1 a pass comes only from a test-result record at the verification commit naming the test passed (a reach or dependence record never evidences a pass). R2 `evidence_hash` is the record's definition hash when present, empty otherwise. R3 `reached` comes from the test-result record's own per-test coverage, else from a reach record at the same commit naming the same (or no) mechanism that was run, else unknown. R4 `depends` comes only from a dependence record at the same commit naming the same mechanism that was run, else unknown. R5 no mechanism on the assertion, no facts. R6 an entry with a `reason` (not run) never yields False. R7 a suite-scope reach record (`reach_scope = "suite"`, one whole-suite run) never sets `reached`; when the fact stays unknown with one present, the verdict says so. R8 the enumeration exercises the whole record schema: every field `schemas/test-result-v1.schema.json` declares (record-level optional fields, every per-test field, every nested field) is carried by at least one enumerated statement, and no enumerated statement carries a field the schema does not declare, so a schema addition without an axis value, or an emitted field the schema has not caught up with, fails the run. | 8 axes, 17640 combinations |
| `check_sound.py` | The flagged set of the sound-witness engine is a SUPERSET of what is unsafe. S1 every site a program declares unsafe by construction is flagged; S2 the verdict is PASS exactly on the programs with no unsafe site and a scope the engine can read; S3 a refusal states which fixed reason it is (an unreadable or empty scope, a file with no language, a file the parser rejects, a sink that does not occur, an exception matching no flagged site). Self-validating: each of the four enumeration features (alias tracking, wrapper discovery, escape hatches, stores to a named target) is switched off in turn and the run FAILS unless the mutant loses a site S1 requires. | 36 programs across Python, JavaScript, Go, Rust, SystemVerilog and VHDL |
| `check_adapters.py` | A1 a mutated file is restored byte-for-byte on normal exit and when the block raises. A2 a mutation changes the file and only within the named definition's lines (plus the documented extras), cross-checked against the parser's span. A3 the compile check runs before the test, on the mutated tree; a failing check is `error` and the runner is never invoked. A4 an uncommitted or unversioned file is refused as `error` and never rewritten. A5 the parser isolates every fixture definition as `symbol`; with the parser unavailable the fallback declines or reports `block` (the HDL keyword scanner: `symbol`), with the documented span. A6 one table of executed lines written in every accepted coverage format reads back identically from both readers. A7 every adapter maps every exit status to exactly `passed` / `failed` / `error`, per its documented table, and in suite mode every JUnit status (and an absent test) maps to the documented outcome and reason. A8 a mutation runs only on an exactly located span: with the parser unavailable, every fixture the fallback locates as a `block` (or not at all) is refused with the documented reason, and every fixture it still isolates as `symbol` (the HDL keyword scanner) is mutated as with the parser. A9 the hook strategy credits dependence only with a marker for the mechanism inside its exactly located span (outside, another file, another mechanism, or absent refuses with the documented reason), and a failing control run records `error` for every pair with no pair run. | 11 mutation fixtures, 12 adapters, 8 exit statuses |

```bash
python formal/check_verifiers.py   # ALL VERIFIER PROPERTIES VERIFIED
python formal/check_types.py       # ALL TYPE PROPERTIES VERIFIED
python formal/check_evidence_records.py  # ALL EVIDENCE RECORD PROPERTIES VERIFIED
python formal/check_adapters.py    # ALL ADAPTER PROPERTIES VERIFIED
python formal/check_sound.py       # ALL SOUND WITNESS PROPERTIES VERIFIED
```

Two of the properties need something beyond this package and say so
rather than passing silently: `check_types.py` T1-T2 need the assertion
type catalogue (`mipiti_mcp.assertion_types`, or a sibling `mcp-server/`
checkout) and print `NOT ESTABLISHED` without it; the parser arm of
`check_adapters.py` A2 and A5 needs the `[ast]` extra
(`tree-sitter-language-pack`) and prints `NOT ESTABLISHED` without it.
The exit status is 0 in both cases; the tests assert the wording, so the
gap is visible in the log.

## Files

| File | Purpose |
|------|---------|
| `VerificationPipeline.tla` | TLA+ specification — the formal design (both modes) |
| `VerificationPipeline.cfg` | TLC configuration — default mode (reverify=false) |
| `VerificationPipeline_reverify.cfg` | TLC configuration — reverify mode (reverify=true) |
| `Tier2RunnerSide.tla` | TLA+ specification — tier-2 runner-side rendering invariants T1–T5 (freshness, secrecy, trusted instructions, data isolation, no legacy fields) |
| `Tier2RunnerSide.cfg` | TLC configuration for `Tier2RunnerSide.tla` |
| `check_pipeline.py` | Python checker — BFS + cross-checks + model-based testing + AST proofs (runs both modes) |
| `check_verifiers.py` | Exhaustive equivalence-class check of every registered structural verifier against an independent spec, plus the `test_attested` fact space against a fact-derived oracle |
| `check_types.py` | Type-design invariants T1-T7: catalogue coverage, param-spec agreement (via `ast`), template bijection and variables, fail-closed + injection clauses on every rendered prompt, evidence class |
| `check_evidence_records.py` | Evidence-record composition R1-R7: which of the test-result, reach and dependence records may supply the pass and each fact, exhaustively over their states; R8: the enumeration and the record schema declare the same fields |
| `check_sound.py` | Sound-witness engine: the flagged set is a superset of the ground truth each program declares, over a grammar of small programs in Python, four tree-sitter languages and two hardware description languages, with a regression self-validation that each enumeration feature is load-bearing |
| `check_adapters.py` | Adapter invariants A1-A9: byte-exact restore, confined mutation, compile gate before run, dirty-file refusal, parser/fallback agreement, coverage-reader agreement, total and closed outcome mapping, mutation only on an exactly located span, hook credit only with the location proof and a passing control run |
| `audit.tla` | TLA+ specification — audit verifier's compromised-platform defense (13 invariants I1–I13) |
| `audit.cfg` | TLC configuration for `audit.tla` |
| `audit-README.md` | Detailed README for the audit-verifier formal artefact (threat model, invariant catalogue, pin-layering table, BFS coverage in CI with real Fulcio) |
