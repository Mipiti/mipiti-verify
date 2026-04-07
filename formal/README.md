# Formal Verification

mipiti-verify's verification pipeline is formally verified using TLA+ specifications with independent model checking, exhaustive state exploration, and cross-checks against the real code.

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

## Files

| File | Purpose |
|------|---------|
| `VerificationPipeline.tla` | TLA+ specification — the formal design (both modes) |
| `VerificationPipeline.cfg` | TLC configuration — default mode (reverify=false) |
| `VerificationPipeline_reverify.cfg` | TLC configuration — reverify mode (reverify=true) |
| `check_pipeline.py` | Python checker — BFS + cross-checks + model-based testing + AST proofs (runs both modes) |
