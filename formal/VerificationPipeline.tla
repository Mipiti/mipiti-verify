----------------------- MODULE VerificationPipeline -------------------------
(*
 * Formal specification of the mipiti-verify verification pipeline.
 *
 * Models the lifecycle of an assertion through Tier 1 (mechanical)
 * and Tier 2 (semantic) verification, and verifies security-critical
 * invariants hold in every reachable state.
 *
 * State: per-assertion tier1 result, tier2 result, submitted status.
 * Actions: RunTier1, RunTier2, SubmitResults, HandleError.
 *
 * Key security invariants:
 *   - Tier 2 never overrides Tier 1 failure (non-LLM gate)
 *   - All error paths produce FAIL, never PASS (fail-closed)
 *   - Every assertion gets a Tier 1 result (completeness)
 *   - Tier 2 only runs after Tier 1 passes
 *   - Results are never submitted without evaluation
 *
 * Run via Python:
 *   python formal/check_pipeline.py
 *)

EXTENDS Naturals, FiniteSets

CONSTANTS
    \* Assertion IDs
    A1, A2,

    \* Tier 1 outcomes
    T1Pass, T1Fail, T1Pending,

    \* Tier 2 outcomes
    T2Pass, T2Fail, T2Skipped, T2Pending,

    \* Error types
    NoError, VerifierError, NetworkError, ParseError

VARIABLES
    \* tier1[a] = T1Pass | T1Fail | T1Pending
    tier1,

    \* tier2[a] = T2Pass | T2Fail | T2Skipped | T2Pending
    tier2,

    \* error[a] = NoError | VerifierError | NetworkError | ParseError
    error,

    \* submitted[a] = TRUE if results have been submitted
    submitted

vars == <<tier1, tier2, error, submitted>>

Assertions == {A1, A2}
T1Outcomes == {T1Pass, T1Fail, T1Pending}
T2Outcomes == {T2Pass, T2Fail, T2Skipped, T2Pending}
Errors == {NoError, VerifierError, NetworkError, ParseError}

-----------------------------------------------------------------------------
(* Helper operators *)

\* Final verdict for an assertion
FinalVerdict(a) ==
    IF error[a] # NoError THEN "fail"
    ELSE IF tier1[a] = T1Fail THEN "fail"
    ELSE IF tier1[a] = T1Pass /\ tier2[a] = T2Pass THEN "pass"
    ELSE IF tier1[a] = T1Pass /\ tier2[a] = T2Fail THEN "fail"
    ELSE IF tier1[a] = T1Pass /\ tier2[a] = T2Skipped THEN "pass"
    ELSE "pending"

\* Is the assertion fully evaluated?
IsEvaluated(a) ==
    tier1[a] # T1Pending /\ tier2[a] # T2Pending

-----------------------------------------------------------------------------
(* Invariants *)

\* I1: Tier 2 never overrides Tier 1 failure (THE critical gate)
Tier2NeverOverridesTier1 ==
    \A a \in Assertions :
        tier1[a] = T1Fail => FinalVerdict(a) = "fail"

\* I2: All error paths produce FAIL (fail-closed)
ErrorsAlwaysFail ==
    \A a \in Assertions :
        error[a] # NoError => FinalVerdict(a) = "fail"

\* I3: PASS requires Tier 1 pass (no false positives from Tier 1)
PassRequiresTier1 ==
    \A a \in Assertions :
        FinalVerdict(a) = "pass" =>
            /\ tier1[a] = T1Pass
            /\ error[a] = NoError

\* I4: Submitted results were evaluated
SubmittedMeansEvaluated ==
    \A a \in Assertions :
        submitted[a] => IsEvaluated(a)

\* I5: Tier 2 only runs after Tier 1 completes
Tier2AfterTier1 ==
    \A a \in Assertions :
        tier2[a] # T2Pending => tier1[a] # T1Pending

\* I6: Tier 1 failure means Tier 2 is skipped
Tier1FailSkipsTier2 ==
    \A a \in Assertions :
        tier1[a] = T1Fail => tier2[a] \in {T2Skipped, T2Pending}

\* I7: Assertion isolation — evaluating one doesn't affect another
\*   (structural: each assertion has independent state variables)

\* I8: Determinism — same inputs produce same Tier 1 result
\*   (structural: verifiers are pure functions)

\* Combined invariant
Invariant ==
    /\ Tier2NeverOverridesTier1
    /\ ErrorsAlwaysFail
    /\ PassRequiresTier1
    /\ SubmittedMeansEvaluated
    /\ Tier2AfterTier1
    /\ Tier1FailSkipsTier2

-----------------------------------------------------------------------------
(* Actions *)

\* RunTier1Pass: Tier 1 verifier passes
RunTier1Pass(a) ==
    /\ tier1[a] = T1Pending
    /\ error[a] = NoError
    /\ tier1' = [tier1 EXCEPT ![a] = T1Pass]
    /\ UNCHANGED <<tier2, error, submitted>>

\* RunTier1Fail: Tier 1 verifier fails
RunTier1Fail(a) ==
    /\ tier1[a] = T1Pending
    /\ error[a] = NoError
    /\ tier1' = [tier1 EXCEPT ![a] = T1Fail]
    \* Tier 2 is auto-skipped on Tier 1 failure
    /\ tier2' = [tier2 EXCEPT ![a] = T2Skipped]
    /\ UNCHANGED <<error, submitted>>

\* RunTier2Pass: Tier 2 (LLM) passes
RunTier2Pass(a) ==
    /\ tier1[a] = T1Pass
    /\ tier2[a] = T2Pending
    /\ error[a] = NoError
    /\ tier2' = [tier2 EXCEPT ![a] = T2Pass]
    /\ UNCHANGED <<tier1, error, submitted>>

\* RunTier2Fail: Tier 2 (LLM) fails
RunTier2Fail(a) ==
    /\ tier1[a] = T1Pass
    /\ tier2[a] = T2Pending
    /\ error[a] = NoError
    /\ tier2' = [tier2 EXCEPT ![a] = T2Fail]
    /\ UNCHANGED <<tier1, error, submitted>>

\* SkipTier2: No provider configured
SkipTier2(a) ==
    /\ tier1[a] = T1Pass
    /\ tier2[a] = T2Pending
    /\ tier2' = [tier2 EXCEPT ![a] = T2Skipped]
    /\ UNCHANGED <<tier1, error, submitted>>

\* HandleError: Error during verification (fail-closed)
HandleError(a, err) ==
    /\ tier1[a] = T1Pending
    /\ error[a] = NoError
    /\ error' = [error EXCEPT ![a] = err]
    /\ tier1' = [tier1 EXCEPT ![a] = T1Fail]
    /\ tier2' = [tier2 EXCEPT ![a] = T2Skipped]
    /\ UNCHANGED submitted

\* SubmitResults: Submit all evaluated assertions
SubmitResults ==
    /\ \A a \in Assertions : IsEvaluated(a)
    /\ \E a \in Assertions : ~submitted[a]
    /\ submitted' = [a \in Assertions |-> TRUE]
    /\ UNCHANGED <<tier1, tier2, error>>

\* Done: system has terminated (all submitted). Allows stuttering
\* so TLC does not report a false deadlock.
Done ==
    /\ \A a \in Assertions : submitted[a]
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(* Initial state and next-state relation *)

Init ==
    /\ tier1 = [a \in Assertions |-> T1Pending]
    /\ tier2 = [a \in Assertions |-> T2Pending]
    /\ error = [a \in Assertions |-> NoError]
    /\ submitted = [a \in Assertions |-> FALSE]

Next ==
    \/ \E a \in Assertions : RunTier1Pass(a)
    \/ \E a \in Assertions : RunTier1Fail(a)
    \/ \E a \in Assertions : RunTier2Pass(a)
    \/ \E a \in Assertions : RunTier2Fail(a)
    \/ \E a \in Assertions : SkipTier2(a)
    \/ \E a \in Assertions, err \in Errors \ {NoError} : HandleError(a, err)
    \/ SubmitResults
    \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties to verify *)

THEOREM Spec => []Invariant

=============================================================================
