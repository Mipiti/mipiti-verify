----------------------- MODULE VerificationPipeline -------------------------
(*
 * Formal specification of the mipiti-verify verification pipeline.
 *
 * Models the lifecycle of an assertion through Tier 1 (mechanical)
 * and Tier 2 (semantic) verification, and verifies security-critical
 * invariants hold in every reachable state.
 *
 * The Reverify constant models the --reverify flag:
 *   FALSE: Tier 1 failure auto-skips Tier 2 (I6a)
 *   TRUE:  All assertions get Tier 2 evaluated for freshness (I6b)
 * Security invariants (I1-I5) hold in both modes.
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
    NoError, VerifierError, NetworkError, ParseError,

    \* Mode flag
    Reverify

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
(* Invariants — hold in BOTH reverify modes *)

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

(* Mode-specific invariants *)

\* I6a (Reverify=FALSE): Tier 1 failure skips Tier 2
Tier1FailSkipsTier2_NoReverify ==
    Reverify \/ \A a \in Assertions :
        tier1[a] = T1Fail => tier2[a] \in {T2Skipped, T2Pending}

\* I6b (Reverify=TRUE): All evaluated assertions have Tier 2 results (no stale data)
\*   If Tier 1 completed, Tier 2 must also complete (not left pending)
AllTier2Evaluated_Reverify ==
    ~Reverify \/ \A a \in Assertions :
        submitted[a] => tier2[a] # T2Pending

\* Combined invariant
Invariant ==
    /\ Tier2NeverOverridesTier1
    /\ ErrorsAlwaysFail
    /\ PassRequiresTier1
    /\ SubmittedMeansEvaluated
    /\ Tier2AfterTier1
    /\ Tier1FailSkipsTier2_NoReverify
    /\ AllTier2Evaluated_Reverify

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
    \* In non-reverify mode, auto-skip Tier 2.
    \* In reverify mode, leave Tier 2 pending (will be evaluated).
    /\ IF ~Reverify
       THEN tier2' = [tier2 EXCEPT ![a] = T2Skipped]
       ELSE UNCHANGED tier2
    /\ UNCHANGED <<error, submitted>>

\* RunTier2Pass: Tier 2 (LLM) passes — allowed after Tier 1 pass or (reverify + Tier 1 fail)
RunTier2Pass(a) ==
    /\ tier2[a] = T2Pending
    /\ error[a] = NoError
    /\ tier1[a] # T1Pending  \* Tier 1 must have completed
    /\ IF ~Reverify THEN tier1[a] = T1Pass ELSE TRUE
    /\ tier2' = [tier2 EXCEPT ![a] = T2Pass]
    /\ UNCHANGED <<tier1, error, submitted>>

\* RunTier2Fail: Tier 2 (LLM) fails
RunTier2Fail(a) ==
    /\ tier2[a] = T2Pending
    /\ error[a] = NoError
    /\ tier1[a] # T1Pending
    /\ IF ~Reverify THEN tier1[a] = T1Pass ELSE TRUE
    /\ tier2' = [tier2 EXCEPT ![a] = T2Fail]
    /\ UNCHANGED <<tier1, error, submitted>>

\* SkipTier2: No provider configured
SkipTier2(a) ==
    /\ tier2[a] = T2Pending
    /\ tier1[a] # T1Pending
    /\ IF ~Reverify THEN tier1[a] = T1Pass ELSE TRUE
    /\ tier2' = [tier2 EXCEPT ![a] = T2Skipped]
    /\ UNCHANGED <<tier1, error, submitted>>

\* HandleError: Error during verification (fail-closed)
HandleError(a, err) ==
    /\ tier1[a] = T1Pending
    /\ error[a] = NoError
    /\ error' = [error EXCEPT ![a] = err]
    /\ tier1' = [tier1 EXCEPT ![a] = T1Fail]
    /\ IF ~Reverify
       THEN tier2' = [tier2 EXCEPT ![a] = T2Skipped]
       ELSE UNCHANGED tier2
    /\ UNCHANGED submitted

\* SubmitResults: Submit all evaluated assertions
SubmitResults ==
    /\ \A a \in Assertions : IsEvaluated(a)
    /\ \E a \in Assertions : ~submitted[a]
    /\ submitted' = [a \in Assertions |-> TRUE]
    /\ UNCHANGED <<tier1, tier2, error>>

\* Done: system has terminated (all submitted)
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
