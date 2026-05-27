---------------------------- MODULE Tier2RunnerSide ---------------------------
(*
 * Formal specification of the tier-2 runner-side prompt rendering.
 *
 * Models the lifecycle of a tier-2 evaluation: the runner receives an
 * assertion payload from the backend, mints a fresh per-call boundary
 * token, renders a per-type Jinja template locally with the token
 * wrapping all untrusted inputs, sends the rendered message to the
 * LLM, and discards the token.
 *
 * Verifies the security-critical invariants for the single-path
 * design (no legacy fallback):
 *
 *   T1 — Freshness:    every render uses a freshly minted boundary
 *                      token; tokens never repeat across renders.
 *   T2 — Secrecy:      the boundary token never leaves the renderer
 *                      (it is not persisted, not transmitted, not
 *                      reused by any other component).
 *   T3 — Trusted instructions: the instruction preamble lives outside
 *                      the boundary in trusted runner-supplied text;
 *                      attacker-controlled inputs sit inside.
 *   T4 — Data isolation: assertion params and source code are wrapped
 *                      inside the per-call boundary; attacker payloads
 *                      cannot escape because the closing tag uses an
 *                      unpredictable token.
 *   T5 — No legacy fields: the backend payload carries only the
 *                      structured (type, params) shape; the legacy
 *                      tier2_prompt / tier2_boundary_token fields no
 *                      longer exist anywhere in the state. A payload
 *                      missing the structured fields fails fast with
 *                      a clear version-mismatch error rather than
 *                      degrading to a less-defended path.
 *
 * Run via Python cross-check:
 *   python formal/check_pipeline.py
 *)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    \* Assertion IDs to model
    A1, A2,

    \* Assertion types (must each have a per-type template)
    TypeFnExists, TypeFileExists,

    \* Token sentinel values used in the model. Real tokens are
    \* random 24-hex-char strings; the model abstracts them to a
    \* finite set of distinct values plus NoToken.
    Tok1, Tok2, Tok3,
    NoToken,

    \* Render lifecycle states for one evaluation
    RUnstarted, RMinted, RRendered, RSent, RDiscarded,

    \* Payload validity (modeling the wire payload from the backend)
    PValid, PMissingType, PMissingParams

VARIABLES
    \* render[a] — current rendering state for assertion a
    render,

    \* token[a] — boundary token minted for this assertion's render;
    \* NoToken before the call, the minted value during the call, and
    \* discarded (never observable after RDiscarded — modeled by
    \* checking it does not leak into transmitted_tokens).
    token,

    \* transmitted_tokens — set of tokens that have ever crossed the
    \* network OR been persisted to durable storage. The renderer
    \* must never add to this set (T2).
    transmitted_tokens,

    \* used_tokens — multiset of tokens already used by any prior
    \* render in this run. A new mint may not collide with this set
    \* (T1, modulo the abstraction that real mints use 96 bits of
    \* entropy so collisions are negligible in practice).
    used_tokens,

    \* payload[a] — the backend wire payload validity for this
    \* assertion. Either PValid (carries type + params), or
    \* PMissingType / PMissingParams (which must fail fast).
    payload,

    \* evaluated[a] — TRUE once the tier-2 evaluation for this
    \* assertion has completed (either succeeded or fail-fast).
    evaluated,

    \* fail_fast[a] — TRUE iff the assertion failed with the
    \* version-mismatch error (payload missing type/params).
    fail_fast,

    \* legacy_fields_present — global flag modeling whether any
    \* assertion in this run carried a legacy tier2_prompt /
    \* tier2_boundary_token field. T5 requires this to be FALSE
    \* in every reachable state (the runner never reads them, and
    \* the new backend never ships them).
    legacy_fields_present

vars == <<render, token, transmitted_tokens, used_tokens,
          payload, evaluated, fail_fast, legacy_fields_present>>

Assertions == {A1, A2}
Types == {TypeFnExists, TypeFileExists}
Tokens == {Tok1, Tok2, Tok3}
RStates == {RUnstarted, RMinted, RRendered, RSent, RDiscarded}
PStates == {PValid, PMissingType, PMissingParams}

-----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ render = [a \in Assertions |-> RUnstarted]
    /\ token = [a \in Assertions |-> NoToken]
    /\ transmitted_tokens = {}
    /\ used_tokens = {}
    /\ payload \in [Assertions -> PStates]
    /\ evaluated = [a \in Assertions |-> FALSE]
    /\ fail_fast = [a \in Assertions |-> FALSE]
    /\ legacy_fields_present = FALSE

-----------------------------------------------------------------------------
(* Helpers *)

\* Modify one entry in a function-valued variable
SetAt(f, k, v) == [f EXCEPT ![k] = v]

\* A token is "fresh" if it has never been used before
IsFresh(t) == t \notin used_tokens /\ t # NoToken

-----------------------------------------------------------------------------
(* Actions *)

\* Action: fail fast when the wire payload lacks `type` or `params`.
\* No token is minted, no template is rendered, no LLM call is made.
\* This is the version-mismatch path.
FailFastInvalidPayload(a) ==
    /\ render[a] = RUnstarted
    /\ payload[a] \in {PMissingType, PMissingParams}
    /\ render' = SetAt(render, a, RDiscarded)
    /\ evaluated' = SetAt(evaluated, a, TRUE)
    /\ fail_fast' = SetAt(fail_fast, a, TRUE)
    /\ UNCHANGED <<token, transmitted_tokens, used_tokens, payload,
                   legacy_fields_present>>

\* Action: mint a fresh per-call boundary token.
MintToken(a, t) ==
    /\ render[a] = RUnstarted
    /\ payload[a] = PValid
    /\ IsFresh(t)
    /\ render' = SetAt(render, a, RMinted)
    /\ token' = SetAt(token, a, t)
    /\ used_tokens' = used_tokens \union {t}
    /\ UNCHANGED <<transmitted_tokens, payload, evaluated, fail_fast,
                   legacy_fields_present>>

\* Action: render the per-type template with the minted token wrapping
\* all untrusted inputs. The instruction preamble sits OUTSIDE the
\* boundary (it is trusted runner text from the template); only the
\* untrusted variables (params + source) are wrapped.
RenderTemplate(a) ==
    /\ render[a] = RMinted
    /\ render' = SetAt(render, a, RRendered)
    /\ UNCHANGED <<token, transmitted_tokens, used_tokens, payload,
                   evaluated, fail_fast, legacy_fields_present>>

\* Action: send the rendered message to the LLM. Critically, only the
\* rendered message body is sent — NOT the token itself as a separate
\* field. The token appears inside the message body as a marker but
\* is not transmitted as out-of-band metadata, nor persisted anywhere.
SendToProvider(a) ==
    /\ render[a] = RRendered
    /\ render' = SetAt(render, a, RSent)
    /\ UNCHANGED <<token, transmitted_tokens, used_tokens, payload,
                   evaluated, fail_fast, legacy_fields_present>>

\* Action: discard the token after the LLM response is parsed.
DiscardToken(a) ==
    /\ render[a] = RSent
    /\ render' = SetAt(render, a, RDiscarded)
    /\ token' = SetAt(token, a, NoToken)
    /\ evaluated' = SetAt(evaluated, a, TRUE)
    /\ UNCHANGED <<transmitted_tokens, used_tokens, payload, fail_fast,
                   legacy_fields_present>>

\* Next-state relation
Next ==
    \/ \E a \in Assertions : FailFastInvalidPayload(a)
    \/ \E a \in Assertions, t \in Tokens : MintToken(a, t)
    \/ \E a \in Assertions : RenderTemplate(a)
    \/ \E a \in Assertions : SendToProvider(a)
    \/ \E a \in Assertions : DiscardToken(a)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

\* T1 — Freshness: no two assertions in the same run reuse the same
\* token. Modeling: any token that has been minted (i.e., is in
\* used_tokens) appears as the minted token for AT MOST one assertion.
T1_Freshness ==
    \A a1, a2 \in Assertions :
        (a1 # a2 /\ token[a1] # NoToken /\ token[a2] # NoToken)
            => token[a1] # token[a2]

\* T2 — Secrecy: the renderer never transmits the token out-of-band
\* (separate field), never persists it, never reuses it. We model
\* the negative property: transmitted_tokens stays empty across all
\* reachable states (no action ever adds to it).
T2_Secrecy ==
    transmitted_tokens = {}

\* T3 — Trusted instructions: the instruction preamble is template
\* text (trusted) and cannot be modified by the rendering action.
\* Modeled as: no action takes the renderer past RRendered without
\* having minted a fresh token (so untrusted inputs cannot reach the
\* LLM without being wrapped). Equivalently: every assertion that
\* reached RSent or RDiscarded via the happy path must have minted a
\* fresh token first.
T3_TrustedInstructions ==
    \A a \in Assertions :
        (render[a] \in {RRendered, RSent}) => token[a] \in Tokens

\* T4 — Data isolation: an attacker controlling assertion params or
\* source code cannot escape the boundary because the closing tag uses
\* an unpredictable token. Modeled as: the token used to wrap is in
\* the Tokens set (i.e., minted) and is fresh w.r.t. all prior renders
\* in the run, so the attacker has zero information about it at the
\* time they supplied the input. Combined with T1 this means the
\* attacker cannot have embedded the exact closing tag in their input.
T4_DataIsolation ==
    \A a \in Assertions :
        (render[a] = RRendered) =>
            /\ token[a] \in Tokens
            /\ token[a] \in used_tokens

\* T5 — No legacy fields: the runner does not consume any
\* tier2_prompt / tier2_boundary_token field from the wire, and the
\* backend does not ship them. We model the strongest version of this:
\* legacy_fields_present is initially FALSE and no action sets it to
\* TRUE. If the backend payload is malformed (missing type/params),
\* the runner fails fast (FailFastInvalidPayload) rather than falling
\* back to any legacy path — modeled by the absence of any action
\* that transitions to RRendered when payload[a] # PValid.
T5_NoLegacyFields ==
    /\ legacy_fields_present = FALSE
    /\ \A a \in Assertions :
        (render[a] = RRendered) => payload[a] = PValid

\* Composite invariant
Invariant ==
    /\ T1_Freshness
    /\ T2_Secrecy
    /\ T3_TrustedInstructions
    /\ T4_DataIsolation
    /\ T5_NoLegacyFields

=============================================================================
