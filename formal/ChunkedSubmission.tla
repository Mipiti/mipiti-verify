-------------------------- MODULE ChunkedSubmission --------------------------
(***************************************************************************)
(* How the runner submits a tier's results (runner.result_chunks,          *)
(* Runner._submit_tier): the results 1..N, in order, each of a size (its   *)
(* JSON and its assertion's record's, runner.payload_cost), are gathered   *)
(* into chunks; a result that would take the open chunk past Bound closes  *)
(* it and opens the next with that result; each closed chunk is submitted  *)
(* naming the assertions of its own results, which is what the platform    *)
(* recomputes the content hash from.                                       *)
(*                                                                         *)
(* A chunk is a range of results: the closed chunk k holds lo[k]..hi[k],   *)
(* and the open one lo..next-1; ``total`` is what each closed chunk's      *)
(* sizes add to, ``used`` the open one's, each kept as results are taken.  *)
(*                                                                         *)
(* Partition: the chunks, closed then open, are consecutive ranges from 1  *)
(* to the last result taken, so every result taken is in exactly one, in   *)
(* order. Bounded: every chunk adds to at most Bound, or holds one result. *)
(* HashBinds: every submitted chunk names exactly its own results.         *)
(* AllSubmitted: once done, the closed chunks cover every result.          *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    N,          \* the results
    MaxSize,    \* the largest size a result has
    Bound,      \* the most a chunk's sizes add to (SUBMISSION_PAYLOAD_BYTES)
    Mutant      \* "none", or the guard a mutant drops

Results == 1..N
Sizes == 1..MaxSize

VARIABLES
    size,       \* each result's size (chosen at the start)
    next,       \* the next result to take
    lo,         \* the first result of the open chunk
    used,       \* what the open chunk's sizes add to
    clo,        \* each closed chunk's first result
    chi,        \* each closed chunk's last result
    total,      \* what each closed chunk's sizes add to
    sent,       \* each closed chunk's submission: the results it names
    done        \* every result taken and the last chunk closed

vars == <<size, next, lo, used, clo, chi, total, sent, done>>

M(name) == Mutant = name

TypeOK ==
    /\ size \in [Results -> Sizes]
    /\ next \in 1..(N + 1)
    /\ lo \in 1..(N + 1)
    /\ used \in Nat
    /\ clo \in Seq(Results) /\ chi \in Seq(Results)
    /\ total \in Seq(Nat) /\ sent \in Seq(SUBSET Results)
    /\ done \in BOOLEAN

Init ==
    /\ size \in [Results -> Sizes]
    /\ next = 1 /\ lo = 1 /\ used = 0
    /\ clo = <<>> /\ chi = <<>> /\ total = <<>> /\ sent = <<>>
    /\ done = FALSE

\* Close the open chunk lo..next-1 and submit it, naming its own results'
\* assertions (the mutant: every assertion of the tier).
Close ==
    /\ clo' = Append(clo, lo)
    /\ chi' = Append(chi, next - 1)
    /\ total' = Append(total, used)
    /\ sent' = Append(sent, IF M("all_assertions") THEN Results ELSE lo..(next - 1))

\* Take the next result: into the open chunk where it fits or the chunk is
\* empty, else close the chunk and open the next with it (the mutant: never
\* close for size).
Take ==
    /\ ~done /\ next <= N
    /\ IF lo < next /\ used + size[next] > Bound /\ ~M("no_split")
          THEN /\ Close
               /\ lo' = next
               /\ used' = size[next]
          ELSE /\ used' = used + size[next]
               /\ UNCHANGED <<lo, clo, chi, total, sent>>
    /\ next' = next + 1
    /\ UNCHANGED <<size, done>>

\* Every result taken: the last chunk is closed and submitted (the mutant:
\* left open, never submitted).
Finish ==
    /\ ~done /\ next = N + 1
    /\ IF lo < next /\ ~M("drop_last")
          THEN /\ Close /\ lo' = next /\ used' = 0
          ELSE UNCHANGED <<lo, used, clo, chi, total, sent>>
    /\ done' = TRUE
    /\ UNCHANGED <<size, next>>

Next == Take \/ Finish

Spec == Init /\ [][Next]_vars

Partition ==
    /\ Len(clo) = Len(chi) /\ Len(total) = Len(clo) /\ Len(sent) = Len(clo)
    /\ Len(clo) > 0 => clo[1] = 1
    /\ Len(clo) = 0 => lo = 1
    /\ \A k \in 1..Len(clo): clo[k] <= chi[k]
    /\ \A k \in 1..(Len(clo) - 1): clo[k + 1] = chi[k] + 1
    /\ Len(clo) > 0 => lo = chi[Len(clo)] + 1
    /\ lo <= next
Bounded ==
    /\ \A k \in 1..Len(clo): total[k] <= Bound \/ clo[k] = chi[k]
    /\ used <= Bound \/ next - lo <= 1
HashBinds == \A k \in 1..Len(sent): sent[k] = clo[k]..chi[k]
AllSubmitted == done => lo = N + 1

\* Witnesses: each must be reachable (TLC finds it violated).
\* A tier submitted in several chunks.
WitSeveral == ~(done /\ Len(clo) >= 2)
\* A result past the bound submitted alone.
WitAlone == ~(\E k \in 1..Len(clo): clo[k] = chi[k] /\ total[k] > Bound)
=============================================================================
