--------------------- MODULE ChunkedSubmissionProofs ---------------------
\* Proofs of ChunkedSubmission.tla's properties for runs of any length, any
\* number of results, any sizes and any bound, checked by TLAPS (tlapm).
\* TLC checks them at five results, sizes up to six and a bound of five.
\*
\* An inductive invariant: Inv holds initially and every step keeps it. A
\* take either extends the open chunk (its total kept within the bound, or
\* the chunk holding one result) or closes it at next-1 and opens the next
\* at next; a finish closes the open chunk at N. Closing is the one step that
\* appends, and CloseKeeps proves what an append of the open chunk keeps.
\* Only the shipped guards are proved (Mutant = "none"); the mutants are the
\* model checker's.

EXTENDS ChunkedSubmission, SequenceTheorems, TLAPS

ASSUME Shipped == Mutant = "none"

ASSUME Constants == /\ N \in Nat /\ MaxSize \in Nat \ {0} /\ Bound \in Nat

\* Once done, every result has been taken.
Aux == done => next = N + 1

Inv == TypeOK /\ Partition /\ Bounded /\ HashBinds /\ AllSubmitted /\ Aux

USE Shipped, Constants DEF Results, Sizes, M

\* AppendProperties at a sequence of sets of results, the set named so the
\* back ends instantiate it.
LEMMA AppendSet ==
    ASSUME NEW s \in Seq(SUBSET Results), NEW e \in SUBSET Results
    PROVE  /\ Append(s, e) \in Seq(SUBSET Results)
           /\ Len(Append(s, e)) = Len(s) + 1
           /\ \A k \in 1..Len(s): Append(s, e)[k] = s[k]
           /\ Append(s, e)[Len(s) + 1] = e
<1> DEFINE S == SUBSET Results
<1>1. s \in Seq(S) /\ e \in S OBVIOUS
<1>2. /\ Append(s, e) \in Seq(S) /\ Len(Append(s, e)) = Len(s) + 1
      /\ \A k \in 1..Len(s): Append(s, e)[k] = s[k] /\ Append(s, e)[Len(s) + 1] = e
    BY <1>1, AppendProperties
<1> QED BY <1>2

LEMMA InitInv == Init => Inv
BY DEF Init, Inv, TypeOK, Partition, Bounded, HashBinds, AllSubmitted, Aux

\* Closing the open chunk lo..next-1 (non-empty) and opening one at next,
\* holding ``u`` of size: every property of the closed chunks and the open
\* one is kept, whatever the open one holds (``u`` within the bound, or one
\* result: ``fresh``).
LEMMA CloseKeeps ==
    ASSUME NEW nx \in 1..(N + 1), NEW u \in Nat
    PROVE  (/\ Inv /\ lo < next /\ next \in 1..(N + 1)
            /\ clo' = Append(clo, lo) /\ chi' = Append(chi, next - 1)
            /\ total' = Append(total, used) /\ sent' = Append(sent, lo..(next - 1))
            /\ next' = nx /\ nx >= next /\ lo' = next
            /\ used' = u /\ (u <= Bound \/ nx - next <= 1))
           => (Partition' /\ Bounded' /\ HashBinds')
<1> SUFFICES ASSUME Inv, lo < next, next \in 1..(N + 1),
                    clo' = Append(clo, lo), chi' = Append(chi, next - 1),
                    total' = Append(total, used), sent' = Append(sent, lo..(next - 1)),
                    next' = nx, nx >= next, lo' = next,
                    used' = u, u <= Bound \/ nx - next <= 1
             PROVE  Partition' /\ Bounded' /\ HashBinds'
    OBVIOUS
<1>1. /\ clo \in Seq(Results) /\ chi \in Seq(Results)
      /\ total \in Seq(Nat) /\ sent \in Seq(SUBSET Results)
      /\ lo \in Results /\ next - 1 \in Results /\ used \in Nat
    BY DEF Inv, TypeOK
<1>2. Len(clo) = Len(chi) /\ Len(total) = Len(clo) /\ Len(sent) = Len(clo)
    BY DEF Inv, Partition
<1>a. lo..(next - 1) \in SUBSET Results BY <1>1
<1>b. /\ Len(Append(clo, lo)) = Len(clo) + 1
      /\ \A k \in 1..Len(clo): Append(clo, lo)[k] = clo[k]
      /\ Append(clo, lo)[Len(clo) + 1] = lo
    BY <1>1, AppendProperties
<1>c. /\ Len(Append(chi, next - 1)) = Len(chi) + 1
      /\ \A k \in 1..Len(chi): Append(chi, next - 1)[k] = chi[k]
      /\ Append(chi, next - 1)[Len(chi) + 1] = next - 1
    BY <1>1, AppendProperties
<1>d. /\ Len(Append(total, used)) = Len(total) + 1
      /\ \A k \in 1..Len(total): Append(total, used)[k] = total[k]
      /\ Append(total, used)[Len(total) + 1] = used
    BY <1>1, AppendProperties
<1>e. /\ Len(Append(sent, lo..(next - 1))) = Len(sent) + 1
      /\ \A k \in 1..Len(sent): Append(sent, lo..(next - 1))[k] = sent[k]
      /\ Append(sent, lo..(next - 1))[Len(sent) + 1] = lo..(next - 1)
    BY <1>1, <1>a, AppendSet
<1>f. /\ Len(clo') = Len(clo) + 1 /\ (\A k \in 1..Len(clo): clo'[k] = clo[k])
      /\ clo'[Len(clo) + 1] = lo
    BY <1>b
<1>g. /\ Len(chi') = Len(clo) + 1 /\ (\A k \in 1..Len(clo): chi'[k] = chi[k])
      /\ chi'[Len(clo) + 1] = next - 1
    BY <1>2, <1>c
<1>h. /\ Len(total') = Len(clo) + 1 /\ (\A k \in 1..Len(clo): total'[k] = total[k])
      /\ total'[Len(clo) + 1] = used
    BY <1>2, <1>d
<1>i. /\ Len(sent') = Len(clo) + 1 /\ (\A k \in 1..Len(clo): sent'[k] = sent[k])
      /\ sent'[Len(clo) + 1] = lo..(next - 1)
    BY <1>2, <1>e
<1>3. /\ Len(clo') = Len(clo) + 1 /\ Len(chi') = Len(clo) + 1
      /\ Len(total') = Len(clo) + 1 /\ Len(sent') = Len(clo) + 1
      /\ \A k \in 1..Len(clo): clo'[k] = clo[k] /\ chi'[k] = chi[k]
                               /\ total'[k] = total[k] /\ sent'[k] = sent[k]
      /\ clo'[Len(clo) + 1] = lo /\ chi'[Len(clo) + 1] = next - 1
      /\ total'[Len(clo) + 1] = used /\ sent'[Len(clo) + 1] = lo..(next - 1)
    BY <1>f, <1>g, <1>h, <1>i
<1>j. Len(clo) \in Nat BY <1>1
<1>4. Partition'
    <2>1. Len(clo') > 0 => clo'[1] = 1
        <3>1. CASE Len(clo) = 0 BY <1>3, <3>1 DEF Inv, Partition
        <3>2. CASE Len(clo) > 0 BY <1>3, <1>j, <3>2 DEF Inv, Partition
        <3> QED BY <1>j, <3>1, <3>2
    <2>2. \A k \in 1..Len(clo'): clo'[k] <= chi'[k]
        <3>1. SUFFICES ASSUME NEW k \in 1..(Len(clo) + 1) PROVE clo'[k] <= chi'[k]
            BY <1>3
        <3>2. CASE k <= Len(clo) BY <1>3, <1>j, <3>2 DEF Inv, Partition
        <3>3. CASE k = Len(clo) + 1 BY <1>3, <1>1, <3>3
        <3> QED BY <1>j, <3>2, <3>3
    <2>3. \A k \in 1..(Len(clo') - 1): clo'[k + 1] = chi'[k] + 1
        <3>1. SUFFICES ASSUME NEW k \in 1..Len(clo) PROVE clo'[k + 1] = chi'[k] + 1
            BY <1>3, <1>j
        <3>2. CASE k < Len(clo) BY <1>3, <1>j, <3>2 DEF Inv, Partition
        <3>3. CASE k = Len(clo) BY <1>3, <1>j, <3>3 DEF Inv, Partition
        <3> QED BY <1>j, <3>2, <3>3
    <2>4. Len(clo') > 0 => lo' = chi'[Len(clo')] + 1 BY <1>3, <1>j
    <2>5. lo' <= next' BY DEF Inv, Partition
    <2> QED BY <1>3, <1>j, <2>1, <2>2, <2>3, <2>4, <2>5 DEF Partition
<1>5. Bounded'
    <2>1. used <= Bound \/ next - lo <= 1 BY DEF Inv, Bounded
    <2>2. used <= Bound \/ lo = next - 1 BY <1>1, <2>1
    <2>3. \A k \in 1..Len(clo'): total'[k] <= Bound \/ clo'[k] = chi'[k]
        <3>1. SUFFICES ASSUME NEW k \in 1..(Len(clo) + 1)
                       PROVE total'[k] <= Bound \/ clo'[k] = chi'[k]
            BY <1>3
        <3>2. CASE k <= Len(clo) BY <1>3, <1>j, <3>2 DEF Inv, Bounded
        <3>3. CASE k = Len(clo) + 1 BY <1>3, <2>2, <3>3
        <3> QED BY <1>j, <3>2, <3>3
    <2>4. used' <= Bound \/ next' - lo' <= 1 OBVIOUS
    <2> QED BY <2>3, <2>4 DEF Bounded
<1>6. HashBinds'
    <2>1. SUFFICES ASSUME NEW k \in 1..(Len(clo) + 1) PROVE sent'[k] = clo'[k]..chi'[k]
        BY <1>3 DEF HashBinds
    <2>2. CASE k <= Len(clo) BY <1>2, <1>3, <1>j, <2>2 DEF Inv, HashBinds
    <2>3. CASE k = Len(clo) + 1 BY <1>3, <2>3
    <2> QED BY <1>j, <2>2, <2>3
<1> QED BY <1>4, <1>5, <1>6

LEMMA TakeStep == Inv /\ Take => Inv'
<1> SUFFICES ASSUME Inv, Take PROVE Inv' OBVIOUS
<1>1. next \in Results /\ size[next] \in Sizes /\ ~done /\ used \in Nat
      /\ lo \in 1..(N + 1) /\ lo <= next
    BY DEF Take, Inv, TypeOK, Partition
<1>2. CASE lo < next /\ used + size[next] > Bound
    <2>1. /\ clo' = Append(clo, lo) /\ chi' = Append(chi, next - 1)
          /\ total' = Append(total, used) /\ sent' = Append(sent, lo..(next - 1))
          /\ lo' = next /\ used' = size[next] /\ next' = next + 1
          /\ UNCHANGED <<size, done>>
        BY <1>2 DEF Take, Close
    <2>2. Partition' /\ Bounded' /\ HashBinds'
        BY <1>1, <1>2, <2>1, CloseKeeps
    <2>3. TypeOK'
        <3>1. /\ clo \in Seq(Results) /\ chi \in Seq(Results)
              /\ total \in Seq(Nat) /\ sent \in Seq(SUBSET Results)
              /\ lo \in Results /\ next - 1 \in Results /\ used \in Nat
              /\ lo..(next - 1) \in SUBSET Results
            BY <1>1, <1>2 DEF Inv, TypeOK
        <3>2. clo' \in Seq(Results) /\ chi' \in Seq(Results)
            BY <2>1, <3>1, AppendProperties
        <3>3. total' \in Seq(Nat) BY <2>1, <3>1, AppendProperties
        <3>4. sent' \in Seq(SUBSET Results) BY <2>1, <3>1, AppendSet
        <3> QED BY <1>1, <2>1, <3>1, <3>2, <3>3, <3>4 DEF Inv, TypeOK
    <2> QED BY <1>1, <2>1, <2>2, <2>3 DEF Inv, AllSubmitted, Aux
<1>3. CASE ~(lo < next /\ used + size[next] > Bound)
    <2>1. /\ used' = used + size[next] /\ next' = next + 1
          /\ UNCHANGED <<lo, clo, chi, total, sent, size, done>>
        BY <1>3 DEF Take
    <2>2. used + size[next] <= Bound \/ lo = next BY <1>1, <1>3
    <2> QED BY <1>1, <2>1, <2>2
        DEF Inv, TypeOK, Partition, Bounded, HashBinds, AllSubmitted, Aux
<1> QED BY <1>2, <1>3

LEMMA FinishStep == Inv /\ Finish => Inv'
<1> SUFFICES ASSUME Inv, Finish PROVE Inv' OBVIOUS
<1>1. next = N + 1 /\ ~done /\ lo \in 1..(N + 1) /\ lo <= next
    BY DEF Finish, Inv, TypeOK, Partition
<1>2. CASE lo < next
    <2>1. /\ clo' = Append(clo, lo) /\ chi' = Append(chi, next - 1)
          /\ total' = Append(total, used) /\ sent' = Append(sent, lo..(next - 1))
          /\ lo' = next /\ used' = 0 /\ done' = TRUE
          /\ UNCHANGED <<size, next>>
        BY <1>2 DEF Finish, Close
    <2>2. Partition' /\ Bounded' /\ HashBinds'
        BY <1>1, <1>2, <2>1, CloseKeeps
    <2>3. TypeOK'
        <3>1. /\ clo \in Seq(Results) /\ chi \in Seq(Results)
              /\ total \in Seq(Nat) /\ sent \in Seq(SUBSET Results)
              /\ lo \in Results /\ next - 1 \in Results /\ used \in Nat
              /\ lo..(next - 1) \in SUBSET Results
            BY <1>1, <1>2 DEF Inv, TypeOK
        <3>2. clo' \in Seq(Results) /\ chi' \in Seq(Results)
            BY <2>1, <3>1, AppendProperties
        <3>3. total' \in Seq(Nat) BY <2>1, <3>1, AppendProperties
        <3>4. sent' \in Seq(SUBSET Results) BY <2>1, <3>1, AppendSet
        <3> QED BY <1>1, <2>1, <3>1, <3>2, <3>3, <3>4 DEF Inv, TypeOK
    <2> QED BY <1>1, <2>1, <2>2, <2>3 DEF Inv, AllSubmitted, Aux
<1>3. CASE ~(lo < next)
    <2>1. /\ done' = TRUE /\ UNCHANGED <<lo, used, clo, chi, total, sent, size, next>>
        BY <1>3 DEF Finish
    <2>2. lo = N + 1 BY <1>1, <1>3
    <2> QED BY <1>1, <2>1, <2>2
        DEF Inv, TypeOK, Partition, Bounded, HashBinds, AllSubmitted, Aux
<1> QED BY <1>2, <1>3

LEMMA NextInv == Inv /\ [Next]_vars => Inv'
<1> SUFFICES ASSUME Inv, [Next]_vars PROVE Inv' OBVIOUS
<1>1. CASE Take BY <1>1, TakeStep
<1>2. CASE Finish BY <1>2, FinishStep
<1>3. CASE UNCHANGED vars
    BY <1>3 DEF vars, Inv, TypeOK, Partition, Bounded, HashBinds, AllSubmitted, Aux
<1> QED BY <1>1, <1>2, <1>3 DEF Next

THEOREM Safety == Spec => []Inv
BY InitInv, NextInv, PTL DEF Spec
=============================================================================
