---------------------- MODULE RepoContainmentProofs ----------------------
\* Proof of RepoContainment.tla's Contained for runs of any length, any
\* sets of paths and raw paths, and every file system (every resolution
\* function), checked by TLAPS (tlapm). TLC checks it at three paths and two
\* raw paths.
\*
\* Every step adds to what is read only a resolved path its source's guard
\* kept, which is under the root, and moves the base only to such a path.
\* Only the shipped guards are proved (Mutant = "none"); the mutants are the
\* model checker's.

EXTENDS RepoContainment, TLAPS

ASSUME Shipped == Mutant = "none"

ASSUME RootInside == Inside \subseteq Paths /\ Root \in Inside

Inv == TypeOK /\ Contained

USE Shipped, RootInside DEF Kept, M

LEMMA InitInv == Init => Inv
BY DEF Init, Inv, TypeOK, Contained

LEMMA ReadOneStep ==
    ASSUME Inv, NEW src \in {"file", "mechanism"}, NEW r \in Raw, ReadOne(src, r)
    PROVE  Inv'
BY DEF ReadOne, Inv, TypeOK, Contained

LEMMA GlobStep ==
    ASSUME Inv, NEW ms \in SUBSET Raw, NEW safe \in BOOLEAN, Glob(ms, safe)
    PROVE  Inv'
BY DEF Glob, Inv, TypeOK, Contained

LEMMA ComponentStep ==
    ASSUME Inv, NEW r \in Raw, Component(r)
    PROVE  Inv'
BY DEF Component, Inv, TypeOK, Contained

LEMMA NextInv == Inv /\ [Next]_vars => Inv'
<1> SUFFICES ASSUME Inv, [Next]_vars PROVE Inv' OBVIOUS
<1>1. CASE \E r \in Raw: ReadOne("file", r) BY <1>1, ReadOneStep
<1>2. CASE \E r \in Raw: ReadOne("mechanism", r) BY <1>2, ReadOneStep
<1>3. CASE \E r \in Raw: Component(r) BY <1>3, ComponentStep
<1>4. CASE \E ms \in SUBSET Raw, safe \in BOOLEAN: Glob(ms, safe) BY <1>4, GlobStep
<1>5. CASE UNCHANGED vars BY <1>5 DEF vars, Inv, TypeOK, Contained
<1> QED BY <1>1, <1>2, <1>3, <1>4, <1>5 DEF Next

THEOREM Safety == Spec => []Inv
BY InitInv, NextInv, PTL DEF Spec
=============================================================================
