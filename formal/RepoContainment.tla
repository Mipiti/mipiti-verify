--------------------------- MODULE RepoContainment ---------------------------
(***************************************************************************)
(* Every file the runner reads or counts for an assertion lies under the   *)
(* project root it was given (verifiers.safe_resolve_path, safe_glob).     *)
(*                                                                         *)
(* A path an assertion or the platform supplies is raw: what it resolves   *)
(* to is the file system's business (a ``..`` segment, an absolute path, a *)
(* link anywhere along it), so resolution here is an arbitrary function    *)
(* from the base a path is taken against and the raw path to a resolved    *)
(* one, and TLC ranges over every such function. Inside is the set of      *)
(* resolved paths under the project root.                                  *)
(*                                                                         *)
(* The sources of reads: a verifier's file parameter and a mechanism's     *)
(* file, each one raw path; a glob pattern (test_exists, tier two's source *)
(* loading), a set of raw matches, its pattern refused when it is absolute *)
(* or climbs; and a component's path, which moves the base every later     *)
(* path is taken against.                                                  *)
(*                                                                         *)
(* Contained: every path read is inside, and so is the base.               *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    Paths,      \* resolved paths
    Inside,     \* the resolved paths under the project root
    Root,       \* the project root itself
    Raw,        \* raw paths an assertion or the platform may supply
    Mutant      \* "none", or the guard a mutant drops

ASSUME Inside \subseteq Paths /\ Root \in Inside

VARIABLES
    resolve,    \* [base -> [raw -> resolved]]: the file system
    base,       \* what later paths are taken against
    read,       \* every resolved path read or counted
    refused     \* whether a request was refused

vars == <<resolve, base, read, refused>>

M(name) == Mutant = name

TypeOK ==
    /\ resolve \in [Paths -> [Raw -> Paths]]
    /\ base \in Paths
    /\ read \subseteq Paths
    /\ refused \in BOOLEAN

Init ==
    /\ resolve \in [Paths -> [Raw -> Paths]]
    /\ base = Root /\ read = {} /\ refused = FALSE

\* The guard a source applies: the resolved path is under the root (the
\* mutant named for the source: no guard).
Kept(src, p) == p \in Inside \/ M(src)

\* A verifier's file parameter, or a mechanism's file: read where kept,
\* else refused.
ReadOne(src, r) ==
    LET p == resolve[base][r] IN
    /\ IF Kept(src, p) THEN read' = read \cup {p} /\ UNCHANGED refused
                       ELSE refused' = TRUE /\ UNCHANGED read
    /\ UNCHANGED <<resolve, base>>

\* A glob pattern matching ``ms``: refused when the pattern itself is
\* absolute or climbs (``safe``); else every match kept is read or counted,
\* each one resolving outside left out. Containment rests on the matches'
\* guard alone (TLC finds no violation with the pattern's refusal dropped):
\* the refusal is so a pattern that could only reach outside fails the check
\* by name rather than by matching nothing.
Glob(ms, safe) ==
    /\ IF ~safe
          THEN refused' = TRUE /\ UNCHANGED read
          ELSE read' = read \cup {resolve[base][r]: r \in {x \in ms: Kept("glob_match", resolve[base][x])}}
               /\ UNCHANGED refused
    /\ UNCHANGED <<resolve, base>>

\* A component's path: the base moves to it where kept, else the run stops.
Component(r) ==
    LET p == resolve[base][r] IN
    /\ IF Kept("component", p) THEN base' = p /\ UNCHANGED refused
                               ELSE refused' = TRUE /\ UNCHANGED base
    /\ UNCHANGED <<resolve, read>>

Next ==
    \/ \E r \in Raw: ReadOne("file", r) \/ ReadOne("mechanism", r) \/ Component(r)
    \/ \E ms \in SUBSET Raw, safe \in BOOLEAN: Glob(ms, safe)

Spec == Init /\ [][Next]_vars

Contained == read \subseteq Inside /\ base \in Inside

\* Witnesses: each must be reachable (TLC finds it violated).
\* A request that would leave the root is refused.
WitRefused == ~refused
\* A component moves the base, and a file is read under it.
WitMoved == ~(base # Root /\ read # {})
=============================================================================
