"""How strongly each clause of a control is proven, recomputed from the
package (``clause_strength``).

An audit package states, per control, each clause's evidence strength beside
its sufficiency, on a tier order

    none < claimed < witnessed < sound < constructed

and with each clause the edges (the evidence offered for it, with every fact
the strength rests on: its class, how it is bound to the clause, both
verification tiers, whether the run was attested and its statement signed,
whether its scope covers the path, what an enumeration decided, demotion and
expiry). The control's strength is its weakest clause's.

This module recomputes every clause's tier and coverage from its edges with
the same rules the platform states, and the control's from its clauses, and
reports any clause or control whose served strength is not what its own
record gives. Nothing here trusts the strength the platform served: a package
whose stated strength its edges do not give is internally inconsistent.

The rules are kept equal to the platform's by a table of cases the platform's
composition produced (``tests/fixtures/strength_cases.json``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

TIER_NONE, TIER_CLAIMED, TIER_WITNESSED = "none", "claimed", "witnessed"
TIER_SOUND, TIER_CONSTRUCTED = "sound", "constructed"
TIER_ORDER = {TIER_NONE: 0, TIER_CLAIMED: 1, TIER_WITNESSED: 2, TIER_SOUND: 3,
              TIER_CONSTRUCTED: 4}

PRESENCE = "presence"
UNDER_APPROXIMATING_SCAN = "under_approximating_scan"
EXISTENTIAL_WITNESS = "existential_witness"
SOUND_OVER_APPROXIMATION = "sound_over_approximation"
BY_CONSTRUCTION = "by_construction"
OPERATOR_CLAIM = "operator_claim"
CI_DERIVED = "ci_derived"

ORIGIN_ORDER = {"inferred": 0, "structural": 1, "declared": 2}
KIND_ATTESTATION = "attestation"
QUANTIFIER_UNIVERSAL = "universal"
PASS, FAIL = "pass", "fail"
SIGNED_PROVENANCE = frozenset({"ci_oidc", "customer_key"})
_LEVEL_ORDER = {"presence": 0, "behavioral": 1, "anchored": 2, "reached": 3, "depended": 4}


def tier_rank(tier: str) -> int:
    return TIER_ORDER.get(tier, 0)


def _enumeration_stands(edge: dict) -> bool:
    total, listed = edge.get("sites"), edge.get("sites_allowlisted")
    if total is None or listed is None:
        return False
    return total > listed >= 0


def _sound_guard(edge: dict) -> bool:
    return bool(edge.get("passes_now")) and edge.get("tier2") == PASS \
        and edge.get("origin") in ("declared", "structural") \
        and edge.get("scope_covers") is True and bool(edge.get("run_attested")) \
        and _enumeration_stands(edge)


def class_tier(edge: dict) -> str:
    """The strongest tier an edge supports, from its class and its facts."""
    if edge.get("expired"):
        return TIER_NONE
    cls = edge.get("evidence_class") or PRESENCE
    if cls == OPERATOR_CLAIM:
        return TIER_CLAIMED
    if cls == CI_DERIVED:
        backing = {**edge, "evidence_class": edge.get("backing_class") or PRESENCE,
                   "expired": False}
        backed = class_tier(backing)
        return backed if tier_rank(backed) <= tier_rank(TIER_WITNESSED) else TIER_WITNESSED
    if cls in (PRESENCE, UNDER_APPROXIMATING_SCAN):
        return TIER_NONE
    if cls == EXISTENTIAL_WITNESS:
        if _LEVEL_ORDER.get(edge.get("level") or "presence", 0) < _LEVEL_ORDER["anchored"] \
                or edge.get("demoted"):
            return TIER_NONE
        if edge.get("tier1") == FAIL or edge.get("tier2") == FAIL:
            return TIER_NONE
        if edge.get("tier1") != PASS:
            return TIER_NONE
        if edge.get("tier2") == PASS and edge.get("run_attested") \
                and (edge.get("statement_provenance") or "") in SIGNED_PROVENANCE:
            return TIER_WITNESSED
        return TIER_CLAIMED
    if cls == SOUND_OVER_APPROXIMATION:
        return TIER_SOUND if _sound_guard(edge) else TIER_NONE
    if cls == BY_CONSTRUCTION:
        return TIER_CONSTRUCTED if _sound_guard(edge) else TIER_NONE
    return TIER_NONE


def required_tier(quantifier: str, clause_class: str) -> str:
    if quantifier == QUANTIFIER_UNIVERSAL:
        return TIER_SOUND
    if (clause_class or "runtime") == "runtime":
        return TIER_CLAIMED
    return TIER_NONE


def admissible(edge: dict, quantifier: str, clause_class: str, required_origin: str) -> bool:
    if edge.get("dropped"):
        return False
    if ORIGIN_ORDER.get(edge.get("origin") or "inferred", 0) \
            < ORIGIN_ORDER.get(required_origin or "inferred", 0):
        return False
    if quantifier == QUANTIFIER_UNIVERSAL and edge.get("kind") == KIND_ATTESTATION:
        return False
    return tier_rank(class_tier(edge)) >= tier_rank(required_tier(quantifier, clause_class))


def compose_clause(clause: dict) -> dict:
    """``{"covered", "tier"}`` from a clause record's own edges."""
    quantifier = clause.get("quantifier") or "unknown"
    clause_class = clause.get("clause_class") or "runtime"
    origin = clause.get("required_origin") or "inferred"
    edges = [e for e in clause.get("edges") or [] if isinstance(e, dict)]
    ok = [e for e in edges if admissible(e, quantifier, clause_class, origin)]
    if not ok:
        return {"covered": False, "tier": TIER_NONE}
    return {"covered": True, "tier": max((class_tier(e) for e in ok), key=tier_rank)}


@dataclass
class ClauseCheck:
    control_id: str
    clause_id: str
    clause: str
    served: str
    recomputed: str
    consistent: bool
    no_longer_passing: list = field(default_factory=list)


@dataclass
class ControlCheck:
    control_id: str
    basis: str
    served: Optional[str]
    recomputed: Optional[str]
    clauses: list = field(default_factory=list)

    @property
    def consistent(self) -> bool:
        return self.served == self.recomputed and all(c.consistent for c in self.clauses)


@dataclass
class Report:
    controls: list = field(default_factory=list)

    @property
    def inconsistent(self) -> list:
        return [c for c in self.controls if not c.consistent]


def check(pkg: dict) -> Report:
    """Every control's stated strength against what its clauses' edges give.
    A strength stated as judged (``at_evaluation``) carries no edges and is
    reported as such, recomputed only from its clauses' stated tiers."""
    section = pkg.get("clause_strength") if isinstance(pkg, dict) else None
    report = Report()
    if not isinstance(section, dict):
        return report
    for control_id, shown in sorted(section.items()):
        if not isinstance(shown, dict):
            continue
        basis = str(shown.get("basis") or "")
        clauses = []
        tiers = []
        for clause in shown.get("clauses") or []:
            if not isinstance(clause, dict):
                continue
            served = str(clause.get("tier") or "")
            if basis == "now":
                again = compose_clause(clause)
                recomputed = again["tier"]
                consistent = again["tier"] == served and again["covered"] == bool(
                    clause.get("covered"))
            else:
                recomputed, consistent = served, True
            tiers.append(recomputed or TIER_NONE)
            clauses.append(ClauseCheck(
                control_id=control_id, clause_id=str(clause.get("clause_id") or ""),
                clause=str(clause.get("clause") or ""), served=served,
                recomputed=recomputed, consistent=consistent,
                no_longer_passing=[str(e.get("evidence_id") or "")
                                   for e in clause.get("evidence") or []
                                   if isinstance(e, dict) and not e.get("passes_now")]))
        served_control = shown.get("soundness_tier")
        if basis != "now" and served_control is None:
            recomputed_control = None
        else:
            recomputed_control = min(tiers, key=tier_rank) if tiers else TIER_NONE
        report.controls.append(ControlCheck(
            control_id=control_id, basis=basis,
            served=served_control if isinstance(served_control, str) else None,
            recomputed=recomputed_control, clauses=clauses))
    return report


__all__ = ["ClauseCheck", "ControlCheck", "Report", "TIER_ORDER", "admissible", "check",
           "class_tier", "compose_clause", "required_tier"]
