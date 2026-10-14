"""What each declared control was checked against, re-checked from the package
(``declared_commitments``).

A control a person declared a behavioural delta for is judged against that
declaration rather than a decomposition of its text: one clause per edit in
words, one per item the declaration says the text commits to that no edit
states. Before such a control can read sufficient, the text is cross-checked
once against the declaration for anything it commits to beyond it, and every
finding of that cross-check must be dismissed by a person. The package states,
per declared control, the declaration (its clauses, who declared it and when,
the spans it says commit to nothing) and the cross-check with each finding and
whether it was dismissed.

This module recomputes what the record lets a reader recompute, and reports any
control whose record disagrees with itself or with the status it was served:

- each clause's id from its words (the id is the clause's fingerprint in a
  clause class of its own, suffixed when two clauses read alike);
- each finding's id from its words;
- that a control served a verdict was declared over its text as the package
  states it;
- that a control served sufficient has a completed cross-check, every finding
  of it dismissed, and every span it says commits to nothing still reading.

The id rules are kept equal to the platform's by a table of cases the platform
produced (``tests/fixtures/commitment_cases.json``).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field

#: The clause class a declared clause is fingerprinted in, and the version of
#: the fingerprint's definition, as the platform mints them.
CLAUSE_CLASS = "declared"
CLAUSE_FP_SCHEMA_VERSION = 1

_WS_RUN = re.compile(r"\s+")


def _canonical(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize("NFC", text).strip()
    return _WS_RUN.sub(" ", text).lower()


def clause_fingerprint(text: str) -> str:
    """A declared clause's fingerprint: of the fingerprint's version, the
    clause class and the clause's words with case, spacing and Unicode form
    folded."""
    material = f"{CLAUSE_FP_SCHEMA_VERSION}\x1f{CLAUSE_CLASS}\x1f{_canonical(text)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def clause_ids(texts: list) -> list:
    """The ids of a declaration's clauses, in order: ``dcl_`` and the
    fingerprint, suffixed ``_n`` for the n-th further clause that reads alike."""
    seen: dict = {}
    out = []
    for text in texts:
        fp = clause_fingerprint(text)
        n = seen.get(fp, 0)
        seen[fp] = n + 1
        out.append(f"dcl_{fp}" + (f"_{n}" if n else ""))
    return out


def finding_id(text: str) -> str:
    """A cross-check finding's id: of its words."""
    return hashlib.sha256((text or "").strip().encode("utf-8")).hexdigest()[:16]


def description_hash(text: str) -> str:
    """The hash a declaration names its control's text by: of the text exactly."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


@dataclass
class ControlCommitments:
    control_id: str
    served: str
    declared_by: str
    declared_at: str
    clauses: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    open_findings: list = field(default_factory=list)
    cross_check_completed: bool = False
    #: Where the record disagrees with itself or with the status it was served.
    problems: list = field(default_factory=list)

    @property
    def consistent(self) -> bool:
        return not self.problems


@dataclass
class Report:
    controls: list = field(default_factory=list)

    @property
    def inconsistent(self) -> list:
        return [c for c in self.controls if not c.consistent]


def _controls(pkg: dict) -> dict:
    raw = pkg.get("controls")
    if isinstance(raw, list):
        return {c.get("id"): c for c in raw if isinstance(c, dict) and c.get("id")}
    if isinstance(raw, dict):
        return {k: v for k, v in raw.items() if isinstance(v, dict)}
    return {}


def _served(pkg: dict, control: dict, control_id: str) -> str:
    suff = control.get("sufficiency") if isinstance(control, dict) else None
    if not isinstance(suff, dict):
        top = pkg.get("sufficiency")
        suff = top.get(control_id) if isinstance(top, dict) else None
    if not isinstance(suff, dict):
        return ""
    return str(suff.get("status") or "")


def check(pkg: dict) -> Report:
    """Every declared control's record against itself and its served status."""
    section = pkg.get("declared_commitments") if isinstance(pkg, dict) else None
    report = Report()
    if not isinstance(section, dict):
        return report
    controls = _controls(pkg)
    for control_id, shown in sorted(section.items()):
        if not isinstance(shown, dict):
            continue
        control = controls.get(control_id) or {}
        served = _served(pkg, control, control_id)
        problems: list = []

        clauses = [c for c in shown.get("clauses") or [] if isinstance(c, dict)]
        texts = [str(c.get("text") or "") for c in clauses]
        for clause, expected in zip(clauses, clause_ids(texts)):
            stated = str(clause.get("clause_id") or "")
            if stated != expected:
                problems.append(f"clause {stated or '(no id)'} is not the clause its words "
                                f"name ({expected})")

        # A record served as a verdict (not stale, not pending) answers the
        # text that stands, so its declaration is of that text.
        description = control.get("description") if isinstance(control, dict) else None
        stated_hash = str(shown.get("description_hash") or "")
        if served in ("sufficient", "insufficient") and isinstance(description, str) \
                and stated_hash and stated_hash != description_hash(description):
            problems.append("the declaration is of another text than the control's")

        xc = shown.get("cross_check")
        completed = isinstance(xc, dict) and bool(xc.get("completed"))
        findings = [f for f in (xc.get("findings") if isinstance(xc, dict) else None) or []
                    if isinstance(f, dict)]
        for f in findings:
            stated = str(f.get("finding_id") or "")
            if stated != finding_id(str(f.get("text") or "")):
                problems.append(f"finding {stated or '(no id)'} is not the finding its "
                                f"words name")
        open_ = [f for f in findings if not f.get("dismissed")]

        if served == "sufficient":
            if not clauses:
                problems.append("served sufficient with no declared clause")
            if not completed:
                problems.append("served sufficient without a completed cross-check")
            if open_:
                problems.append(f"served sufficient with {len(open_)} cross-check "
                                f"finding(s) no person dismissed")
            unread = [s for s in shown.get("nothing_spans") or []
                      if isinstance(s, dict) and s.get("text") is None]
            if unread:
                problems.append(f"served sufficient with {len(unread)} span(s) said to "
                                f"commit to nothing that no longer read in the text")

        report.controls.append(ControlCommitments(
            control_id=control_id, served=served,
            declared_by=str(shown.get("declared_by") or ""),
            declared_at=str(shown.get("declared_at") or ""),
            clauses=texts, findings=findings, open_findings=open_,
            cross_check_completed=completed, problems=problems))
    return report


__all__ = ["CLAUSE_CLASS", "ControlCommitments", "Report", "check", "clause_fingerprint",
           "clause_ids", "description_hash", "finding_id"]
