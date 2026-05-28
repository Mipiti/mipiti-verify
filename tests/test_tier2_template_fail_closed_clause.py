"""Every ``tier2_*.j2`` template carries a universal fail-closed clause.

The clause instructs the LLM that lack of visible evidence in
SOURCE_CODE is NEVER a YES verdict, and that the assertion's
``description`` is a claim — not evidence. This closes a false-pass
class of bug where the LLM could rationalize YES from the params
alone, regardless of the source content. Applying it uniformly to
every template is the contract the test enforces — adding a new
template without the clause is rejected.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "mipiti_verify"
    / "templates"
)

REQUIRED_PHRASES: tuple[str, ...] = (
    "Fail-closed rule",
    "SOURCE_CODE",
    "Lack of visible evidence is NEVER YES",
    "description",  # references the assertion's description as a CLAIM
    "claim",  # case-insensitive check below
)


@pytest.mark.parametrize(
    "template_path",
    sorted(TEMPLATES_DIR.glob("tier2_*.j2")),
    ids=lambda p: p.name,
)
def test_template_contains_fail_closed_clause(template_path: Path) -> None:
    text = template_path.read_text(encoding="utf-8")
    for phrase in REQUIRED_PHRASES:
        # Match case-insensitively for prose phrases; the literal token
        # "SOURCE_CODE" must appear verbatim.
        if phrase == "SOURCE_CODE":
            assert phrase in text, (
                f"{template_path.name}: missing literal {phrase!r}"
            )
        else:
            assert phrase.lower() in text.lower(), (
                f"{template_path.name}: missing phrase {phrase!r}"
            )


def test_every_tier2_template_covered() -> None:
    """Bumper test — at least 21 tier2 templates exist. If the count
    drops, the templating layout changed and the per-type coverage
    should be revisited."""
    files = sorted(TEMPLATES_DIR.glob("tier2_*.j2"))
    assert len(files) >= 21, f"expected ≥21 tier2 templates, found {len(files)}"


def test_clause_appears_before_per_type_criterion() -> None:
    """The universal clause must come BEFORE the per-type criterion so
    the LLM reads the fail-closed instruction before the type-specific
    YES/NO guidance."""
    for tpl in sorted(TEMPLATES_DIR.glob("tier2_*.j2")):
        text = tpl.read_text(encoding="utf-8")
        clause_pos = text.find("Fail-closed rule")
        criterion_pos = text.find("Per-type criterion")
        assert clause_pos != -1, f"{tpl.name}: missing fail-closed clause"
        assert criterion_pos != -1, f"{tpl.name}: missing per-type criterion"
        assert clause_pos < criterion_pos, (
            f"{tpl.name}: fail-closed clause must precede per-type criterion"
        )
