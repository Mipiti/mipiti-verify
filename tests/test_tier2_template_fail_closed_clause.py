"""Every ``tier2_*.j2`` template carries a universal fail-closed clause.

The clause instructs the LLM that lack of visible evidence in
SOURCE_CODE is NEVER a YES verdict, and that the assertion's
``description`` is a claim — not evidence. This closes a false-pass
class of bug where the LLM could rationalize YES from the params
alone, regardless of the source content. Applying it uniformly to
every template is the contract the test enforces — adding a new
template without the clause is rejected.

The contract is enforced on the RENDERED prompt, once per subject a
template can be rendered for. A template branches on ``SUBJECT_KIND``,
so the clause can be present in the file and still be missing from
what an LLM is actually sent: a regression confined to one arm of a
conditional survives any check that reads the template source. Every
arm that can reach a provider is rendered here and checked in its own
right.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mipiti_verify.tier2 import (
    SUBJECT_FEATURE_DESCRIPTION,
    SUBJECT_REPOSITORY_FILE,
    _build_message,
)

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

# Every subject a template may be rendered for. The runner settles the
# subject when it loads the content; each value it can settle on
# produces a prompt an LLM will be sent, so each has to carry the
# clause. An unrecognised value is included because the render falls
# back to the repository-file wording rather than failing.
SUBJECT_KINDS: tuple[str, ...] = (
    SUBJECT_REPOSITORY_FILE,
    SUBJECT_FEATURE_DESCRIPTION,
    "an_unrecognised_subject",
)

# Params used for every render. Deliberately free of the words the
# clause is checked for, so a phrase can only be found because the
# template put it there — not because the test fed it in.
_RENDER_PARAMS: dict[str, str] = {
    "file": "app.py",
    "pattern": "x",
    "name": "handler",
    "caller": "handler",
    "module": "app",
    "signal": "clk",
    "port": "rst_n",
    "register": "cfg",
}

_RENDER_SOURCE = "def handler():\n    return 1\n"


def _template_types() -> list[str]:
    return sorted(p.name[len("tier2_"):-len(".j2")] for p in TEMPLATES_DIR.glob("tier2_*.j2"))


def _render(assertion_type: str, subject_kind: str) -> str:
    return _build_message(
        assertion_type=assertion_type,
        assertion_params=dict(_RENDER_PARAMS),
        source_code=_RENDER_SOURCE,
        subject_kind=subject_kind,
    )


@pytest.mark.parametrize("subject_kind", SUBJECT_KINDS)
@pytest.mark.parametrize("assertion_type", _template_types())
def test_rendered_prompt_contains_fail_closed_clause(
    assertion_type: str, subject_kind: str,
) -> None:
    """The clause reaches the LLM for every type, on every subject."""
    rendered = _render(assertion_type, subject_kind)
    for phrase in REQUIRED_PHRASES:
        # Match case-insensitively for prose phrases; the literal token
        # "SOURCE_CODE" must appear verbatim.
        if phrase == "SOURCE_CODE":
            assert phrase in rendered, (
                f"{assertion_type} ({subject_kind}): missing literal {phrase!r}"
            )
        else:
            assert phrase.lower() in rendered.lower(), (
                f"{assertion_type} ({subject_kind}): missing phrase {phrase!r}"
            )


@pytest.mark.parametrize("subject_kind", SUBJECT_KINDS)
@pytest.mark.parametrize("assertion_type", _template_types())
def test_rendered_clause_precedes_the_per_type_criterion(
    assertion_type: str, subject_kind: str,
) -> None:
    """The universal clause must come BEFORE the per-type criterion so
    the LLM reads the fail-closed instruction before the type-specific
    YES/NO guidance — in the prompt as sent, not merely in the template
    source, since either may be produced by a branch."""
    rendered = _render(assertion_type, subject_kind)
    clause_pos = rendered.find("Fail-closed rule")
    criterion_pos = rendered.find("Per-type criterion")
    assert clause_pos != -1, (
        f"{assertion_type} ({subject_kind}): missing fail-closed clause"
    )
    assert criterion_pos != -1, (
        f"{assertion_type} ({subject_kind}): missing per-type criterion"
    )
    assert clause_pos < criterion_pos, (
        f"{assertion_type} ({subject_kind}): fail-closed clause must precede "
        f"the per-type criterion"
    )


@pytest.mark.parametrize("subject_kind", SUBJECT_KINDS)
@pytest.mark.parametrize("assertion_type", _template_types())
def test_rendered_prompt_leaves_no_unrendered_branch(
    assertion_type: str, subject_kind: str,
) -> None:
    """A rendered prompt carries no Jinja control syntax. Catches a
    branch left unclosed or a tag mistyped into literal text, which
    would otherwise ship template source to the LLM."""
    rendered = _render(assertion_type, subject_kind)
    assert not re.search(r"{%-?\s*(if|else|elif|endif)\b", rendered), (
        f"{assertion_type} ({subject_kind}): unrendered Jinja control syntax"
    )


def test_every_tier2_template_covered() -> None:
    """Bumper test — at least 28 tier2 templates exist. If the count
    drops, the templating layout changed and the per-type coverage
    should be revisited."""
    files = sorted(TEMPLATES_DIR.glob("tier2_*.j2"))
    assert len(files) >= 28, f"expected ≥28 tier2 templates, found {len(files)}"
    # The rendering tests above are driven by the same glob; if it ever
    # resolved to nothing they would silently cover nothing at all.
    assert _template_types(), "no templates discovered to render"
