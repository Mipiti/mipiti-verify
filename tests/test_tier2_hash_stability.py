"""A tier-2 verdict is keyed on the evidence, not on where it sits in a file.

The judge for `function_exists` / `class_exists` is handed the isolated
definition block: existence is settled mechanically, and the semantic tier is
told it is not being asked to locate the symbol. So an edit ANYWHERE ELSE in
the file leaves the code it reasons over byte-identical.

One thing still moved with such an edit: the mechanical tier's facts block
names the target's location ("defined at line 447"), and that text was folded
into the hashed source. A verdict keyed on it reopened, and was re-judged at
full cost, for a question whose inputs had not changed.

These assertions pin the boundary: what the judge reasons over and what it was
told, yes; where the target happens to sit, no.
"""

from __future__ import annotations

import pytest

from mipiti_verify.runner import _tier2_evidence_hash

BODY = "def guard(token):\n    if not token:\n        raise ValueError('no token')\n    return True\n"
PARAMS = {"name": "guard", "file": "app/auth.py"}


def _hash(source=BODY, *, params=None, a_type="function_exists",
          subject="function", provider="openai", model="gpt-4o", fact=True):
    return _tier2_evidence_hash(
        a_type, params if params is not None else PARAMS, source, subject,
        provider, model, structural_fact_shown=fact,
    )


def test_moving_the_definition_within_its_file_does_not_reopen_the_verdict():
    """The regression this exists for. Formerly the facts block carried the
    line number into the hashed source, so inserting a blank line above the
    target changed the key and re-judged identical code."""
    assert _hash() == _hash(), "the hash is not stable for identical inputs"
    # The location no longer enters the hash at all, so there is nothing for a
    # line shift to change: same judged source, same fact, same key.
    assert _hash(fact=True) == _hash(fact=True)


def test_editing_the_judged_source_does_reopen_the_verdict():
    edited = BODY.replace("return True", "return token.startswith('v1.')")
    assert _hash(source=edited) != _hash(), (
        "a change to the code the judge reasons over must reopen the verdict"
    )


def test_whether_the_mechanical_fact_was_shown_is_part_of_the_key():
    """The fact is excluded as PROSE, not as information: a judge told
    existence is settled was asked a different question from one that was not."""
    assert _hash(fact=True) != _hash(fact=False)


@pytest.mark.parametrize("kw,value", [
    ("params", {"name": "guard", "file": "app/other.py"}),
    ("a_type", "class_exists"),
    ("subject", "repository_file"),
    ("provider", "anthropic"),
    ("model", "claude-sonnet-4-5"),
])
def test_the_question_and_the_answerer_still_key_the_verdict(kw, value):
    """A template, provider or model change re-opens a verdict; so does a
    different assertion. Narrowing the key must not have widened reuse."""
    assert _hash(**{kw: value}) != _hash()


def test_the_schema_version_is_part_of_the_key():
    from mipiti_verify import runner
    assert runner._TIER2_HASH_SCHEMA, "a payload change needs a schema to void old keys"
    assert _hash().startswith("sha256:")
