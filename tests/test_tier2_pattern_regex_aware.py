"""The ``pattern_matches`` / ``pattern_absent`` tier-2 prompts must be
regex-aware.

The ``pattern`` param of these types is a REGULAR EXPRESSION: tier-1
matches it with ``re.search``, so a literal like ``foo.get(bar)`` is
authored escaped as ``foo\\.get\\(bar\\)``. If the tier-2 prompt tells
the model to treat ``pattern`` as a literal string to locate, the
model can answer NO on an escaped pattern whose backslashes do not
appear verbatim in the source — even though tier-1 already matched it,
producing a tier-1 PASS / tier-2 FAIL split on the same correct
assertion.

These tests assert on the RENDERED prompt text only (no live LLM
calls): the model must be told the field is a regular expression that a
prior step already resolved, and that tier-2 judges whether the matched
(or confirmed-absent) code MEANINGFULLY proves the control.
"""

from __future__ import annotations

from mipiti_verify.tier2 import _build_message


class TestPatternMatchesRegexAware:
    def test_prompt_frames_pattern_as_already_matched_regex(self):
        msg = _build_message(
            assertion_type="pattern_matches",
            assertion_params={"pattern": r"foo\.get\(bar\)", "file": "x.py"},
            source_code="x = foo.get(bar)\n",
        )
        lowered = msg.lower()
        # The model is told the field is a regular expression.
        assert "regular expression" in lowered
        # ... that a prior step already confirmed it matches.
        assert "already" in lowered
        assert "match" in lowered
        # ... and that tier-2 judges meaningfulness, not verbatim text.
        assert "meaningful" in lowered
        assert "verbatim" in lowered

    def test_escaped_pattern_reaches_prompt_unchanged(self):
        # The escaped regex (with backslashes) is still handed to the
        # model as data; the framing tells it not to require that text
        # verbatim in the source.
        msg = _build_message(
            assertion_type="pattern_matches",
            assertion_params={"pattern": r"foo\.get\(bar\)"},
            source_code="x = foo.get(bar)\n",
        )
        assert r"foo\\.get\\(bar\\)" in msg or r"foo\.get\(bar\)" in msg


class TestPatternAbsentRegexAware:
    def test_prompt_frames_pattern_as_confirmed_absent_regex(self):
        msg = _build_message(
            assertion_type="pattern_absent",
            assertion_params={"pattern": r"eval\(", "file": "x.py"},
            source_code="def safe(): return 1\n",
        )
        lowered = msg.lower()
        assert "regular expression" in lowered
        assert "already" in lowered
        assert "absent" in lowered
        assert "meaningful" in lowered
        assert "verbatim" in lowered

    def test_absent_prompt_keeps_fail_closed_on_empty_source(self):
        # Regex-awareness must not weaken the fail-closed contract: the
        # prompt still instructs NO on empty / irrelevant source.
        msg = _build_message(
            assertion_type="pattern_absent",
            assertion_params={"pattern": r"eval\("},
            source_code="",
        )
        assert "Fail-closed rule" in msg
        assert "Lack of visible evidence is NEVER YES" in msg
