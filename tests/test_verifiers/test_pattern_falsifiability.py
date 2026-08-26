"""A pattern assertion must be capable of failing.

``pattern_matches`` and ``pattern_absent`` are the two types whose
subject may be the model's feature description rather than a repository
file, and a degenerate regex is worth more there than anywhere else: it
mints a passing design-level claim about the specification. These tests
pin the two degenerate shapes the verifiers reject, the zero-width match
they refuse to accept as proof, and — just as load-bearing — the fact
that every inconclusive signal lets the assertion through.
"""

import pytest

from mipiti_verify.verifiers.file_based import (
    PatternAbsentVerifier,
    PatternMatchesVerifier,
    _reject_degenerate_pattern,
    _reject_unwitnessed_match,
)
from mipiti_verify.verifiers import safe_regex_search


DESIGN = "Uploads are scanned before they reach the bucket."


# Regexes the empty subject already satisfies: tier 1 would report a
# match against literally any content.
UNFALSIFIABLE = [r".*", r"", r"a?", r"(?s).*", r"^", r"$", r"(?m)^", r"\B", r"(?:)"]

# Regexes that say something about content and must be left alone.
GENUINE = [
    r"\bverify_signature\(",
    r"^import hmac",
    r"(?i)authorization:\s*bearer",
    r"[a-z]+",
    r".",
    r"def validate_\w+",
    r"eval\(",
]

# Regexes no subject can satisfy: their absence holds of everything.
VACUOUS = [r"[^\x00-\x{10FFFF}]", r"$a", r"[^\s\S]"]


class TestRejectDegeneratePatternUnit:
    """The shared helper, judged on the regex alone."""

    @pytest.mark.parametrize("pattern", UNFALSIFIABLE)
    def test_unfalsifiable_rejected_for_pattern_matches(self, pattern):
        details = _reject_degenerate_pattern(pattern, absent=False)
        assert details is not None
        assert details.startswith("Unfalsifiable pattern - matches any content")
        assert pattern in details

    @pytest.mark.parametrize("pattern", GENUINE + VACUOUS)
    def test_pattern_matches_accepts_everything_else(self, pattern):
        assert _reject_degenerate_pattern(pattern, absent=False) is None

    @pytest.mark.parametrize("pattern", VACUOUS)
    def test_vacuous_rejected_for_pattern_absent(self, pattern):
        details = _reject_degenerate_pattern(pattern, absent=True)
        assert details is not None
        assert details.startswith("Vacuous pattern - cannot match any content")
        assert pattern in details

    @pytest.mark.parametrize("pattern", GENUINE + UNFALSIFIABLE)
    def test_pattern_absent_accepts_everything_else(self, pattern):
        assert _reject_degenerate_pattern(pattern, absent=True) is None

    @pytest.mark.parametrize("pattern", [r"\b", r"\B"])
    def test_word_boundary_is_not_vacuous(self, pattern):
        """``\\b`` and ``\\B`` collapse the possible-match range without
        being impossible. The non-empty probes are what separates them
        from a regex nothing can satisfy."""
        assert _reject_degenerate_pattern(pattern, absent=True) is None

    def test_an_uncompilable_pattern_is_left_to_the_existing_path(self):
        """RE2 rejects lookahead. The guard says nothing about it so the
        caller's invalid-pattern reporting stays the one that speaks."""
        pattern = r"(?m)def.*verification.*(?!.*Depends).*:$"
        assert _reject_degenerate_pattern(pattern, absent=False) is None
        assert _reject_degenerate_pattern(pattern, absent=True) is None


class TestRejectUnwitnessedMatchUnit:
    def test_zero_width_match_is_rejected(self):
        match = safe_regex_search(r"\b", "hello world")
        details = _reject_unwitnessed_match(match, r"\b")
        assert details is not None
        assert details.startswith("Unwitnessed pattern - matched zero characters")

    def test_a_match_that_consumed_content_is_accepted(self):
        match = safe_regex_search(r"scanned", DESIGN)
        assert _reject_unwitnessed_match(match, r"scanned") is None

    def test_a_match_object_without_a_span_is_inconclusive(self):
        assert _reject_unwitnessed_match(object(), r"whatever") is None


class TestPatternMatchesRejectsUnfalsifiable:
    @pytest.mark.parametrize("pattern", UNFALSIFIABLE)
    def test_rejected_against_a_file_subject(self, pattern, project_root):
        (project_root / "code.py").write_text("def validate_input(data):\n    return True\n")
        r = PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": pattern}, project_root
        )
        assert r.passed is False
        assert "Unfalsifiable pattern" in r.details

    @pytest.mark.parametrize("pattern", UNFALSIFIABLE)
    def test_rejected_against_a_target_subject(self, pattern, project_root):
        r = PatternMatchesVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": pattern,
            },
            project_root,
        )
        assert r.passed is False
        assert "Unfalsifiable pattern" in r.details

    def test_rejected_even_when_the_subject_is_empty(self, project_root):
        """The shape the guard exists for: no content at all, and tier 1
        would still have reported a match."""
        (project_root / "empty.py").write_text("")
        r = PatternMatchesVerifier().verify(
            {"file": "empty.py", "pattern": r".*"}, project_root
        )
        assert r.passed is False
        assert "Unfalsifiable pattern" in r.details

    def test_the_flag_applied_pattern_is_what_is_judged(self, project_root):
        """The guard runs on the pattern tier 1 evaluates, inline flag
        modifiers already prepended."""
        r = PatternMatchesVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": r".*",
                "multiline": "true",
                "dotall": "true",
            },
            project_root,
        )
        assert r.passed is False
        assert "(?ms).*" in r.details


class TestPatternMatchesRejectsUnwitnessedMatch:
    def test_zero_width_match_against_a_file_subject(self, project_root):
        (project_root / "code.py").write_text("def validate_input(data):\n    return True\n")
        r = PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": r"\b"}, project_root
        )
        assert r.passed is False
        assert "Unwitnessed pattern" in r.details

    def test_zero_width_match_against_a_target_subject(self, project_root):
        r = PatternMatchesVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": r"\b",
            },
            project_root,
        )
        assert r.passed is False
        assert "Unwitnessed pattern" in r.details


class TestPatternAbsentRejectsVacuous:
    @pytest.mark.parametrize("pattern", VACUOUS)
    def test_rejected_against_a_file_subject(self, pattern, project_root):
        (project_root / "clean.py").write_text("x = 42\n")
        r = PatternAbsentVerifier().verify(
            {"file": "clean.py", "pattern": pattern}, project_root
        )
        assert r.passed is False
        assert "Vacuous pattern" in r.details

    @pytest.mark.parametrize("pattern", VACUOUS)
    def test_rejected_against_a_target_subject(self, pattern, project_root):
        r = PatternAbsentVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": pattern,
            },
            project_root,
        )
        assert r.passed is False
        assert "Vacuous pattern" in r.details

    def test_the_flag_applied_pattern_is_what_is_judged(self, project_root):
        r = PatternAbsentVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": r"$a",
                "multiline": "true",
            },
            project_root,
        )
        assert r.passed is False
        assert "(?m)$a" in r.details

    def test_a_zero_width_match_still_reports_the_pattern_as_present(self, project_root):
        """``pattern_absent`` mints nothing on a match, so the
        zero-width guard has no work to do here: the assertion already
        fails, and it fails saying what was found."""
        (project_root / "code.py").write_text("x = 42\n")
        r = PatternAbsentVerifier().verify(
            {"file": "code.py", "pattern": r"\b"}, project_root
        )
        assert r.passed is False
        assert "should be absent" in r.details


class TestGenuineAssertionsStillPass:
    def test_pattern_matches_against_a_file_subject(self, project_root):
        (project_root / "code.py").write_text("def validate_input(data):\n    return True\n")
        r = PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": r"def validate_\w+"}, project_root
        )
        assert r.passed is True
        assert "Pattern found" in r.details

    def test_pattern_matches_against_a_target_subject(self, project_root):
        r = PatternMatchesVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": "scanned before",
            },
            project_root,
        )
        assert r.passed is True
        assert "Pattern found" in r.details

    def test_pattern_absent_against_a_file_subject(self, project_root):
        (project_root / "clean.py").write_text("x = 42\n")
        r = PatternAbsentVerifier().verify(
            {"file": "clean.py", "pattern": r"eval\("}, project_root
        )
        assert r.passed is True
        assert "correctly absent" in r.details

    def test_pattern_absent_against_a_target_subject(self, project_root):
        r = PatternAbsentVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": "plaintext",
            },
            project_root,
        )
        assert r.passed is True
        assert "correctly absent" in r.details

    def test_a_pattern_only_a_word_boundary_makes_reachable_still_passes(
        self, project_root
    ):
        """A boundary in the middle of a pattern is not a zero-width
        match — the surrounding literal is still what matched."""
        r = PatternAbsentVerifier().verify(
            {
                "target": "feature_description",
                "target_content": DESIGN,
                "pattern": r"\bplaintext\b",
            },
            project_root,
        )
        assert r.passed is True


class TestInvalidPatternPathIsUnchanged:
    """A pattern RE2 cannot compile keeps reporting itself as one."""

    def test_pattern_matches_reports_the_invalid_pattern(self, project_root):
        (project_root / "code.py").write_text("def verification(db = Depends(get_db)):\n")
        r = PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": r"(?m)def.*verification.*(?!.*Depends).*:$"},
            project_root,
        )
        assert r.passed is False
        assert "Invalid regex pattern" in r.details

    def test_pattern_absent_reports_the_invalid_pattern(self, project_root):
        (project_root / "code.py").write_text("x = 42\n")
        r = PatternAbsentVerifier().verify(
            {"file": "code.py", "pattern": r"(?!secret)"}, project_root
        )
        assert r.passed is False
        assert "Invalid regex pattern" in r.details

    def test_no_absl_noise_reaches_stderr(self, project_root, capfd):
        """The guard compiles the pattern before tier 1 does. It must
        use the shared silenced options, or an invalid pattern would
        leak a red C++ log line into CI output."""
        (project_root / "code.py").write_text("x = 42\n")
        PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": r"(?!secret)"}, project_root
        )
        captured = capfd.readouterr()
        assert "invalid perl operator" not in captured.err
        assert "re2.cc" not in captured.err


class TestFailsOpenOnAnIndeterminateSignal:
    """Wrongly rejecting a genuine assertion is the worse error, so
    anything the guard cannot read cleanly lets the assertion through.
    ``safe_regex_search`` keeps its own module-level ``re2`` handle, so
    patching the one the guard uses leaves tier 1 itself intact."""

    def test_an_unreadable_empty_probe_lets_pattern_matches_through(
        self, project_root, monkeypatch
    ):
        import mipiti_verify.verifiers.file_based as fb

        class _Broken:
            def search(self, *a, **kw):
                raise RuntimeError("probe unavailable")

            def compile(self, *a, **kw):
                raise RuntimeError("probe unavailable")

        monkeypatch.setattr(fb, "re2", _Broken())
        (project_root / "code.py").write_text("hello\n")
        r = PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": r".*"}, project_root
        )
        assert r.passed is True
        assert "Pattern found" in r.details

    def test_an_unreadable_match_range_lets_pattern_absent_through(
        self, project_root, monkeypatch
    ):
        import mipiti_verify.verifiers.file_based as fb
        import re2 as real_re2

        class _NoRange:
            error = real_re2.error

            def search(self, *a, **kw):
                return real_re2.search(*a, **kw)

            def compile(self, *a, **kw):
                raise RuntimeError("possiblematchrange unavailable")

        monkeypatch.setattr(fb, "re2", _NoRange())
        (project_root / "clean.py").write_text("x = 42\n")
        r = PatternAbsentVerifier().verify(
            {"file": "clean.py", "pattern": r"$a"}, project_root
        )
        assert r.passed is True
        assert "correctly absent" in r.details

    def test_an_unreadable_probe_search_lets_pattern_absent_through(
        self, project_root, monkeypatch
    ):
        import mipiti_verify.verifiers.file_based as fb
        import re2 as real_re2

        class _ProbeFails:
            error = real_re2.error

            def search(self, pattern, content, *a, **kw):
                if content:
                    raise RuntimeError("probe unavailable")
                return real_re2.search(pattern, content, *a, **kw)

            def compile(self, *a, **kw):
                return real_re2.compile(*a, **kw)

        monkeypatch.setattr(fb, "re2", _ProbeFails())
        (project_root / "clean.py").write_text("x = 42\n")
        r = PatternAbsentVerifier().verify(
            {"file": "clean.py", "pattern": r"$a"}, project_root
        )
        assert r.passed is True
        assert "correctly absent" in r.details

    def test_an_unreadable_match_span_lets_pattern_matches_through(
        self, project_root, monkeypatch
    ):
        import mipiti_verify.verifiers.file_based as fb

        monkeypatch.setattr(
            fb, "safe_regex_search", lambda pattern, content, **kw: object()
        )
        (project_root / "code.py").write_text("def validate_input(data):\n")
        r = PatternMatchesVerifier().verify(
            {"file": "code.py", "pattern": r"def validate_\w+"}, project_root
        )
        assert r.passed is True
        assert "Pattern found" in r.details
