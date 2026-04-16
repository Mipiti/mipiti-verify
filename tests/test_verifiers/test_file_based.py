"""Tests for file-based verifiers."""

import hashlib
from pathlib import Path

import pytest

from mipiti_verify.verifiers.file_based import (
    FileExistsVerifier,
    FileHashVerifier,
    NoPlaintextSecretVerifier,
    PatternAbsentVerifier,
    PatternMatchesVerifier,
    _apply_inline_regex_flags,
)


class TestFileExists:
    def test_file_exists(self, project_root):
        (project_root / "test.txt").write_text("hello")
        v = FileExistsVerifier()
        r = v.verify({"file": "test.txt"}, project_root)
        assert r.passed is True

    def test_file_missing(self, project_root):
        v = FileExistsVerifier()
        r = v.verify({"file": "missing.txt"}, project_root)
        assert r.passed is False

    def test_directory_not_a_file(self, project_root):
        (project_root / "subdir").mkdir()
        v = FileExistsVerifier()
        r = v.verify({"file": "subdir"}, project_root)
        assert r.passed is False


class TestFileHash:
    def test_hash_matches(self, project_root):
        f = project_root / "data.txt"
        f.write_bytes(b"hello world")
        expected = hashlib.sha256(b"hello world").hexdigest()

        v = FileHashVerifier()
        r = v.verify({"file": "data.txt", "algorithm": "sha256", "expected_hash": expected}, project_root)
        assert r.passed is True

    def test_hash_mismatch(self, project_root):
        f = project_root / "data.txt"
        f.write_bytes(b"hello world")

        v = FileHashVerifier()
        r = v.verify({"file": "data.txt", "algorithm": "sha256", "expected_hash": "wronghash"}, project_root)
        assert r.passed is False

    def test_md5_algorithm(self, project_root):
        f = project_root / "data.txt"
        f.write_bytes(b"test")
        expected = hashlib.md5(b"test").hexdigest()

        v = FileHashVerifier()
        r = v.verify({"file": "data.txt", "algorithm": "md5", "expected_hash": expected}, project_root)
        assert r.passed is True

    def test_unsupported_algorithm(self, project_root):
        f = project_root / "data.txt"
        f.write_bytes(b"test")

        v = FileHashVerifier()
        r = v.verify({"file": "data.txt", "algorithm": "invalidalgo", "expected_hash": "x"}, project_root)
        assert r.passed is False
        assert "Unsupported" in r.details

    def test_file_missing(self, project_root):
        v = FileHashVerifier()
        r = v.verify({"file": "missing.txt", "algorithm": "sha256", "expected_hash": "x"}, project_root)
        assert r.passed is False


class TestPatternMatches:
    def test_pattern_found(self, project_root):
        f = project_root / "code.py"
        f.write_text("def validate_input(data):\n    return True\n")

        v = PatternMatchesVerifier()
        r = v.verify({"file": "code.py", "pattern": r"def validate_\w+"}, project_root)
        assert r.passed is True

    def test_pattern_not_found(self, project_root):
        f = project_root / "code.py"
        f.write_text("def other_func():\n    pass\n")

        v = PatternMatchesVerifier()
        r = v.verify({"file": "code.py", "pattern": r"def validate_\w+"}, project_root)
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = PatternMatchesVerifier()
        r = v.verify({"file": "missing.py", "pattern": r"def validate_\w+"}, project_root)
        assert r.passed is False

    def test_lookahead_pattern_returns_clean_failure(self, project_root, capfd):
        """Agent-submitted patterns using lookahead (unsupported by RE2) must
        fail with a clean details string, and must not emit the google-re2
        ABSL ``E0000 ... re2.cc:... Error parsing ... invalid perl operator``
        noise to stderr. google-re2 1.1.x lets us silence that via
        ``re2.Options(log_errors=False)``.
        """
        f = project_root / "code.py"
        f.write_text("def verification(db = Depends(get_db)):\n    return True\n")

        v = PatternMatchesVerifier()
        # Pattern lifted from the CI incident: (?m)def.*verification.*(?!.*Depends).*:$
        r = v.verify(
            {"file": "code.py", "pattern": r"(?m)def.*verification.*(?!.*Depends).*:$"},
            project_root,
        )

        # The assertion should fail gracefully, not raise.
        assert r.passed is False
        assert "Invalid regex pattern" in r.details

        # And the C++ ABSL logger should have been silenced — no red E0000 lines
        # leaking out to CI logs.
        captured = capfd.readouterr()
        assert "invalid perl operator" not in captured.err
        assert "re2.cc" not in captured.err


class TestApplyInlineRegexFlags:
    """Unit tests for the helper that translates assertion flags → RE2 inline modifiers."""

    def test_no_flags_returns_pattern_unchanged(self):
        assert _apply_inline_regex_flags(r"^foo", {}) == r"^foo"

    def test_multiline_true_string(self):
        assert _apply_inline_regex_flags(r"^foo", {"multiline": "true"}) == r"(?m)^foo"

    def test_multiline_one_string(self):
        assert _apply_inline_regex_flags(r"^foo", {"multiline": "1"}) == r"(?m)^foo"

    def test_multiline_false(self):
        assert _apply_inline_regex_flags(r"^foo", {"multiline": "false"}) == r"^foo"

    def test_dotall_true(self):
        assert _apply_inline_regex_flags(r"foo.bar", {"dotall": "true"}) == r"(?s)foo.bar"

    def test_both_flags_combined(self):
        result = _apply_inline_regex_flags(r"^foo.*$", {"multiline": "true", "dotall": "true"})
        assert result == r"(?ms)^foo.*$"

    def test_case_insensitive_string_value(self):
        assert _apply_inline_regex_flags(r"^x", {"multiline": "TRUE"}) == r"(?m)^x"

    def test_unrelated_params_ignored(self):
        assert _apply_inline_regex_flags(r"x", {"file": "foo.txt", "scope_start": "x"}) == r"x"


class TestPatternMatchesWithFlags:
    """Regression tests for the google-re2 flag bug.

    google-re2 does not accept Python ``re`` flag integers — they must be
    embedded as inline modifiers in the pattern. Before the fix, passing
    ``multiline: true`` produced an AttributeError on the worker thread
    and the verifier silently failed.
    """

    def test_multiline_anchor_matches_after_newline(self, project_root):
        f = project_root / "multi.py"
        f.write_text("first line\nsecond line\nthird line\n")
        v = PatternMatchesVerifier()
        # Without multiline, ^ matches only at the start of the whole string
        r_default = v.verify({"file": "multi.py", "pattern": r"^second"}, project_root)
        assert r_default.passed is False
        # With multiline, ^ matches at the start of every line
        r_multi = v.verify(
            {"file": "multi.py", "pattern": r"^second", "multiline": "true"},
            project_root,
        )
        assert r_multi.passed is True

    def test_dotall_dot_matches_newline(self, project_root):
        f = project_root / "spans.py"
        f.write_text("start\n... middle ...\nend")
        v = PatternMatchesVerifier()
        # Without dotall, . does not match newline
        r_default = v.verify({"file": "spans.py", "pattern": r"start.*end"}, project_root)
        assert r_default.passed is False
        # With dotall, . matches everything including newlines
        r_dot = v.verify(
            {"file": "spans.py", "pattern": r"start.*end", "dotall": "true"},
            project_root,
        )
        assert r_dot.passed is True

    def test_pattern_absent_with_multiline(self, project_root):
        f = project_root / "noeval.py"
        f.write_text("safe = 1\nalso_safe = 2\n")
        v = PatternAbsentVerifier()
        r = v.verify(
            {"file": "noeval.py", "pattern": r"^eval", "multiline": "true"},
            project_root,
        )
        assert r.passed is True


class TestPatternAbsent:
    def test_pattern_absent(self, project_root):
        f = project_root / "clean.py"
        f.write_text("x = 42\n")

        v = PatternAbsentVerifier()
        r = v.verify({"file": "clean.py", "pattern": r"eval\("}, project_root)
        assert r.passed is True

    def test_pattern_present(self, project_root):
        f = project_root / "dirty.py"
        f.write_text('result = eval("1+1")\n')

        v = PatternAbsentVerifier()
        r = v.verify({"file": "dirty.py", "pattern": r"eval\("}, project_root)
        assert r.passed is False


class TestNoPlaintextSecret:
    def test_no_secrets(self, project_root):
        f = project_root / "settings.py"
        f.write_text('DB_URL = os.getenv("DATABASE_URL")\nSECRET = os.getenv("SECRET")\n')

        v = NoPlaintextSecretVerifier()
        r = v.verify(
            {"file": "settings.py", "patterns": [r"password\s*=\s*['\"][^'\"]+['\"]", r"secret_key\s*=\s*['\"][^'\"]+['\"]"]},
            project_root,
        )
        assert r.passed is True

    def test_secret_found(self, project_root):
        f = project_root / "settings.py"
        f.write_text('password = "hunter2"\n')

        v = NoPlaintextSecretVerifier()
        r = v.verify(
            {"file": "settings.py", "patterns": [r"password\s*=\s*['\"][^'\"]+['\"]"]},
            project_root,
        )
        assert r.passed is False

    def test_multiple_patterns(self, project_root):
        f = project_root / "settings.py"
        f.write_text('api_key = "sk-abc123"\npassword = "secret"\n')

        v = NoPlaintextSecretVerifier()
        r = v.verify(
            {"file": "settings.py", "patterns": [r"password\s*=\s*['\"]", r"api_key\s*=\s*['\"]"]},
            project_root,
        )
        assert r.passed is False
        assert "password" in r.details or "api_key" in r.details
