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
