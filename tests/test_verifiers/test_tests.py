"""Tests for test verifiers."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.verifiers.tests import TestExistsVerifier, TestPassesVerifier


class TestTestExists:
    def test_test_files_found(self, project_root):
        test_dir = project_root / "tests"
        test_dir.mkdir()
        (test_dir / "test_auth.py").write_text("def test_login(): pass\n")
        (test_dir / "test_api.py").write_text("def test_endpoint(): pass\n")

        v = TestExistsVerifier()
        r = v.verify({"pattern": "tests/test_*.py"}, project_root)
        assert r.passed is True
        assert "2" in r.details

    def test_no_matching_files(self, project_root):
        v = TestExistsVerifier()
        r = v.verify({"pattern": "tests/test_*.py"}, project_root)
        assert r.passed is False

    def test_recursive_glob(self, project_root):
        nested = project_root / "src" / "tests"
        nested.mkdir(parents=True)
        (nested / "test_deep.py").write_text("def test_deep(): pass\n")

        v = TestExistsVerifier()
        r = v.verify({"pattern": "**/test_*.py"}, project_root)
        assert r.passed is True


class TestTestPasses:
    @patch("mipiti_verify.verifiers.tests.subprocess")
    def test_tests_pass(self, mock_subprocess, project_root):
        mock_subprocess.run.return_value = MagicMock(returncode=0, stdout="1 passed", stderr="")
        (project_root / "pyproject.toml").write_text("[tool.pytest]\n")

        v = TestPassesVerifier()
        r = v.verify({"pattern": "test_auth"}, project_root)
        assert r.passed is True

    @patch("mipiti_verify.verifiers.tests.subprocess")
    def test_tests_fail(self, mock_subprocess, project_root):
        mock_subprocess.run.return_value = MagicMock(returncode=1, stdout="1 failed", stderr="")
        (project_root / "pyproject.toml").write_text("[tool.pytest]\n")

        v = TestPassesVerifier()
        r = v.verify({"pattern": "test_auth"}, project_root)
        assert r.passed is False

    @patch("mipiti_verify.verifiers.tests.subprocess")
    def test_tests_timeout(self, mock_subprocess, project_root):
        import subprocess as real_subprocess

        mock_subprocess.run.side_effect = real_subprocess.TimeoutExpired(cmd="pytest", timeout=300)
        mock_subprocess.TimeoutExpired = real_subprocess.TimeoutExpired
        (project_root / "pyproject.toml").write_text("[tool.pytest]\n")

        v = TestPassesVerifier()
        r = v.verify({"pattern": "test_auth"}, project_root)
        assert r.passed is False
        assert "timed out" in r.details
