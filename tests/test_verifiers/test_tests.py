"""Tests for test verifiers."""

from mipiti_verify.verifiers.tests import TestExistsVerifier


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


# Coverage for test_attested lives in tests/test_test_attested.py.
