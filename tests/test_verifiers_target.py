"""Tests for verifiers using target_content instead of file (Flow M).

Only pattern_matches and pattern_absent accept a target; every other type
verifies a repository file and refuses one.
"""

from pathlib import Path

from mipiti_verify.verifiers.file_based import (
    NoPlaintextSecretVerifier,
    PatternAbsentVerifier,
    PatternMatchesVerifier,
)
from mipiti_verify.verifiers.code_structure import FunctionExistsVerifier
from mipiti_verify.verifiers.config import EnvVarReferencedVerifier


class TestPatternMatchesWithTarget:
    def test_pattern_matches_with_target_content(self, project_root: Path):
        """pattern_matches verifier passes when pattern found in target_content."""
        params = {
            "target": "feature_description",
            "target_content": "The system uses TLS encryption for all API calls.",
            "pattern": "TLS",
        }
        v = PatternMatchesVerifier()
        r = v.verify(params, project_root)
        assert r.passed is True
        assert "Pattern found" in r.details

    def test_pattern_matches_not_found_with_target_content(self, project_root: Path):
        """pattern_matches verifier fails when pattern not found in target_content."""
        params = {
            "target": "feature_description",
            "target_content": "The system uses HTTP for all API calls.",
            "pattern": "TLS",
        }
        v = PatternMatchesVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False


class TestPatternAbsentWithTarget:
    def test_pattern_absent_with_target_content(self, project_root: Path):
        """pattern_absent verifier passes when pattern not in target_content."""
        params = {
            "target": "feature_description",
            "target_content": "The system uses TLS encryption for all API calls.",
            "pattern": "plaintext",
        }
        v = PatternAbsentVerifier()
        r = v.verify(params, project_root)
        assert r.passed is True
        assert "correctly absent" in r.details

    def test_pattern_absent_fails_when_present(self, project_root: Path):
        """pattern_absent verifier fails when pattern found in target_content."""
        params = {
            "target": "feature_description",
            "target_content": "Data is sent in plaintext over the network.",
            "pattern": "plaintext",
        }
        v = PatternAbsentVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False



class TestFunctionExistsRefusesTarget:
    """function_exists verifies a repository file; a platform target is refused."""

    def test_target_is_refused_when_content_would_pass(self, project_root: Path):
        """Refusal, not a pass, when target_content holds a matching definition."""
        params = {
            "target": "feature_description",
            "target_content": "def validate_input(data):\n    return len(data) > 0\n",
            "name": "validate_input",
        }
        v = FunctionExistsVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False
        assert "does not accept a 'target'" in r.details

    def test_target_is_refused_when_content_would_fail(self, project_root: Path):
        """Refusal, not a symbol-absent failure, when target_content lacks the name."""
        params = {
            "target": "feature_description",
            "target_content": "def other_function(x):\n    pass\n",
            "name": "validate_input",
        }
        v = FunctionExistsVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False
        assert "does not accept a 'target'" in r.details


class TestNoPlaintextSecretRefusesTarget:
    """no_plaintext_secret verifies a repository file; a platform target is refused."""

    def test_target_is_refused_when_content_would_pass(self, project_root: Path):
        """Refusal, not a pass, when target_content holds no secret."""
        params = {
            "target": "feature_description",
            "target_content": 'DB_URL = os.getenv("DATABASE_URL")\nAPI_KEY = os.getenv("API_KEY")\n',
            "patterns": [
                r"password\s*=\s*['\"][^'\"]+['\"]",
                r"secret_key\s*=\s*['\"][^'\"]+['\"]",
            ],
        }
        v = NoPlaintextSecretVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False
        assert "does not accept a 'target'" in r.details

    def test_target_is_refused_when_content_would_fail(self, project_root: Path):
        """Refusal, not a secret-found failure, when target_content holds a secret."""
        params = {
            "target": "feature_description",
            "target_content": 'password = "hunter2"\n',
            "patterns": [r"password\s*=\s*['\"][^'\"]+['\"]"],
        }
        v = NoPlaintextSecretVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False
        assert "does not accept a 'target'" in r.details


class TestEnvVarReferencedRefusesTarget:
    """env_var_referenced verifies a repository file; a platform target is refused."""

    def test_target_is_refused_when_content_would_pass(self, project_root: Path):
        """Refusal, not a pass, when target_content references the variable."""
        params = {
            "target": "feature_description",
            "target_content": 'secret = os.getenv("SECRET_KEY")\n',
            "variable": "SECRET_KEY",
        }
        v = EnvVarReferencedVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False
        assert "does not accept a 'target'" in r.details

    def test_target_is_refused_when_content_would_fail(self, project_root: Path):
        """Refusal, not a variable-absent failure, when target_content omits it."""
        params = {
            "target": "feature_description",
            "target_content": "x = 42\n",
            "variable": "SECRET_KEY",
        }
        v = EnvVarReferencedVerifier()
        r = v.verify(params, project_root)
        assert r.passed is False
        assert "does not accept a 'target'" in r.details
