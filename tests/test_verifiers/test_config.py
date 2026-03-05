"""Tests for config verifiers."""

from pathlib import Path

import pytest

from mipiti_verify.verifiers.config import (
    ConfigKeyExistsVerifier,
    ConfigValueMatchesVerifier,
    EnvVarReferencedVerifier,
)


class TestConfigKeyExists:
    def test_json_key_exists(self, config_json, project_root):
        v = ConfigKeyExistsVerifier()
        r = v.verify({"file": "config.json", "key": "debug"}, project_root)
        assert r.passed is True

    def test_json_nested_key(self, config_json, project_root):
        v = ConfigKeyExistsVerifier()
        r = v.verify({"file": "config.json", "key": "database.host"}, project_root)
        assert r.passed is True

    def test_json_key_missing(self, config_json, project_root):
        v = ConfigKeyExistsVerifier()
        r = v.verify({"file": "config.json", "key": "nonexistent"}, project_root)
        assert r.passed is False

    def test_env_key_exists(self, env_file, project_root):
        v = ConfigKeyExistsVerifier()
        r = v.verify({"file": ".env", "key": "DATABASE_URL"}, project_root)
        assert r.passed is True

    def test_yaml_key(self, project_root):
        f = project_root / "config.yaml"
        f.write_text("database:\n  host: localhost\n  port: 5432\n")
        v = ConfigKeyExistsVerifier()
        # Simple k:v parser fallback should find "database"
        r = v.verify({"file": "config.yaml", "key": "database"}, project_root)
        assert r.passed is True

    def test_file_missing(self, project_root):
        v = ConfigKeyExistsVerifier()
        r = v.verify({"file": "missing.json", "key": "test"}, project_root)
        assert r.passed is False


class TestConfigValueMatches:
    def test_value_matches(self, config_json, project_root):
        v = ConfigValueMatchesVerifier()
        r = v.verify({"file": "config.json", "key": "debug", "pattern": "false|False"}, project_root)
        assert r.passed is True

    def test_nested_value_matches(self, config_json, project_root):
        v = ConfigValueMatchesVerifier()
        r = v.verify({"file": "config.json", "key": "database.host", "pattern": "localhost"}, project_root)
        assert r.passed is True

    def test_value_no_match(self, config_json, project_root):
        v = ConfigValueMatchesVerifier()
        r = v.verify({"file": "config.json", "key": "debug", "pattern": "^true$"}, project_root)
        assert r.passed is False

    def test_key_missing(self, config_json, project_root):
        v = ConfigValueMatchesVerifier()
        r = v.verify({"file": "config.json", "key": "nonexistent", "pattern": ".*"}, project_root)
        assert r.passed is False


class TestEnvVarReferenced:
    def test_python_os_getenv(self, project_root):
        f = project_root / "settings.py"
        f.write_text('SECRET = os.getenv("API_SECRET")\n')
        v = EnvVarReferencedVerifier()
        r = v.verify({"file": "settings.py", "variable": "API_SECRET"}, project_root)
        assert r.passed is True

    def test_js_process_env(self, project_root):
        f = project_root / "config.js"
        f.write_text("const secret = process.env.API_SECRET;\n")
        v = EnvVarReferencedVerifier()
        r = v.verify({"file": "config.js", "variable": "API_SECRET"}, project_root)
        assert r.passed is True

    def test_env_var_missing(self, project_root):
        f = project_root / "code.py"
        f.write_text("x = 42\n")
        v = EnvVarReferencedVerifier()
        r = v.verify({"file": "code.py", "variable": "API_SECRET"}, project_root)
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = EnvVarReferencedVerifier()
        r = v.verify({"file": "missing.py", "variable": "API_SECRET"}, project_root)
        assert r.passed is False
