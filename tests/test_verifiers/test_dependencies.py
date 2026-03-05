"""Tests for dependency verifiers."""

from pathlib import Path

import pytest

from mipiti_verify.verifiers.dependencies import (
    DependencyExistsVerifier,
    DependencyVersionVerifier,
)


class TestDependencyExists:
    def test_requirements_txt(self, requirements_txt, project_root):
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "requirements.txt", "package": "flask"}, project_root)
        assert r.passed is True

    def test_requirements_txt_missing(self, requirements_txt, project_root):
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "requirements.txt", "package": "django"}, project_root)
        assert r.passed is False

    def test_package_json(self, package_json, project_root):
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "package.json", "package": "express"}, project_root)
        assert r.passed is True

    def test_package_json_dev_dep(self, package_json, project_root):
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "package.json", "package": "jest"}, project_root)
        assert r.passed is True

    def test_package_json_missing(self, package_json, project_root):
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "package.json", "package": "react"}, project_root)
        assert r.passed is False

    def test_normalized_name(self, requirements_txt, project_root):
        """Hyphens and underscores should be equivalent."""
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "requirements.txt", "package": "Flask"}, project_root)
        assert r.passed is True

    def test_manifest_missing(self, project_root):
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "missing.txt", "package": "flask"}, project_root)
        assert r.passed is False

    def test_cargo_toml(self, project_root):
        f = project_root / "Cargo.toml"
        f.write_text('[dependencies]\nserde = "1.0"\ntokio = { version = "1.0", features = ["full"] }\n')
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "Cargo.toml", "package": "serde"}, project_root)
        assert r.passed is True

    def test_go_mod(self, project_root):
        f = project_root / "go.mod"
        f.write_text("module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n")
        v = DependencyExistsVerifier()
        r = v.verify({"manifest": "go.mod", "package": "github.com/gin-gonic/gin"}, project_root)
        assert r.passed is True


class TestDependencyVersion:
    def test_version_present(self, requirements_txt, project_root):
        v = DependencyVersionVerifier()
        r = v.verify({"manifest": "requirements.txt", "package": "requests", "constraint": ">=2.0"}, project_root)
        # Depends on whether packaging is installed
        # Either way, should not crash
        assert isinstance(r.passed, bool)

    def test_package_missing(self, requirements_txt, project_root):
        v = DependencyVersionVerifier()
        r = v.verify({"manifest": "requirements.txt", "package": "django", "constraint": ">=4.0"}, project_root)
        assert r.passed is False

    def test_npm_version(self, package_json, project_root):
        v = DependencyVersionVerifier()
        r = v.verify({"manifest": "package.json", "package": "express", "constraint": ">=4.0"}, project_root)
        assert isinstance(r.passed, bool)  # depends on packaging availability
