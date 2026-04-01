"""Tests for resolve_content() (Flow F + M)."""

from pathlib import Path

import pytest

from mipiti_verify.verifiers import resolve_content


class TestResolveContentFromFile:
    def test_resolve_content_from_file(self, project_root: Path):
        """file param resolves via safe_read_file."""
        f = project_root / "example.py"
        f.write_text("print('hello')", encoding="utf-8")

        content, source = resolve_content({"file": "example.py"}, project_root)

        assert content == "print('hello')"
        assert source == "example.py"

    def test_resolve_content_file_missing(self, project_root: Path):
        """file param with missing file returns (None, filename)."""
        content, source = resolve_content({"file": "nonexistent.py"}, project_root)

        assert content is None
        assert source == "nonexistent.py"


class TestResolveContentFromTarget:
    def test_resolve_content_from_target(self, project_root: Path):
        """target='feature_description' with target_content returns content."""
        params = {
            "target": "feature_description",
            "target_content": "The system uses TLS encryption for all API calls.",
        }

        content, source = resolve_content(params, project_root)

        assert content == "The system uses TLS encryption for all API calls."
        assert source == "target:feature_description"

    def test_resolve_content_target_without_content(self, project_root: Path):
        """target='feature_description' without target_content returns (None, 'target:feature_description')."""
        params = {"target": "feature_description"}

        content, source = resolve_content(params, project_root)

        assert content is None
        assert source == "target:feature_description"


class TestResolveContentMutualExclusion:
    def test_resolve_content_mutual_exclusion(self, project_root: Path):
        """Both target and file raises ValueError."""
        params = {
            "target": "feature_description",
            "file": "example.py",
        }

        with pytest.raises(ValueError, match="mutually exclusive"):
            resolve_content(params, project_root)


class TestResolveContentInvalidTarget:
    def test_resolve_content_invalid_target(self, project_root: Path):
        """target='invalid' raises ValueError."""
        params = {"target": "invalid"}

        with pytest.raises(ValueError, match="Invalid assertion target"):
            resolve_content(params, project_root)


class TestResolveContentNoSource:
    def test_resolve_content_no_source(self, project_root: Path):
        """Neither target nor file returns (None, '<no source>')."""
        content, source = resolve_content({}, project_root)

        assert content is None
        assert source == "<no source>"
