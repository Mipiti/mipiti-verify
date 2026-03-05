"""Tests for Tier 2 AI provider abstraction."""

import pytest

from mipiti_verify.tier2 import _build_message, _parse_response, get_provider


class TestParseResponse:
    def test_yes_response(self):
        passed, reasoning = _parse_response("YES\nThe function validates input.")
        assert passed is True
        assert "validates input" in reasoning

    def test_no_response(self):
        passed, reasoning = _parse_response("NO\nNo validation found.")
        assert passed is False
        assert "validation" in reasoning

    def test_pass_response(self):
        passed, reasoning = _parse_response("PASS\nAll checks pass.")
        assert passed is True

    def test_fail_response(self):
        passed, reasoning = _parse_response("FAIL\nMissing error handling.")
        assert passed is False

    def test_verified_response(self):
        passed, reasoning = _parse_response("VERIFIED\nCorrectly implemented.")
        assert passed is True

    def test_not_verified_response(self):
        passed, reasoning = _parse_response("NOT VERIFIED\nImplementation incomplete.")
        assert passed is False

    def test_ambiguous_response(self):
        passed, reasoning = _parse_response("Maybe this is valid, maybe it isn't.")
        assert passed is False
        assert "Ambiguous" in reasoning

    def test_single_line_yes(self):
        passed, reasoning = _parse_response("YES")
        assert passed is True

    def test_coherent_response(self):
        passed, _ = _parse_response("COHERENT\nGood match.")
        assert passed is True

    def test_incoherent_response(self):
        passed, _ = _parse_response("INCOHERENT\nBad match.")
        assert passed is False


class TestBuildMessage:
    def test_with_source_code(self):
        msg = _build_message("Check this", "def foo(): pass")
        assert "Check this" in msg
        assert "Source Code" in msg
        assert "def foo" in msg

    def test_without_source_code(self):
        msg = _build_message("Check this", "")
        assert "Check this" in msg
        assert "Source Code" not in msg


class TestGetProvider:
    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown"):
            get_provider("invalid")

    def test_openai_without_package(self, monkeypatch):
        """If openai is not installed, should raise ImportError."""
        import sys
        # Save and temporarily remove openai
        saved = sys.modules.get("openai")
        sys.modules["openai"] = None  # type: ignore
        try:
            with pytest.raises(ImportError):
                get_provider("openai")
        finally:
            if saved is not None:
                sys.modules["openai"] = saved
            else:
                sys.modules.pop("openai", None)

    def test_anthropic_without_package(self, monkeypatch):
        """If anthropic is not installed, should raise ImportError."""
        import sys
        saved = sys.modules.get("anthropic")
        sys.modules["anthropic"] = None  # type: ignore
        try:
            with pytest.raises(ImportError):
                get_provider("anthropic")
        finally:
            if saved is not None:
                sys.modules["anthropic"] = saved
            else:
                sys.modules.pop("anthropic", None)
