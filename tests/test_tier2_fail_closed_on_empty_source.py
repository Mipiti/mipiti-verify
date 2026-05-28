"""Pre-LLM fail-closed guard.

When a tier-2 assertion's source-loading path produces empty content
for a type that requires source-code evidence, the runner must return
a tier-2 ``fail`` result WITHOUT invoking the LLM. Asking the model
to evaluate empty evidence is a false-pass risk: the model may
rationalize YES from the assertion's ``description`` (which is a
CLAIM, not evidence), or it may interpret the empty boundary block as
an injection attempt and return INJECTION_DETECTED — neither verdict
reflects the source code.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mipiti_verify.runner import Runner


class TestFailClosedOnEmptySource:
    def test_missing_file_fails_closed_without_llm_call(self, tmp_path):
        """``function_exists`` requires the source code of the named
        file. When the file is missing, source_code stays empty — the
        guard must return ``fail`` without calling provider.evaluate."""
        client = MagicMock()
        runner = Runner(
            client=client,
            project_root=str(tmp_path),
            tier2_provider="anthropic",
            repo="acme/widgets",
        )

        llm_called = {"called": False}

        class FakeProvider:
            def evaluate(self, *, assertion_type, assertion_params, source_code):
                llm_called["called"] = True
                return True, "YES"

        with patch("mipiti_verify.tier2.get_provider", return_value=FakeProvider()):
            result = runner._verify_tier2(
                {
                    "id": "asrt_001",
                    "type": "function_exists",
                    "params": {"file": "nope.py", "name": "verify_token"},
                    "repo": "acme/widgets",
                }
            )

        assert result["status"] == "fail"
        assert "no source content" in result["details"].lower()
        assert llm_called["called"] is False

    def test_no_match_pattern_fails_closed_without_llm_call(self, tmp_path):
        """``test_exists`` resolves ``params["pattern"]``; when no file
        matches, the source-loading path produces empty content. The
        guard must short-circuit before the LLM call."""
        client = MagicMock()
        runner = Runner(
            client=client,
            project_root=str(tmp_path),
            tier2_provider="anthropic",
            repo="acme/widgets",
        )

        llm_called = {"called": False}

        class FakeProvider:
            def evaluate(self, *, assertion_type, assertion_params, source_code):
                llm_called["called"] = True
                return True, "YES"

        with patch("mipiti_verify.tier2.get_provider", return_value=FakeProvider()):
            result = runner._verify_tier2(
                {
                    "id": "asrt_pattern_empty",
                    "type": "test_exists",
                    "params": {"pattern": "tests/nope_*.py"},
                    "repo": "acme/widgets",
                }
            )

        assert result["status"] == "fail"
        assert "no source content" in result["details"].lower()
        assert llm_called["called"] is False

    def test_non_empty_source_proceeds_to_llm(self, tmp_path):
        """The guard must NOT block when source-loading succeeded — the
        LLM is still consulted in the normal case."""
        (tmp_path / "auth.py").write_text(
            "def verify_token(t):\n    return t is not None\n", encoding="utf-8"
        )
        client = MagicMock()
        runner = Runner(
            client=client,
            project_root=str(tmp_path),
            tier2_provider="anthropic",
            repo="acme/widgets",
        )

        llm_called = {"called": False, "source": ""}

        class FakeProvider:
            def evaluate(self, *, assertion_type, assertion_params, source_code):
                llm_called["called"] = True
                llm_called["source"] = source_code
                return True, "YES"

        with patch("mipiti_verify.tier2.get_provider", return_value=FakeProvider()):
            result = runner._verify_tier2(
                {
                    "id": "asrt_002",
                    "type": "function_exists",
                    "params": {"file": "auth.py", "name": "verify_token"},
                    "repo": "acme/widgets",
                }
            )

        assert result["status"] == "pass"
        assert llm_called["called"] is True
        assert "verify_token" in llm_called["source"]
