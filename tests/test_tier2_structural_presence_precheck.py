"""Deterministic structural-presence precheck for existence types.

Tier 2 is a semantic (quality) judgment and must never be the authority for
whether a symbol EXISTS. Handed a file that is present and non-empty but does
NOT contain the named symbol, the model has been observed to answer YES by
rationalizing from the assertion's own name/description — a false-pass that the
empty-source guard cannot catch (the source is non-empty). The runner re-runs
the authoritative structural verifier on the full file before calling the LLM
and refuses when the symbol is absent.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mipiti_verify.runner import Runner


class _FakeYesProvider:
    """Simulates the false-pass: the model rubber-stamps YES regardless."""

    def __init__(self, called):
        self._called = called

    def evaluate(
        self, *, assertion_type, assertion_params, source_code,
        subject_kind="repository_file",
    ):
        self._called["called"] = True
        return True, "YES"


class TestStructuralPresencePrecheck:
    def test_absent_function_in_nonempty_file_fails_without_llm(self, tmp_path):
        # File exists and is non-empty but lacks `_sign_bundle`. The empty-source
        # guard does NOT fire; the structural-presence precheck must, refusing
        # the LLM even though the mocked model would affirm existence.
        (tmp_path / "svc.py").write_text(
            "def build_config():\n    return {}\n", encoding="utf-8"
        )
        called = {"called": False}
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider",
                   return_value=_FakeYesProvider(called)):
            result = runner._verify_tier2({
                "id": "asrt_x", "type": "function_exists",
                "params": {"file": "svc.py", "name": "_sign_bundle"},
                "repo": "acme/widgets",
            })
        assert result["status"] == "fail"
        assert "not present" in result["details"].lower()
        assert called["called"] is False  # LLM never consulted

    def test_absent_class_in_nonempty_file_fails_without_llm(self, tmp_path):
        (tmp_path / "svc.py").write_text(
            "class Config:\n    pass\n", encoding="utf-8"
        )
        called = {"called": False}
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider",
                   return_value=_FakeYesProvider(called)):
            result = runner._verify_tier2({
                "id": "asrt_y", "type": "class_exists",
                "params": {"file": "svc.py", "name": "Signer"},
                "repo": "acme/widgets",
            })
        assert result["status"] == "fail"
        assert called["called"] is False

    def test_present_symbol_still_proceeds_to_llm(self, tmp_path):
        # A genuinely present symbol must NOT be blocked — the precheck only
        # turns a would-be false-pass into a fail, never a real one.
        (tmp_path / "svc.py").write_text(
            "def _sign_bundle(b):\n    return b\n", encoding="utf-8"
        )
        called = {"called": False}
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider",
                   return_value=_FakeYesProvider(called)):
            result = runner._verify_tier2({
                "id": "asrt_z", "type": "function_exists",
                "params": {"file": "svc.py", "name": "_sign_bundle"},
                "repo": "acme/widgets",
            })
        assert result["status"] == "pass"
        assert called["called"] is True  # quality check still runs
