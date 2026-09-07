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
        assert "does not hold structurally" in result["details"].lower()
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


class _RefusingProvider:
    """Declines with a declared reason, per the templates' output contract."""

    def __init__(self, reason: str, called=None):
        self._reason = reason
        self._called = called if called is not None else {}

    def evaluate(self, *, assertion_type, assertion_params, source_code,
                 subject_kind="repository_file"):
        self._called["called"] = True
        return False, f"NO\nREASON: {self._reason}\nbecause of reasons"


class TestSemanticTierCannotDenyAStructuralFact:
    """The boundary holds in BOTH directions.

    The precheck stops the semantic tier affirming a criterion that does not
    hold. This is the other side: once the structural check holds, a semantic
    refusal that declares it could not FIND the target is contradicting a
    settled fact rather than judging quality, and cannot stand.
    """

    def _runner(self, tmp_path):
        (tmp_path / "svc.py").write_text(
            "def _sign_bundle():\n    return compute()\n", encoding="utf-8")
        return Runner(client=MagicMock(), project_root=str(tmp_path),
                      tier2_provider="anthropic", repo="acme/widgets")

    def _verify(self, runner, provider):
        with patch("mipiti_verify.tier2.get_provider", return_value=provider):
            return runner._verify_tier2({
                "id": "asrt_x", "type": "function_exists",
                "params": {"file": "svc.py", "name": "_sign_bundle"},
                "repo": "acme/widgets",
            })

    def test_not_found_refusal_is_discarded_when_the_target_is_present(self, tmp_path):
        runner = self._runner(tmp_path)
        result = self._verify(runner, _RefusingProvider("NOT_FOUND"))
        assert result["status"] == "skipped", (
            "a refusal claiming the target is absent was recorded as a failure, "
            "against a structural check confirming it is present"
        )

    def test_the_discarded_verdict_is_not_converted_into_a_pass(self, tmp_path):
        """Inconclusive, not affirmed: inventing a pass would be the same
        boundary violation in the opposite direction."""
        runner = self._runner(tmp_path)
        result = self._verify(runner, _RefusingProvider("NOT_FOUND"))
        assert result["status"] != "pass"

    def test_a_quality_refusal_still_stands(self, tmp_path):
        """The guard must not blunt real downgrades: the target exists and the
        semantic tier judged it insufficient, which is its job."""
        runner = self._runner(tmp_path)
        result = self._verify(runner, _RefusingProvider("QUALITY"))
        assert result["status"] == "fail"

    def test_a_refusal_without_a_declared_reason_still_stands(self, tmp_path):
        """Older or third-party providers emit no reason line. The check reads
        the declared reason and never infers one, so those verdicts are
        untouched."""
        runner = self._runner(tmp_path)

        class _Bare:
            def evaluate(self, **kw):
                return False, "NO\nit does not contain the function"

        assert self._verify(runner, _Bare())["status"] == "fail"


class TestPrecheckCoversDeclarationTypesBeyondSymbols:
    def test_absent_import_is_refused_without_the_llm(self, tmp_path):
        """The criterion tier 1 owns is not only symbol existence."""
        (tmp_path / "svc.py").write_text("x = 1\n", encoding="utf-8")
        called = {"called": False}
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider",
                   return_value=_FakeYesProvider(called)):
            result = runner._verify_tier2({
                "id": "asrt_i", "type": "import_present",
                "params": {"file": "svc.py", "module": "hashlib"},
                "repo": "acme/widgets",
            })
        assert result["status"] == "fail"
        assert called["called"] is False

    def test_target_based_assertions_skip_the_file_precheck(self, tmp_path):
        """Judged against supplied content, not a repository file, so a
        file-oriented verifier has nothing to re-check."""
        called = {"called": False}
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider",
                   return_value=_FakeYesProvider(called)):
            runner._verify_tier2({
                "id": "asrt_t", "type": "pattern_matches",
                "params": {"pattern": "x", "target": "feature_description",
                           "target_content": "some x here"},
                "repo": "acme/widgets",
            })
        assert called["called"] is True, "the semantic tier was wrongly skipped"


class TestAbsenceTypesAreJudgedNotDiscarded:
    """For an absence assertion the structural check passes when the target is
    NOT there. A "not found" refusal is then a restatement of that fact, not a
    contradiction of it, so the verdict stands as the quality judgment it is:
    setting it aside would leave tier 2 pending forever on every assertion
    whose evidence is a lack.
    """

    def _runner(self, tmp_path):
        (tmp_path / "Markdown.tsx").write_text(
            "import ReactMarkdown from 'react-markdown';\n"
            "export const Md = ({t}) => <ReactMarkdown>{t}</ReactMarkdown>;\n",
            encoding="utf-8")
        (tmp_path / "config.py").write_text("DEBUG = False\n", encoding="utf-8")
        return Runner(client=MagicMock(), project_root=str(tmp_path),
                      tier2_provider="anthropic", repo="acme/widgets")

    def _verify(self, runner, provider, assertion):
        with patch("mipiti_verify.tier2.get_provider", return_value=provider):
            return runner._verify_tier2(assertion)

    _PATTERN_ABSENT = {
        "id": "asrt_a", "type": "pattern_absent",
        "params": {"file": "Markdown.tsx", "pattern": r"rehype-?[Rr]aw"},
        "repo": "acme/widgets",
    }
    _NO_SECRET = {
        "id": "asrt_b", "type": "no_plaintext_secret",
        "params": {"file": "config.py", "patterns": [r"AKIA[0-9A-Z]{16}"]},
        "repo": "acme/widgets",
    }

    def test_a_not_found_refusal_on_pattern_absent_is_a_fail_not_a_skip(self, tmp_path):
        runner = self._runner(tmp_path)
        result = self._verify(runner, _RefusingProvider("NOT_FOUND"), self._PATTERN_ABSENT)
        assert result["status"] == "fail", (
            "an absence assertion's refusal was discarded as if 'not found' "
            "contradicted the structural check; for this type it IS the "
            "structural result, and the verdict must stand"
        )

    def test_a_not_found_refusal_on_no_plaintext_secret_is_a_fail_not_a_skip(self, tmp_path):
        runner = self._runner(tmp_path)
        result = self._verify(runner, _RefusingProvider("NOT_FOUND"), self._NO_SECRET)
        assert result["status"] == "fail"

    def test_a_quality_refusal_on_pattern_absent_stands(self, tmp_path):
        runner = self._runner(tmp_path)
        result = self._verify(runner, _RefusingProvider("QUALITY"), self._PATTERN_ABSENT)
        assert result["status"] == "fail"

    def test_a_pass_on_pattern_absent_is_recorded(self, tmp_path):
        runner = self._runner(tmp_path)
        called = {}
        result = self._verify(runner, _FakeYesProvider(called), self._PATTERN_ABSENT)
        assert called.get("called") is True
        assert result["status"] == "pass"

    def test_a_present_pattern_never_reaches_the_llm(self, tmp_path):
        """The other direction is unchanged: when the pattern IS there the
        structural check fails and tier 2 refuses without a model call."""
        (tmp_path / "Markdown.tsx").write_text(
            "import rehypeRaw from 'rehype-raw';\n", encoding="utf-8")
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        called = {}
        result = self._verify(runner, _FakeYesProvider(called), self._PATTERN_ABSENT)
        assert called.get("called") is None
        assert result["status"] == "fail"
