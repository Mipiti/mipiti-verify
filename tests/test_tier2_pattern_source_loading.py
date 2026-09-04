"""Tier-2 pattern-based source loading.

Pattern-based tier-2 types (``test_exists``) use
``params["pattern"]`` instead of ``params["file"]``. The runner must
glob the pattern the same way tier-1 does and load the matched file
content into SOURCE_CODE — previously it looked up ``params["file"]``
and silently received an empty source.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mipiti_verify.runner import Runner, _load_pattern_source


class TestLoadPatternSource:
    def test_loads_single_match(self, tmp_path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_auth.py").write_text(
            "def test_token_verification():\n    assert verify_token('x')\n",
            encoding="utf-8",
        )
        source = _load_pattern_source(
            tmp_path, {"pattern": "tests/test_auth.py"}
        )
        assert "test_token_verification" in source
        assert "# === " in source  # separator present
        assert "tests/test_auth.py" in source

    def test_loads_glob_recursive(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "test_x.py").write_text("def test_a(): pass\n")
        (tmp_path / "b" / "test_y.py").write_text("def test_b(): pass\n")
        source = _load_pattern_source(tmp_path, {"pattern": "**/test_*.py"})
        assert "test_a" in source
        assert "test_b" in source
        # Each match gets a separator with its relative path.
        assert source.count("# === ") == 2

    def test_empty_when_no_match(self, tmp_path):
        assert _load_pattern_source(tmp_path, {"pattern": "tests/nope_*.py"}) == ""

    def test_empty_when_pattern_missing(self, tmp_path):
        assert _load_pattern_source(tmp_path, {}) == ""
        assert _load_pattern_source(tmp_path, {"pattern": ""}) == ""

    def test_truncates_at_16k(self, tmp_path):
        (tmp_path / "tests").mkdir()
        big = "x" * 50_000
        (tmp_path / "tests" / "test_big.py").write_text(big)
        source = _load_pattern_source(
            tmp_path, {"pattern": "tests/test_big.py"}
        )
        # Truncation marker appears once the combined content exceeds 16K.
        assert "... (truncated)" in source
        assert len(source) <= 16000 + len("\n... (truncated)")


class TestRunnerLoadsPatternSource:
    """End-to-end: when a pattern-based assertion enters ``_verify_tier2``,
    the runner loads the matched file's content and passes it to the
    provider as SOURCE_CODE — proving the tier-1/tier-2 source-key
    mismatch is fixed for these types."""

    def test_test_exists_source_code_populated(self, tmp_path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_token.py").write_text(
            "def test_verify_token_rejects_expired():\n"
            "    expired = make_token(exp=0)\n"
            "    assert verify_token(expired) is False\n",
            encoding="utf-8",
        )

        client = MagicMock()
        runner = Runner(
            client=client,
            project_root=str(tmp_path),
            tier2_provider="anthropic",
            repo="acme/widgets",
        )

        captured = {}

        class FakeProvider:
            def evaluate(
                self, *, assertion_type, assertion_params, source_code,
                subject_kind="repository_file",
            ):
                captured["type"] = assertion_type
                captured["params"] = dict(assertion_params)
                captured["source_code"] = source_code
                return True, "YES"

        with patch("mipiti_verify.tier2.get_provider", return_value=FakeProvider()):
            result = runner._verify_tier2(
                {
                    "id": "asrt_pattern",
                    "type": "test_exists",
                    "params": {"pattern": "tests/test_token.py"},
                    "repo": "acme/widgets",
                }
            )

        assert result["status"] == "pass"
        assert "test_verify_token_rejects_expired" in captured["source_code"]
        assert "# === " in captured["source_code"]

    def test_test_attested_source_is_the_attestation(self, tmp_path):
        """test_attested has no source file to glob -- its evidence is the
        signed statement, so tier 2 is handed that instead of empty content."""
        import json as _json

        from mipiti_verify.attestation import (
            ATTESTATION_DIR, build_statement, parse_junit, sign_statement,
        )

        report = tmp_path / "r.xml"
        report.write_text(
            '<testsuites><testsuite name="s">'
            '<testcase classname="t" name="test_thing"/>'
            "</testsuite></testsuites>",
            encoding="utf-8",
        )
        # The attestation binds to a commit, so the fixture project needs one
        # to be bound to; without it the structural tier refuses before tier 2
        # is reached.
        (tmp_path / ".git").mkdir(exist_ok=True)
        (tmp_path / ".git" / "HEAD").write_text("a" * 40, encoding="utf-8")
        statement = build_statement(
            commit="a" * 40, summary=parse_junit(report), invocation=["pytest"],
        )
        att_dir = tmp_path / ATTESTATION_DIR
        att_dir.mkdir(parents=True)
        attestation, _ = sign_statement(statement)
        (att_dir / "tests.json").write_text(attestation, encoding="utf-8")

        client = MagicMock()
        runner = Runner(
            client=client,
            project_root=str(tmp_path),
            tier2_provider="anthropic",
            repo="acme/widgets",
        )
        captured = {}

        class FakeProvider:
            def evaluate(
                self, *, assertion_type, assertion_params, source_code,
                subject_kind="repository_file",
            ):
                captured["source_code"] = source_code
                return True, "YES"

        with patch("mipiti_verify.tier2.get_provider", return_value=FakeProvider()):
            runner._verify_tier2(
                {
                    "id": "asrt_attested_1",
                    "type": "test_attested",
                    "params": {"test": "test_thing"},
                    "repo": "acme/widgets",
                }
            )

        assert "test_thing" in captured["source_code"]
        assert "predicate" in captured["source_code"]
