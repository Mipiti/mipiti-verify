"""Tier-2 self-consistency and evidence-keyed verdict reuse.

A nondeterministic LLM judge flickers a control's verified status across runs.
The runner runs N judgments per fresh evidence and lets the spread decide — a
PASS requires every judgment to agree, so a split can never verify a control;
a split is reported not-verified and NOT cached (re-judged next run) so a
borderline verdict is never frozen. When the platform hands back a stored
verdict for the same evidence hash, the runner reuses it with no judge call.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mipiti_verify.runner import Runner, _tier2_evidence_hash


class _Seq:
    """A provider returning a fixed sequence of (passed, reasoning), one per
    call, so a test can script a split or a unanimous vote."""

    def __init__(self, seq):
        self._seq = list(seq)
        self.calls = 0

    def evaluate(self, *, assertion_type, assertion_params, source_code,
                 subject_kind="repository_file"):
        v = self._seq[self.calls % len(self._seq)]
        self.calls += 1
        return v


def _runner(tmp_path, n=3):
    (tmp_path / "svc.py").write_text(
        "import os\n\n\ndef _guard():\n    return check()\n", encoding="utf-8")
    return Runner(client=MagicMock(), project_root=str(tmp_path),
                  tier2_provider="anthropic", repo="acme/widgets",
                  tier2_consistency_n=n)


_A = {"id": "asrt_x", "type": "function_exists",
      "params": {"file": "svc.py", "name": "_guard"}, "repo": "acme/widgets"}


def _verify(runner, provider, assertion=None):
    with patch("mipiti_verify.tier2.get_provider", return_value=provider):
        return runner._verify_tier2(dict(assertion or _A))


class TestSelfConsistency:
    def test_unanimous_pass_verifies_and_carries_the_hash(self, tmp_path):
        r = _runner(tmp_path)
        p = _Seq([(True, "YES ok")] * 3)
        res = _verify(r, p)
        assert p.calls == 3
        assert res["status"] == "pass"
        assert res["tier2_evidence_hash"].startswith("sha256:")

    def test_unanimous_fail_is_confident_and_carries_the_hash(self, tmp_path):
        r = _runner(tmp_path)
        p = _Seq([(False, "NO\nREASON: QUALITY\nstub")] * 3)
        res = _verify(r, p)
        assert res["status"] == "fail"
        assert res["tier2_evidence_hash"].startswith("sha256:")

    def test_a_split_never_verifies_and_is_not_cached(self, tmp_path):
        r = _runner(tmp_path)
        # two pass, one fail — not unanimous.
        p = _Seq([(True, "YES"), (True, "YES"), (False, "NO\nREASON: QUALITY\nmeh")])
        res = _verify(r, p)
        assert res["status"] == "fail", "a split must not verify a control"
        assert "BORDERLINE" in res["details"]
        assert "tier2_evidence_hash" not in res, "a borderline verdict must not be cached"

    def test_one_dissent_denies_the_pass(self, tmp_path):
        r = _runner(tmp_path, n=5)
        p = _Seq([(True, "YES")] * 4 + [(False, "NO\nREASON: QUALITY\nx")])
        res = _verify(r, p)
        assert res["status"] == "fail"
        assert "tier2_evidence_hash" not in res

    def test_n_is_configurable(self, tmp_path):
        r = _runner(tmp_path, n=5)
        p = _Seq([(True, "YES")] * 5)
        res = _verify(r, p)
        assert p.calls == 5
        assert res["status"] == "pass"


class TestEvidenceReuse:
    def test_a_matching_cached_verdict_is_reused_without_judging(self, tmp_path):
        r = _runner(tmp_path)
        # First, learn the evidence hash this assertion would produce.
        probe = _Seq([(True, "YES")] * 3)
        h = _verify(r, probe)["tier2_evidence_hash"]
        # Now hand it back as a cached pass; the judge must not be called.
        p = _Seq([(False, "NO")])  # would fail if consulted
        a = dict(_A, tier2_cached={"evidence_hash": h, "status": "pass", "reasoning": "prior"})
        res = _verify(r, p, a)
        assert p.calls == 0, "an unchanged evidence hash must not re-judge"
        assert res["status"] == "pass"
        assert res["reviewer"] == "cache"

    def test_a_stale_cached_hash_is_ignored_and_the_judge_runs(self, tmp_path):
        r = _runner(tmp_path)
        p = _Seq([(True, "YES")] * 3)
        a = dict(_A, tier2_cached={"evidence_hash": "sha256:stale", "status": "pass"})
        res = _verify(r, p, a)
        assert p.calls == 3, "a non-matching hash must be re-judged"
        assert res["status"] == "pass"


def test_hash_is_stable_for_the_same_inputs():
    h1 = _tier2_evidence_hash("function_exists", {"file": "a.py", "name": "f"},
                              "def f(): pass", "repository_file", "anthropic", "claude")
    h2 = _tier2_evidence_hash("function_exists", {"file": "a.py", "name": "f"},
                              "def f(): pass", "repository_file", "anthropic", "claude")
    assert h1 == h2 and h1.startswith("sha256:")


def test_hash_changes_with_the_source():
    a = _tier2_evidence_hash("function_exists", {"file": "a.py"}, "one", "repository_file", "anthropic", "claude")
    b = _tier2_evidence_hash("function_exists", {"file": "a.py"}, "two", "repository_file", "anthropic", "claude")
    assert a != b


def test_hash_changes_with_the_model():
    a = _tier2_evidence_hash("function_exists", {"file": "a.py"}, "s", "repository_file", "openai", "gpt-4o")
    b = _tier2_evidence_hash("function_exists", {"file": "a.py"}, "s", "repository_file", "openai", "gpt-5")
    assert a != b
