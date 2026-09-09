"""Tier-2 self-consistency and evidence-keyed verdict reuse.

A nondeterministic LLM judge flickers a control's verified status across runs.
The runner runs N judgments per fresh evidence and lets the spread decide — a
PASS requires every judgment to agree, so a split can never verify a control;
a split is reported not-verified, and it is KEPT: it carries the evidence hash
like any other verdict the judge reached, so the same unchanged question is not
asked again. Discarding it meant asking until the judgments happened to agree,
and since a stored verdict is reused rather than improved upon, the only
outcome repetition could arrive at was the unanimous one.

The count a verdict was reached over travels with it, so a run asking for more
scrutiny than the stored verdict carries judges again, and one asking for the
same or less reuses it.
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


def _runner(tmp_path, n=3, rejudge=None):
    (tmp_path / "svc.py").write_text(
        "import os\n\n\ndef _guard():\n    return check()\n", encoding="utf-8")
    return Runner(client=MagicMock(), project_root=str(tmp_path),
                  tier2_provider="anthropic", repo="acme/widgets",
                  tier2_consistency_n=n, rejudge=rejudge)


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

    def test_a_split_never_verifies_and_is_kept(self, tmp_path):
        """A split does not verify a control — that is the soundness rule, and
        it is unchanged. What it does now is STAY: it carries the evidence hash,
        so the same question is not asked again while nothing about it has
        moved. Discarding it meant asking until the judgments happened to
        agree, and the only outcome that could then be kept was a pass."""
        r = _runner(tmp_path)
        # two pass, one fail — not unanimous.
        p = _Seq([(True, "YES"), (True, "YES"), (False, "NO\nREASON: QUALITY\nmeh")])
        res = _verify(r, p)
        assert res["status"] == "skipped", "a split must not verify a control"
        assert "BORDERLINE" in res["details"]
        assert res["tier2_evidence_hash"], "a split is a verdict about this evidence"
        assert res["tier2_consistency_n"] == 3

    def test_one_dissent_denies_the_pass(self, tmp_path):
        """Unanimity is still what a pass requires; one dissent in five denies
        it. The verdict is recorded as reached-but-undecided, not as a finding
        against the evidence, and it carries the count it was reached over."""
        r = _runner(tmp_path, n=5)
        p = _Seq([(True, "YES")] * 4 + [(False, "NO\nREASON: QUALITY\nx")])
        res = _verify(r, p)
        assert res["status"] == "skipped"
        assert res["tier2_evidence_hash"]
        assert res["tier2_consistency_n"] == 5

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
        a = dict(_A, tier2_cached={"evidence_hash": h, "status": "pass",
                                   "reasoning": "prior", "consistency_n": 3})
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


class TestScrutinyCount:
    """The count a verdict was reached over decides whether a later run may
    reuse it. Without it the count is a lever with nothing to act on: once
    every assertion carries a verdict, asking for more scrutiny would find an
    unchanged hash and judge nothing."""

    def _cached(self, r, n_stored):
        probe = _Seq([(True, "YES")] * 9)
        h = _verify(r, probe)["tier2_evidence_hash"]
        return dict(_A, tier2_cached={"evidence_hash": h, "status": "pass",
                                      "reasoning": "prior", "consistency_n": n_stored})

    def test_asking_for_less_scrutiny_reuses_the_stronger_verdict(self, tmp_path):
        """A verdict reached over 7 judgments already clears a bar of 3."""
        r = _runner(tmp_path, n=3)
        a = self._cached(r, 7)
        p = _Seq([(False, "NO")])
        res = _verify(r, p, a)
        assert p.calls == 0
        assert res["reviewer"] == "cache"

    def test_asking_for_more_scrutiny_judges_again(self, tmp_path):
        """The run paid for a stricter reading and gets one."""
        r = _runner(tmp_path, n=5)
        a = self._cached(r, 3)
        p = _Seq([(True, "YES")] * 5)
        res = _verify(r, p, a)
        assert p.calls == 5, "a stored verdict below the requested count must be re-judged"
        assert res["status"] == "pass"
        assert res["tier2_consistency_n"] == 5

    def test_a_verdict_from_before_the_count_existed_is_judged_again(self, tmp_path):
        """0 is below any count a run can ask for, so such a verdict is judged
        once more and then carries its own — rather than being reused as though
        it had met a bar nobody recorded."""
        r = _runner(tmp_path, n=3)
        probe = _Seq([(True, "YES")] * 3)
        h = _verify(r, probe)["tier2_evidence_hash"]
        a = dict(_A, tier2_cached={"evidence_hash": h, "status": "pass"})
        p = _Seq([(True, "YES")] * 3)
        _verify(r, p, a)
        assert p.calls == 3

    def test_a_kept_split_is_reused_rather_than_re_asked(self, tmp_path):
        """The point of the change: the same undecided question is not put to
        the judge again while its evidence is unchanged."""
        r = _runner(tmp_path, n=3)
        probe = _Seq([(True, "YES")] * 3)
        h = _verify(r, probe)["tier2_evidence_hash"]
        a = dict(_A, tier2_cached={"evidence_hash": h, "status": "skipped",
                                   "reasoning": "BORDERLINE", "consistency_n": 3})
        p = _Seq([(True, "YES")] * 3)
        res = _verify(r, p, a)
        assert p.calls == 0, "a kept split must not be asked again"
        assert res["status"] == "skipped"


class TestRejudge:
    """The escape hatch. A verdict reached on judgments that disagreed would
    otherwise stay until the evidence changes, which invites a no-op edit made
    only to clear it."""

    def test_a_named_assertion_is_judged_again_despite_a_matching_verdict(self, tmp_path):
        r0 = _runner(tmp_path)
        h = _verify(r0, _Seq([(True, "YES")] * 3))["tier2_evidence_hash"]
        a = dict(_A, tier2_cached={"evidence_hash": h, "status": "skipped",
                                   "reasoning": "BORDERLINE", "consistency_n": 3})
        r = _runner(tmp_path, rejudge={a["id"]})
        p = _Seq([(True, "YES")] * 3)
        res = _verify(r, p, a)
        assert p.calls == 3, "the named assertion must be judged again"
        assert res["status"] == "pass"

    def test_an_unnamed_assertion_still_reuses_its_verdict(self, tmp_path):
        """Naming one assertion must not reopen the rest: a blanket reopen is
        the repetition this caching exists to prevent."""
        r0 = _runner(tmp_path)
        h = _verify(r0, _Seq([(True, "YES")] * 3))["tier2_evidence_hash"]
        a = dict(_A, tier2_cached={"evidence_hash": h, "status": "pass",
                                   "reasoning": "prior", "consistency_n": 3})
        r = _runner(tmp_path, rejudge={"asrt_someone_else"})
        p = _Seq([(False, "NO")])
        assert _verify(r, p, a)["reviewer"] == "cache"
        assert p.calls == 0
