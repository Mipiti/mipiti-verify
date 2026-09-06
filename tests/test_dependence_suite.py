"""Dependence from a whole-suite run: one disable and one suite command per
mechanism, outcomes read from the JUnit report the command wrote."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mipiti_verify.dependence import (
    REASON_BUDGET_EXHAUSTED, REASON_NO_REPORT, REASON_NOT_IN_REPORT, REASON_SKIPPED,
    group_by_mechanism, run_suite_dependence, suite_outcome,
)
from mipiti_verify.languages.adapters import DisableError, detect_adapter

JUNIT = """<testsuites><testsuite name="s">
  <testcase classname="tests.test_guard" name="test_refuses"><failure message="boom"/></testcase>
  <testcase classname="tests.test_guard" name="test_errors"><error message="boom"/></testcase>
  <testcase classname="tests.test_guard" name="test_unrelated"/>
  <testcase classname="tests.test_guard" name="test_skipped"><skipped/></testcase>
  <testcase classname="tests.other" name="test_dup"/>
  <testcase classname="tests.another" name="test_dup"/>
</testsuite></testsuites>
"""


class TestGrouping:
    def test_groups_by_mechanism_in_first_seen_order_and_dedups(self):
        groups = group_by_mechanism([
            ("t1", "a.go::F"), ("t2", "b.go::G"), ("t3", "a.go::F"), ("t1", "a.go::F"),
        ])
        assert groups == [("a.go::F", ["t1", "t3"]), ("b.go::G", ["t2"])]

    @pytest.mark.parametrize("status,expected", [
        ("passed", ("passed", "")),
        ("failed", ("failed", "")),
        ("error", ("error", "")),
        ("skipped", ("error", REASON_SKIPPED)),
        (None, ("error", REASON_NOT_IN_REPORT)),
    ])
    def test_outcome_from_report_status(self, status, expected):
        assert suite_outcome(status) == expected


def _writing_runner(report: Path, body: str = JUNIT):
    def run(argv, **kwargs):
        run.calls.append((argv, kwargs.get("env", {})))
        report.write_text(body)
        return subprocess.CompletedProcess(argv, 1, "", "")
    run.calls = []
    return run


class TestSuiteRun:
    def test_outcomes_come_from_the_report(self, tmp_path):
        report = tmp_path / "out.xml"
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        with patch.object(type(adapter), "disable", _null_disable):
            summary = run_suite_dependence(tmp_path, [
                ("test_refuses", "m"), ("test_errors", "m"), ("test_unrelated", "m"),
                ("test_skipped", "m"), ("test_nowhere", "m"), ("test_dup", "m"),
            ], suite_cmd="make sim JUNIT=out.xml", suite_junit="out.xml", adapter=adapter,
                runner=_writing_runner(report))
        by = {t["id"]: t["fails_without"][0] for t in summary["tests"]}
        assert by["test_refuses"] == {"mechanism": "m", "status": "failed"}
        assert by["test_errors"] == {"mechanism": "m", "status": "error"}
        assert by["test_unrelated"] == {"mechanism": "m", "status": "passed"}
        assert by["test_skipped"] == {"mechanism": "m", "status": "error", "reason": REASON_SKIPPED}
        assert by["test_nowhere"] == {"mechanism": "m", "status": "error", "reason": REASON_NOT_IN_REPORT}
        assert by["test_dup"]["status"] == "error" and "more than one" in by["test_dup"]["reason"]
        assert summary["totals"] == {"total": 6, "passed": 1, "failed": 1, "skipped": 0, "errors": 4}

    def test_one_run_per_mechanism_and_a_stale_report_is_removed(self, tmp_path):
        report = tmp_path / "out.xml"
        report.write_text(JUNIT)
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        seen = []

        def run(argv, **kwargs):
            seen.append(report.exists())
            report.write_text(JUNIT)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with patch.object(type(adapter), "disable", _null_disable):
            summary = run_suite_dependence(tmp_path, [
                ("test_refuses", "a"), ("test_unrelated", "a"), ("test_refuses", "b"),
            ], suite_cmd="make sim", suite_junit="out.xml", adapter=adapter, runner=run)
        assert seen == [False, False]
        assert [t["fails_without"][0]["mechanism"] for t in summary["tests"]] == ["a", "a", "b"]

    def test_no_report_and_gate_failure_fan_out_to_every_pair(self, tmp_path):
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")

        def silent(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, "", "")

        with patch.object(type(adapter), "disable", _null_disable):
            summary = run_suite_dependence(tmp_path, [("t1", "a"), ("t2", "a")],
                                           suite_cmd="make sim", suite_junit="out.xml",
                                           adapter=adapter, runner=silent)
        assert all(t["fails_without"][0] == {"mechanism": "a", "status": "error", "reason": REASON_NO_REPORT}
                   for t in summary["tests"])

        with patch.object(type(adapter), "disable", _failing_disable):
            summary = run_suite_dependence(tmp_path, [("t1", "a"), ("t2", "a"), ("t3", "b")],
                                           suite_cmd="make sim", suite_junit="out.xml",
                                           adapter=adapter, runner=silent)
        reasons = [t["fails_without"][0]["reason"] for t in summary["tests"]]
        assert reasons == ["mutated tree does not compile: nope"] * 3

    def test_budget_is_spent_across_mechanisms(self, tmp_path):
        report = tmp_path / "out.xml"
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        now = [0.0]

        def clock():
            return now[0]

        def run(argv, **kwargs):
            now[0] += 100.0
            report.write_text(JUNIT)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with patch.object(type(adapter), "disable", _null_disable):
            summary = run_suite_dependence(tmp_path, [
                ("test_refuses", "a"), ("test_unrelated", "a"), ("test_refuses", "b"), ("test_refuses", "c"),
            ], suite_cmd="make sim", suite_junit="out.xml", adapter=adapter, runner=run,
                total_timeout=150, clock=clock)
        assert summary["not_run"] == 1
        statuses = [(t["fails_without"][0]["status"], t["fails_without"][0].get("reason", "")) for t in summary["tests"]]
        assert statuses == [("failed", ""), ("passed", ""), ("failed", ""), ("error", REASON_BUDGET_EXHAUSTED)]

    def test_a_timed_out_suite_is_an_error_for_its_pairs(self, tmp_path):
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")

        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with patch.object(type(adapter), "disable", _null_disable):
            summary = run_suite_dependence(tmp_path, [("t1", "a")], suite_cmd="make sim",
                                           suite_junit="out.xml", adapter=adapter, runner=slow, timeout=7)
        assert "timed out" in summary["tests"][0]["fails_without"][0]["reason"]

    def test_end_to_end_with_pytest_as_the_suite_command(self, tmp_path, monkeypatch):
        for name, body in {
            "pytest.ini": "[pytest]\n",
            "app/__init__.py": "",
            "app/guard.py": "def require_token(t):\n    if not t:\n        raise PermissionError()\n    return True\n",
            "tests/__init__.py": "",
            "tests/test_guard.py": (
                "import pytest\nfrom app.guard import require_token\n\n"
                "def test_refuses():\n    with pytest.raises(PermissionError):\n        require_token('')\n\n"
                "def test_unrelated():\n    assert 1 + 1 == 2\n"
            ),
        }.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        monkeypatch.setenv("PYTHONPATH", str(tmp_path))
        adapter = detect_adapter(tmp_path)
        assert adapter.name == "pytest"
        summary = run_suite_dependence(tmp_path, [
            ("tests/test_guard.py::test_refuses", "app/guard.py::require_token"),
            ("tests/test_guard.py::test_unrelated", "app/guard.py::require_token"),
            ("test_refuses", "app/guard.py::require_token"),
        ], suite_cmd=f"{sys.executable} -m pytest -q --junitxml=report.xml",
            suite_junit="report.xml", adapter=adapter, timeout=300)
        by = {t["id"]: t["fails_without"][0] for t in summary["tests"]}
        # pytest ids in the report are classname::name; a node id is not in it.
        assert by["tests/test_guard.py::test_refuses"]["reason"] == REASON_NOT_IN_REPORT
        assert by["test_refuses"] == {"mechanism": "app/guard.py::require_token", "status": "failed"}
        assert by["tests/test_guard.py::test_unrelated"]["reason"] == REASON_NOT_IN_REPORT

    def test_end_to_end_bare_names(self, tmp_path, monkeypatch):
        for name, body in {
            "pytest.ini": "[pytest]\n",
            "app/__init__.py": "",
            "app/guard.py": "def require_token(t):\n    if not t:\n        raise PermissionError()\n    return True\n",
            "tests/__init__.py": "",
            "tests/test_guard.py": (
                "import pytest\nfrom app.guard import require_token\n\n"
                "def test_refuses():\n    with pytest.raises(PermissionError):\n        require_token('')\n\n"
                "def test_unrelated():\n    assert 1 + 1 == 2\n"
            ),
        }.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        monkeypatch.setenv("PYTHONPATH", str(tmp_path))
        adapter = detect_adapter(tmp_path)
        summary = run_suite_dependence(tmp_path, [
            ("test_refuses", "app/guard.py::require_token"),
            ("test_unrelated", "app/guard.py::require_token"),
        ], suite_cmd=f"{sys.executable} -m pytest -q --junitxml=report.xml",
            suite_junit="report.xml", adapter=adapter, timeout=300)
        by = {t["id"]: t["fails_without"][0]["status"] for t in summary["tests"]}
        assert by == {"test_refuses": "failed", "test_unrelated": "passed"}
        assert summary["runner"] == "pytest"


class TestCli:
    def test_suite_options_go_together(self, tmp_path):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        result = CliRunner().invoke(main, ["attest-dependence", "--project-root", str(tmp_path),
                                           "--pair", "t=a.go::F", "--suite-cmd", "make sim"])
        assert result.exit_code == 1 and "go together" in result.output

    def test_suite_mode_writes_a_dependence_record(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.attestation import ATTESTATION_DIR, statement_of
        from mipiti_verify.cli import main

        for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL", "GITHUB_SHA",
                    "MIPITI_ATTESTATION_PUBLIC_KEY"):
            monkeypatch.delenv(var, raising=False)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("a" * 40)
        report = tmp_path / "out.xml"

        def fake_run(argv, **kwargs):
            if argv[:1] == ["make"]:
                report.write_text(JUNIT)
            return subprocess.CompletedProcess(argv, 0, "", "")

        from mipiti_verify.languages.adapters.generic import GenericAdapter
        with patch("mipiti_verify.languages.adapters._common.subprocess.run", fake_run), \
                patch.object(GenericAdapter, "disable", _null_disable):
            result = CliRunner().invoke(main, [
                "attest-dependence", "--project-root", str(tmp_path), "--runner", "command",
                "--suite-cmd", "make sim JUNIT=out.xml", "--suite-junit", "out.xml",
                "--pair", "test_refuses=rtl/alu.sv::module:alu",
                "--pair", "test_unrelated=rtl/alu.sv::module:alu",
            ])
        assert result.exit_code == 0, result.output
        assert "1 mechanism(s), 2 pair(s)" in result.output
        path = next((tmp_path / ATTESTATION_DIR).glob("*-dependence.json"))
        predicate = statement_of(path.read_text())["predicate"]
        assert predicate["kind"] == "dependence"
        assert predicate["invocation"][-1] == "--suite"
        assert [t["fails_without"][0]["status"] for t in predicate["tests"]] == ["failed", "passed"]


from contextlib import contextmanager  # noqa: E402

from mipiti_verify.languages.adapters import DisableHandle  # noqa: E402


@contextmanager
def _null_disable(self, mechanism):
    yield DisableHandle()


@contextmanager
def _failing_disable(self, mechanism):
    raise DisableError("mutated tree does not compile: nope")
    yield
