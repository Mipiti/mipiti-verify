"""Reach from a whole-suite run: the suite runs once under coverage, every
nominated test records what the suite reached in its mechanism's file as
``suite_reached`` under ``reach_scope = "suite"``, and nothing in the record
is ever ``reached``."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from mipiti_verify.attestation import build_statement
from mipiti_verify.languages.adapters import detect_adapter
from mipiti_verify.reach import REASON_NO_REPORT, run_suite_reach

LCOV = "SF:rtl/alu.sv\nDA:3,1\nDA:4,0\nDA:7,2\nend_of_record\nSF:rtl/fsm.sv\nDA:1,1\nend_of_record\n"


def _writing_runner(report: Path, body: str = LCOV, returncode: int = 0):
    def run(argv, **kwargs):
        run.calls.append(argv)
        if body is not None:
            report.write_text(body)
        return subprocess.CompletedProcess(argv, returncode, "", "")
    run.calls = []
    return run


class TestSuiteRun:
    PAIRS = [
        ("tb_alu", "rtl/alu.sv::module:alu"),
        ("tb_fsm", "rtl/fsm.sv::always:seq"),
        ("tb_none", "rtl/top.sv::module:top"),
    ]

    def test_one_run_and_suite_reached_per_mechanism_file(self, tmp_path):
        report = tmp_path / "cov.info"
        runner = _writing_runner(report)
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        summary = run_suite_reach(tmp_path, self.PAIRS, suite_cmd="make cov", coverage_file="cov.info",
                                  adapter=adapter, runner=runner)
        assert runner.calls == [["make", "cov"]]
        by_id = {t["id"]: t for t in summary["tests"]}
        assert by_id["tb_alu"]["suite_reached"] == [{"file": "rtl/alu.sv", "lines": [3, 7]}]
        assert by_id["tb_fsm"]["suite_reached"] == [{"file": "rtl/fsm.sv", "lines": [1]}]
        assert by_id["tb_none"]["suite_reached"] == []
        assert all("reached" not in t for t in summary["tests"])
        assert all(t["status"] == "passed" for t in summary["tests"])
        assert summary["totals"] == {"total": 3, "passed": 3, "failed": 0, "skipped": 0, "errors": 0}

    def test_a_failing_suite_still_records_what_it_reached(self, tmp_path):
        report = tmp_path / "cov.info"
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        summary = run_suite_reach(tmp_path, self.PAIRS[:1], suite_cmd="make cov", coverage_file="cov.info",
                                  adapter=adapter, runner=_writing_runner(report, returncode=1))
        assert summary["tests"][0]["status"] == "failed"
        assert summary["tests"][0]["suite_reached"] == [{"file": "rtl/alu.sv", "lines": [3, 7]}]

    def test_no_report_and_a_stale_report_are_not_read(self, tmp_path):
        report = tmp_path / "cov.info"
        report.write_text(LCOV)  # stale, from an earlier run
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        summary = run_suite_reach(tmp_path, self.PAIRS, suite_cmd="make cov", coverage_file="cov.info",
                                  adapter=adapter, runner=_writing_runner(report, body=None))
        assert all(t["status"] == "error" and t["reason"] == REASON_NO_REPORT for t in summary["tests"])
        assert all("suite_reached" not in t and "reached" not in t for t in summary["tests"])
        assert summary["totals"]["errors"] == 3

    def test_a_run_that_could_not_happen_is_an_error_for_every_pair(self, tmp_path):
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")

        def timing_out(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))

        summary = run_suite_reach(tmp_path, self.PAIRS, suite_cmd="make cov", coverage_file="cov.info",
                                  adapter=adapter, runner=timing_out, timeout=7)
        assert [t["reason"] for t in summary["tests"]] == ["timed out after 7s"] * 3

    def test_an_unreadable_report_is_an_error(self, tmp_path):
        report = tmp_path / "cov.info"
        adapter = detect_adapter(tmp_path, run_cmd="x {test}")
        summary = run_suite_reach(tmp_path, self.PAIRS[:1], suite_cmd="make cov", coverage_file="cov.info",
                                  adapter=adapter, runner=_writing_runner(report, body="not a report"))
        assert summary["tests"][0]["status"] == "error"
        assert "cannot read the coverage report" in summary["tests"][0]["reason"]

    def test_statement_carries_the_scope(self):
        statement = build_statement(commit="a" * 40, summary={"totals": {
            "total": 0, "passed": 0, "failed": 0, "skipped": 0, "errors": 0}, "tests": []},
            invocation=[], kind="reach", reach_scope="suite")
        assert statement["predicate"]["reach_scope"] == "suite"
        plain = build_statement(commit="a" * 40, summary={"totals": {
            "total": 0, "passed": 0, "failed": 0, "skipped": 0, "errors": 0}, "tests": []},
            invocation=[], kind="reach")
        assert "reach_scope" not in plain["predicate"]


class TestCli:
    def _no_ci(self, monkeypatch, tmp_path):
        for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL", "GITHUB_SHA",
                    "MIPITI_ATTESTATION_PUBLIC_KEY", "MIPITI_SUITE_CMD", "MIPITI_COVERAGE_FILE"):
            monkeypatch.delenv(var, raising=False)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("a" * 40)

    def test_suite_cmd_needs_coverage_file(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        self._no_ci(monkeypatch, tmp_path)
        result = CliRunner().invoke(main, ["attest-reach", "--project-root", str(tmp_path),
                                           "--pair", "t=a.go::F", "--suite-cmd", "make cov"])
        assert result.exit_code == 1 and "needs --coverage-file" in result.output

    def test_suite_mode_writes_a_suite_scope_reach_record(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.attestation import ATTESTATION_DIR, statement_of
        from mipiti_verify.cli import main

        self._no_ci(monkeypatch, tmp_path)
        report = tmp_path / "cov.info"

        def fake_run(argv, **kwargs):
            if argv[:1] == ["make"]:
                report.write_text(LCOV)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with patch("mipiti_verify.languages.adapters._common.subprocess.run", fake_run):
            result = CliRunner().invoke(main, [
                "attest-reach", "--project-root", str(tmp_path), "--runner", "command",
                "--suite-cmd", "make cov", "--coverage-file", "cov.info",
                "--pair", "tb_alu=rtl/alu.sv::module:alu",
                "--pair", "tb_top=rtl/top.sv::module:top",
            ])
        assert result.exit_code == 0, result.output
        assert "suite-level reach" in result.output
        assert "per-test reach stays unknown" in result.output
        path = next((tmp_path / ATTESTATION_DIR).glob("*-reach.json"))
        predicate = statement_of(path.read_text())["predicate"]
        assert predicate["kind"] == "reach"
        assert predicate["reach_scope"] == "suite"
        assert predicate["invocation"] == ["mipiti-verify", "attest-reach", "--runner", "command", "--suite"]
        assert [t["suite_reached"] for t in predicate["tests"]] == [
            [{"file": "rtl/alu.sv", "lines": [3, 7]}], []]
        assert all("reached" not in t for t in predicate["tests"])

    def test_per_test_mode_is_scoped_to_the_test(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.attestation import ATTESTATION_DIR, statement_of
        from mipiti_verify.cli import main

        self._no_ci(monkeypatch, tmp_path)
        report = tmp_path / "cov.info"

        def fake_run(argv, **kwargs):
            report.write_text(LCOV)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with patch("mipiti_verify.languages.adapters._common.subprocess.run", fake_run):
            result = CliRunner().invoke(main, [
                "attest-reach", "--project-root", str(tmp_path),
                "--run-cmd", "make sim TEST={test}", "--coverage-file", "cov.info",
                "--pair", "tb_alu=rtl/alu.sv::module:alu",
            ])
        assert result.exit_code == 0, result.output
        path = next((tmp_path / ATTESTATION_DIR).glob("*-reach.json"))
        predicate = statement_of(path.read_text())["predicate"]
        assert predicate["reach_scope"] == "test"
        assert predicate["tests"][0]["reached"] == [{"file": "rtl/alu.sv", "lines": [3, 7]}]
