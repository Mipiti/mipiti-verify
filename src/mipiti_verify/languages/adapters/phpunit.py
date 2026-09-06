"""phpunit."""

from __future__ import annotations

from pathlib import Path
from . import AdapterError, RunnerAdapter
from ._common import OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, Outcome, tail
from .coverage_convert import clover_to_lcov


def selector(test_id: str) -> list[str]:
    text = str(test_id or "").strip()
    if "::" in text:
        file, _, name = text.partition("::")
        return ["--filter", name.strip(), file.strip()]
    if text.endswith(".php"):
        return [text]
    return ["--filter", text]


class PhpunitAdapter(RunnerAdapter):
    name = "phpunit"
    languages = ("php",)
    mutation_languages = ()

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        return any(Path(project_root).glob("phpunit.xml*"))

    def _phpunit(self) -> list[str]:
        local = self.project_root / "vendor" / "bin" / "phpunit"
        return [str(local)] if local.is_file() else ["phpunit"]

    def select_argv(self, test_id: str) -> list[str]:
        return self._phpunit() + selector(test_id)

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        text = stdout + stderr
        if "No tests executed" in text:
            return Outcome(OUTCOME_ERROR, returncode, "phpunit selected no tests")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        # 1: failures; 2: errors raised inside tests. Both are the test not
        # passing; anything else is the run not happening.
        if returncode in (1, 2):
            return Outcome(OUTCOME_FAILED, returncode)
        return Outcome(OUTCOME_ERROR, returncode, f"phpunit exit status {returncode}: {tail(text, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        clover = Path(work_dir) / "clover.xml"
        argv = self._phpunit() + ["--coverage-clover", str(clover)] + selector(test_id)
        outcome = self._execute(argv, env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "phpunit could not run under coverage")
        if not clover.is_file():
            raise AdapterError("phpunit wrote no clover report; is a coverage driver (xdebug/pcov) enabled?")
        report = Path(work_dir) / "lcov.info"
        report.write_text(clover_to_lcov(clover.read_text(encoding="utf-8"), self.project_root), encoding="utf-8")
        return report
