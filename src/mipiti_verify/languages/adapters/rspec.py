"""rspec."""

from __future__ import annotations

import re
from pathlib import Path
from . import AdapterError, RunnerAdapter
from ._common import OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, Outcome, tail
from .coverage_convert import simplecov_resultset_to_lcov


def selector(test_id: str) -> list[str]:
    text = str(test_id or "").strip()
    if "::" in text:
        file, _, name = text.partition("::")
        return [file.strip(), "-e", name.strip()]
    if re.search(r"_spec\.rb(?::\d+)?$", text):
        return [text]
    return ["-e", text]


class RspecAdapter(RunnerAdapter):
    name = "rspec"
    languages = ("ruby",)
    mutation_languages = ()

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        return (root / ".rspec").is_file() or ((root / "Gemfile").is_file() and (root / "spec").is_dir())

    def _rspec(self) -> list[str]:
        if (self.project_root / "Gemfile").is_file():
            return ["bundle", "exec", "rspec"]
        return ["rspec"]

    def select_argv(self, test_id: str) -> list[str]:
        return self._rspec() + selector(test_id)

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        m = re.search(r"(\d+) examples?, (\d+) failures?", stdout)
        if m is not None and int(m.group(1)) == 0:
            return Outcome(OUTCOME_ERROR, returncode, "rspec selected no examples")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1 and m is not None:
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"rspec exit status {returncode}: {tail(stderr or stdout, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        helper = Path(work_dir) / "mipiti_simplecov.rb"
        helper.write_text(
            "require 'simplecov'\n"
            f"SimpleCov.coverage_dir {str(Path(work_dir).as_posix())!r}\n"
            "SimpleCov.start\n", encoding="utf-8")
        argv = self._rspec() + ["-r", str(helper)] + selector(test_id)
        outcome = self._execute(argv, env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "rspec could not run under coverage (is simplecov installed?)")
        resultset = Path(work_dir) / ".resultset.json"
        if not resultset.is_file():
            raise AdapterError("simplecov wrote no .resultset.json")
        report = Path(work_dir) / "lcov.info"
        report.write_text(simplecov_resultset_to_lcov(resultset.read_text(encoding="utf-8"), self.project_root),
                          encoding="utf-8")
        return report
