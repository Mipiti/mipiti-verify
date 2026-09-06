"""The generic command adapter: a run command with ``{test}`` in it.

For simulators and custom harnesses (Verilator, Icarus, GHDL, NVC, Questa,
VCS, a Makefile). The command's exit status is the outcome: 0 passed, 1
failed, anything else error. Coverage comes from ``--coverage-cmd`` (run
instead of, or before reading, ``--coverage-file``). Mechanisms are
disabled by source mutation in every language that has one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import AdapterError, RunnerAdapter, split_template
from ._common import OUTCOME_ERROR, Outcome
from .mutation import MUTATION_LANGUAGES


class GenericAdapter(RunnerAdapter):
    name = "command"
    languages = ()
    mutation_languages = tuple(MUTATION_LANGUAGES) + ("verilog", "systemverilog", "vhdl")

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        return False

    def select_argv(self, test_id: str) -> list[str]:
        if not self.run_cmd:
            raise AdapterError("the command adapter needs --run-cmd with {test} in it")
        return split_template(self.run_cmd, test_id)

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        try:
            argv = self.select_argv(test_id)
        except AdapterError as e:
            return Outcome(OUTCOME_ERROR, -1, str(e))
        return self._execute(argv, env=env, timeout=timeout)

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        if not self.coverage_file:
            raise AdapterError("the command adapter needs --coverage-file naming the report the run writes")
        template = self.coverage_cmd or self.run_cmd
        if not template:
            raise AdapterError("the command adapter needs --coverage-cmd or --run-cmd")
        report = self.project_root / self.coverage_file
        if report.exists():
            report.unlink()
        outcome = self._execute(split_template(template, test_id), env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "the coverage command could not run")
        if not report.is_file():
            raise AdapterError(f"the coverage command did not write {self.coverage_file}")
        return report
