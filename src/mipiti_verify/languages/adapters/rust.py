"""``cargo test``."""

from __future__ import annotations

import re
from pathlib import Path
from . import AdapterError, RunnerAdapter
from ._common import OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, Outcome, run_command, tail, which


def test_name(test_id: str) -> str:
    """The test path ``cargo test`` filters on; a leading ``file.rs::`` is
    dropped, a JUnit-style ``module::name`` is kept."""
    text = str(test_id or "").strip()
    if "::" in text:
        head, _, rest = text.partition("::")
        if head.endswith(".rs") or "/" in head:
            return rest.strip()
    return text


class CargoAdapter(RunnerAdapter):
    name = "cargo"
    languages = ("rust",)
    mutation_languages = ("rust",)

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        return (Path(project_root) / "Cargo.toml").is_file()

    def select_argv(self, test_id: str) -> list[str]:
        return ["cargo", "test", "--quiet", test_name(test_id), "--", "--exact"]

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        text = stdout + stderr
        if "could not compile" in text or re.search(r"^error(\[E\d+\])?:", text, re.M):
            return Outcome(OUTCOME_ERROR, returncode, f"cargo could not compile: {tail(stderr or stdout, 4)}")
        ran = [int(n) for n in re.findall(r"running (\d+) tests?", text)]
        if ran and sum(ran) == 0:
            return Outcome(OUTCOME_ERROR, returncode, "cargo test selected no tests")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 101:
            return Outcome(OUTCOME_FAILED, 101)
        return Outcome(OUTCOME_ERROR, returncode, f"cargo test exit status {returncode}: {tail(text, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        if which("cargo") is None:
            raise AdapterError("cargo is not installed")
        code, _, _, note = run_command(["cargo", "llvm-cov", "--version"], cwd=self.project_root,
                                       timeout=60, runner=self.runner)
        if note or code != 0:
            raise AdapterError("cargo-llvm-cov is not installed (cargo install cargo-llvm-cov)")
        report = Path(work_dir) / "lcov.info"
        argv = ["cargo", "llvm-cov", "test", "--quiet", "--lcov", "--output-path", str(report),
                test_name(test_id), "--", "--exact"]
        outcome = self._execute(argv, env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "cargo llvm-cov could not run")
        if not report.is_file():
            raise AdapterError("cargo llvm-cov wrote no report")
        return report
