"""``go test -run``."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from . import AdapterError, RunnerAdapter
from ._common import OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, Outcome, tail
from .coverage_convert import go_coverprofile_to_lcov, go_module_path


def split_test_id(test_id: str) -> tuple[str, str]:
    """``(package pattern, -run regex)``. ``pkg/path::TestName`` selects
    one package; a bare ``TestName`` (or ``TestName/Sub``) runs across
    ``./...``."""
    text = str(test_id or "").strip()
    pkg = "./..."
    if "::" in text:
        head, _, text = text.partition("::")
        head = head.strip().replace("\\", "/")
        if head.endswith(".go"):
            head = head.rsplit("/", 1)[0] if "/" in head else "."
        pkg = head if head.startswith((".", "/")) else f"./{head}"
    parts = [f"^{re.escape(p)}$" for p in text.strip().split("/") if p]
    return pkg, "/".join(parts)


class GoAdapter(RunnerAdapter):
    name = "go"
    languages = ("go",)
    mutation_languages = ("go",)

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        return (root / "go.mod").is_file() or any(root.glob("*/go.mod"))

    def _module(self) -> tuple[Path, str, str]:
        """``(module dir, import path, module dir relative to root)``."""
        root = self.project_root
        candidates = [root / "go.mod"] if (root / "go.mod").is_file() else sorted(root.glob("*/go.mod"))
        if not candidates:
            return root, "", ""
        go_mod = candidates[0]
        rel = go_mod.parent.relative_to(root).as_posix() if go_mod.parent != root else ""
        return go_mod.parent, go_module_path(go_mod), "" if rel == "." else rel

    def select_argv(self, test_id: str) -> list[str]:
        pkg, pattern = split_test_id(test_id)
        return ["go", "test", "-count=1", "-run", pattern, pkg]

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        module_dir, _, _ = self._module()
        return self._execute(self.select_argv(test_id), env=env, timeout=timeout, cwd=module_dir)

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        text = stdout + stderr
        if "[build failed]" in text or "[setup failed]" in text or "cannot find package" in text:
            return Outcome(OUTCOME_ERROR, returncode, f"go test could not build: {tail(text, 4)}")
        if "no tests to run" in text or "no test files" in text and "ok" not in stdout:
            if not re.search(r"^(?:ok|FAIL)\s", stdout, re.M) or "no tests to run" in text:
                return Outcome(OUTCOME_ERROR, returncode, "go test selected no tests")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1:
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"go test exit status {returncode}: {tail(text, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        module_dir, module_path, module_rel = self._module()
        profile = Path(work_dir) / "cover.out"
        pkg, pattern = split_test_id(test_id)
        argv = ["go", "test", "-count=1", "-run", pattern, f"-coverprofile={profile}",
                "-coverpkg=./...", pkg]
        outcome = self._execute(argv, env=None, timeout=timeout, cwd=module_dir)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "go test could not run under coverage")
        if not profile.is_file():
            raise AdapterError("go test wrote no coverage profile")
        report = Path(work_dir) / "lcov.info"
        report.write_text(
            go_coverprofile_to_lcov(profile.read_text(encoding="utf-8"), module_path, module_dir=module_rel),
            encoding="utf-8")
        return report
