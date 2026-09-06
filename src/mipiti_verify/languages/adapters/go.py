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


HOOK_TAG = "mipiti_hooks"
ENV_MECHANISM = "MIPITI_DISABLE_MECHANISM"


class GoAdapter(RunnerAdapter):
    name = "go"
    languages = ("go",)
    mutation_languages = ("go",)
    supports_hooks = True

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

    # -- hook-instrumented build: one test binary per package ------------

    def _package_dir(self, test_id: str) -> Path:
        """The package directory a test lives in. A ``pkg::Test`` id names
        it; a bare name is found by the ``_test.go`` file that defines it."""
        module_dir, _, _ = self._module()
        pkg, _pattern = split_test_id(test_id)
        if pkg != "./...":
            return (module_dir / pkg).resolve()
        leaf = test_id.strip().split("/", 1)[0]
        pattern = re.compile(rf"^func\s+{re.escape(leaf)}\s*\(", re.M)
        for path in sorted(module_dir.rglob("*_test.go")):
            try:
                if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                    return path.parent
            except OSError:
                continue
        raise AdapterError(f"no _test.go file under the module defines {leaf}")

    def hook_build(self, tests: list[str], *, timeout: int, work_dir: Path) -> None:
        self._hook_bins: dict[Path, Path] = {}
        module_dir, _, _ = self._module()
        for test in tests:
            pkg_dir = self._package_dir(test)
            if pkg_dir in self._hook_bins:
                continue
            binary = Path(work_dir) / f"hooks-{len(self._hook_bins)}.test"
            argv = ["go", "test", "-c", "-tags", HOOK_TAG, "-cover", "-coverpkg=./...",
                    "-o", str(binary), "./" + pkg_dir.relative_to(module_dir).as_posix()
                    if pkg_dir != module_dir else "."]
            outcome = self._execute(argv, env=None, timeout=timeout, cwd=module_dir)
            if outcome.status != OUTCOME_PASSED or not binary.is_file():
                raise AdapterError(f"go test -c -tags {HOOK_TAG} failed: {outcome.note or tail(self.last_output, 6)}")
            self._hook_bins[pkg_dir] = binary

    def _hook_argv(self, test_id: str) -> tuple[list[str], Path]:
        bins = getattr(self, "_hook_bins", None) or {}
        pkg_dir = self._package_dir(test_id)
        binary = bins.get(pkg_dir)
        if binary is None:
            raise AdapterError(f"no hook build for the package of {test_id}; hook_build runs first")
        _pkg, pattern = split_test_id(test_id)
        return [str(binary), "-test.run", pattern, "-test.count=1"], pkg_dir

    def hook_run(self, test_id: str, mechanism: str, *, timeout: int) -> Outcome:
        argv, pkg_dir = self._hook_argv(test_id)
        env = {ENV_MECHANISM: mechanism} if mechanism else {ENV_MECHANISM: ""}
        return self._execute(argv, env=env, timeout=timeout, cwd=pkg_dir)

    def hook_run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        _module_dir, module_path, module_rel = self._module()
        argv, pkg_dir = self._hook_argv(test_id)
        profile = Path(work_dir) / "cover.out"
        outcome = self._execute(argv + [f"-test.coverprofile={profile}"], env={ENV_MECHANISM: ""},
                                timeout=timeout, cwd=pkg_dir)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "the hook build could not run under coverage")
        if not profile.is_file():
            raise AdapterError("the hook build wrote no coverage profile")
        report = Path(work_dir) / "lcov.info"
        report.write_text(
            go_coverprofile_to_lcov(profile.read_text(encoding="utf-8"), module_path, module_dir=module_rel),
            encoding="utf-8")
        return report

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
