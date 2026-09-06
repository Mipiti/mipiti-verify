"""pytest (and cocotb suites driven by pytest)."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from . import AdapterError, RunnerAdapter
from ._common import (
    OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, DisableHandle, Outcome,
    parse_mechanism, run_command, tail, temp_dir,
)

ENV_MECHANISM = "MIPITI_DISABLE_MECHANISM"
ENV_MARKER = "MIPITI_DISABLE_MARKER"
ENV_PLUGINS = "PYTEST_PLUGINS"
PLUGIN = "mipiti_verify._disable_plugin"

_MARKERS = ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "conftest.py")


def test_selector(test: str) -> list[str]:
    """pytest arguments that select one test.

    A ``path::name`` node id is used as given. A bare name -- or a
    ``classname::name`` id from a JUnit report, whose dotted prefix pytest
    cannot select by -- becomes a ``-k`` expression on the function name.
    """
    from ...attestation import base_test_name

    text = str(test or "").strip()
    if "::" in text:
        head = text.split("::", 1)[0]
        if head.endswith(".py") or "/" in head:
            return [text]
        text = text.rsplit("::", 1)[-1]
    return ["-k", base_test_name(text)]


class PytestAdapter(RunnerAdapter):
    name = "pytest"
    languages = ("python",)
    mutation_languages = ("verilog", "systemverilog", "vhdl")

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        if any((root / m).is_file() for m in _MARKERS):
            if (root / "pyproject.toml").is_file() and not any(
                    (root / m).is_file() for m in _MARKERS[1:]):
                # pyproject.toml alone is any Python project; a test tree
                # or pytest configuration says it is a pytest one.
                try:
                    text = (root / "pyproject.toml").read_text(encoding="utf-8")
                except OSError:
                    text = ""
                return "pytest" in text or (root / "tests").is_dir() or bool(list(root.glob("test_*.py")))
            return True
        return (root / "tests").is_dir() and any(root.glob("tests/**/test_*.py"))

    def select_argv(self, test_id: str) -> list[str]:
        return [sys.executable, "-m", "pytest", "-q", *test_selector(test_id)]

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        env = dict(env or {})
        argv = [sys.executable, "-m", "pytest", "-q"]
        if env.get(ENV_MECHANISM):
            # The plugin goes on the command line here; the environment
            # route exists for a suite command this adapter does not build.
            argv += ["-p", PLUGIN]
            env.pop(ENV_PLUGINS, None)
        argv += test_selector(test_id)
        outcome = self._execute(argv, env=env, timeout=timeout)
        marker = env.get(ENV_MARKER)
        if marker and Path(marker).is_file():
            try:
                note = Path(marker).read_text(encoding="utf-8").strip()
            except OSError:
                note = ""
            return Outcome(OUTCOME_ERROR, outcome.returncode, note or "mechanism could not be disabled")
        return outcome

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        # pytest exits 0 when every selected test passed, 1 when one failed,
        # and other codes when the run could not happen (interrupted, usage
        # error, nothing collected).
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1:
            return Outcome(OUTCOME_FAILED, 1)
        if returncode == 5:
            return Outcome(OUTCOME_ERROR, 5, "pytest selected no tests")
        return Outcome(OUTCOME_ERROR, returncode, f"pytest exit status {returncode}: {tail(stderr or stdout, 4)}")

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        probe, _, _, note = run_command(
            [sys.executable, "-c", "import coverage"], cwd=self.project_root, timeout=60, runner=self.runner)
        if note or probe != 0:
            raise AdapterError("the coverage package is not installed in this interpreter")
        data_file = Path(work_dir) / ".coverage"
        env = {"COVERAGE_FILE": str(data_file)}
        argv = [sys.executable, "-m", "coverage", "run", f"--context={test_id}",
                "-m", "pytest", "-q", *test_selector(test_id)]
        outcome = self._execute(argv, env=env, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "the coverage run could not happen")
        report = Path(work_dir) / "coverage.json"
        code, out, err, note = run_command(
            [sys.executable, "-m", "coverage", "json", "--show-contexts", "-o", str(report)],
            cwd=self.project_root, env=env, timeout=timeout, runner=self.runner)
        if note or code != 0 or not report.is_file():
            raise AdapterError(f"coverage json failed: {note or tail(err or out, 4)}")
        return report

    @contextmanager
    def disable(self, mechanism: str) -> Iterator[DisableHandle]:
        mech = parse_mechanism(mechanism)
        if mech.language != "python":
            with self.mutation_disable(mech) as handle:
                yield handle
            return
        with temp_dir("mipiti-dep-") as tmp:
            marker = Path(tmp) / "marker"
            # PYTEST_PLUGINS loads the plugin into any pytest the run starts,
            # which is how a whole-suite command (``--suite-cmd``) gets it
            # without the command naming it.
            plugins = os.environ.get(ENV_PLUGINS, "")
            plugins = f"{plugins},{PLUGIN}" if plugins and PLUGIN not in plugins.split(",") else (plugins or PLUGIN)
            yield DisableHandle(
                env={ENV_MECHANISM: mech.spec if not mech.kind else f"{mech.file}::{mech.name}",
                     ENV_MARKER: str(marker), ENV_PLUGINS: plugins},
                marker=marker,
            )
