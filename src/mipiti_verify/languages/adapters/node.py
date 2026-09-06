"""jest, vitest and mocha.

A JavaScript or TypeScript mechanism is disabled by a setup file registered
for the run that mocks the module by its resolved path and replaces the
named export (``default``, a function, or ``Class.method`` on the
prototype) with a function that throws. jest takes the file through
``--setupFilesAfterEnv``; vitest through a temporary config that extends
the project's own with an extra ``setupFiles`` entry (the CLI has no flag
for it, and replacing the list would drop the project's setup); mocha
through ``--require``, which patches the CommonJS export object in place.
"""

from __future__ import annotations

import json
import re
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from . import AdapterError, RunnerAdapter
from ._common import (
    DISABLED_MESSAGE, OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, DisableError,
    DisableHandle, Mechanism, Outcome, parse_mechanism, tail, temp_dir, which,
)

ENV_SETUP = "MIPITI_NODE_SETUP_FILE"
ENV_CONFIG = "MIPITI_NODE_CONFIG_FILE"


def _package_json(root: Path) -> dict:
    try:
        return json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _has_dependency(root: Path, name: str) -> bool:
    pkg = _package_json(root)
    for key in ("devDependencies", "dependencies", "optionalDependencies"):
        if isinstance(pkg.get(key), dict) and name in pkg[key]:
            return True
    return (root / "node_modules" / name).is_dir()


def _has_config(root: Path, stems: tuple[str, ...]) -> bool:
    for stem in stems:
        if list(root.glob(stem + ".*")):
            return True
    return False


def _bin(root: Path, name: str) -> list[str]:
    local = root / "node_modules" / ".bin" / name
    if local.is_file():
        return [str(local)]
    return ["npx", "--no-install", name]


def split_test_id(test_id: str) -> tuple[str, str]:
    """``(file, name)``: ``path::name`` splits; a bare path is a file; a
    bare name has no file."""
    text = str(test_id or "").strip()
    if "::" in text:
        file, _, name = text.partition("::")
        return file.strip().replace("\\", "/"), name.strip()
    if re.search(r"\.(?:[cm]?[jt]sx?)$", text) or "/" in text:
        return text.replace("\\", "/"), ""
    return "", text


def _summary_without_a_run(text: str) -> bool:
    """The runner's ``Tests`` summary names no passed or failed count: a
    name filter that matched nothing leaves every test skipped and, for
    jest and vitest, an exit status of 0."""
    m = re.search(r"^\s*Tests:?\s+([^\n]*)", text, re.M)
    if m is None:
        return False
    return re.search(r"\d+ (?:passed|failed)", m.group(1)) is None


def _escape_regex(name: str) -> str:
    return re.escape(name).replace("\\ ", " ")


def _stub_js(mech: Mechanism) -> str:
    """The body that rewrites a module's export object in place."""
    owner, leaf = mech.owner, mech.leaf
    lines = [
        f'const disabled = function () {{ throw new Error("{DISABLED_MESSAGE}"); }};',
    ]
    if owner:
        target = "out.default" if owner == "default" else f"out[{json.dumps(owner)}]"
        lines.append(
            f"if ({target} && {target}.prototype) {{ {target}.prototype[{json.dumps(leaf)}] = disabled; }}"
            f" else if ({target}) {{ {target}[{json.dumps(leaf)}] = disabled; }}"
            f" else {{ throw new Error(\"mipiti: {owner} is not exported by the mechanism module\"); }}")
    else:
        key = "default" if leaf == "default" else leaf
        lines.append(
            f"if (!({json.dumps(key)} in out)) {{ throw new Error(\"mipiti: {key} is not exported by the mechanism module\"); }}")
        lines.append(f"out[{json.dumps(key)}] = disabled;")
    return "\n".join(lines)


class _NodeAdapter(RunnerAdapter):
    languages = ("javascript", "typescript")
    mutation_languages = ()

    def _resolved_mechanism_path(self, mech: Mechanism) -> str:
        path = (self.project_root / mech.file).resolve()
        if not path.is_file():
            raise DisableError(f"{mech.file} is not a file under the project root")
        return path.as_posix()

    @contextmanager
    def disable(self, mechanism: str) -> Iterator[DisableHandle]:
        mech = parse_mechanism(mechanism)
        if mech.language not in self.languages:
            raise DisableError(
                f"the {self.name} adapter disables JavaScript and TypeScript mechanisms only, not {mech.file}")
        target = self._resolved_mechanism_path(mech)
        with temp_dir("mipiti-node-") as tmp:
            setup = Path(tmp) / self._setup_name()
            setup.write_text(self._setup_source(target, mech), encoding="utf-8")
            with self._registered(setup) as env:
                yield DisableHandle(env=env)

    def _setup_name(self) -> str:
        return "mipiti-disable.cjs"

    def _setup_source(self, target: str, mech: Mechanism) -> str:
        raise NotImplementedError

    @contextmanager
    def _registered(self, setup: Path) -> Iterator[dict]:
        yield {ENV_SETUP: str(setup)}

    def _no_tests(self, stdout: str, stderr: str) -> bool:
        raise NotImplementedError

    def _ran(self, stdout: str, stderr: str) -> bool:
        """Whether the runner got as far as reporting on tests; an exit
        status of 1 without a summary is the run not happening (a config or
        setup error), not a failing test."""
        return "Tests:" in stdout + stderr or "Test Files" in stdout + stderr

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        if self._no_tests(stdout, stderr):
            return Outcome(OUTCOME_ERROR, returncode, f"{self.name} selected no tests")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1 and self._ran(stdout, stderr):
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"{self.name} exit status {returncode}: {tail(stderr or stdout, 4)}")


class JestAdapter(_NodeAdapter):
    name = "jest"

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        if not (root / "package.json").is_file():
            return False
        return _has_dependency(root, "jest") or "jest" in _package_json(root) or _has_config(root, ("jest.config",))

    def select_argv(self, test_id: str, env: Optional[dict] = None) -> list[str]:
        file, name = split_test_id(test_id)
        argv = _bin(self.project_root, "jest") + ["--ci", "--silent"]
        if env and env.get(ENV_SETUP):
            argv += ["--setupFilesAfterEnv", env[ENV_SETUP]]
        if file:
            argv += ["--runTestsByPath", file]
        if name:
            argv += ["-t", f"^{_escape_regex(name)}$"]
        return argv

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        return self._execute(self.select_argv(test_id, env), env=env, timeout=timeout)

    def _no_tests(self, stdout: str, stderr: str) -> bool:
        text = stdout + stderr
        return "No tests found" in text or "Tests:       0 total" in text or _summary_without_a_run(text)

    def _setup_source(self, target: str, mech: Mechanism) -> str:
        return (
            f"const target = {json.dumps(target)};\n"
            f"jest.mock(target, () => {{\n"
            f"  const actual = jest.requireActual(target);\n"
            f"  const out = Object.assign({{}}, actual);\n"
            f"  if (actual && actual.__esModule) {{ Object.defineProperty(out, '__esModule', {{ value: true }}); }}\n"
            f"{_stub_js(mech)}\n"
            f"  return out;\n"
            f"}});\n"
        )

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        argv = self.select_argv(test_id) + [
            "--coverage", "--coverageReporters=lcov", f"--coverageDirectory={work_dir}"]
        outcome = self._execute(argv, env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "jest could not run under coverage")
        report = Path(work_dir) / "lcov.info"
        if not report.is_file():
            raise AdapterError("jest wrote no lcov.info; is coverage collection configured?")
        return report


class VitestAdapter(_NodeAdapter):
    name = "vitest"

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        if not (root / "package.json").is_file():
            return False
        return _has_dependency(root, "vitest") or _has_config(root, ("vitest.config", "vitest.workspace"))

    def select_argv(self, test_id: str, env: Optional[dict] = None) -> list[str]:
        file, name = split_test_id(test_id)
        argv = _bin(self.project_root, "vitest") + ["run"]
        if env and env.get(ENV_CONFIG):
            argv += ["--config", env[ENV_CONFIG]]
        if file:
            argv.append(file)
        if name:
            argv += ["-t", f"^{_escape_regex(name)}$"]
        return argv

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        return self._execute(self.select_argv(test_id, env), env=env, timeout=timeout)

    def _no_tests(self, stdout: str, stderr: str) -> bool:
        text = stdout + stderr
        return ("No test files found" in text or "No test suite found" in text
                or "No test found in suite" in text or _summary_without_a_run(text))

    def _setup_name(self) -> str:
        return "mipiti-disable.mjs"

    def _setup_source(self, target: str, mech: Mechanism) -> str:
        return (
            # vi.mock is hoisted above every import, so its path must be a
            # literal: a variable would be read before it is initialised.
            f"import {{ vi }} from 'vitest';\n"
            f"vi.mock({json.dumps(target)}, async (importOriginal) => {{\n"
            f"  const actual = await importOriginal();\n"
            f"  const out = Object.assign({{}}, actual);\n"
            f"{_stub_js(mech)}\n"
            f"  return out;\n"
            f"}});\n"
        )

    def _project_config(self) -> Optional[Path]:
        for stem in ("vitest.config", "vite.config"):
            for candidate in sorted(self.project_root.glob(stem + ".*")):
                if candidate.suffix in (".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"):
                    return candidate
        return None

    @contextmanager
    def _registered(self, setup: Path) -> Iterator[dict]:
        # The temporary config lives in the project root so that
        # 'vitest/config' and the project's own config resolve from it; it
        # is removed when the run ends.
        base = self._project_config()
        config = self.project_root / f".mipiti-vitest-{uuid.uuid4().hex[:8]}.config.mjs"
        if base is not None:
            source = (
                "import { defineConfig, mergeConfig } from 'vitest/config';\n"
                f"import base from './{base.name}';\n"
                "const resolved = typeof base === 'function' ? await base({ mode: 'test', command: 'serve' }) : base;\n"
                "export default mergeConfig(resolved, defineConfig({ test: { setupFiles: ["
                f"{json.dumps(setup.as_posix())}] }} }}));\n"
            )
        else:
            source = (
                "import { defineConfig } from 'vitest/config';\n"
                f"export default defineConfig({{ test: {{ setupFiles: [{json.dumps(setup.as_posix())}] }} }});\n"
            )
        config.write_text(source, encoding="utf-8")
        try:
            yield {ENV_SETUP: str(setup), ENV_CONFIG: str(config)}
        finally:
            try:
                config.unlink()
            except OSError:
                pass

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        argv = self.select_argv(test_id) + [
            "--coverage.enabled", "--coverage.reporter=lcov",
            f"--coverage.reportsDirectory={work_dir}", "--coverage.all=false"]
        outcome = self._execute(argv, env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "vitest could not run under coverage")
        report = Path(work_dir) / "lcov.info"
        if not report.is_file():
            raise AdapterError(
                "vitest wrote no lcov.info; install @vitest/coverage-v8 (or -istanbul)")
        return report


class MochaAdapter(_NodeAdapter):
    name = "mocha"

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        root = Path(project_root)
        if not (root / "package.json").is_file():
            return False
        return _has_dependency(root, "mocha") or _has_config(root, (".mocharc",))

    def select_argv(self, test_id: str, env: Optional[dict] = None) -> list[str]:
        file, name = split_test_id(test_id)
        argv = _bin(self.project_root, "mocha")
        if env and env.get(ENV_SETUP):
            argv += ["--require", env[ENV_SETUP]]
        if file:
            argv.append(file)
        if name:
            argv += ["-g", f"^{_escape_regex(name)}$"]
        return argv

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        return self._execute(self.select_argv(test_id, env), env=env, timeout=timeout)

    def _no_tests(self, stdout: str, stderr: str) -> bool:
        # mocha exits 0 for a grep that matches nothing; the counts say so.
        m = re.search(r"(\d+) passing", stdout)
        f = re.search(r"(\d+) failing", stdout)
        return (m is None or int(m.group(1)) == 0) and f is None

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        if self._no_tests(stdout, stderr):
            return Outcome(OUTCOME_ERROR, returncode, "mocha selected no tests")
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        # mocha's exit status is the number of failures.
        if re.search(r"\d+ failing", stdout):
            return Outcome(OUTCOME_FAILED, returncode)
        return Outcome(OUTCOME_ERROR, returncode, f"mocha exit status {returncode}: {tail(stderr or stdout, 4)}")

    def _setup_source(self, target: str, mech: Mechanism) -> str:
        return (
            f"const target = {json.dumps(target)};\n"
            f"const out = require(target);\n"
            f"{_stub_js(mech)}\n"
        )

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        if (self.project_root / "node_modules" / ".bin" / "c8").is_file() or which("c8"):
            prefix = _bin(self.project_root, "c8") + ["--reporter=lcov", f"--reports-dir={work_dir}"]
        elif (self.project_root / "node_modules" / ".bin" / "nyc").is_file() or which("nyc"):
            prefix = _bin(self.project_root, "nyc") + ["--reporter=lcov", f"--report-dir={work_dir}"]
        else:
            raise AdapterError("mocha coverage needs c8 or nyc installed")
        outcome = self._execute(prefix + self.select_argv(test_id), env=None, timeout=timeout)
        if outcome.status == OUTCOME_ERROR:
            raise AdapterError(outcome.note or "mocha could not run under coverage")
        report = Path(work_dir) / "lcov.info"
        if not report.is_file():
            raise AdapterError("no lcov.info was written by the coverage run")
        return report
