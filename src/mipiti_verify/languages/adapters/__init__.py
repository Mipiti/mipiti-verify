"""Runner adapters: one per test runner, each able to select one test, run
it, run it under coverage, and disable a mechanism for the run.

``attest-dependence`` and ``attest-reach`` are runner-agnostic; every
runner-specific fact lives behind ``RunnerAdapter``. The registry picks an
adapter from the project's files (``detect_adapter``), and ``--runner``
overrides it. The invariants every adapter keeps:

* ``run`` maps the runner's exit status to ``passed`` / ``failed`` /
  ``error``; a run that selected no test, could not start, timed out, or
  failed to build is ``error``, never ``failed``.
* ``disable`` either disables the mechanism for the whole run or raises
  ``DisableError`` with the reason; a source mutation is compile-checked
  first and restored byte-for-byte afterwards.
* ``run_with_coverage`` returns a report the coverage readers accept or
  raises ``AdapterError`` with the reason.
"""

from __future__ import annotations

import shlex
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from ._common import (
    DISABLED_MESSAGE, OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, DisableError,
    DisableHandle, Mechanism, Outcome, Runner, language_of, mutated_file,
    parse_mechanism, run_command, tail,
)

__all__ = [
    "AdapterError", "DisableError", "DisableHandle", "Mechanism", "Outcome",
    "RunnerAdapter", "adapter_names", "detect_adapter", "language_of",
    "parse_mechanism", "OUTCOME_PASSED", "OUTCOME_FAILED", "OUTCOME_ERROR",
    "DISABLED_MESSAGE",
]


class AdapterError(Exception):
    """The adapter could not do what was asked; the message is the reason
    recorded on the pair."""


class RunnerAdapter:
    """Base class. Subclasses set ``name`` and ``languages`` and implement
    ``detect``, ``select_argv``, ``run``, ``run_with_coverage`` and
    ``disable``."""

    name = ""
    languages: tuple[str, ...] = ()
    #: Languages whose mechanisms this adapter disables by source mutation.
    mutation_languages: tuple[str, ...] = ()

    #: Whether the adapter can build once with hooks on and run tests
    #: against that build (``--strategy hook``); the refusal names why not.
    supports_hooks = False
    hook_refusal = "hook builds are supported by the go, cargo and command runners"

    def __init__(self, project_root: Path, *, runner: Optional[Runner] = None,
                 run_cmd: str = "", coverage_cmd: str = "", coverage_file: str = "",
                 build_cmd: str = "") -> None:
        self.project_root = Path(project_root)
        self.runner = runner
        self.run_cmd = run_cmd
        self.coverage_cmd = coverage_cmd
        self.coverage_file = coverage_file
        self.build_cmd = build_cmd
        self.last_outcome: Optional[Outcome] = None
        #: The combined output of the last command ``_execute`` ran, for a
        #: caller that reads a marker out of it (the hook strategy).
        self.last_output = ""

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, project_root: Path) -> bool:
        raise NotImplementedError

    # -- running -----------------------------------------------------------

    def select_argv(self, test_id: str) -> list[str]:
        raise NotImplementedError

    def run(self, test_id: str, *, env: Optional[dict] = None, timeout: int) -> Outcome:
        argv = self.select_argv(test_id)
        return self._execute(argv, env=env, timeout=timeout)

    def run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        raise AdapterError(f"the {self.name} adapter has no coverage run")

    def _execute(self, argv: list[str], *, env: Optional[dict], timeout: int,
                 cwd: Optional[Path] = None) -> Outcome:
        code, out, err, note = run_command(
            argv, cwd=cwd or self.project_root, env=env, timeout=timeout, runner=self.runner)
        outcome = Outcome(OUTCOME_ERROR, code, note) if note else self.classify(code, out, err)
        # Kept for callers that need the outcome of a run whose return value
        # is something else (a coverage run returns its report).
        self.last_outcome = outcome
        self.last_output = (out or "") + (err or "")
        return outcome

    # -- hook-instrumented builds -----------------------------------------

    def hook_build(self, tests: list[str], *, timeout: int, work_dir: Path) -> None:
        """Build once with the tripwire hooks compiled in, for the tests
        named. Raises ``AdapterError`` when the adapter has no hook route
        or the build fails."""
        raise AdapterError(self.hook_refusal)

    def hook_run(self, test_id: str, mechanism: str, *, timeout: int) -> Outcome:
        """Run one test against the hook build with the mechanism named in
        the environment (empty ``mechanism`` runs it with nothing named).
        The output is left in ``last_output`` for the marker check."""
        raise AdapterError(self.hook_refusal)

    def hook_run_with_coverage(self, test_id: str, *, timeout: int, work_dir: Path) -> Path:
        """Run one test against the hook build under coverage, no
        mechanism named; the report the readers accept."""
        raise AdapterError(self.hook_refusal)

    def classify(self, returncode: int, stdout: str, stderr: str) -> Outcome:
        """Default mapping: 0 passed, 1 failed, anything else error."""
        if returncode == 0:
            return Outcome(OUTCOME_PASSED, 0)
        if returncode == 1:
            return Outcome(OUTCOME_FAILED, 1)
        return Outcome(OUTCOME_ERROR, returncode, f"exit status {returncode}: {tail(stderr or stdout, 4)}")

    # -- disabling ---------------------------------------------------------

    @contextmanager
    def disable(self, mechanism: str) -> Iterator[DisableHandle]:
        """Disable ``mechanism`` for the block. The default strategy is a
        source mutation for the languages the adapter names in
        ``mutation_languages``; anything else is an error."""
        mech = parse_mechanism(mechanism)
        with self.mutation_disable(mech) as handle:
            yield handle

    @contextmanager
    def mutation_disable(self, mech: Mechanism) -> Iterator[DisableHandle]:
        from .checks import compile_check
        from .hdl import mutate_verilog, mutate_vhdl
        from .mutation import MUTATION_LANGUAGES, mutate_source
        from ._common import temp_dir

        language = mech.language
        if language not in self.mutation_languages:
            raise DisableError(
                f"the {self.name} adapter cannot disable a "
                f"{language or Path(mech.file).suffix or 'mechanism of unknown language'} mechanism")
        path = self.project_root / mech.file
        if not path.is_file():
            raise DisableError(f"{mech.file} is not a file under the project root")
        original = path.read_bytes()
        try:
            content = original.decode("utf-8")
        except UnicodeDecodeError:
            raise DisableError(f"{mech.file} is not UTF-8 text") from None
        if language in ("verilog", "systemverilog"):
            mutated = mutate_verilog(content, mech)
        elif language == "vhdl":
            mutated = mutate_vhdl(content, mech)
        elif language in MUTATION_LANGUAGES:
            mutated = mutate_source(content, mech, language)
        else:
            raise DisableError(f"no source mutation is defined for {language}")
        # Keep the file's own newline convention so the compile check sees
        # what the author wrote, apart from the body.
        if b"\r\n" in original and "\r\n" not in mutated:
            mutated = mutated.replace("\n", "\r\n")
        with temp_dir("mipiti-check-") as scratch:
            with mutated_file(self.project_root, mech.file, mutated.encode("utf-8"), runner=self.runner):
                reason = compile_check(language, self.project_root, mech.file,
                                       runner=self.runner, work_dir=Path(scratch))
                if reason:
                    raise DisableError(f"mutated tree does not compile: {reason}")
                yield DisableHandle()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _all_adapters() -> list[type[RunnerAdapter]]:
    from .pytest_ import PytestAdapter
    from .node import JestAdapter, MochaAdapter, VitestAdapter
    from .go import GoAdapter
    from .rust import CargoAdapter
    from .jvm import GradleAdapter, MavenAdapter
    from .dotnet import DotnetAdapter
    from .rspec import RspecAdapter
    from .phpunit import PhpunitAdapter
    from .generic import GenericAdapter

    # Detection order: project files that name exactly one runner first.
    return [
        PytestAdapter, JestAdapter, VitestAdapter, MochaAdapter, GoAdapter,
        CargoAdapter, MavenAdapter, GradleAdapter, DotnetAdapter, RspecAdapter,
        PhpunitAdapter, GenericAdapter,
    ]


def adapter_names() -> list[str]:
    return [a.name for a in _all_adapters()]


def detect_adapter(project_root: Path, override: str = "", *, run_cmd: str = "",
                   coverage_cmd: str = "", coverage_file: str = "", build_cmd: str = "",
                   prefer_language: str = "", runner: Optional[Runner] = None) -> RunnerAdapter:
    """The adapter for the project.

    ``override`` names one explicitly. A ``run_cmd`` selects the generic
    command adapter. Otherwise the project's files decide; when several
    runners are present, ``prefer_language`` (the language of the
    mechanisms under test) breaks the tie, and a project with no marker at
    all is treated as pytest, the historical default.
    """
    root = Path(project_root)
    kwargs = dict(runner=runner, run_cmd=run_cmd, coverage_cmd=coverage_cmd, coverage_file=coverage_file,
                  build_cmd=build_cmd)
    adapters = _all_adapters()
    if override:
        for cls in adapters:
            if cls.name == override.strip().lower():
                return cls(root, **kwargs)
        raise AdapterError(
            f"unknown runner {override!r}; one of: {', '.join(a.name for a in adapters)}")
    if run_cmd:
        from .generic import GenericAdapter
        return GenericAdapter(root, **kwargs)
    detected = [cls for cls in adapters if cls.name != "command" and cls.detect(root)]
    if prefer_language:
        for cls in detected:
            if prefer_language in cls.languages:
                return cls(root, **kwargs)
    if detected:
        return detected[0](root, **kwargs)
    from .pytest_ import PytestAdapter
    return PytestAdapter(root, **kwargs)


def split_template(template: str, test_id: str) -> list[str]:
    """``shlex``-split a command template, substituting ``{test}`` inside
    tokens so an id with spaces stays one argument."""
    return [token.replace("{test}", test_id) for token in shlex.split(template)]
