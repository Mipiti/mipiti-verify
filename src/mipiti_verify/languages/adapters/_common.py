"""Pieces every runner adapter shares.

The invariants the adapters enforce live here so that no adapter can drift
from them: a mechanism reference has one grammar; a source file that is
mutated for a run is restored byte-for-byte, verified by hash, and is never
touched while the working tree already has changes to it; a command that
cannot run is an ``error`` outcome, never a ``failed`` one.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

OUTCOME_PASSED = "passed"
OUTCOME_FAILED = "failed"
OUTCOME_ERROR = "error"

DISABLED_MESSAGE = "mipiti: mechanism disabled"

# Reference kinds a mechanism may name explicitly, as ``file::kind:name``.
KINDS = (
    "function", "method", "class", "struct", "impl", "module", "task",
    "always", "initial", "property", "sequence", "assert", "entity",
    "architecture", "process", "procedure",
)


class DisableError(Exception):
    """The mechanism could not be disabled; the pair's outcome is ``error``
    and the message is its recorded reason."""


# A mutation rewrites exactly the definition the mechanism names, so the
# language layer must have isolated that definition: a span it reports as
# ``block`` (the line heuristic, which cannot tell two same-named
# definitions apart) may cover a different definition, and a mutation of
# the wrong block can still compile, which would attribute a test's outcome
# to the wrong mechanism. Such a span is refused with this reason.
REASON_NOT_ISOLATED = (
    "definition not isolated exactly (install mipiti-verify[ast] or nominate a unique symbol)"
)


def located_exactly(content: str, kinds: tuple, name: str, language: str) -> Optional[bool]:
    """Whether the language layer isolates ``name`` as exactly one
    definition of one of ``kinds`` (``scope == "symbol"``). ``False`` when
    it only finds a block; ``None`` when it finds nothing at all."""
    from ..definitions import SCOPE_SYMBOL, locate

    seen_block = False
    for kind in kinds:
        found = locate(content, kind, name, language=language)
        if found is None:
            continue
        if found.scope == SCOPE_SYMBOL:
            return True
        seen_block = True
    return False if seen_block else None


def require_exact(content: str, kinds: tuple, name: str, language: str, mutate,
                  exact: Optional[bool] = None) -> str:
    """``mutate()`` only when the definition is isolated exactly.

    ``exact`` may be supplied by a caller that established it another
    way; otherwise ``located_exactly`` decides. When the language layer
    finds nothing, ``mutate()`` still runs so the reason recorded is its
    own ("not defined in the file"); should it find something to rewrite
    anyway, that rewrite is refused too, since no exact span backs it.
    """
    if exact is None:
        exact = located_exactly(content, kinds, name, language)
    if exact is True:
        return mutate()
    mutate()
    raise DisableError(REASON_NOT_ISOLATED)


@dataclass
class Outcome:
    """What one run of one test produced."""

    status: str
    returncode: int = 0
    note: str = ""

    def as_record(self) -> dict:
        record = {"status": self.status, "returncode": self.returncode}
        if self.note:
            record["note"] = self.note
        return record


@dataclass
class DisableHandle:
    """What a ``disable()`` context hands the run: environment the runner
    must carry, and a place for the disabling side to leave a reason when
    it failed after the run started (the Python plugin writes a marker)."""

    env: dict = field(default_factory=dict)
    marker: Optional[Path] = None

    def failure_reason(self) -> str:
        if self.marker is None or not self.marker.is_file():
            return ""
        try:
            return self.marker.read_text(encoding="utf-8").strip() or "mechanism could not be disabled"
        except OSError:
            return "mechanism could not be disabled"


@dataclass(frozen=True)
class Mechanism:
    """``<file>::<symbol>``, ``<file>::<Class.method>`` or
    ``<file>::<kind>:<name>``."""

    file: str
    name: str
    kind: str = ""

    @property
    def spec(self) -> str:
        return f"{self.file}::{self.kind + ':' if self.kind else ''}{self.name}"

    @property
    def owner(self) -> str:
        return self.name.rpartition(".")[0]

    @property
    def leaf(self) -> str:
        return self.name.rpartition(".")[2]

    @property
    def language(self) -> str:
        return language_of(self.file)


def parse_mechanism(text: str) -> Mechanism:
    spec = str(text or "").strip()
    file, sep, rest = spec.partition("::")
    file = file.strip().replace("\\", "/")
    rest = rest.strip()
    if not sep or not file or not rest:
        raise DisableError(f"mechanism {spec!r} is not <file>::<symbol>")
    kind = ""
    if ":" in rest:
        head, _, tail = rest.partition(":")
        if head.strip().lower() in KINDS and tail.strip():
            kind, rest = head.strip().lower(), tail.strip()
    return Mechanism(file=file, name=rest, kind=kind)


_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".rb": "ruby",
    ".php": "php",
    ".v": "verilog", ".vh": "verilog", ".sv": "systemverilog", ".svh": "systemverilog",
    ".vhd": "vhdl", ".vhdl": "vhdl",
}


def language_of(file: str) -> str:
    return _LANGUAGE_BY_SUFFIX.get(Path(file).suffix.lower(), "")


# ---------------------------------------------------------------------------
# Running commands
# ---------------------------------------------------------------------------

Runner = Callable[..., subprocess.CompletedProcess]


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    env: Optional[dict] = None,
    timeout: int,
    runner: Optional[Runner] = None,
) -> tuple[int, str, str, str]:
    """``(returncode, output, "", note)``; a run that could not happen
    returns ``-1`` and a note saying why.

    The command's stdout and stderr are streamed, interleaved, into a
    temporary file rather than buffered in memory, and only the last
    ``OUTPUT_TAIL_BYTES`` are read back, so memory stays bounded whatever
    the harness prints. The combined text is returned in the ``stdout``
    slot; the ``stderr`` slot is empty. A ``runner`` that hands back text
    of its own (a recording stand-in) is read as before.
    """
    call = runner or subprocess.run
    merged = dict(os.environ)
    if env:
        merged.update({k: str(v) for k, v in env.items()})
    fd, sink = tempfile.mkstemp(prefix="mipiti-run-", suffix=".log")
    try:
        with os.fdopen(fd, "w+b") as fh:
            try:
                completed = call(
                    argv, cwd=str(cwd), env=merged, stdout=fh, stderr=subprocess.STDOUT,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return -1, "", "", f"timed out after {timeout}s"
            except OSError as e:
                return -1, "", "", f"could not start {argv[0]}: {e}"
            fh.flush()
            output = _tail_bytes(fh, OUTPUT_TAIL_BYTES)
    finally:
        try:
            os.unlink(sink)
        except OSError:
            pass
    if not output:
        # A stand-in runner returns its text on the completed process.
        own = str(getattr(completed, "stdout", "") or "") + str(getattr(completed, "stderr", "") or "")
        output = own[-OUTPUT_TAIL_BYTES:]
    return int(completed.returncode), output, "", ""


# How much of a command's output is kept for a reason string.
OUTPUT_TAIL_BYTES = 64 * 1024


def _tail_bytes(fh, limit: int) -> str:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    fh.seek(max(0, size - limit))
    return fh.read().decode("utf-8", errors="replace")


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def tail(text: str, lines: int = 8, width: int = 400) -> str:
    """The last few lines of a tool's output, for a reason string."""
    kept = [ln.rstrip() for ln in str(text or "").splitlines() if ln.strip()][-lines:]
    joined = " | ".join(kept)
    return joined[-width:]


# ---------------------------------------------------------------------------
# Mutating a source file for one run
# ---------------------------------------------------------------------------

def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_has_changes(project_root: Path, rel_file: str) -> Optional[bool]:
    """Whether the working tree already differs from HEAD for ``rel_file``.

    ``None`` when the answer cannot be established (no git, not a checkout);
    a mutation then refuses as well, because it could not prove the file
    would be restored to a known state. Always asks git itself: the
    injectable runner stands in for the test runner and the compilers, never
    for the question of what state the tree is in.
    """
    if which("git") is None:
        return None
    code, out, _err, note = run_command(
        ["git", "status", "--porcelain", "--", rel_file],
        cwd=project_root, timeout=30, runner=subprocess.run,
    )
    if note or code != 0:
        return None
    return bool(out.strip())


@contextmanager
def mutated_file(
    project_root: Path,
    rel_file: str,
    mutated: bytes,
    *,
    runner: Optional[Runner] = None,
) -> Iterator[Path]:
    """Write ``mutated`` over ``rel_file`` for the duration of the block and
    restore the original bytes afterwards, whatever happened inside.

    Refuses when the file is not under version control in a clean state, so
    a run can never leave a change behind that the tree did not already
    have. Restoration is verified by hash; a mismatch raises after the
    original bytes were written again, so it is reported rather than hidden.
    """
    path = project_root / rel_file
    if not path.is_file():
        raise DisableError(f"{rel_file} is not a file under the project root")
    dirty = git_has_changes(project_root, rel_file)
    if dirty is None:
        raise DisableError(
            f"{rel_file} is not in a git checkout, so a mutation could not be "
            f"proven restored; commit the file first")
    if dirty:
        raise DisableError(
            f"{rel_file} has uncommitted changes; a mutation is only applied "
            f"to a file the working tree could restore. Commit or stash them")
    original = path.read_bytes()
    digest = sha256_of(original)
    path.write_bytes(mutated)
    try:
        yield path
    finally:
        path.write_bytes(original)
        restored = path.read_bytes()
        if sha256_of(restored) != digest:
            raise DisableError(
                f"{rel_file} could not be restored to its original content")


def temp_dir(prefix: str = "mipiti-") -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix=prefix)
