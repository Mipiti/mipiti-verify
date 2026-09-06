"""Read a coverage report, in any of the common formats, into one shape.

A ``CoverageReport`` separates what can be attributed to a single test
(``per_test``) from what only the run as a whole is known to have executed
(``suite``). Reach is a claim about one test, so the distinction is the
whole point: an aggregate report can say a mechanism was executed by *the
suite*, never that *this test* executed it.

Formats, detected from content, never from the extension:

- coverage.py JSON (``coverage json``): ``executed_lines`` per file; with
  ``--show-contexts`` each line's ``contexts`` attribute it to tests.
- LCOV (``.info`` / ``.lcov``; also what ``verilator_coverage --write-info``
  emits): ``SF:`` / ``DA:`` records, aggregate.
- Cobertura XML: ``<class filename>`` with ``<line number hits>``, aggregate.
- JaCoCo XML: ``<package name>`` / ``<sourcefile name>`` with ``<line nr ci>``,
  aggregate.

A directory is read as one report per test: each file ``<test id>.<ext>``
(``::`` in the id written as ``__``) is that test's own run, whatever its
format, and its executed lines become that test's ``per_test`` entry.
"""

from __future__ import annotations

import json
import posixpath
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Where JaCoCo's ``package/Source.java`` paths are usually rooted. Tried in
# order against the checkout; a path found nowhere is kept as given.
_JAVA_SOURCE_ROOTS = (
    "src/main/java", "src/main/kotlin", "src/test/java", "src/test/kotlin",
    "src/main/scala", "src", "app/src/main/java", "app/src/main/kotlin",
)


class CoverageReadError(ValueError):
    """The report could not be read or is not in a recognised format."""


@dataclass
class CoverageReport:
    #: test id -> file -> executed lines. Only from reports that attribute
    #: lines to tests (coverage.py contexts) or from per-test files.
    per_test: dict[str, dict[str, set[int]]] = field(default_factory=dict)
    #: file -> executed lines for the run as a whole.
    suite: dict[str, set[int]] = field(default_factory=dict)
    #: ``coverage.py`` / ``lcov`` / ``cobertura`` / ``jacoco`` / ``directory``.
    format: str = ""

    @property
    def attributed(self) -> bool:
        """Whether any line is attributed to a specific test."""
        return bool(self.per_test)

    def all_lines(self) -> dict[str, set[int]]:
        """Every executed line, per file, whatever it was attributed to."""
        merged: dict[str, set[int]] = {}
        for path, lines in self.suite.items():
            merged.setdefault(path, set()).update(lines)
        for per_file in self.per_test.values():
            for path, lines in per_file.items():
                merged.setdefault(path, set()).update(lines)
        return merged


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _relative(raw: str, project_root: Optional[Path], candidates: tuple[str, ...] = ()) -> str:
    """``raw`` as a repository-relative POSIX path when it can be placed
    under ``project_root`` (directly, or under one of ``candidates``);
    otherwise as given, normalised. A relative path that climbs out of the
    root (a ``..`` segment left after normalisation) names nothing in the
    repository and is dropped (``""``)."""
    text = str(raw or "").replace("\\", "/").strip()
    if not text:
        return ""
    if project_root is None:
        return _normalised(text)
    try:
        root = project_root.resolve()
    except OSError:
        return _normalised(text)
    path = Path(text)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            return text
    if (root / text).exists():
        return _normalised(text)
    for prefix in candidates:
        joined = Path(prefix.replace("\\", "/")) / text
        if (root / joined).exists():
            return _normalised(joined.as_posix())
        if Path(prefix).is_absolute():
            try:
                rel = (Path(prefix) / text).resolve().relative_to(root).as_posix()
            except (ValueError, OSError):
                continue
            if (root / rel).exists():
                return rel
    return _normalised(text)


def _normalised(text: str) -> str:
    """A relative POSIX path with ``.`` and ``..`` segments folded, or
    ``""`` when nothing is left or the path climbs above its root. An
    absolute path is returned as it is: it is not relative to anything."""
    if Path(text).is_absolute():
        norm = posixpath.normpath(text)
        return "" if norm == "/" else norm
    norm = posixpath.normpath(text)
    if norm in (".", "..") or norm.startswith("../"):
        return ""
    return norm


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------

def read_coverage(path: str | Path, project_root: Optional[Path] = None) -> CoverageReport:
    """Read the report (or per-test directory) at ``path``."""
    location = Path(path)
    if location.is_dir():
        return _read_directory(location, project_root)
    try:
        text = location.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise CoverageReadError(f"cannot read coverage report {location}: {e}") from e
    return read_coverage_text(text, project_root, source=str(location))


def read_coverage_text(text: str, project_root: Optional[Path] = None, *,
                       source: str = "coverage report") -> CoverageReport:
    """Read a report from its content, detecting the format."""
    body = text.lstrip("﻿ \t\r\n")
    if body.startswith("{"):
        try:
            data = json.loads(body)
        except ValueError as e:
            raise CoverageReadError(
                f"cannot read coverage report {source}: {e}. Expected the JSON that "
                f"'coverage json --show-contexts' writes."
            ) from e
        return read_coveragepy(data, project_root)
    if body.startswith("<"):
        try:
            root = ET.fromstring(body)
        except ET.ParseError as e:
            raise CoverageReadError(f"cannot read coverage report {source}: not well-formed XML: {e}") from e
        tag = root.tag.rsplit("}", 1)[-1]
        if tag == "coverage":
            return _read_cobertura(root, project_root)
        if tag == "report":
            return _read_jacoco(root, project_root)
        raise CoverageReadError(
            f"cannot read coverage report {source}: XML root <{tag}> is neither "
            f"Cobertura (<coverage>) nor JaCoCo (<report>)."
        )
    if _looks_like_lcov(body):
        return _read_lcov(body, project_root)
    raise CoverageReadError(
        f"cannot read coverage report {source}: not a recognised format. Accepted: "
        f"coverage.py JSON ('coverage json --show-contexts' for per-test reach), "
        f"LCOV, Cobertura XML, JaCoCo XML, or a directory of one report per test."
    )


def _looks_like_lcov(body: str) -> bool:
    for line in body.splitlines()[:50]:
        if line.startswith(("SF:", "TN:", "DA:", "end_of_record")):
            return True
    return False


def read_coveragepy(data: object, project_root: Optional[Path] = None) -> CoverageReport:
    """A parsed coverage.py JSON export."""
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise CoverageReadError(
            "Coverage report is not a coverage.py JSON export: expected a "
            "top-level 'files' object. Produce it with "
            "'coverage json --show-contexts'."
        )
    report = CoverageReport(format="coverage.py")
    for raw_path, entry in data["files"].items():
        if not isinstance(entry, dict):
            continue
        rel = _relative(str(raw_path), project_root)
        if not rel:
            continue
        executed = entry.get("executed_lines")
        if isinstance(executed, list):
            for value in executed:
                line = _int(value)
                if line:
                    report.suite.setdefault(rel, set()).add(line)
        contexts = entry.get("contexts")
        if not isinstance(contexts, dict):
            continue
        for line_str, names in contexts.items():
            line = _int(line_str)
            if not line or not isinstance(names, list):
                continue
            for ctx in names:
                key = str(ctx or "").rsplit("|", 1)[0].strip()
                if not key:
                    continue  # the empty (global) context attributes nothing
                report.per_test.setdefault(key, {}).setdefault(rel, set()).add(line)
    return report


def _read_lcov(body: str, project_root: Optional[Path]) -> CoverageReport:
    report = CoverageReport(format="lcov")
    current = ""
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = _relative(line[3:], project_root)
            if current:
                report.suite.setdefault(current, set())
        elif line.startswith("DA:") and current:
            parts = line[3:].split(",")
            if len(parts) >= 2 and _int(parts[1]) and _int(parts[0]):
                report.suite[current].add(_int(parts[0]))
        elif line == "end_of_record":
            current = ""
    return report


def _read_cobertura(root, project_root: Optional[Path]) -> CoverageReport:
    report = CoverageReport(format="cobertura")
    sources = tuple(
        (s.text or "").strip() for s in root.iter("source") if (s.text or "").strip()
    )
    for cls in root.iter("class"):
        filename = cls.get("filename") or ""
        rel = _relative(filename, project_root, sources)
        if not rel:
            continue
        lines = report.suite.setdefault(rel, set())
        for ln in cls.iter("line"):
            number = _int(ln.get("number"))
            hits = _int(ln.get("hits"))
            if number and hits:
                lines.add(number)
    return report


def _read_jacoco(root, project_root: Optional[Path]) -> CoverageReport:
    report = CoverageReport(format="jacoco")
    for package in root.iter("package"):
        prefix = (package.get("name") or "").strip().replace("\\", "/").strip("/")
        for source in package.iter("sourcefile"):
            name = (source.get("name") or "").strip()
            if not name:
                continue
            joined = f"{prefix}/{name}" if prefix else name
            rel = _relative(joined, project_root, _JAVA_SOURCE_ROOTS)
            if not rel:
                continue
            lines = report.suite.setdefault(rel, set())
            for ln in source.iter("line"):
                number = _int(ln.get("nr"))
                covered = _int(ln.get("ci"))
                if number and covered:
                    lines.add(number)
    return report


def _read_directory(directory: Path, project_root: Optional[Path]) -> CoverageReport:
    report = CoverageReport(format="directory")
    files = sorted(p for p in directory.rglob("*") if p.is_file())
    if not files:
        raise CoverageReadError(f"coverage directory {directory} holds no reports.")
    for file in files:
        stem = file.relative_to(directory).as_posix()
        if "." in file.name:
            stem = stem[: -(len(file.name) - file.name.rfind("."))]
        # The stem is kept as written (``::`` in a test id is spelled ``__``
        # in a file name); the reader matching tests to keys accepts both.
        key = stem
        try:
            one = read_coverage(file, project_root)
        except CoverageReadError as e:
            raise CoverageReadError(f"in coverage directory {directory}: {e}") from e
        lines = one.all_lines()
        report.per_test[key] = {path: set(ls) for path, ls in lines.items()}
    return report


def _int(value: object) -> int:
    """``value`` as a positive integer, or ``0``: a line number or a hit
    count below 1 records nothing."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0
