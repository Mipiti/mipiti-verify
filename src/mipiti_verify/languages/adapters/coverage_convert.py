"""Converters from runner-native coverage formats to LCOV.

Every adapter hands ``attest-reach`` a report in a format the coverage
readers accept. Three runners produce something else natively and are
converted here: Go's ``-coverprofile``, SimpleCov's ``.resultset.json`` and
PHPUnit's Clover XML. Each converter emits per-file ``DA:`` records and
nothing else; the reach fact only needs executed lines.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable


def _lcov(files: dict[str, dict[int, int]]) -> str:
    out = []
    for path in sorted(files):
        out.append(f"SF:{path}")
        for line in sorted(files[path]):
            out.append(f"DA:{line},{files[path][line]}")
        out.append("end_of_record")
    return "\n".join(out) + ("\n" if out else "")


_COVERPROFILE_LINE = re.compile(
    r"^(?P<file>[^:]+):(?P<sl>\d+)\.(?P<sc>\d+),(?P<el>\d+)\.(?P<ec>\d+)\s+(?P<stmts>\d+)\s+(?P<count>\d+)\s*$")


def go_coverprofile_to_lcov(profile: str, module_path: str = "", *, module_dir: str = "") -> str:
    """Go ``-coverprofile`` text to LCOV.

    Each block ``file:start.col,end.col statements count`` marks every line
    from ``start`` to ``end`` with ``count``; a line covered by one executed
    block and one skipped block is executed. File names are import paths;
    ``module_path`` (from ``go.mod``) is stripped so the LCOV names the file
    relative to the module root, under ``module_dir`` when the module is
    not the project root.
    """
    files: dict[str, dict[int, int]] = {}
    prefix = module_path.rstrip("/") + "/" if module_path else ""
    for raw in profile.splitlines():
        line = raw.strip()
        if not line or line.startswith("mode:"):
            continue
        m = _COVERPROFILE_LINE.match(line)
        if m is None:
            continue
        name = m.group("file")
        if prefix and name.startswith(prefix):
            name = name[len(prefix):]
        if module_dir:
            name = module_dir.rstrip("/") + "/" + name
        count = int(m.group("count"))
        per = files.setdefault(name, {})
        for n in range(int(m.group("sl")), int(m.group("el")) + 1):
            per[n] = max(per.get(n, 0), count)
    return _lcov(files)


def go_module_path(go_mod: Path) -> str:
    try:
        text = go_mod.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = re.search(r"^\s*module\s+(\S+)", text, re.M)
    return m.group(1).strip('"') if m else ""


def simplecov_resultset_to_lcov(resultset: object, project_root: Path) -> str:
    """SimpleCov ``.resultset.json`` (either the ``{"lines": [...]}`` or the
    bare-array per-file shape) to LCOV with project-relative paths."""
    if isinstance(resultset, (str, bytes)):
        resultset = json.loads(resultset)
    files: dict[str, dict[int, int]] = {}
    if not isinstance(resultset, dict):
        return ""
    root = project_root.resolve()
    for _suite, data in resultset.items():
        coverage = (data or {}).get("coverage") if isinstance(data, dict) else None
        if not isinstance(coverage, dict):
            continue
        for raw_path, entry in coverage.items():
            lines = entry.get("lines") if isinstance(entry, dict) else entry
            if not isinstance(lines, list):
                continue
            rel = _relative(raw_path, root)
            if rel is None:
                continue
            per = files.setdefault(rel, {})
            for idx, count in enumerate(lines, start=1):
                if isinstance(count, int):
                    per[idx] = max(per.get(idx, 0), count)
    return _lcov(files)


def clover_to_lcov(xml_text: str, project_root: Path) -> str:
    """Clover XML (PHPUnit ``--coverage-clover``) to LCOV."""
    try:
        tree = ET.fromstring(xml_text)
    except ET.ParseError:
        return ""
    root = project_root.resolve()
    files: dict[str, dict[int, int]] = {}
    for file_el in tree.iter("file"):
        name = file_el.get("path") or file_el.get("name") or ""
        rel = _relative(name, root)
        if rel is None:
            continue
        per = files.setdefault(rel, {})
        for line_el in file_el.iter("line"):
            try:
                num = int(line_el.get("num") or 0)
                count = int(line_el.get("count") or 0)
            except ValueError:
                continue
            if num > 0:
                per[num] = max(per.get(num, 0), count)
    return _lcov(files)


def _relative(raw_path: str, root: Path) -> str | None:
    path = Path(str(raw_path))
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            return None
    return path.as_posix()


def lines_from_lcov(text: str) -> dict[str, set[int]]:
    """Executed lines per ``SF:`` file of an LCOV report."""
    files: dict[str, set[int]] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = line[3:].strip().replace("\\", "/")
            files.setdefault(current, set())
        elif line.startswith("DA:") and current:
            parts = line[3:].split(",")
            try:
                n, count = int(parts[0]), int(parts[1])
            except (IndexError, ValueError):
                continue
            if count > 0:
                files[current].add(n)
        elif line == "end_of_record":
            current = ""
    return files


def merge_lines(reports: Iterable[dict[str, set[int]]]) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for report in reports:
        for f, lines in report.items():
            out.setdefault(f, set()).update(lines)
    return out
