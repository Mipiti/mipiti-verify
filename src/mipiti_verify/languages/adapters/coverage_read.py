"""Executed lines per file, from any report an adapter produces.

``attest-reach`` runs one test at a time, so every executed line in the
report belongs to that test and no per-test context is needed. The
package's coverage readers are preferred when present; this module is the
fallback that understands exactly the formats the adapters emit: coverage.py
JSON, LCOV, Cobertura XML and JaCoCo XML.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .coverage_convert import lines_from_lcov


def executed_lines(report: Path, project_root: Path) -> dict[str, set[int]]:
    """``{project-relative file: executed lines}`` for the report."""
    text = report.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    root = project_root.resolve()
    if stripped.startswith("{"):
        return _from_coverage_json(json.loads(text), root)
    if stripped.startswith("<"):
        return _from_xml(text, root)
    return _relativise(lines_from_lcov(text), root)


def _relativise(files: dict[str, set[int]], root: Path) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for raw, lines in files.items():
        path = Path(raw)
        if path.is_absolute():
            try:
                rel = path.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
        else:
            rel = path.as_posix()
        out.setdefault(rel, set()).update(lines)
    return out


def _from_coverage_json(data: object, root: Path) -> dict[str, set[int]]:
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    out: dict[str, set[int]] = {}
    for raw, entry in files.items():
        if not isinstance(entry, dict):
            continue
        lines = entry.get("executed_lines")
        found: set[int] = set()
        if isinstance(lines, list):
            found.update(int(n) for n in lines if isinstance(n, int))
        contexts = entry.get("contexts")
        if isinstance(contexts, dict):
            for key in contexts:
                try:
                    found.add(int(key))
                except (TypeError, ValueError):
                    continue
        out[raw] = found
    return _relativise(out, root)


def _from_xml(text: str, root: Path) -> dict[str, set[int]]:
    try:
        tree = ET.fromstring(text)
    except ET.ParseError:
        return {}
    tag = tree.tag.lower()
    if tag == "coverage" and tree.find("packages") is not None:
        return _from_cobertura(tree, root)
    if tag == "report":
        return _from_jacoco(tree, root)
    if tag == "coverage" and tree.find(".//file") is not None:
        from .coverage_convert import clover_to_lcov
        return _relativise(lines_from_lcov(clover_to_lcov(text, root)), root)
    return {}


def _from_cobertura(tree: ET.Element, root: Path) -> dict[str, set[int]]:
    sources = [s.text.strip() for s in tree.iter("source") if s.text and s.text.strip()]
    out: dict[str, set[int]] = {}
    for cls in tree.iter("class"):
        filename = cls.get("filename") or ""
        if not filename:
            continue
        path = Path(filename)
        if not path.is_absolute():
            for src in sources:
                candidate = Path(src) / filename
                if candidate.is_file():
                    path = candidate
                    break
        lines = set()
        for line_el in cls.iter("line"):
            try:
                if int(line_el.get("hits") or 0) > 0:
                    lines.add(int(line_el.get("number") or 0))
            except ValueError:
                continue
        out.setdefault(str(path), set()).update(lines)
    return _relativise(out, root)


def _from_jacoco(tree: ET.Element, root: Path) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for package in tree.iter("package"):
        pkg = package.get("name") or ""
        for sf in package.iter("sourcefile"):
            name = sf.get("name") or ""
            rel = f"{pkg}/{name}" if pkg else name
            lines = set()
            for line_el in sf.iter("line"):
                try:
                    if int(line_el.get("ci") or 0) > 0:
                        lines.add(int(line_el.get("nr") or 0))
                except ValueError:
                    continue
            # JaCoCo names files by package path; the source root
            # (src/main/java, src/main/kotlin, ...) is found in the tree.
            resolved = rel
            for src_root in ("src/main/java", "src/main/kotlin", "src/main/scala", "src", ""):
                candidate = (root / src_root / rel) if src_root else (root / rel)
                if candidate.is_file():
                    resolved = (Path(src_root) / rel).as_posix() if src_root else rel
                    break
            out.setdefault(resolved, set()).update(lines)
    return out
