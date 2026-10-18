"""CHANGELOG.md has a section only for versions that exist.

Every merged change is released, and a release writes its version's section
from the pull requests it ships, so the changelog never carries an
"Unreleased" section and never names a version twice.
"""

from __future__ import annotations

import re
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
_SECTION = re.compile(r"^## (.+)$", re.MULTILINE)
_RELEASE = re.compile(r"^\[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$")
_HISTORY = re.compile(r"^\[\d+\.\d+\.\d+ and earlier\]$")


def section_problems(text: str) -> list[str]:
    problems: list[str] = []
    seen: set[str] = set()
    for heading in _SECTION.findall(text):
        heading = heading.strip()
        if "unreleased" in heading.lower():
            problems.append(f"an Unreleased section: {heading!r}")
            continue
        release = _RELEASE.match(heading)
        if release is None and not _HISTORY.match(heading):
            problems.append(f"a section that names no released version: {heading!r}")
        elif release is not None:
            if release.group(1) in seen:
                problems.append(f"version {release.group(1)} has two sections")
            seen.add(release.group(1))
    return problems


def test_every_section_is_a_released_version():
    assert section_problems(CHANGELOG.read_text(encoding="utf-8")) == []


def test_the_guard_refuses_what_it_is_for():
    assert section_problems("## [Unreleased]\n") == ["an Unreleased section: '[Unreleased]'"]
    assert section_problems("## Unreleased\n")
    assert section_problems("## [0.57.0]\n")  # no date: not as a release writes it
    assert section_problems("## [0.57.0] - 2026-10-18\n## [0.57.0] - 2026-10-19\n") == [
        "version 0.57.0 has two sections"]
    assert section_problems("## [0.57.0] - 2026-10-18\n## [0.56.0 and earlier]\n") == []
