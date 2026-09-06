"""Property-based checks over the coverage readers and the JUnit reader.

A report is whatever a tool wrote, so the readers must answer or refuse on
any bytes: ``read_coverage`` returns a report or raises
``CoverageReadError`` and nothing else, and what it returns holds only
positive line numbers under repository-relative paths (no ``..`` or
``.`` segment; an absolute path outside the checkout is the documented
exception, kept as given); ``parse_junit`` returns a summary or raises
``AttestationError``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mipiti_verify.attestation import AttestationError, parse_junit
from mipiti_verify.coverage_readers import CoverageReadError, CoverageReport, read_coverage

FAST = settings(max_examples=200, deadline=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])

paths = st.one_of(
    st.text(max_size=40),
    st.sampled_from(("app/guard.py", "../x.py", "/abs/x.py", "a/../b.py", "..", ".", "",
                     "C:\\x\\y.py", "rtl\\alu.sv", "src/main/java/A.java", "a//b", "./a.py")),
)
numbers = st.one_of(st.integers(-5, 400), st.text(max_size=6), st.none(), st.floats(allow_nan=True))
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=10),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=6), children, max_size=4),
    max_leaves=12,
)


@st.composite
def coveragepy_like(draw):
    files = {}
    for _ in range(draw(st.integers(0, 3))):
        entry = {
            "executed_lines": draw(st.lists(numbers, max_size=6)),
            "contexts": draw(st.dictionaries(st.text(max_size=4),
                                             st.one_of(st.lists(st.text(max_size=8), max_size=3), json_values),
                                             max_size=3)),
        }
        if draw(st.booleans()):
            entry = draw(json_values)
        files[draw(paths)] = entry
    payload = {"files": files} if draw(st.booleans()) else draw(json_values)
    return json.dumps(payload, default=str).encode("utf-8")


@st.composite
def lcov_like(draw):
    lines = []
    for _ in range(draw(st.integers(0, 6))):
        kind = draw(st.sampled_from(("SF", "DA", "TN", "end_of_record", "junk")))
        if kind == "SF":
            lines.append("SF:" + draw(paths))
        elif kind == "DA":
            lines.append("DA:" + ",".join(str(draw(numbers)) for _ in range(draw(st.integers(0, 3)))))
        elif kind == "TN":
            lines.append("TN:" + draw(st.text(max_size=6)))
        elif kind == "end_of_record":
            lines.append("end_of_record")
        else:
            lines.append(draw(st.text(max_size=20)))
    return "\n".join(lines).encode("utf-8", errors="replace")


def _attr(value: object) -> str:
    return str(value).replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


@st.composite
def cobertura_like(draw):
    out = ["<coverage>"]
    for _ in range(draw(st.integers(0, 2))):
        out.append(f"<sources><source>{_attr(draw(paths))}</source></sources>")
    for _ in range(draw(st.integers(0, 3))):
        out.append(f'<packages><package><classes><class filename="{_attr(draw(paths))}"><lines>')
        for _ in range(draw(st.integers(0, 4))):
            out.append(f'<line number="{_attr(draw(numbers))}" hits="{_attr(draw(numbers))}"/>')
        out.append("</lines></class></classes></package></packages>")
    out.append("</coverage>")
    body = "\n".join(out)
    if draw(st.booleans()):
        body = body[: draw(st.integers(0, len(body)))]  # truncated: not well-formed
    return body.encode("utf-8", errors="replace")


@st.composite
def jacoco_like(draw):
    out = ["<report>"]
    for _ in range(draw(st.integers(0, 3))):
        out.append(f'<package name="{_attr(draw(paths))}"><sourcefile name="{_attr(draw(paths))}">')
        for _ in range(draw(st.integers(0, 4))):
            out.append(f'<line nr="{_attr(draw(numbers))}" ci="{_attr(draw(numbers))}"/>')
        out.append("</sourcefile></package>")
    out.append("</report>")
    return "\n".join(out).encode("utf-8", errors="replace")


@st.composite
def xmlish(draw):
    tag = draw(st.sampled_from(("coverage", "report", "testsuites", "x", "")))
    body = draw(st.text(max_size=200))
    return f"<{tag}>{body}</{tag}>".encode("utf-8", errors="replace")


report_bytes = st.one_of(
    st.binary(max_size=300), coveragepy_like(), lcov_like(), cobertura_like(), jacoco_like(), xmlish(),
    st.sampled_from((b"\xef\xbb\xbf{", b"{", b"<", b"SF:\n", b"", b"\0\0", b"{\"files\": 1}")),
)


def _check_report(report: CoverageReport, root: Path) -> None:
    per_file = dict(report.suite)
    for per in report.per_test.values():
        per_file.update(per)
    for path, lines in per_file.items():
        assert isinstance(path, str) and path
        assert "\\" not in path
        assert ".." not in path.split("/"), path
        assert "." not in path.split("/"), path
        for n in lines:
            assert isinstance(n, int) and n >= 1


@FAST
@given(data=report_bytes)
def test_read_coverage_never_raises_anything_but_its_own_error(tmp_path_factory, data):
    root = tmp_path_factory.mktemp("cov")
    (root / "app").mkdir()
    (root / "app" / "guard.py").write_text("x = 1\n")
    path = root / "report"
    path.write_bytes(data)
    try:
        report = read_coverage(path, root)
    except CoverageReadError:
        return
    _check_report(report, root)


@FAST
@given(data=report_bytes, name=st.sampled_from(("test_a.info", "tests.test_x__test_a.json", "t.xml", "noext")))
def test_read_coverage_directory_never_raises_anything_but_its_own_error(tmp_path_factory, data, name):
    root = tmp_path_factory.mktemp("cov")
    (root / "reports").mkdir()
    (root / "reports" / name).write_bytes(data)
    try:
        report = read_coverage(root / "reports", root)
    except CoverageReadError:
        return
    assert report.format == "directory"
    _check_report(report, root)


@FAST
@given(text=st.one_of(xmlish().map(bytes.decode), st.text(max_size=300)))
def test_parse_junit_returns_a_summary_or_its_own_error(tmp_path_factory, text):
    path = tmp_path_factory.mktemp("junit") / "report.xml"
    path.write_text(text, encoding="utf-8", errors="replace")
    try:
        summary = parse_junit(path)
    except AttestationError:
        return
    totals = summary["totals"]
    assert totals["total"] == len(summary["tests"])
    assert totals["total"] == totals["passed"] + totals["failed"] + totals["skipped"] + totals["errors"]
    assert all(t["status"] in ("passed", "failed", "skipped", "error") for t in summary["tests"])
