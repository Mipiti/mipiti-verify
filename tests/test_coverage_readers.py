"""Coverage readers: every format into one shape, and the per-test rule.

Reach is a claim about one test. A report that attributes lines to tests
yields ``reached`` per test; an aggregate report yields ``suite_reached``
and leaves reach unknown, whatever format it came in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mipiti_verify.attestation import AttestationError, merge_coverage
from mipiti_verify.coverage_readers import (
    CoverageReadError,
    CoverageReport,
    read_coverage,
    read_coverage_text,
    read_coveragepy,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "guard.py").write_text("def require_token(r):\n    return r\n")
    (tmp_path / "src" / "main" / "java" / "com" / "acme").mkdir(parents=True)
    (tmp_path / "src" / "main" / "java" / "com" / "acme" / "Guard.java").write_text("class Guard {}\n")
    (tmp_path / "rtl").mkdir()
    (tmp_path / "rtl" / "alu.sv").write_text("module alu; endmodule\n")
    return tmp_path


def _coveragepy(root: Path, *, contexts: bool) -> dict:
    entry = {"executed_lines": [1, 2]}
    if contexts:
        entry["contexts"] = {
            "1": ["tests/test_guard.py::test_a|run", "tests/test_guard.py::TestX::test_b[p0]|run"],
            "2": ["tests/test_guard.py::test_a|run", ""],
        }
    return {"files": {str(root / "app" / "guard.py"): entry, "app/other.py": {"executed_lines": [7]}}}


LCOV = """TN:
SF:{root}/app/guard.py
DA:1,1
DA:2,0
LF:2
LH:1
end_of_record
SF:rtl/alu.sv
DA:1,3
end_of_record
"""

COBERTURA = """<?xml version="1.0" ?>
<coverage line-rate="0.5" version="7.4">
  <sources><source>{root}</source></sources>
  <packages><package name="app"><classes>
    <class name="guard.py" filename="app/guard.py"><methods/><lines>
      <line number="1" hits="2"/><line number="2" hits="0"/>
    </lines></class>
  </classes></package></packages>
</coverage>
"""

JACOCO = """<?xml version="1.0" encoding="UTF-8"?>
<report name="acme">
  <package name="com/acme">
    <sourcefile name="Guard.java">
      <line nr="10" mi="0" ci="3" mb="0" cb="0"/>
      <line nr="11" mi="2" ci="0" mb="0" cb="0"/>
    </sourcefile>
    <sourcefile name="Missing.java">
      <line nr="4" mi="0" ci="1" mb="0" cb="0"/>
    </sourcefile>
  </package>
</report>
"""


class TestFormats:
    def test_coveragepy_with_contexts_attributes_lines_to_tests(self, root):
        report = read_coveragepy(_coveragepy(root, contexts=True), root)
        assert report.format == "coverage.py"
        assert report.attributed
        assert report.per_test == {
            "tests/test_guard.py::test_a": {"app/guard.py": {1, 2}},
            "tests/test_guard.py::TestX::test_b[p0]": {"app/guard.py": {1}},
        }
        assert report.suite == {"app/guard.py": {1, 2}, "app/other.py": {7}}

    def test_coveragepy_without_contexts_is_suite_only(self, root):
        report = read_coveragepy(_coveragepy(root, contexts=False), root)
        assert not report.attributed
        assert report.suite == {"app/guard.py": {1, 2}, "app/other.py": {7}}

    def test_coveragepy_refuses_a_non_export(self, root):
        with pytest.raises(CoverageReadError, match="'files'"):
            read_coveragepy({"totals": {}}, root)

    def test_lcov(self, root):
        report = read_coverage_text(LCOV.format(root=root), root)
        assert report.format == "lcov" and not report.attributed
        assert report.suite == {"app/guard.py": {1}, "rtl/alu.sv": {1}}

    def test_cobertura(self, root):
        report = read_coverage_text(COBERTURA.format(root=root), root)
        assert report.format == "cobertura" and not report.attributed
        assert report.suite == {"app/guard.py": {1}}

    def test_jacoco_places_sources_under_the_usual_roots(self, root):
        report = read_coverage_text(JACOCO, root)
        assert report.format == "jacoco" and not report.attributed
        assert report.suite == {
            "src/main/java/com/acme/Guard.java": {10},
            "com/acme/Missing.java": {4},   # not found: kept as given
        }

    def test_format_is_detected_from_content_not_extension(self, root):
        path = root / "report.json"
        path.write_text("﻿\n" + LCOV.format(root=root))
        assert read_coverage(path, root).format == "lcov"
        xml = root / "cov.txt"
        xml.write_text(JACOCO)
        assert read_coverage(xml, root).format == "jacoco"

    def test_unrecognised_content_is_refused_with_the_accepted_formats(self, root):
        path = root / "cov.dat"
        path.write_text("C '0' 1\n")
        with pytest.raises(CoverageReadError, match="cannot read coverage report") as e:
            read_coverage(path, root)
        assert "coverage json --show-contexts" in str(e.value)
        with pytest.raises(CoverageReadError, match="not well-formed"):
            read_coverage_text("<coverage><unclosed>", root)
        with pytest.raises(CoverageReadError, match="neither Cobertura"):
            read_coverage_text("<testsuites/>", root)
        with pytest.raises(CoverageReadError, match="coverage json --show-contexts"):
            read_coverage_text("{not json", root)

    def test_missing_file_is_refused(self, root):
        with pytest.raises(CoverageReadError, match="cannot read"):
            read_coverage(root / "nope.info", root)

    def test_paths_outside_the_root_are_kept_as_given(self, tmp_path):
        other = tmp_path / "elsewhere"
        other.mkdir()
        report = read_coverage_text("SF:/somewhere/else/x.py\nDA:1,1\nend_of_record\n", other)
        assert report.suite == {"/somewhere/else/x.py": {1}}


class TestPerTestDirectory:
    def test_each_file_is_one_tests_run(self, root):
        cov = root / "cov"
        (cov / "nested").mkdir(parents=True)
        (cov / "tests.test_guard__test_a.info").write_text(LCOV.format(root=root))
        (cov / "nested" / "tests.test_guard__test_b.json").write_text(
            json.dumps(_coveragepy(root, contexts=False)))
        report = read_coverage(cov, root)
        assert report.format == "directory" and report.attributed
        assert report.per_test == {
            "tests.test_guard__test_a": {"app/guard.py": {1}, "rtl/alu.sv": {1}},
            "nested/tests.test_guard__test_b": {"app/guard.py": {1, 2}, "app/other.py": {7}},
        }
        assert report.suite == {}

    def test_an_unreadable_member_names_the_directory(self, root):
        cov = root / "cov"
        cov.mkdir()
        (cov / "x.info").write_text("garbage\n")
        with pytest.raises(CoverageReadError, match="in coverage directory"):
            read_coverage(cov, root)

    def test_an_empty_directory_is_refused(self, root):
        (root / "cov").mkdir()
        with pytest.raises(CoverageReadError, match="no reports"):
            read_coverage(root / "cov", root)


def _tests() -> list[dict]:
    return [
        {"id": "tests.test_guard::test_a", "name": "test_a", "classname": "tests.test_guard",
         "file": "tests/test_guard.py", "status": "passed"},
        {"id": "tests.test_guard.TestX::test_b[p0]", "name": "test_b[p0]",
         "classname": "tests.test_guard.TestX", "file": "tests/test_guard.py", "status": "passed"},
        {"id": "tests.test_other::test_c", "name": "test_c", "classname": "tests.test_other",
         "status": "passed"},   # not located
    ]


class TestMergeCoverageRule:
    def test_attributed_report_gives_reached_per_test(self, root):
        summary = {"tests": _tests()}
        merge_coverage(summary, _coveragepy(root, contexts=True), root)
        a, b, c = summary["tests"]
        assert a["reached"] == [{"file": "app/guard.py", "lines": [1, 2]}]
        assert b["reached"] == [{"file": "app/guard.py", "lines": [1]}]
        assert c["reached"] == []          # a fact: coverage ran, nothing attributed
        assert all("suite_reached" not in t for t in summary["tests"])

    def test_aggregate_report_gives_suite_reached_and_no_reached(self, root):
        path = root / "coverage.info"
        path.write_text(LCOV.format(root=root))
        summary = {"tests": _tests()}
        merge_coverage(summary, path, root)
        for entry in summary["tests"]:
            assert "reached" not in entry
            assert entry["suite_reached"] == [
                {"file": "app/guard.py", "lines": [1]}, {"file": "rtl/alu.sv", "lines": [1]}]
        # Each entry owns its own copy.
        summary["tests"][0]["suite_reached"][0]["lines"].append(99)
        assert summary["tests"][1]["suite_reached"][0]["lines"] == [1]

    def test_coveragepy_without_contexts_is_aggregate(self, root):
        summary = {"tests": _tests()}
        merge_coverage(summary, _coveragepy(root, contexts=False), root)
        assert "reached" not in summary["tests"][0]
        assert summary["tests"][0]["suite_reached"][0] == {"file": "app/guard.py", "lines": [1, 2]}

    def test_per_test_directory_matches_ids_names_and_paths(self, root):
        cov = root / "cov"
        cov.mkdir()
        (cov / "tests.test_guard__test_a.info").write_text(LCOV.format(root=root))
        (cov / "test_b[p0].info").write_text("SF:rtl/alu.sv\nDA:5,1\nend_of_record\n")
        (cov / "tests__test_guard.py__test_c.info").write_text("SF:rtl/alu.sv\nDA:9,1\nend_of_record\n")
        (cov / "tests.test_guard__test_zzz.info").write_text("SF:rtl/alu.sv\nDA:7,1\nend_of_record\n")
        summary = {"tests": _tests()}
        merge_coverage(summary, cov, root)
        a, b, c = summary["tests"]
        assert a["reached"] == [{"file": "app/guard.py", "lines": [1]}, {"file": "rtl/alu.sv", "lines": [1]}]
        assert b["reached"] == [{"file": "rtl/alu.sv", "lines": [5]}]
        assert c["reached"] == []   # a stem naming another file is not this test

    def test_context_in_another_file_does_not_count_for_a_located_test(self, root):
        summary = {"tests": _tests()}
        cov = {"files": {"app/guard.py": {"executed_lines": [1], "contexts": {
            "1": ["tests/test_other.py::test_a|run", "tests/test_guard.py::test_c|run"]}}}}
        merge_coverage(summary, cov, root)
        assert summary["tests"][0]["reached"] == []                      # located elsewhere
        assert summary["tests"][2]["reached"] == [{"file": "app/guard.py", "lines": [1]}]  # not located

    def test_a_report_object_is_accepted(self, root):
        report = CoverageReport(per_test={"test_a": {"app/guard.py": {3}}})
        summary = {"tests": _tests()}
        merge_coverage(summary, report, root)
        assert summary["tests"][0]["reached"] == [{"file": "app/guard.py", "lines": [3]}]

    def test_read_errors_become_attestation_errors(self, root):
        with pytest.raises(AttestationError, match="'files'"):
            merge_coverage({"tests": []}, {"totals": {}}, root)
        with pytest.raises(AttestationError, match="cannot read coverage report"):
            merge_coverage({"tests": []}, root / "missing.info", root)

    def test_a_second_merge_replaces_the_other_shape(self, root):
        summary = {"tests": _tests()}
        merge_coverage(summary, _coveragepy(root, contexts=False), root)
        merge_coverage(summary, _coveragepy(root, contexts=True), root)
        assert "suite_reached" not in summary["tests"][0]
        assert summary["tests"][0]["reached"]
