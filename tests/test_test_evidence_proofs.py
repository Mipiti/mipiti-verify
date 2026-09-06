"""Test evidence carries its definition, what it reached, and what it fails
without; the verifier reports those facts and the reviewer reads them.

Fixtures follow ``test_test_attested.py``: a checkout with a HEAD commit, an
attestation built with the real producer and signed with a real key.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.attestation import (
    ATTESTATION_DIR,
    AttestationError,
    build_statement,
    definition_sha256,
    locate_test_definitions,
    merge_coverage,
    parse_junit,
    sign_statement,
)
from mipiti_verify.verifiers import get_verifier

COMMIT = "abc123def456abc123def456abc123def456abcd"

GUARD_SRC = '''"""A mechanism under test."""


def require_token(request):
    if not request.get("token"):
        raise PermissionError("no token")
    return True


class Limiter:
    def __init__(self, limit=3):
        self.limit = limit

    def allow(self, count):
        return count <= self.limit
'''

TEST_SRC = '''import pytest

from app.guard import Limiter, require_token


@pytest.mark.parametrize("payload", [{}, {"token": ""}])
def test_missing_token_is_refused(payload):
    with pytest.raises(PermissionError):
        require_token(payload)


class TestLimiter:
    def test_over_limit_is_refused(self):
        assert Limiter(limit=1).allow(2) is False


def test_unrelated_arithmetic():
    assert 1 + 1 == 2
'''

JUNIT = """<testsuites>
  <testsuite name="s">
    <testcase classname="tests.test_guard" name="test_missing_token_is_refused[payload0]"/>
    <testcase classname="tests.test_guard" name="test_missing_token_is_refused[payload1]"/>
    <testcase classname="tests.test_guard.TestLimiter" name="test_over_limit_is_refused"/>
    <testcase classname="tests.test_guard" name="test_unrelated_arithmetic"/>
    <testcase classname="tests.test_missing" name="test_nowhere"/>
  </testsuite>
</testsuites>
"""


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text(COMMIT)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "guard.py").write_text(GUARD_SRC)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("")
    (tmp_path / "tests" / "test_guard.py").write_text(TEST_SRC)
    return tmp_path


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    d = tmp_path_factory.mktemp("keys")
    priv = d / "signing.pem"
    priv.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return str(priv), pub


def _summary(project: Path, junit: str = JUNIT, coverage: dict | None = None) -> dict:
    report = project / "report.xml"
    report.write_text(junit)
    summary = parse_junit(report)
    locate_test_definitions(project, summary["tests"])
    if coverage is not None:
        merge_coverage(summary, coverage, project)
    return summary


def _write(project: Path, statement: dict, name: str, key_path: str = "") -> Path:
    attestation, _ = sign_statement(statement, key_path=key_path)
    out = project / ATTESTATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    path.write_text(attestation)
    return path


def _entry(summary: dict, name: str) -> dict:
    return next(t for t in summary["tests"] if t["name"] == name)


def _no_ci(monkeypatch, public_key: str = ""):
    for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL", "GITHUB_SHA"):
        monkeypatch.delenv(var, raising=False)
    if public_key:
        monkeypatch.setenv("MIPITI_ATTESTATION_PUBLIC_KEY", public_key)
    else:
        monkeypatch.delenv("MIPITI_ATTESTATION_PUBLIC_KEY", raising=False)


def _coverage_for(project: Path, guard_lines: list[int], test_ctx: str) -> dict:
    return {
        "files": {
            "app/guard.py": {
                "executed_lines": guard_lines,
                "contexts": {str(n): [test_ctx] for n in guard_lines},
            }
        }
    }


# ---------------------------------------------------------------------------
# A. Definition in the attestation
# ---------------------------------------------------------------------------

class TestDefinitionLocation:
    def test_function_is_located_and_hashed_over_its_block(self, project):
        summary = _summary(project)
        entry = _entry(summary, "test_unrelated_arithmetic")
        assert entry["file"] == "tests/test_guard.py"
        expected = definition_sha256(
            "def test_unrelated_arithmetic():\n    assert 1 + 1 == 2"
        )
        assert entry["definition_sha256"] == expected
        assert entry["definition_scope"] == "symbol"
        assert entry["parser"] == "ast"

    def test_method_hash_covers_the_method_inside_its_class(self, project):
        summary = _summary(project)
        entry = _entry(summary, "test_over_limit_is_refused")
        assert entry["file"] == "tests/test_guard.py"
        expected = definition_sha256(
            "    def test_over_limit_is_refused(self):\n"
            "        assert Limiter(limit=1).allow(2) is False"
        )
        assert entry["definition_sha256"] == expected

    def test_parametrized_ids_share_one_definition(self, project):
        summary = _summary(project)
        a = _entry(summary, "test_missing_token_is_refused[payload0]")
        b = _entry(summary, "test_missing_token_is_refused[payload1]")
        assert a["definition_sha256"] == b["definition_sha256"]
        # Decorators are part of the definition.
        expected = definition_sha256(
            '@pytest.mark.parametrize("payload", [{}, {"token": ""}])\n'
            "def test_missing_token_is_refused(payload):\n"
            "    with pytest.raises(PermissionError):\n"
            "        require_token(payload)"
        )
        assert a["definition_sha256"] == expected

    def test_whitespace_and_line_endings_do_not_change_the_hash(self, project):
        before = _entry(_summary(project), "test_unrelated_arithmetic")["definition_sha256"]
        src = (project / "tests" / "test_guard.py").read_text()
        (project / "tests" / "test_guard.py").write_text(
            src.replace("\n", "   \r\n"), newline="")
        after = _entry(_summary(project), "test_unrelated_arithmetic")["definition_sha256"]
        assert before == after

    def test_file_fallback_when_the_function_cannot_be_isolated(self, project):
        (project / "tests" / "test_dyn.py").write_text(
            "globals()['test_generated'] = lambda: None\n")
        junit = """<testsuites><testsuite name="s">
          <testcase classname="tests.test_dyn" name="test_generated"/>
        </testsuite></testsuites>"""
        entry = _entry(_summary(project, junit), "test_generated")
        assert entry["file"] == "tests/test_dyn.py"
        assert entry["definition_scope"] == "file"
        assert entry["definition_sha256"] == definition_sha256(
            (project / "tests" / "test_dyn.py").read_text())

    def test_junit_file_attribute_locates_a_non_python_test(self, project):
        (project / "spec").mkdir()
        (project / "spec" / "auth.test.js").write_text(
            "function test_refuses() {\n  expect(guard()).toBe(false);\n}\n")
        junit = """<testsuites><testsuite name="s">
          <testcase classname="auth" name="test_refuses" file="spec/auth.test.js"/>
        </testsuite></testsuites>"""
        entry = _entry(_summary(project, junit), "test_refuses")
        assert entry["file"] == "spec/auth.test.js"
        assert entry["definition_sha256"] == definition_sha256(
            "function test_refuses() {\n  expect(guard()).toBe(false);\n}")

    def test_unresolvable_test_carries_neither_field(self, project):
        entry = _entry(_summary(project), "test_nowhere")
        assert "file" not in entry
        assert "definition_sha256" not in entry

    def test_a_path_outside_the_checkout_is_not_resolved(self, project):
        junit = """<testsuites><testsuite name="s">
          <testcase classname="x" name="test_escape" file="../../etc/passwd"/>
        </testsuite></testsuites>"""
        entry = _entry(_summary(project, junit), "test_escape")
        assert "file" not in entry
        assert "definition_sha256" not in entry

    def test_location_never_raises(self, project):
        tests = [{"name": None, "classname": 3}, "not a dict", {"name": "x", "classname": "..."}]
        locate_test_definitions(project, tests)
        assert "definition_sha256" not in tests[0]
        assert "definition_sha256" not in tests[2]


# ---------------------------------------------------------------------------
# B. Coverage -> reach
# ---------------------------------------------------------------------------

class TestCoverageMerge:
    def test_context_naming_the_test_records_what_it_reached(self, project):
        cov = _coverage_for(project, [4, 5, 6], "tests/test_guard.py::test_missing_token_is_refused[payload0]|run")
        summary = _summary(project, coverage=cov)
        entry = _entry(summary, "test_missing_token_is_refused[payload0]")
        assert entry["reached"] == [{"file": "app/guard.py", "lines": [4, 5, 6]}]

    def test_method_context_matches_through_its_class(self, project):
        cov = _coverage_for(project, [14], "tests/test_guard.py::TestLimiter::test_over_limit_is_refused|run")
        summary = _summary(project, coverage=cov)
        assert _entry(summary, "test_over_limit_is_refused")["reached"] == [
            {"file": "app/guard.py", "lines": [14]}]

    def test_a_test_no_context_names_gets_an_explicitly_empty_reach(self, project):
        cov = _coverage_for(project, [4], "tests/test_guard.py::test_missing_token_is_refused|run")
        summary = _summary(project, coverage=cov)
        assert _entry(summary, "test_unrelated_arithmetic")["reached"] == []

    def test_a_context_in_another_file_does_not_count_for_a_located_test(self, project):
        cov = _coverage_for(project, [4], "tests/test_other.py::test_unrelated_arithmetic|run")
        summary = _summary(project, coverage=cov)
        assert _entry(summary, "test_unrelated_arithmetic")["reached"] == []

    def test_absolute_paths_are_made_repository_relative(self, project):
        cov = {"files": {str(project / "app" / "guard.py"): {
            "executed_lines": [4],
            "contexts": {"4": ["tests/test_guard.py::test_unrelated_arithmetic|run"]}}}}
        summary = _summary(project, coverage=cov)
        assert _entry(summary, "test_unrelated_arithmetic")["reached"] == [
            {"file": "app/guard.py", "lines": [4]}]

    def test_a_report_without_contexts_records_suite_reach_only(self, project):
        # An aggregate report says what the suite executed, not what this
        # test did: it is recorded as suite_reached, and reach stays unknown.
        summary = _summary(project, coverage={"files": {"app/guard.py": {"executed_lines": [4]}}})
        entry = _entry(summary, "test_unrelated_arithmetic")
        assert "reached" not in entry
        assert entry["suite_reached"] == [{"file": "app/guard.py", "lines": [4]}]

    def test_not_a_coverage_export_is_refused(self, project):
        with pytest.raises(AttestationError, match="'files'"):
            merge_coverage({"tests": []}, {"totals": {}}, project)

    def test_cli_rejects_bad_json_with_a_clear_message(self, project, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        _no_ci(monkeypatch)
        (project / "report.xml").write_text(JUNIT)
        (project / "coverage.json").write_text("{not json")
        result = CliRunner().invoke(main, [
            "attest-tests", "--junit", str(project / "report.xml"),
            "--coverage", str(project / "coverage.json"),
            "--project-root", str(project),
        ])
        assert result.exit_code == 1
        assert "coverage report" in result.output
        assert "coverage json --show-contexts" in result.output

    def test_cli_records_definitions_and_reach(self, project, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.attestation import statement_of
        from mipiti_verify.cli import main

        _no_ci(monkeypatch)
        (project / "report.xml").write_text(JUNIT)
        (project / "coverage.json").write_text(json.dumps(
            _coverage_for(project, [4], "tests/test_guard.py::test_missing_token_is_refused[payload0]|run")))
        result = CliRunner().invoke(main, [
            "attest-tests", "--junit", str(project / "report.xml"),
            "--coverage", str(project / "coverage.json"),
            "--project-root", str(project),
        ])
        assert result.exit_code == 0, result.output
        assert "definition(s) located" in result.output
        raw = next((project / ATTESTATION_DIR).glob("*.json")).read_text()
        tests = statement_of(raw)["predicate"]["tests"]
        by_name = {t["name"]: t for t in tests}
        assert by_name["test_missing_token_is_refused[payload0]"]["reached"] == [
            {"file": "app/guard.py", "lines": [4]}]
        assert by_name["test_unrelated_arithmetic"]["definition_sha256"]


# ---------------------------------------------------------------------------
# C. Dependence
# ---------------------------------------------------------------------------

class TestDependence:
    @pytest.mark.parametrize("returncode,marker,expected", [
        (0, False, "passed"),
        (1, False, "failed"),
        (2, False, "error"),
        (4, False, "error"),
        (5, False, "error"),
        (0, True, "error"),
    ])
    def test_outcome_mapping(self, returncode, marker, expected):
        from mipiti_verify.dependence import outcome_of

        assert outcome_of(returncode, marker) == expected

    def test_run_pair_uses_the_plugin_and_the_selector(self, project):
        from mipiti_verify.dependence import run_pair

        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["env"] = kwargs["env"]
            seen["cwd"] = kwargs["cwd"]
            return subprocess.CompletedProcess(argv, 1, "", "")

        record = run_pair(project, "tests/test_guard.py::test_x", "app/guard.py::require_token", runner=fake_run)
        assert record["status"] == "failed"
        assert seen["argv"][:5] == [sys.executable, "-m", "pytest", "-q", "-p"]
        assert seen["argv"][5] == "mipiti_verify._disable_plugin"
        assert seen["argv"][-1] == "tests/test_guard.py::test_x"
        assert seen["env"]["MIPITI_DISABLE_MECHANISM"] == "app/guard.py::require_token"
        assert seen["cwd"] == str(project)

    def test_a_bare_name_becomes_a_k_expression(self):
        from mipiti_verify.dependence import test_selector

        assert test_selector("test_x") == ["-k", "test_x"]
        assert test_selector("tests.test_guard::test_x[case-1]") == ["-k", "test_x"]
        assert test_selector("tests/test_guard.py::TestC::test_x") == ["tests/test_guard.py::TestC::test_x"]

    def test_timeout_is_an_error(self, project):
        from mipiti_verify.dependence import run_pair

        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        record = run_pair(project, "test_x", "app/guard.py::require_token", runner=slow, timeout=7)
        assert record["status"] == "error"
        assert "timed out" in record["note"]

    def test_summary_shape_counts_pairs(self, project):
        from mipiti_verify.dependence import run_dependence

        codes = iter([1, 0, 5])

        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, next(codes), "", "")

        summary = run_dependence(project, [
            ("tests/test_guard.py::test_a", "app/guard.py::require_token"),
            ("test_b", "app/guard.py::require_token"),
            ("test_c", "app/guard.py::Limiter"),
        ], runner=fake_run)
        assert summary["totals"] == {"total": 3, "passed": 1, "failed": 1, "skipped": 0, "errors": 1}
        assert summary["tests"][0]["fails_without"] == [
            {"mechanism": "app/guard.py::require_token", "status": "failed"}]
        assert summary["tests"][0]["name"] == "test_a"
        statement = build_statement(commit=COMMIT, summary=summary, invocation=[], kind="dependence")
        assert statement["predicate"]["kind"] == "dependence"

    def test_total_budget_records_unrun_pairs_without_an_outcome(self, project):
        from mipiti_verify.dependence import REASON_BUDGET_EXHAUSTED, run_dependence

        # Each pair takes 100 simulated seconds; the budget covers two.
        now = [0.0]

        def clock():
            return now[0]

        def fake_run(argv, **kwargs):
            now[0] += 100.0
            return subprocess.CompletedProcess(argv, 1, "", "")

        summary = run_dependence(project, [
            ("test_a", "app/guard.py::require_token"),
            ("test_b", "app/guard.py::require_token"),
            ("test_c", "app/guard.py::require_token"),
            ("test_d", "app/guard.py::Limiter"),
        ], runner=fake_run, total_timeout=200, clock=clock)
        assert summary["not_run"] == 2
        assert summary["totals"] == {"total": 4, "passed": 0, "failed": 2, "skipped": 0, "errors": 2}
        assert [t["status"] for t in summary["tests"]] == ["failed", "failed", "error", "error"]
        unrun = summary["tests"][2]["fails_without"][0]
        assert unrun == {"mechanism": "app/guard.py::require_token", "status": "error",
                         "reason": REASON_BUDGET_EXHAUSTED}
        assert "reason" not in summary["tests"][0]["fails_without"][0]

    def test_cli_total_timeout_prints_the_run_and_not_run_counts(self, project, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        _no_ci(monkeypatch)
        monkeypatch.setenv("MIPITI_DEPENDENCE_TOTAL_TIMEOUT", "0")

        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "")

        with patch("mipiti_verify.dependence.subprocess.run", fake_run):
            result = CliRunner().invoke(main, [
                "attest-dependence", "--project-root", str(project),
                "--pair", "test_a=app/guard.py::require_token",
                "--pair", "test_b=app/guard.py::require_token",
                "--total-timeout", "1",
            ])
        assert result.exit_code == 0, result.output
        assert "Ran 2 of 2 pair(s)." in result.output

    def test_plugin_stubs_a_function_and_a_class(self, project, monkeypatch):
        from mipiti_verify._disable_plugin import disable_symbol, import_mechanism_module

        monkeypatch.syspath_prepend(str(project))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                monkeypatch.delitem(sys.modules, name)
        module = import_mechanism_module(project, "app/guard.py")
        with pytest.raises(PermissionError):
            module.require_token({})
        disable_symbol(module, "require_token")
        assert module.require_token({}) is None
        import importlib
        assert importlib.import_module("app.guard").require_token({}) is None

        disable_symbol(module, "Limiter")
        assert module.Limiter(limit=1).allow(2) is None
        assert module.Limiter.allow(None, 2) is None

    def test_plugin_patches_a_method_on_its_class(self, project, monkeypatch):
        from mipiti_verify._disable_plugin import disable_symbol, import_mechanism_module

        monkeypatch.syspath_prepend(str(project))
        for name in list(sys.modules):
            if name == "app" or name.startswith("app."):
                monkeypatch.delitem(sys.modules, name)
        module = import_mechanism_module(project, "app/guard.py")
        disable_symbol(module, "Limiter.allow")
        assert module.Limiter(limit=1).allow(2) is None
        assert module.Limiter(limit=1).limit == 1

    def test_plugin_refuses_a_missing_symbol(self, project, monkeypatch):
        from mipiti_verify._disable_plugin import disable_symbol, import_mechanism_module

        monkeypatch.syspath_prepend(str(project))
        module = import_mechanism_module(project, "app/guard.py")
        with pytest.raises(AttributeError):
            disable_symbol(module, "no_such_thing")

    def test_end_to_end_a_test_fails_without_its_mechanism(self, project):
        """The real thing: pytest in a subprocess with the plugin loaded."""
        from mipiti_verify.dependence import run_pair

        depends = run_pair(
            project, "tests/test_guard.py::test_missing_token_is_refused",
            "app/guard.py::require_token", timeout=120)
        assert depends["status"] == "failed", depends
        unrelated = run_pair(
            project, "tests/test_guard.py::test_unrelated_arithmetic",
            "app/guard.py::require_token", timeout=120)
        assert unrelated["status"] == "passed", unrelated
        missing = run_pair(
            project, "tests/test_guard.py::test_unrelated_arithmetic",
            "app/nowhere.py::require_token", timeout=120)
        assert missing["status"] == "error", missing

    def test_pairs_from_a_models_assertions(self):
        from mipiti_verify.dependence import pairs_from_assertions

        payload = {"controls": {"CTRL-1": [
            {"type": "test_attested", "params": {"test": "test_a", "mechanism": "app/guard.py::require_token"}},
            {"type": "test_attested", "params": {"test": "test_b"}},
            {"type": "function_exists", "params": {"file": "app/guard.py", "name": "require_token"}},
        ]}, "assumptions": {"AS-1": [
            {"type": "test_attested", "params": {"test": "tests/test_guard.py::test_c", "mechanism": "app/guard.py::Limiter"}},
            {"type": "test_attested", "params": {"test": "test_a", "mechanism": "app/guard.py::require_token"}},
        ]}}
        assert pairs_from_assertions(payload) == [
            ("test_a", "app/guard.py::require_token"),
            ("tests/test_guard.py::test_c", "app/guard.py::Limiter"),
        ]

    def test_cli_from_model_pairs_and_writes_a_dependence_record(self, project, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.attestation import statement_of
        from mipiti_verify.cli import main

        _no_ci(monkeypatch)
        client = MagicMock()
        client.get_all_assertions.return_value = {"controls": {"CTRL-1": [
            {"type": "test_attested", "params": {
                "test": "tests/test_guard.py::test_missing_token_is_refused",
                "mechanism": "app/guard.py::require_token"}},
        ]}}
        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv[-1], kwargs["env"]["MIPITI_DISABLE_MECHANISM"]))
            return subprocess.CompletedProcess(argv, 1, "", "")

        with patch("mipiti_verify.cli.MipitiClient", return_value=client), \
                patch("mipiti_verify.dependence.subprocess.run", fake_run):
            result = CliRunner().invoke(main, [
                "attest-dependence", "--from-model", "m1", "--api-key", "mv_x",
                "--repo", "acme/widgets", "--project-root", str(project),
            ])
        assert result.exit_code == 0, result.output
        client.get_all_assertions.assert_called_once_with("m1", repo="acme/widgets")
        assert calls == [("tests/test_guard.py::test_missing_token_is_refused",
                          "app/guard.py::require_token")]
        path = next((project / ATTESTATION_DIR).glob("*-dependence.json"))
        predicate = statement_of(path.read_text())["predicate"]
        assert predicate["kind"] == "dependence"
        assert predicate["commit"] == COMMIT
        assert predicate["tests"][0]["fails_without"][0]["status"] == "failed"
        assert "1 depend on their mechanism" in result.output

    def test_cli_with_nothing_to_run_is_an_error(self, project):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        result = CliRunner().invoke(main, ["attest-dependence", "--project-root", str(project)])
        assert result.exit_code == 1
        assert "--pair" in result.output

    def test_help_says_it_runs_tests(self):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        result = CliRunner().invoke(main, ["attest-dependence", "--help"])
        assert "RUNS TESTS" in result.output
        assert "opt-in" in result.output


# ---------------------------------------------------------------------------
# D. The verifier reports facts
# ---------------------------------------------------------------------------

TEST = "test_missing_token_is_refused[payload0]"
MECHANISM = "app/guard.py::require_token"


def _attest(project, *, coverage=None, key_path=""):
    summary = _summary(project, coverage=coverage)
    statement = build_statement(commit=COMMIT, summary=summary, invocation=["pytest"])
    _write(project, statement, "tests.json", key_path)
    return summary


def _attest_dependence(project, status, *, commit=COMMIT, key_path="", test=TEST, mechanism=MECHANISM):
    summary = {
        "totals": {"total": 1, "passed": int(status == "passed"),
                   "failed": int(status == "failed"), "skipped": 0,
                   "errors": int(status == "error")},
        "tests": [{"id": test, "name": test, "status": status,
                   "fails_without": [{"mechanism": mechanism, "status": status}]}],
    }
    statement = build_statement(commit=commit, summary=summary, invocation=[], kind="dependence")
    _write(project, statement, "tests-dependence.json", key_path)


def _attest_reach(project, reached, *, commit=COMMIT, key_path="", test=TEST, mechanism=MECHANISM,
                  reason="", reach_scope=""):
    """A reach record as ``attest-reach`` writes it: the test run alone, its
    per-test coverage of the mechanism's file, the mechanism it ran for.
    With ``reach_scope="suite"``, the suite-mode record: what the suite
    reached, as ``suite_reached``, and never ``reached``."""
    entry = {"id": test, "name": test, "status": "passed", "mechanism": mechanism}
    if reason:
        entry.update({"status": "error", "reason": reason})
    elif reach_scope == "suite":
        entry["suite_reached"] = reached
    else:
        entry["reached"] = reached
    summary = {
        "totals": {"total": 1, "passed": 0 if reason else 1, "failed": 0, "skipped": 0,
                   "errors": 1 if reason else 0},
        "tests": [entry],
    }
    statement = build_statement(commit=commit, summary=summary, invocation=[], kind="reach",
                                reach_scope=reach_scope)
    _write(project, statement, f"tests-reach{'-suite' if reach_scope == 'suite' else ''}.json", key_path)


class TestReachRecords:
    """A reach record supplies the reach fact when the test-result record has
    no per-test coverage; it never supplies the pass."""

    def test_reach_record_fills_reached_when_test_result_has_none(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}])
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.reached is True

    def test_reach_record_can_say_no(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [1]}])
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.reached is False

    def test_test_result_coverage_wins_over_reach_record(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [5, 6], f"tests/test_guard.py::{TEST}|run"))
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [1]}])
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.reached is True

    def test_unrun_reach_pair_is_unknown(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [], reason="not run: reach budget exhausted")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.reached is None

    def test_reach_record_for_another_mechanism_is_ignored(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}],
                      mechanism="app/other.py::thing")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.reached is None

    def test_reach_record_alone_never_evidences_a_pass(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}])
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert not r.passed


class TestSuiteScopeReachRecords:
    """A suite-scope reach record says what the suite executed. It never
    supplies the reach fact; it only qualifies the unknown."""

    def test_suite_scope_record_leaves_reach_unknown_and_says_so(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}], reach_scope="suite")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.reached is None and r.reach_scope == "suite"
        assert "reached mechanism: unknown (suite-level coverage only)" in r.details

    def test_per_test_fact_wins_over_a_suite_scope_record(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}], reach_scope="suite")
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [1]}])
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.reached is False and r.reach_scope == ""
        assert "reached mechanism: no" in r.details

    def test_suite_scope_record_for_another_test_does_not_qualify(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}],
                      reach_scope="suite", test="test_elsewhere")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.reached is None and r.reach_scope == ""
        assert "reached mechanism: unknown;" in r.details

    def test_suite_scope_record_alone_never_evidences_a_pass(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}], reach_scope="suite")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert not r.passed


class TestVerifierFacts:
    def test_evidence_hash_is_the_attested_definition_hash(self, project, keypair, monkeypatch):
        key_path, public = keypair
        _no_ci(monkeypatch, public)
        summary = _attest(project, key_path=key_path)
        r = get_verifier("test_attested").verify({"test": TEST}, project)
        assert r.passed
        assert r.evidence_hash == "sha256:" + _entry(summary, TEST)["definition_sha256"]
        assert r.reached is None and r.depends is None
        assert "definition sha256:" in r.details

    def test_no_definition_means_no_hash(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        r = get_verifier("test_attested").verify({"test": "test_nowhere"}, project)
        assert r.passed
        assert r.evidence_hash == ""

    def test_reached_is_true_when_coverage_hits_the_mechanism(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [5, 6], f"tests/test_guard.py::{TEST}|run"))
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed
        assert r.reached is True
        assert "reached mechanism: yes" in r.details

    def test_reached_is_false_when_coverage_misses_the_mechanism(self, project, monkeypatch):
        _no_ci(monkeypatch)
        # Line 14 is inside Limiter, not require_token.
        _attest(project, coverage=_coverage_for(project, [14], f"tests/test_guard.py::{TEST}|run"))
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed
        assert r.reached is False
        assert "reached mechanism: no" in r.details

    def test_empty_reach_is_false_not_unknown(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [5], "tests/test_guard.py::test_unrelated_arithmetic|run"))
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed
        assert r.reached is False

    def test_reached_is_unknown_without_coverage(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed
        assert r.reached is None
        assert "reached mechanism: unknown" in r.details

    def test_reached_is_unknown_when_the_mechanism_is_not_in_the_checkout(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [5], f"tests/test_guard.py::{TEST}|run"))
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": "app/guard.py::vanished"}, project)
        assert r.passed
        assert r.reached is None

    def test_depends_is_true_when_the_test_fails_without_the_mechanism(self, project, keypair, monkeypatch):
        key_path, public = keypair
        _no_ci(monkeypatch, public)
        _attest(project, key_path=key_path)
        _attest_dependence(project, "failed", key_path=key_path)
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed
        assert r.depends is True
        assert "fails without mechanism: yes" in r.details

    def test_an_error_outcome_also_counts_as_dependence(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_dependence(project, "error")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.depends is True

    def test_depends_is_false_when_the_test_still_passes(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_dependence(project, "passed")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed
        assert r.depends is False
        assert "fails without mechanism: no" in r.details

    def test_an_unrun_pair_is_unknown_not_dependence(self, project, monkeypatch):
        from mipiti_verify.dependence import REASON_BUDGET_EXHAUSTED

        _no_ci(monkeypatch)
        _attest(project)
        summary = {
            "totals": {"total": 1, "passed": 0, "failed": 0, "skipped": 0, "errors": 1},
            "tests": [{"id": TEST, "name": TEST, "status": "error",
                       "fails_without": [{"mechanism": MECHANISM, "status": "error",
                                          "reason": REASON_BUDGET_EXHAUSTED}]}],
        }
        _write(project, build_statement(commit=COMMIT, summary=summary, invocation=[],
                                        kind="dependence"), "tests-dependence.json")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.depends is None
        assert "fails without mechanism: not established (not run: dependence budget exhausted)" in r.details

    def test_depends_is_unknown_without_a_record(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.depends is None

    def test_depends_is_unknown_when_the_record_names_another_mechanism(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_dependence(project, "failed", mechanism="app/guard.py::Limiter")
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.depends is None

    def test_depends_is_unknown_when_the_record_is_for_another_commit(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_dependence(project, "failed", commit="b" * 40)
        r = get_verifier("test_attested").verify({"test": TEST, "mechanism": MECHANISM}, project)
        assert r.passed and r.depends is None

    def test_a_dependence_record_alone_never_evidences_a_pass(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest_dependence(project, "passed")
        r = get_verifier("test_attested").verify({"test": TEST}, project)
        assert not r.passed

    def test_tier1_result_carries_the_facts(self, project, monkeypatch):
        from mipiti_verify.runner import Runner, _result_row

        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [5], f"tests/test_guard.py::{TEST}|run"))
        _attest_dependence(project, "failed")
        runner = Runner(client=MagicMock(), project_root=str(project), repo="acme/widgets")
        out = runner._verify_tier1({"id": "a1", "type": "test_attested",
                                    "params": {"test": TEST, "mechanism": MECHANISM}})
        assert out["status"] == "pass"
        assert out["evidence_hash"].startswith("sha256:")
        assert out["reached"] is True and out["depends"] is True
        row = _result_row("a1", "test_attested", 1, out)
        assert row["evidence_hash"] == out["evidence_hash"]
        assert row["reached"] is True and row["depends"] is True

    def test_unknown_facts_are_omitted_from_the_result(self, project, monkeypatch):
        from mipiti_verify.runner import Runner, _result_row

        _no_ci(monkeypatch)
        _attest(project)
        runner = Runner(client=MagicMock(), project_root=str(project), repo="acme/widgets")
        out = runner._verify_tier1({"id": "a1", "type": "test_attested", "params": {"test": TEST}})
        assert out["status"] == "pass"
        assert "reached" not in out and "depends" not in out
        row = _result_row("a1", "test_attested", 1, out)
        assert "reached" not in row and "depends" not in row


# ---------------------------------------------------------------------------
# E. Never skipped under --changed-files
# ---------------------------------------------------------------------------

class TestChangedFilesKeepsTestBacked:
    def _controls(self):
        return {"CTRL-01": [
            {"id": "a_src", "type": "function_exists", "params": {"file": "app/guard.py", "name": "require_token"}},
            {"id": "a_test_fn", "type": "function_exists", "params": {"file": "tests/test_guard.py", "name": "test_unrelated_arithmetic"}},
            {"id": "a_spec", "type": "class_exists", "params": {"file": "src/auth.spec.ts", "name": "AuthSpec"}},
            {"id": "a_attested", "type": "test_attested", "params": {"test": TEST, "file": "tests/test_guard.py"}},
            {"id": "a_exists", "type": "test_exists", "params": {"pattern": "tests/**/*.py", "file": "tests/x.py"}},
            {"id": "a_other", "type": "file_exists", "params": {"file": "README.md"}},
        ]}

    def test_test_backed_assertions_survive_the_filter(self, project):
        from mipiti_verify.runner import Runner

        client = MagicMock()
        client.get_pending.return_value = {"model_id": "m1", "controls": self._controls()}
        runner = Runner(client=client, project_root=str(project), repo="acme/widgets",
                        changed_files={"app/other.py"}, reverify=False, dry_run=True)
        _, _, kept = runner._run_tier("m1", tier=1)
        assert {a["id"] for a in kept} == {"a_test_fn", "a_spec", "a_attested", "a_exists"}

    def test_a_changed_source_file_is_still_verified(self, project):
        from mipiti_verify.runner import Runner

        client = MagicMock()
        client.get_pending.return_value = {"model_id": "m1", "controls": self._controls()}
        runner = Runner(client=client, project_root=str(project), repo="acme/widgets",
                        changed_files={"app/guard.py"}, reverify=False, dry_run=True)
        _, _, kept = runner._run_tier("m1", tier=1)
        assert "a_src" in {a["id"] for a in kept}
        assert "a_other" not in {a["id"] for a in kept}

    def test_verbose_reports_how_many_were_kept(self, project):
        from mipiti_verify import runner as runner_mod
        from mipiti_verify.runner import Runner

        client = MagicMock()
        client.get_pending.return_value = {"model_id": "m1", "controls": self._controls()}
        runner = Runner(client=client, project_root=str(project), repo="acme/widgets",
                        changed_files={"app/other.py"}, reverify=False, dry_run=True, verbose=True)
        with patch.object(runner_mod.console, "print") as printer:
            runner._run_tier("m1", tier=1)
        printed = " ".join(str(c.args[0]) for c in printer.call_args_list if c.args)
        assert "kept 4 test-backed" in printed

    def test_a_pattern_marks_tests_the_heuristic_misses(self, project):
        from mipiti_verify.runner import Runner

        controls = {"CTRL-01": [
            {"id": "a_spec", "type": "function_exists",
             "params": {"file": "specs/auth.py", "name": "verifies_token"}},
        ]}
        client = MagicMock()
        client.get_pending.return_value = {"model_id": "m1", "controls": controls}
        without = Runner(client=client, project_root=str(project), repo="acme/widgets",
                         changed_files={"app/other.py"}, reverify=False, dry_run=True)
        _, _, kept = without._run_tier("m1", tier=1)
        assert kept == []
        client.get_pending.return_value = {"model_id": "m1", "controls": controls}
        with_pattern = Runner(client=client, project_root=str(project), repo="acme/widgets",
                              changed_files={"app/other.py"}, reverify=False, dry_run=True,
                              test_file_pattern=r"^specs/")
        _, _, kept = with_pattern._run_tier("m1", tier=1)
        assert [a["id"] for a in kept] == ["a_spec"]

    def test_an_invalid_pattern_fails_fast(self, project):
        from mipiti_verify.runner import Runner

        with pytest.raises(ValueError, match="not a valid regular expression"):
            Runner(client=MagicMock(), project_root=str(project), repo="acme/widgets",
                   test_file_pattern="(unclosed")

    def test_cli_rejects_an_invalid_pattern_with_a_clear_message(self, project):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        with patch("mipiti_verify.cli.MipitiClient") as client_cls:
            client_cls.return_value.get_model.return_value = {"title": "t"}
            result = CliRunner().invoke(main, [
                "run", "m1", "--api-key", "mv_x", "--project-root", str(project),
                "--repo", "acme/widgets", "--test-file-pattern", "(unclosed",
            ])
        assert result.exit_code == 1
        assert "not a valid regular expression" in result.output

    @pytest.mark.parametrize("path,expected", [
        ("tests/test_guard.py", True), ("app/tests/x.py", True), ("src/__tests__/a.js", True),
        ("test/a.go", True), ("conftest.py", True), ("src/auth_test.go", True),
        ("src/auth.spec.ts", True), ("src/auth.test.js", True), ("src/auth_spec.rb", True),
        ("app/guard.py", False), ("src/attestation.py", False), ("testing/helpers.py", False),
    ])
    def test_test_file_heuristic(self, path, expected):
        from mipiti_verify.runner import _is_test_file

        assert _is_test_file(path) is expected

    def test_pattern_adds_to_the_heuristic_without_replacing_it(self):
        import re

        from mipiti_verify.runner import _is_test_file

        pattern = re.compile(r"^specs/")
        assert _is_test_file("specs/auth.py", pattern) is True
        assert _is_test_file("tests/test_x.py", pattern) is True
        assert _is_test_file("app/guard.py", pattern) is False


# ---------------------------------------------------------------------------
# F. The reviewer reads the closure
# ---------------------------------------------------------------------------

class _CapturingProvider:
    def __init__(self):
        self.seen = None

    def evaluate(self, *, assertion_type, assertion_params, source_code, subject_kind):
        self.seen = source_code
        return True, "ok"


class TestTier2ReadsTheClosure:
    def _review(self, project, params):
        from mipiti_verify.runner import Runner

        provider = _CapturingProvider()
        runner = Runner(client=MagicMock(), project_root=str(project),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider", return_value=provider):
            result = runner._verify_tier2({"id": "a1", "type": "test_attested", "params": params})
        return result, provider.seen

    def test_source_is_the_test_definition_the_mechanism_and_the_facts(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [5], f"tests/test_guard.py::{TEST}|run"))
        _attest_dependence(project, "failed")
        result, source = self._review(project, {"test": TEST, "mechanism": MECHANISM})
        assert result["status"] == "pass"
        assert "--- Test tests/test_guard.py::test_missing_token_is_refused ---" in source
        assert "def test_missing_token_is_refused(payload):" in source
        assert "--- Mechanism app/guard.py::require_token ---" in source
        assert "def require_token(request):" in source
        assert "--- Facts ---" in source
        assert "definition_sha256 matches attestation: yes" in source
        assert "reached mechanism: yes" in source
        assert "fails without mechanism: yes" in source
        # The whole statement is no longer what the reviewer is shown.
        assert "predicateType" not in source

    def test_facts_say_no_when_the_run_shows_no_dependence(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project, coverage=_coverage_for(project, [14], f"tests/test_guard.py::{TEST}|run"))
        _attest_dependence(project, "passed")
        _, source = self._review(project, {"test": TEST, "mechanism": MECHANISM})
        assert "reached mechanism: no" in source
        assert "fails without mechanism: no" in source

    def test_facts_are_unknown_without_coverage_or_dependence(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _, source = self._review(project, {"test": TEST, "mechanism": MECHANISM})
        assert "reached mechanism: unknown\n" in source
        assert "fails without mechanism: unknown" in source

    def test_facts_name_suite_level_coverage_as_the_reason_reach_is_unknown(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _attest_reach(project, [{"file": MECHANISM.split("::")[0], "lines": [5, 6]}], reach_scope="suite")
        _, source = self._review(project, {"test": TEST, "mechanism": MECHANISM})
        assert "reached mechanism: unknown (suite-level coverage only)" in source

    def test_a_changed_definition_is_reported_as_a_mismatch(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        src = (project / "tests" / "test_guard.py").read_text()
        (project / "tests" / "test_guard.py").write_text(
            src.replace("require_token(payload)", "require_token(dict(payload, token='x'))"))
        _, source = self._review(project, {"test": TEST})
        assert "definition_sha256 matches attestation: no" in source
        assert "reached mechanism" not in source  # no mechanism named

    def test_method_definition_is_shown_for_a_class_test(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _, source = self._review(project, {"test": "tests.test_guard.TestLimiter::test_over_limit_is_refused",
                                           "mechanism": "app/guard.py::Limiter"})
        assert "def test_over_limit_is_refused(self):" in source
        assert "--- Mechanism app/guard.py::Limiter ---" in source
        assert "class Limiter:" in source

    def test_falls_back_to_the_statement_without_a_located_definition(self, project, monkeypatch):
        _no_ci(monkeypatch)
        _attest(project)
        _, source = self._review(project, {"test": "test_nowhere"})
        assert "predicateType" in source
        assert "definition_sha256 matches attestation: unknown" in source

    def test_template_criterion_fails_closed_on_the_facts(self):
        template = (Path(__file__).resolve().parent.parent / "src" / "mipiti_verify"
                    / "templates" / "tier2_test_attested.j2").read_text()
        assert "exercises the named mechanism" in template
        assert '"fails without mechanism: no"' in template
        assert '"reached mechanism: no"' in template
        assert "is a NO regardless" in template
        assert "--- Facts ---" in template


# ---------------------------------------------------------------------------
# G. Schema
# ---------------------------------------------------------------------------

class TestSchema:
    def test_new_fields_validate_and_absence_still_validates(self, project):
        import jsonschema

        schema = json.loads((Path(__file__).resolve().parent.parent / "schemas"
                             / "test-result-v1.schema.json").read_text())
        summary = _summary(project, coverage=_coverage_for(project, [5], f"tests/test_guard.py::{TEST}|run"))
        predicate = build_statement(commit=COMMIT, summary=summary, invocation=["pytest"])["predicate"]
        jsonschema.validate(predicate, schema)
        dep = build_statement(commit=COMMIT, summary={
            "totals": {"total": 1, "passed": 0, "failed": 1, "skipped": 0, "errors": 0},
            "tests": [{"id": TEST, "name": TEST, "status": "failed",
                       "fails_without": [{"mechanism": MECHANISM, "status": "failed"}]}],
        }, invocation=[], kind="dependence")["predicate"]
        jsonschema.validate(dep, schema)
        bare = {k: v for k, v in predicate.items()}
        bare["tests"] = [{"name": "t", "status": "passed"}]
        jsonschema.validate(bare, schema)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(dict(predicate, kind="other"), schema)
