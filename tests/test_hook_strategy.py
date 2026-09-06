"""Strategy B: dependence and reach from a hook-instrumented build."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from mipiti_verify.hook import (
    REASON_CONTROL_FAILED, REASON_NO_MARKER, REASON_OTHER_HOOK, REASON_OUTSIDE,
    classify_hook_run, control_run, marker_within, parse_marker, run_hook_dependence,
    run_hook_reach,
)
from mipiti_verify.languages.adapters import AdapterError, Outcome, detect_adapter
from mipiti_verify.languages.adapters._common import REASON_NOT_ISOLATED

GO_GUARD = (
    "package guard\n\n"
    "// RequireToken refuses an empty token.\n"
    "func RequireToken(t string) bool {\n"
    "\tTripwire(\"guard.go::RequireToken\")\n"
    "\tif t == \"\" {\n\t\treturn false\n\t}\n"
    "\treturn true\n}\n"
)


@pytest.fixture
def go_root(tmp_path):
    (tmp_path / "guard.go").write_text(GO_GUARD)
    return tmp_path


class TestMarker:
    def test_parse(self):
        m = parse_marker("panic: mipiti-hook internal/auth/guard.go::RequireToken at /abs/internal/auth/guard.go:12\n\ngoroutine 1")
        assert m is not None
        assert (m.mechanism, m.file, m.line) == ("internal/auth/guard.go::RequireToken", "/abs/internal/auth/guard.go", 12)
        assert parse_marker("--- FAIL: TestX\nFAIL") is None
        assert parse_marker("mipiti-hook a.sv::module:alu at rtl\\a.sv:3").file == "rtl/a.sv"

    def test_marker_inside_span_credits(self, go_root):
        inside = parse_marker(f"mipiti-hook guard.go::RequireToken at {go_root / 'guard.go'}:5")
        assert marker_within(go_root, "guard.go::RequireToken", inside) == (True, "")
        assert marker_within(go_root, "guard.go::RequireToken",
                             parse_marker("mipiti-hook guard.go::RequireToken at guard.go:6")) == (True, "")

    def test_marker_outside_other_file_or_other_mechanism_refuses(self, go_root):
        ok, reason = marker_within(go_root, "guard.go::RequireToken",
                                   parse_marker("mipiti-hook guard.go::RequireToken at guard.go:1"))
        assert not ok and reason.startswith(REASON_OUTSIDE)
        ok, reason = marker_within(go_root, "guard.go::RequireToken",
                                   parse_marker("mipiti-hook guard.go::RequireToken at helpers/x.go:5"))
        assert not ok and reason.startswith(REASON_OUTSIDE)
        ok, reason = marker_within(go_root, "guard.go::RequireToken",
                                   parse_marker("mipiti-hook guard.go::Other at guard.go:5"))
        assert not ok and reason == REASON_OTHER_HOOK

    def test_a_definition_not_isolated_exactly_is_refused(self, tmp_path, monkeypatch):
        from mipiti_verify.languages import definitions as D

        (tmp_path / "guard.go").write_text(GO_GUARD)
        original = D.locate

        def block_only(content, kind, name, *, language=""):
            found = original(content, kind, name, language=language)
            return found._replace(scope=D.SCOPE_BLOCK) if found is not None else None

        monkeypatch.setattr(D, "locate", block_only)
        ok, reason = marker_within(tmp_path, "guard.go::RequireToken",
                                   parse_marker("mipiti-hook guard.go::RequireToken at guard.go:5"))
        assert not ok and REASON_NOT_ISOLATED in reason

    @pytest.mark.parametrize("status,note,output,expected", [
        ("passed", "", "", ("passed", "", "")),
        ("failed", "", "panic: mipiti-hook guard.go::RequireToken at guard.go:5", ("failed", "", "guard.go:5")),
        ("failed", "", "--- FAIL: TestX", ("error", REASON_NO_MARKER, "")),
        ("failed", "", "panic: mipiti-hook guard.go::RequireToken at guard.go:40", None),
        ("error", "go test selected no tests", "", ("error", "go test selected no tests", "")),
    ])
    def test_classification(self, go_root, status, note, output, expected):
        got = classify_hook_run(status, note, output, go_root, "guard.go::RequireToken")
        if expected is None:
            assert got[0] == "error" and got[1].startswith(REASON_OUTSIDE) and got[2] == "guard.go:40"
        else:
            assert got == expected


class _Fake:
    name = "fake"
    supports_hooks = True
    hook_refusal = ""

    def __init__(self, outputs: dict, build_error: str = ""):
        self.outputs = outputs
        self.build_error = build_error
        self.last_output = ""
        self.last_outcome = None
        self.runs: list[tuple[str, str]] = []
        self.built: list[str] = []

    def hook_build(self, tests, *, timeout, work_dir):
        self.built.append(list(tests))
        if self.build_error:
            raise AdapterError(self.build_error)

    def hook_run(self, test_id, mechanism, *, timeout):
        self.runs.append((test_id, mechanism))
        status, output = self.outputs.get((test_id, mechanism), self.outputs.get((test_id, "*"), ("passed", "")))
        self.last_output = output
        return Outcome(status, 0 if status == "passed" else 1)


class TestRun:
    def test_control_run_names_a_value_no_hook_answers_to(self):
        fake = _Fake({})
        control = control_run(fake, ["t1", "t2", "t1"], timeout=5)
        assert control["status"] == "passed" and control["mechanism"].startswith("mipiti-control-")
        assert [t["id"] for t in control["tests"]] == ["t1", "t2", "t1"]
        assert all(m == control["mechanism"] for _, m in fake.runs)

    def test_pairs_after_a_passing_control_run(self, go_root):
        fake = _Fake({
            ("TestRequires", "guard.go::RequireToken"): ("failed", "panic: mipiti-hook guard.go::RequireToken at guard.go:5"),
            ("TestUnrelated", "guard.go::RequireToken"): ("passed", ""),
            ("TestOther", "guard.go::RequireToken"): ("failed", "--- FAIL: TestOther"),
        })
        summary = run_hook_dependence(go_root, [
            ("TestRequires", "guard.go::RequireToken"), ("TestUnrelated", "guard.go::RequireToken"),
            ("TestOther", "guard.go::RequireToken"),
        ], adapter=fake)
        assert fake.built == [["TestRequires", "TestUnrelated", "TestOther"]]
        assert summary["strategy"] == "hook" and summary["control_run"]["status"] == "passed"
        by = {t["id"]: t["fails_without"][0] for t in summary["tests"]}
        assert by["TestRequires"] == {"mechanism": "guard.go::RequireToken", "status": "failed", "hook_location": "guard.go:5"}
        assert by["TestUnrelated"] == {"mechanism": "guard.go::RequireToken", "status": "passed"}
        assert by["TestOther"] == {"mechanism": "guard.go::RequireToken", "status": "error", "reason": REASON_NO_MARKER}
        assert summary["totals"] == {"total": 3, "passed": 1, "failed": 1, "skipped": 0, "errors": 1}

    def test_a_failing_control_run_stops_everything(self, go_root):
        fake = _Fake({("TestRequires", "*"): ("failed", "panic: mipiti-hook guard.go::RequireToken at guard.go:5")})
        summary = run_hook_dependence(go_root, [
            ("TestRequires", "guard.go::RequireToken"), ("TestUnrelated", "guard.go::RequireToken"),
        ], adapter=fake)
        assert summary["control_run"]["status"] == "failed"
        assert [t["fails_without"][0]["reason"] for t in summary["tests"]] == [REASON_CONTROL_FAILED] * 2
        assert all(m.startswith("mipiti-control-") for _, m in fake.runs)

    def test_a_failed_build_is_an_error_for_every_pair(self, go_root):
        fake = _Fake({}, build_error="go test -c failed: undefined: Tripwire")
        summary = run_hook_dependence(go_root, [("t", "guard.go::RequireToken")], adapter=fake)
        assert summary["control_run"] is None
        assert "hook build failed" in summary["tests"][0]["fails_without"][0]["reason"]

    def test_budget_across_pairs(self, go_root):
        fake = _Fake({})
        now = [0.0]

        def clock():
            now[0] += 100.0
            return now[0]

        summary = run_hook_dependence(go_root, [("a", "guard.go::RequireToken"), ("b", "guard.go::RequireToken")],
                                      adapter=fake, total_timeout=150, clock=clock)
        assert summary["tests"][1]["fails_without"][0]["reason"].startswith("not run")

    def test_runtime_runners_refuse_the_strategy(self, tmp_path):
        for name in ("pytest", "jest", "vitest", "mocha"):
            adapter = detect_adapter(tmp_path, name)
            assert not adapter.supports_hooks and "runtime" in adapter.hook_refusal
            with pytest.raises(Exception, match="runtime"):
                run_hook_dependence(tmp_path, [("t", "a.py::f")], adapter=adapter)
        for name in ("go", "cargo", "command"):
            assert detect_adapter(tmp_path, name, run_cmd="x {test}").supports_hooks


class TestCli:
    def test_hook_strategy_writes_strategy_and_control_run(self, tmp_path, monkeypatch):
        from click.testing import CliRunner
        from unittest.mock import patch

        from mipiti_verify.attestation import ATTESTATION_DIR, statement_of
        from mipiti_verify.cli import main

        for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL", "GITHUB_SHA",
                    "MIPITI_ATTESTATION_PUBLIC_KEY"):
            monkeypatch.delenv(var, raising=False)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("a" * 40)
        (tmp_path / "guard.go").write_text(GO_GUARD)

        def fake_run(argv, **kwargs):
            mech = kwargs["env"].get("MIPITI_DISABLE_MECHANISM", "")
            if argv[:1] == ["build"]:
                return subprocess.CompletedProcess(argv, 0, "built", "")
            if argv[-1] == "TestRequires" and mech == "guard.go::RequireToken":
                return subprocess.CompletedProcess(argv, 1, "panic: mipiti-hook guard.go::RequireToken at guard.go:5", "")
            return subprocess.CompletedProcess(argv, 0, "ok", "")

        with patch("mipiti_verify.languages.adapters._common.subprocess.run", fake_run):
            result = CliRunner().invoke(main, [
                "attest-dependence", "--project-root", str(tmp_path), "--strategy", "hook",
                "--build-cmd", "build hooks", "--run-cmd", "run {test}",
                "--pair", "TestRequires=guard.go::RequireToken",
                "--pair", "TestUnrelated=guard.go::RequireToken",
            ])
        assert result.exit_code == 0, result.output
        assert "Control run: passed (2 test(s))" in result.output
        predicate = statement_of(next((tmp_path / ATTESTATION_DIR).glob("*-dependence.json")).read_text())["predicate"]
        assert predicate["strategy"] == "hook" and predicate["control_run"]["status"] == "passed"
        assert predicate["invocation"][-2:] == ["--strategy", "hook"]
        assert predicate["tests"][0]["fails_without"][0]["hook_location"] == "guard.go:5"
        assert predicate["tests"][1]["fails_without"][0]["status"] == "passed"

    def test_pytest_refuses(self, tmp_path):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        (tmp_path / "pytest.ini").write_text("[pytest]\n")
        result = CliRunner().invoke(main, ["attest-dependence", "--project-root", str(tmp_path),
                                           "--strategy", "hook", "--commit", "a" * 40, "--pair", "t=a.py::f"])
        assert result.exit_code == 1 and "omit --strategy hook" in result.output


# ---------------------------------------------------------------------------
# End to end with Go
# ---------------------------------------------------------------------------

needs_go = pytest.mark.skipif(shutil.which("go") is None, reason="go is not installed")

HOOKS_ON = (
    "//go:build mipiti_hooks\n\npackage guard\n\n"
    "import (\n\t\"fmt\"\n\t\"os\"\n\t\"runtime\"\n)\n\n"
    "func Tripwire(id string) {\n"
    "\tif os.Getenv(\"MIPITI_DISABLE_MECHANISM\") != id {\n\t\treturn\n\t}\n"
    "\t_, file, line, _ := runtime.Caller(1)\n"
    "\tpanic(fmt.Sprintf(\"mipiti-hook %s at %s:%d\", id, file, line))\n}\n"
)
HOOKS_OFF = "//go:build !mipiti_hooks\n\npackage guard\n\nfunc Tripwire(string) {}\n"
GO_TEST = (
    "package guard\n\nimport \"testing\"\n\n"
    "func TestRequiresToken(t *testing.T) {\n"
    "\tif RequireToken(\"\") { t.Fatal(\"empty token accepted\") }\n"
    "\tif !RequireToken(\"x\") { t.Fatal(\"token refused\") }\n}\n\n"
    "func TestUnrelated(t *testing.T) {\n\tif 1+1 != 2 { t.Fatal(\"arithmetic\") }\n}\n"
)


def _go_project(root: Path, files: dict[str, str], monkeypatch) -> None:
    for name, body in files.items():
        (root / name).write_text(body)
    monkeypatch.setenv("GOTOOLCHAIN", "local")
    monkeypatch.setenv("GOFLAGS", "-mod=mod")


@needs_go
class TestGoEndToEnd:
    def test_build_once_control_passes_pairs_true_and_false(self, tmp_path, monkeypatch):
        _go_project(tmp_path, {
            "go.mod": "module example.com/guard\n\ngo 1.21\n",
            "guard.go": GO_GUARD, "hooks_on.go": HOOKS_ON, "hooks_off.go": HOOKS_OFF,
            "guard_test.go": GO_TEST,
        }, monkeypatch)
        adapter = detect_adapter(tmp_path)
        assert adapter.name == "go"
        # Not a git checkout and never needs to be: nothing is rewritten.
        summary = run_hook_dependence(tmp_path, [
            ("TestRequiresToken", "guard.go::RequireToken"),
            ("TestUnrelated", "guard.go::RequireToken"),
        ], adapter=adapter, timeout=600)
        assert summary["control_run"]["status"] == "passed"
        by = {t["id"]: t["fails_without"][0] for t in summary["tests"]}
        assert by["TestRequiresToken"]["status"] == "failed"
        assert by["TestRequiresToken"]["hook_location"].endswith("guard.go:5")
        assert by["TestUnrelated"] == {"mechanism": "guard.go::RequireToken", "status": "passed"}
        assert (tmp_path / "guard.go").read_text() == GO_GUARD

        reach = run_hook_reach(tmp_path, [
            ("TestRequiresToken", "guard.go::RequireToken"),
            ("TestUnrelated", "guard.go::RequireToken"),
        ], adapter=adapter, timeout=600)
        assert reach["strategy"] == "hook"
        by = {t["id"]: t for t in reach["tests"]}
        assert {5, 6, 9} <= set(by["TestRequiresToken"]["reached"][0]["lines"])
        assert by["TestUnrelated"]["reached"] == []

    def test_a_tripwire_in_a_test_helper_fails_the_control_run(self, tmp_path, monkeypatch):
        # The helper fires on any value at all, which a hook that answers
        # only to its own id never does; the control run is what catches it.
        helper_on = HOOKS_ON.replace('if os.Getenv("MIPITI_DISABLE_MECHANISM") != id {',
                                     'if os.Getenv("MIPITI_DISABLE_MECHANISM") == "" {')
        test_src = GO_TEST.replace("func TestRequiresToken(t *testing.T) {\n",
                                   "func setup() { Tripwire(\"guard.go::RequireToken\") }\n\n"
                                   "func TestRequiresToken(t *testing.T) {\n\tsetup()\n") \
                          .replace("func TestUnrelated(t *testing.T) {\n", "func TestUnrelated(t *testing.T) {\n\tsetup()\n")
        _go_project(tmp_path, {
            "go.mod": "module example.com/guard\n\ngo 1.21\n",
            "guard.go": GO_GUARD.replace("\tTripwire(\"guard.go::RequireToken\")\n", ""),
            "hooks_on.go": helper_on, "hooks_off.go": HOOKS_OFF, "guard_test.go": test_src,
        }, monkeypatch)
        summary = run_hook_dependence(tmp_path, [
            ("TestRequiresToken", "guard.go::RequireToken"),
            ("TestUnrelated", "guard.go::RequireToken"),
        ], adapter=detect_adapter(tmp_path), timeout=600)
        assert summary["control_run"]["status"] == "failed"
        assert all(t["fails_without"][0]["reason"] == REASON_CONTROL_FAILED for t in summary["tests"])
