"""End-to-end runs through real toolchains, each gated on the tool being
installed. Every test builds a fresh checkout with a mechanism and two
tests, one that depends on the mechanism and one that does not, and checks
that the dependence fact comes out true for the first and false for the
second, that the tree is restored, and where the toolchain has a coverage
tool, that reach names the mechanism's lines."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mipiti_verify.dependence import run_dependence
from mipiti_verify.languages.adapters import detect_adapter
from mipiti_verify.reach import run_reach


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t",
                    "-c", "commit.gpgsign=false", *args],
                   cwd=root, check=True, capture_output=True)


def _checkout(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")


def _facts(summary: dict) -> dict[str, str]:
    return {t["id"]: t["fails_without"][0]["status"] for t in summary["tests"]}


def _reasons(summary: dict) -> dict[str, str]:
    return {t["id"]: t["fails_without"][0].get("reason", "") for t in summary["tests"]}


# A tool absent from the machine skips its test, so the suite runs anywhere.
# That makes a skip invisible in a green run: fine while the absence is a fact
# about a developer's laptop, not fine where a job was configured to install
# the tool, because there a skip means the install stopped working and the
# coverage went away without saying so. ``MIPITI_TEST_REQUIRE_TOOLCHAINS``
# names the tools a caller has undertaken to provide;
# ``test_the_declared_toolchains_are_installed`` fails when one is not there,
# so the gates below stay plain skips and the guarantee is stated once.
REQUIRED_TOOLS = sorted(set(os.environ.get("MIPITI_TEST_REQUIRE_TOOLCHAINS", "").split()))


def test_the_declared_toolchains_are_installed():
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    assert not missing, (
        f"MIPITI_TEST_REQUIRE_TOOLCHAINS names {missing} but they are not on PATH, "
        "so the tests that need them would report as skipped and this suite would "
        "stay green while covering nothing. Install them, or drop them from the "
        "variable to say the coverage is not expected here"
    )


# The command-runner tests wrap their toolchain in ``sh -c``; a runner
# without a POSIX shell skips them rather than failing on the wrapper.
needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX shell (sh) on this runner")
needs_go = pytest.mark.skipif(shutil.which("go") is None, reason="go is not installed")
needs_cc = pytest.mark.skipif(shutil.which("cc") is None, reason="cc is not installed")
needs_javac = pytest.mark.skipif(shutil.which("javac") is None or shutil.which("java") is None,
                                 reason="javac/java are not installed")
needs_swiftc = pytest.mark.skipif(shutil.which("swiftc") is None, reason="swiftc is not installed")
needs_iverilog = pytest.mark.skipif(shutil.which("iverilog") is None or shutil.which("vvp") is None,
                                    reason="iverilog is not installed")
# Either analyser satisfies a VHDL check, exactly as ``checks.check_vhdl``
# accepts either; the test drives whichever this machine has.
VHDL_TOOL = "ghdl" if shutil.which("ghdl") else ("nvc" if shutil.which("nvc") else "")
needs_vhdl = pytest.mark.skipif(not VHDL_TOOL,
                                reason="no VHDL analyser (ghdl or nvc) is installed")
needs_coverage = pytest.mark.skipif(
    subprocess.run([sys.executable, "-c", "import coverage"], capture_output=True).returncode != 0,
    reason="coverage.py is not installed")

NODE_MODULES = os.environ.get("MIPITI_TEST_NODE_MODULES", "")
needs_vitest = pytest.mark.skipif(
    not (NODE_MODULES and (Path(NODE_MODULES) / ".bin" / "vitest").exists() and shutil.which("node")),
    reason="set MIPITI_TEST_NODE_MODULES to a node_modules directory that has vitest installed")


@needs_go
class TestGo:
    FILES = {
        "go.mod": "module example.com/guard\n\ngo 1.21\n",
        "guard.go": (
            "package guard\n\n"
            "// RequireToken refuses an empty token.\n"
            "func RequireToken(t string) bool {\n"
            "\tif t == \"\" {\n\t\treturn false\n\t}\n"
            "\treturn true\n}\n"
        ),
        "guard_test.go": (
            "package guard\n\nimport \"testing\"\n\n"
            "func TestRequiresToken(t *testing.T) {\n"
            "\tif RequireToken(\"\") { t.Fatal(\"empty token accepted\") }\n"
            "\tif !RequireToken(\"x\") { t.Fatal(\"token refused\") }\n}\n\n"
            "func TestUnrelated(t *testing.T) {\n\tif 1+1 != 2 { t.Fatal(\"arithmetic\") }\n}\n"
        ),
    }

    @pytest.fixture
    def project(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GOTOOLCHAIN", "local")
        monkeypatch.setenv("GOFLAGS", "-mod=mod")
        _checkout(tmp_path, self.FILES)
        return tmp_path

    def test_dependence_true_and_false(self, project):
        summary = run_dependence(project, [
            ("TestRequiresToken", "guard.go::RequireToken"),
            ("TestUnrelated", "guard.go::RequireToken"),
            ("TestNowhere", "guard.go::RequireToken"),
        ], timeout=600)
        assert summary["runner"] == "go"
        facts = _facts(summary)
        assert facts["TestRequiresToken"] == "failed"
        assert facts["TestUnrelated"] == "passed"
        assert facts["TestNowhere"] == "error"
        assert "no tests" in _reasons(summary)["TestNowhere"]
        assert (project / "guard.go").read_text() == self.FILES["guard.go"]
        assert not subprocess.run(["git", "status", "--porcelain"], cwd=project,
                                  capture_output=True, text=True).stdout.strip()

    def test_reach_names_the_mechanism_lines(self, project):
        adapter = detect_adapter(project)
        summary = run_reach(project, [
            ("TestRequiresToken", "guard.go::RequireToken"),
            ("TestUnrelated", "guard.go::RequireToken"),
        ], adapter=adapter, timeout=600)
        by_id = {t["id"]: t for t in summary["tests"]}
        reached = by_id["TestRequiresToken"]["reached"]
        assert reached and reached[0]["file"] == "guard.go"
        assert {5, 6, 8} <= set(reached[0]["lines"])
        assert by_id["TestUnrelated"]["reached"] == []
        assert by_id["TestRequiresToken"]["status"] == "passed"


@needs_coverage
class TestPytestReach:
    def test_reach_through_coverage_py(self, tmp_path, monkeypatch):
        _checkout(tmp_path, {
            "pytest.ini": "[pytest]\n",
            "app/__init__.py": "",
            "app/guard.py": "def require_token(t):\n    if not t:\n        raise PermissionError()\n    return True\n",
            "tests/__init__.py": "",
            "tests/test_guard.py": (
                "import pytest\nfrom app.guard import require_token\n\n"
                "def test_refuses():\n    with pytest.raises(PermissionError):\n        require_token('')\n\n"
                "def test_unrelated():\n    assert 1 + 1 == 2\n"
            ),
        })
        monkeypatch.setenv("PYTHONPATH", str(tmp_path))
        adapter = detect_adapter(tmp_path)
        assert adapter.name == "pytest"
        summary = run_reach(tmp_path, [
            ("tests/test_guard.py::test_refuses", "app/guard.py::require_token"),
            ("tests/test_guard.py::test_unrelated", "app/guard.py::require_token"),
        ], adapter=adapter, timeout=300)
        by_id = {t["id"]: t for t in summary["tests"]}
        assert {2, 3} <= set(by_id["tests/test_guard.py::test_refuses"]["reached"][0]["lines"])
        # The module is imported (its def line runs) but the body is not.
        unrelated = by_id["tests/test_guard.py::test_unrelated"]["reached"]
        assert not unrelated or 3 not in unrelated[0]["lines"]


@needs_sh
@needs_cc
class TestC:
    FILES = {
        "guard.h": "int require_token(const char *t);\n",
        "guard.c": "#include \"guard.h\"\n\nint require_token(const char *t) {\n    return t != 0 && t[0] != 0;\n}\n",
        "test_guard.c": (
            "#include <string.h>\n#include \"guard.h\"\n"
            "int main(int argc, char **argv) {\n"
            "    if (argc > 1 && strcmp(argv[1], \"unrelated\") == 0) return 1 + 1 == 2 ? 0 : 1;\n"
            "    return require_token(\"\") == 0 && require_token(\"x\") == 1 ? 0 : 1;\n}\n"
        ),
    }

    def test_dependence_through_the_command_runner(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        adapter = detect_adapter(
            tmp_path, run_cmd='sh -c "cc -o t_bin test_guard.c guard.c && ./t_bin {test} || exit 1"')
        summary = run_dependence(tmp_path, [
            ("requires_token", "guard.c::require_token"),
            ("unrelated", "guard.c::require_token"),
        ], adapter=adapter, timeout=300)
        facts = _facts(summary)
        assert facts == {"requires_token": "failed", "unrelated": "passed"}
        assert (tmp_path / "guard.c").read_text() == self.FILES["guard.c"]


@needs_sh
@needs_javac
class TestJava:
    FILES = {
        "Guard.java": "public class Guard {\n    public static boolean requireToken(String t) {\n        return t != null && !t.isEmpty();\n    }\n}\n",
        "GuardTest.java": (
            "public class GuardTest {\n"
            "    public static void main(String[] args) {\n"
            "        if (args.length > 0 && args[0].equals(\"unrelated\")) { System.exit(1 + 1 == 2 ? 0 : 1); }\n"
            "        boolean ok = !Guard.requireToken(\"\") && Guard.requireToken(\"x\");\n"
            "        System.exit(ok ? 0 : 1);\n    }\n}\n"
        ),
    }

    def test_dependence_with_javac_compile_check(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        adapter = detect_adapter(
            tmp_path, run_cmd='sh -c "javac -d out Guard.java GuardTest.java && java -cp out GuardTest {test} || exit 1"')
        summary = run_dependence(tmp_path, [
            ("requires_token", "Guard.java::requireToken"),
            ("unrelated", "Guard.java::Guard.requireToken"),
        ], adapter=adapter, timeout=600)
        assert _facts(summary) == {"requires_token": "failed", "unrelated": "passed"}
        assert (tmp_path / "Guard.java").read_text() == self.FILES["Guard.java"]


@needs_sh
@needs_swiftc
class TestSwift:
    FILES = {
        "Guard.swift": "func requireToken(_ t: String?) -> Bool {\n    guard let t = t, !t.isEmpty else { return false }\n    return true\n}\n",
        "main.swift": (
            "import Foundation\n"
            "if CommandLine.arguments.count > 1 && CommandLine.arguments[1] == \"unrelated\" { exit(1 + 1 == 2 ? 0 : 1) }\n"
            "exit(!requireToken(\"\") && requireToken(\"x\") ? 0 : 1)\n"
        ),
    }

    def test_dependence_with_swiftc_typecheck(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        adapter = detect_adapter(
            tmp_path, run_cmd='sh -c "swiftc -o t_bin Guard.swift main.swift 2>/dev/null && ./t_bin {test} || exit 1"')
        summary = run_dependence(tmp_path, [
            ("requires_token", "Guard.swift::requireToken"),
            ("unrelated", "Guard.swift::requireToken"),
        ], adapter=adapter, timeout=600)
        assert _facts(summary) == {"requires_token": "failed", "unrelated": "passed"}
        assert (tmp_path / "Guard.swift").read_text() == self.FILES["Guard.swift"]


@needs_sh
@needs_iverilog
class TestIcarus:
    FILES = {
        "guard.v": "module guard(input a, output y);\n  assign y = ~a;\nendmodule\n",
        "tb.v": (
            "module tb;\n  reg a; wire y;\n  guard dut(.a(a), .y(y));\n"
            "  initial begin\n    a = 1'b1; #1;\n"
            "    if ($test$plusargs(\"unrelated\")) begin $display(\"PASS\"); $finish; end\n"
            "    if (y === 1'bx) $fatal(1, \"y is x\");\n"
            "    if (y !== 1'b0) $fatal(1, \"y wrong\");\n"
            "    $display(\"PASS\"); $finish;\n  end\nendmodule\n"
        ),
    }

    def test_dependence_through_icarus(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        adapter = detect_adapter(
            tmp_path, run_cmd='sh -c "iverilog -g2012 -o sim.vvp tb.v guard.v && vvp -N sim.vvp +{test} || exit 1"')
        summary = run_dependence(tmp_path, [
            ("tb_guard", "guard.v::module:guard"),
            ("unrelated", "guard.v::guard"),
        ], adapter=adapter, timeout=300)
        assert _facts(summary) == {"tb_guard": "failed", "unrelated": "passed"}
        assert (tmp_path / "guard.v").read_text() == self.FILES["guard.v"]


@needs_sh
@needs_iverilog
class TestIcarusNonAnsi:
    """A non-ANSI module: the stub re-emits the body port declarations, so
    the mutated file still elaborates through the lint gate, and every
    output reads ``x`` in the simulation."""

    FILES = {
        "guard.v": (
            "module guard(clk, a, y, z);\n  input clk;\n  input a;\n  output y;\n"
            "  output reg z;\n  assign y = ~a;\n  always @(posedge clk) z <= a;\nendmodule\n"
        ),
        "tb.v": (
            "module tb;\n  reg clk, a; wire y, z;\n  guard dut(.clk(clk), .a(a), .y(y), .z(z));\n"
            "  initial begin\n    clk = 0; a = 1'b1; #1 clk = 1; #1;\n"
            "    if ($test$plusargs(\"unrelated\")) begin $display(\"PASS\"); $finish; end\n"
            "    if (y === 1'bx || z === 1'bx) $fatal(1, \"an output is x\");\n"
            "    if (y !== 1'b0 || z !== 1'b1) $fatal(1, \"an output is wrong\");\n"
            "    $display(\"PASS\"); $finish;\n  end\nendmodule\n"
        ),
    }

    def test_dependence_through_icarus(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        adapter = detect_adapter(
            tmp_path, run_cmd='sh -c "iverilog -g2012 -o sim.vvp tb.v guard.v && vvp -N sim.vvp +{test} || exit 1"')
        summary = run_dependence(tmp_path, [
            ("tb_guard", "guard.v::module:guard"),
            ("unrelated", "guard.v::guard"),
        ], adapter=adapter, timeout=300)
        assert _facts(summary) == {"tb_guard": "failed", "unrelated": "passed"}
        assert _reasons(summary) == {"tb_guard": "", "unrelated": ""}
        assert (tmp_path / "guard.v").read_text() == self.FILES["guard.v"]


@needs_vitest
class TestVitest:
    FILES = {
        "package.json": '{"name": "g", "type": "module", "devDependencies": {"vitest": "*"}}\n',
        "src/guard.js": "export function requireToken(t) {\n  if (!t) throw new Error('no token');\n  return true;\n}\n",
        "src/guard.test.js": (
            "import { expect, test } from 'vitest';\nimport { requireToken } from './guard.js';\n\n"
            "test('refuses a missing token', () => { expect(() => requireToken('')).toThrow('no token'); });\n"
            "test('unrelated', () => { expect(1 + 1).toBe(2); });\n"
        ),
    }

    def test_dependence_through_a_mocking_setup_file(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        os.symlink(NODE_MODULES, tmp_path / "node_modules")
        adapter = detect_adapter(tmp_path)
        assert adapter.name == "vitest"
        summary = run_dependence(tmp_path, [
            ("src/guard.test.js::refuses a missing token", "src/guard.js::requireToken"),
            ("src/guard.test.js::unrelated", "src/guard.js::requireToken"),
            ("src/guard.test.js::nowhere", "src/guard.js::requireToken"),
        ], adapter=adapter, timeout=600)
        facts = _facts(summary)
        assert facts["src/guard.test.js::refuses a missing token"] == "failed"
        assert facts["src/guard.test.js::unrelated"] == "passed"
        assert facts["src/guard.test.js::nowhere"] == "error"
        assert not list(tmp_path.glob(".mipiti-vitest-*"))

    def test_reach_without_a_coverage_provider_is_a_reasoned_error(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        os.symlink(NODE_MODULES, tmp_path / "node_modules")
        adapter = detect_adapter(tmp_path)
        summary = run_reach(tmp_path, [
            ("src/guard.test.js::refuses a missing token", "src/guard.js::requireToken"),
        ], adapter=adapter, timeout=600)
        entry = summary["tests"][0]
        if entry["status"] == "error":
            assert "coverage" in entry["reason"]
        else:
            assert entry["reached"] and entry["reached"][0]["file"] == "src/guard.js"


@needs_sh
@needs_vhdl
class TestVhdl:
    """A VHDL architecture: emptying its body leaves the outputs undriven, so
    the testbench that reads one fails and the one that does not still passes.

    VHDL has no plusargs, so the two tests are two top-level entities and
    ``{test}`` names the one to elaborate and run -- the same shape the Icarus
    tests get from ``+{test}``.
    """

    FILES = {
        "guard.vhd": (
            "library ieee;\nuse ieee.std_logic_1164.all;\n\n"
            "entity guard is\n  port (a : in std_logic; y : out std_logic);\nend entity;\n\n"
            "architecture rtl of guard is\nbegin\n  y <= not a;\nend architecture;\n"
        ),
        "tb.vhd": (
            "library ieee;\nuse ieee.std_logic_1164.all;\n\n"
            "entity tb_guard is\nend entity;\n\n"
            "architecture sim of tb_guard is\n"
            "  signal a : std_logic := '1';\n  signal y : std_logic;\n"
            "begin\n"
            "  dut : entity work.guard port map (a => a, y => y);\n"
            "  check : process\n  begin\n    wait for 1 ns;\n"
            "    assert y = '0' report \"y is not driven low\" severity failure;\n"
            "    report \"PASS\";\n    wait;\n  end process;\n"
            "end architecture;\n\n"
            "entity unrelated is\nend entity;\n\n"
            "architecture sim of unrelated is\nbegin\n"
            "  check : process\n  begin\n    wait for 1 ns;\n"
            "    assert true report \"unreachable\" severity failure;\n"
            "    report \"PASS\";\n    wait;\n  end process;\n"
            "end architecture;\n"
        ),
    }

    #: ``ghdl`` and ``nvc`` take different arguments for the same three steps,
    #: so the command is built for whichever the machine has -- the choice
    #: ``checks.check_vhdl`` makes for the compile gate, made here for the run.
    RUN = {
        "ghdl": 'sh -c "ghdl -a --std=08 guard.vhd tb.vhd && ghdl -e --std=08 {test} && ghdl -r --std=08 {test}"',
        "nvc": 'sh -c "nvc --std=2008 -a guard.vhd tb.vhd && nvc --std=2008 -e {test} && nvc --std=2008 -r {test}"',
    }

    def test_dependence_through_the_vhdl_analyser(self, tmp_path):
        _checkout(tmp_path, self.FILES)
        adapter = detect_adapter(tmp_path, run_cmd=self.RUN[VHDL_TOOL])
        summary = run_dependence(tmp_path, [
            ("tb_guard", "guard.vhd::architecture:rtl"),
            ("unrelated", "guard.vhd::architecture:rtl"),
        ], adapter=adapter, timeout=300)
        assert _facts(summary) == {"tb_guard": "failed", "unrelated": "passed"}
        assert (tmp_path / "guard.vhd").read_text() == self.FILES["guard.vhd"]
