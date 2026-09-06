"""Runner adapters: detection, one-test selection, outcome mapping, the
coverage converters, and the source mutations every language gets."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from mipiti_verify.languages.adapters import (
    AdapterError, DisableError, adapter_names, detect_adapter, parse_mechanism,
)
from mipiti_verify.languages.adapters._common import mutated_file
from mipiti_verify.languages.adapters.coverage_convert import (
    clover_to_lcov, go_coverprofile_to_lcov, lines_from_lcov, simplecov_resultset_to_lcov,
)
from mipiti_verify.languages.adapters.hdl import mutate_verilog, mutate_vhdl
from mipiti_verify.languages.adapters.mutation import mutate_source

DISABLED = "mipiti: mechanism disabled"


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t",
                    "-c", "commit.gpgsign=false", *args],
                   cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    return tmp_path


def _commit_all(root: Path) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_names(self):
        assert adapter_names() == [
            "pytest", "jest", "vitest", "mocha", "go", "cargo", "maven", "gradle",
            "dotnet", "rspec", "phpunit", "command"]

    @pytest.mark.parametrize("files,expected", [
        ({"pytest.ini": ""}, "pytest"),
        ({"pyproject.toml": "[tool.pytest.ini_options]\n"}, "pytest"),
        ({"setup.cfg": ""}, "pytest"),
        ({"package.json": '{"devDependencies": {"jest": "^29"}}'}, "jest"),
        ({"package.json": '{"devDependencies": {"vitest": "^1"}}'}, "vitest"),
        ({"package.json": "{}", "vitest.config.ts": ""}, "vitest"),
        ({"package.json": '{"devDependencies": {"mocha": "^10"}}'}, "mocha"),
        ({"package.json": "{}", ".mocharc.yml": ""}, "mocha"),
        ({"go.mod": "module x\n"}, "go"),
        ({"Cargo.toml": ""}, "cargo"),
        ({"pom.xml": ""}, "maven"),
        ({"build.gradle.kts": ""}, "gradle"),
        ({"app.csproj": ""}, "dotnet"),
        ({"app.sln": ""}, "dotnet"),
        ({"Gemfile": "", ".rspec": ""}, "rspec"),
        ({"phpunit.xml.dist": ""}, "phpunit"),
        ({}, "pytest"),
    ])
    def test_detection_by_project_files(self, tmp_path, files, expected):
        for name, body in files.items():
            (tmp_path / name).write_text(body)
        assert detect_adapter(tmp_path).name == expected

    def test_run_cmd_selects_the_command_adapter(self, tmp_path):
        (tmp_path / "go.mod").write_text("module x\n")
        adapter = detect_adapter(tmp_path, run_cmd="make sim TEST={test}")
        assert adapter.name == "command"
        assert adapter.select_argv("t1") == ["make", "sim", "TEST=t1"]

    def test_override_wins_and_unknown_is_refused(self, tmp_path):
        (tmp_path / "go.mod").write_text("module x\n")
        assert detect_adapter(tmp_path, "pytest").name == "pytest"
        with pytest.raises(AdapterError):
            detect_adapter(tmp_path, "nose")

    def test_mechanism_language_breaks_a_polyglot_tie(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
        (tmp_path / "go.mod").write_text("module x\n")
        assert detect_adapter(tmp_path).name == "pytest"
        assert detect_adapter(tmp_path, prefer_language="go").name == "go"

    def test_command_template_keeps_a_test_id_with_spaces_as_one_argument(self, tmp_path):
        adapter = detect_adapter(tmp_path, run_cmd='make sim "TEST={test}"')
        assert adapter.select_argv("a b") == ["make", "sim", "TEST=a b"]


# ---------------------------------------------------------------------------
# Selection and outcome mapping per adapter
# ---------------------------------------------------------------------------

class TestSelection:
    def test_pytest(self, tmp_path):
        a = detect_adapter(tmp_path, "pytest")
        assert a.select_argv("tests/test_x.py::test_y")[-1] == "tests/test_x.py::test_y"
        assert a.select_argv("test_y")[-2:] == ["-k", "test_y"]
        assert a.classify(5, "", "").status == "error"
        assert a.classify(1, "", "").status == "failed"

    def test_jest(self, tmp_path):
        a = detect_adapter(tmp_path, "jest")
        argv = a.select_argv("src/auth.test.js::rejects a missing token")
        assert argv[-4:] == ["--runTestsByPath", "src/auth.test.js", "-t", "^rejects a missing token$"]
        assert a.classify(1, "No tests found, exiting with code 1", "").status == "error"
        assert a.classify(1, "Tests:       1 failed, 1 total", "").status == "failed"
        assert a.classify(1, "", "Error: Cannot find module").status == "error"

    def test_vitest(self, tmp_path):
        a = detect_adapter(tmp_path, "vitest")
        argv = a.select_argv("src/auth.test.ts::rejects")
        assert argv[-3:] == ["src/auth.test.ts", "-t", "^rejects$"]
        assert "run" in argv
        assert a.classify(1, "No test files found", "").status == "error"

    def test_mocha_counts_decide(self, tmp_path):
        a = detect_adapter(tmp_path, "mocha")
        assert a.select_argv("test/auth.js::rejects")[-3:] == ["test/auth.js", "-g", "^rejects$"]
        assert a.classify(0, "  0 passing (5ms)", "").status == "error"
        assert a.classify(0, "  1 passing (5ms)", "").status == "passed"
        assert a.classify(2, "  1 passing\n  2 failing", "").status == "failed"

    def test_go(self, tmp_path):
        a = detect_adapter(tmp_path, "go")
        assert a.select_argv("TestGuard") == ["go", "test", "-count=1", "-run", "^TestGuard$", "./..."]
        assert a.select_argv("internal/auth::TestGuard/Sub")[-2:] == ["^TestGuard$/^Sub$", "./internal/auth"]
        assert a.classify(0, "testing: warning: no tests to run\nok  x 0.1s", "").status == "error"
        assert a.classify(1, "FAIL x [build failed]", "").status == "error"
        assert a.classify(1, "--- FAIL: TestGuard\nFAIL", "").status == "failed"
        assert a.classify(0, "ok  x 0.1s", "").status == "passed"

    def test_cargo(self, tmp_path):
        a = detect_adapter(tmp_path, "cargo")
        assert a.select_argv("src/lib.rs::tests::guard")[2:] == ["--quiet", "tests::guard", "--", "--exact"]
        assert a.classify(101, "", "error[E0425]: cannot find value\nerror: could not compile").status == "error"
        assert a.classify(0, "running 0 tests", "").status == "error"
        assert a.classify(101, "running 1 test\ntest tests::guard ... FAILED", "").status == "failed"

    def test_maven_and_gradle(self, tmp_path):
        m = detect_adapter(tmp_path, "maven")
        assert "-Dtest=GuardTest#rejects" in m.select_argv("GuardTest::rejects")
        assert "-Dtest=com.x.GuardTest#rejects" in m.select_argv("com.x.GuardTest.rejects")
        assert m.classify(1, "[ERROR] COMPILATION ERROR", "").status == "error"
        assert m.classify(1, "No tests were executed!", "").status == "error"
        assert m.classify(1, "Tests run: 1, Failures: 1", "").status == "failed"
        g = detect_adapter(tmp_path, "gradle")
        assert g.select_argv("GuardTest::rejects")[-3:] == ["--tests", "GuardTest.rejects", "-q"]
        assert g.classify(1, "No tests found for given includes", "").status == "error"

    def test_dotnet(self, tmp_path):
        a = detect_adapter(tmp_path, "dotnet")
        assert a.select_argv("GuardTests::Rejects")[-1] == "FullyQualifiedName~GuardTests.Rejects"
        assert a.select_argv("App.Tests.GuardTests.Rejects")[-1] == "FullyQualifiedName=App.Tests.GuardTests.Rejects"
        assert a.classify(0, "No test matches the given testcase filter", "").status == "error"
        assert a.classify(1, "", "error CS0103").status == "error"

    def test_rspec_and_phpunit(self, tmp_path):
        r = detect_adapter(tmp_path, "rspec")
        assert r.select_argv("spec/guard_spec.rb::rejects")[-3:] == ["spec/guard_spec.rb", "-e", "rejects"]
        assert r.classify(0, "0 examples, 0 failures", "").status == "error"
        assert r.classify(1, "1 example, 1 failure", "").status == "failed"
        p = detect_adapter(tmp_path, "phpunit")
        assert p.select_argv("tests/GuardTest.php::testRejects")[-3:] == ["--filter", "testRejects", "tests/GuardTest.php"]
        assert p.classify(1, "No tests executed!", "").status == "error"
        assert p.classify(2, "There was 1 error", "").status == "failed"

    def test_command_adapter_maps_exit_codes(self, tmp_path):
        a = detect_adapter(tmp_path, run_cmd="x {test}")
        assert a.classify(0, "", "").status == "passed"
        assert a.classify(1, "", "").status == "failed"
        assert a.classify(2, "", "").status == "error"

    def test_a_timeout_is_an_error(self, tmp_path):
        def slow(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        a = detect_adapter(tmp_path, run_cmd="x {test}", runner=slow)
        outcome = a.run("t", timeout=3)
        assert outcome.status == "error" and "timed out" in outcome.note


# ---------------------------------------------------------------------------
# Coverage converters
# ---------------------------------------------------------------------------

class TestConverters:
    def test_go_coverprofile_to_lcov(self):
        profile = (
            "mode: set\n"
            "example.com/guard/guard.go:3.32,4.12 1 1\n"
            "example.com/guard/guard.go:4.12,6.3 1 0\n"
            "example.com/guard/guard.go:7.2,7.13 1 1\n"
            "example.com/guard/other.go:1.1,2.2 1 0\n"
        )
        lcov = go_coverprofile_to_lcov(profile, "example.com/guard")
        assert "SF:guard.go" in lcov and "SF:other.go" in lcov
        files = lines_from_lcov(lcov)
        assert files["guard.go"] == {3, 4, 7}
        assert files["other.go"] == set()
        nested = go_coverprofile_to_lcov(profile, "example.com/guard", module_dir="backend")
        assert "SF:backend/guard.go" in nested

    def test_simplecov_both_shapes(self, tmp_path):
        f = tmp_path / "lib" / "guard.rb"
        f.parent.mkdir()
        f.write_text("x")
        new_shape = {"RSpec": {"coverage": {str(f): {"lines": [None, 1, 0, 2]}}}}
        old_shape = {"RSpec": {"coverage": {str(f): [None, 1, 0, 2]}}}
        for shape in (new_shape, old_shape):
            assert lines_from_lcov(simplecov_resultset_to_lcov(shape, tmp_path)) == {"lib/guard.rb": {2, 4}}

    def test_clover(self, tmp_path):
        f = tmp_path / "src" / "Guard.php"
        f.parent.mkdir()
        f.write_text("x")
        xml = f'''<?xml version="1.0"?><coverage><project><file name="{f}">
            <line num="3" type="stmt" count="1"/><line num="4" type="stmt" count="0"/>
            </file></project></coverage>'''
        assert lines_from_lcov(clover_to_lcov(xml, tmp_path)) == {"src/Guard.php": {3}}


# ---------------------------------------------------------------------------
# Source mutation
# ---------------------------------------------------------------------------

GO = 'package a\n\nfunc Guard(t string) bool {\n\tif t == "" {\n\t\treturn false\n\t}\n\treturn true\n}\n\nfunc (l *Limiter) Allow(n int) bool { return n < l.max }\n'
RUST = 'pub fn guard(t: &str) -> bool {\n    !t.is_empty()\n}\nimpl Limiter {\n    pub fn allow(&self, n: u32) -> bool { n < self.max }\n}\n'
JAVA = 'public class A {\n    @Override\n    public static boolean guard(String t) throws Exception {\n        return t != null;\n    }\n    private int count = compute(3);\n    int other() { return 1; }\n}\n'
KOTLIN = 'class A {\n    fun guard(t: String?): Boolean = t != null\n    fun other(n: Int): Int {\n        return n\n    }\n}\n'
C = 'int guard(const char *t) {\n    return t && *t;\n}\n'
CPP = '#include <cstdlib>\nbool Guard::check(const std::string& t) const {\n    return !t.empty();\n}\n'
CSHARP = 'public class Guard {\n    public bool Check(string t) => t != null;\n    public int Other(int n) { return n; }\n}\n'
SWIFT = 'func guardToken(t: String?) -> Bool {\n    return t != nil\n}\nstruct L { func allow(n: Int, f: () -> Void = {}) -> Bool { n < 3 } }\n'


class TestMutation:
    @pytest.mark.parametrize("file,src,mechanism,expect,keep", [
        ("a.go", GO, "a.go::Guard", 'func Guard(t string) bool { panic("mipiti: mechanism disabled") }', "return n < l.max"),
        ("a.go", GO, "a.go::Limiter.Allow", 'Allow(n int) bool { panic("mipiti: mechanism disabled") }', 'if t == ""'),
        ("a.go", GO, "a.go::Limiter", 'Allow(n int) bool { panic("mipiti: mechanism disabled") }', 'if t == ""'),
        ("a.rs", RUST, "a.rs::guard", 'pub fn guard(t: &str) -> bool { panic!("mipiti: mechanism disabled") }', "n < self.max"),
        ("a.rs", RUST, "a.rs::Limiter.allow", 'allow(&self, n: u32) -> bool { panic!("mipiti: mechanism disabled") }', "!t.is_empty()"),
        ("a.rs", RUST, "a.rs::impl:Limiter", 'allow(&self, n: u32) -> bool { panic!("mipiti: mechanism disabled") }', "!t.is_empty()"),
        ("A.java", JAVA, "A.java::guard", 'throws Exception { throw new IllegalStateException("mipiti: mechanism disabled"); }', "int other() { return 1; }"),
        ("A.java", JAVA, "A.java::A.other", 'int other() { throw new IllegalStateException("mipiti: mechanism disabled"); }', "return t != null;"),
        ("A.java", JAVA, "A.java::class:A", 'int other() { throw new IllegalStateException("mipiti: mechanism disabled"); }', "compute(3)"),
        ("a.kt", KOTLIN, "a.kt::guard", 'fun guard(t: String?): Boolean { throw IllegalStateException("mipiti: mechanism disabled") }', "return n"),
        ("a.kt", KOTLIN, "a.kt::A.other", 'fun other(n: Int): Int { throw IllegalStateException("mipiti: mechanism disabled") }', "= t != null"),
        ("a.c", C, "a.c::guard", 'int guard(const char *t) { abort(); }', "#include <stdlib.h>"),
        ("a.cpp", CPP, "a.cpp::Guard.check", 'const { abort(); }', "#include <cstdlib>"),
        ("a.cs", CSHARP, "a.cs::Guard.Check", 'public bool Check(string t) { throw new System.InvalidOperationException("mipiti: mechanism disabled"); }', "return n;"),
        ("a.cs", CSHARP, "a.cs::Other", 'public int Other(int n) { throw new System.InvalidOperationException("mipiti: mechanism disabled"); }', "=> t != null;"),
        ("a.swift", SWIFT, "a.swift::guardToken", 'func guardToken(t: String?) -> Bool { fatalError("mipiti: mechanism disabled") }', "n < 3"),
        ("a.swift", SWIFT, "a.swift::L.allow", '-> Bool { fatalError("mipiti: mechanism disabled") }', "return t != nil"),
    ])
    def test_body_is_replaced_and_the_rest_kept(self, file, src, mechanism, expect, keep):
        out = mutate_source(src, parse_mechanism(mechanism))
        assert expect in out, out
        assert keep in out, out

    def test_c_include_is_added_once(self):
        out = mutate_source(C, parse_mechanism("a.c::guard"))
        assert out.startswith("#include <stdlib.h>\n")
        already = "#include <stdlib.h>\n" + C
        assert mutate_source(already, parse_mechanism("a.c::guard")).count("#include <stdlib.h>") == 1

    def test_an_absent_symbol_is_a_reason_not_a_guess(self):
        with pytest.raises(DisableError, match="not defined"):
            mutate_source(GO, parse_mechanism("a.go::Missing"))
        with pytest.raises(DisableError):
            mutate_source(GO, parse_mechanism("a.rb::x"), "ruby")

    def test_braces_in_strings_and_comments_do_not_end_the_body(self):
        src = 'func Guard(t string) bool {\n\t// } not the end\n\ts := "}"\n\treturn s != ""\n}\nfunc Other() {}\n'
        out = mutate_source(src, parse_mechanism("a.go::Guard"))
        assert out == 'func Guard(t string) bool { panic("mipiti: mechanism disabled") }\nfunc Other() {}\n'


SV = '''module guard #(parameter W = 8) (
  input  logic          clk,
  input  logic [W-1:0]  a, b,
  output logic [W-1:0]  y,
  output                ok
);
  // "endmodule" in a string: $display("endmodule");
  function automatic logic [W-1:0] clamp(input logic [W-1:0] v);
    return v > 8'd200 ? 8'd200 : v;
  endfunction
  task check;
    input x;
    begin
      if (x) $display("x");
    end
  endtask
  always_ff @(posedge clk) begin : upd
    y <= clamp(a + b);
  end
  assign ok = 1'b1;
  property p_stable;
    @(posedge clk) ok |-> ##1 ok;
  endproperty
  a_stable: assert property (p_stable) else $error("unstable");
  a_ok: assert property (@(posedge clk) ok);
endmodule
'''

# A non-ANSI module: directions, ranges, kinds and comma lists are declared
# in the body, and a task carries a port declaration of its own.
NONANSI_V = '''module guard #(parameter W = 8) (clk, a, b, y, ok, z, q, io);
  input clk;
  input wire [W-1:0] a, b;
  output y;
  output reg [W-1:0] z, q;  // "output fake;" in a comment
  output signed [3:0] ok;
  inout io;
  task check;
    input x;
    begin
      if (x) $display("x");
    end
  endtask
  assign y = a[0] ^ b[0];
  assign ok = 4'sd1;
  always @(posedge clk) begin z <= a; q <= b; end
endmodule
'''

VHDL = '''-- comment with begin end
architecture rtl of guard is
  function clamp(v : integer) return integer is
    variable r : integer;
  begin
    if v > 200 then r := 200; else r := v; end if;
    return r;
  end function clamp;
  signal s : std_logic;
begin
  upd : process (clk)
  begin
    if rising_edge(clk) then
      s <= a;
    end if;
  end process upd;
  y <= s;
end architecture rtl;
'''


class _parser_off:
    """The optional parser extra is unimportable inside the block."""

    def __enter__(self):
        from unittest.mock import patch

        from mipiti_verify.languages import definitions as D

        self._patch = patch.dict("sys.modules", {"tree_sitter_language_pack": None})
        self._patch.__enter__()
        D._get_parser.cache_clear()
        return self

    def __exit__(self, *exc):
        from mipiti_verify.languages import definitions as D

        self._patch.__exit__(*exc)
        D._get_parser.cache_clear()
        return False


class _parser_on:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestHdlMutation:
    def test_module_stub_keeps_the_header_and_drives_outputs_x(self):
        out = mutate_verilog(SV, parse_mechanism("g.sv::module:guard"))
        assert out.startswith("module guard #(parameter W = 8) (")
        assert "  initial y = 'bx;\n  assign ok = 'bx;\nendmodule" in out
        assert "clamp" not in out and "always_ff" not in out

    NONANSI_STUB = (
        "module guard #(parameter W = 8) (clk, a, b, y, ok, z, q, io);\n"
        "  input clk;\n"
        "  input wire [W-1:0] a, b;\n"
        "  output y;\n"
        "  output reg [W-1:0] z, q;\n"
        "  output signed [3:0] ok;\n"
        "  inout io;\n"
        "  assign y = 'bx;\n"
        "  {driver} z = 'bx;\n"
        "  {driver} q = 'bx;\n"
        "  assign ok = 'bx;\n"
        "endmodule\n"
    )

    @pytest.mark.parametrize("parser", ["tree-sitter", "keyword scanner"])
    def test_non_ansi_module_keeps_its_port_declarations_and_drives_outputs_x(self, parser):
        from mipiti_verify.languages import definitions as D

        with _parser_off() if parser == "keyword scanner" else _parser_on():
            if parser == "tree-sitter" and not D.tree_sitter_available("verilog"):
                pytest.skip("tree-sitter-language-pack is not installed")
            out_v = mutate_verilog(NONANSI_V, parse_mechanism("n.v::module:guard"))
            out_sv = mutate_verilog(NONANSI_V, parse_mechanism("n.sv::guard"))
        assert out_v == self.NONANSI_STUB.format(driver="always @*")
        assert out_sv == self.NONANSI_STUB.format(driver="always_comb")
        assert "task check" not in out_v and "input x;" not in out_v

    def test_ansi_module_stub_is_unchanged(self):
        out = mutate_verilog(SV, parse_mechanism("g.sv::module:guard"))
        assert out == "module guard #(parameter W = 8) (\n  input  logic          clk,\n" \
            "  input  logic [W-1:0]  a, b,\n  output logic [W-1:0]  y,\n  output                ok\n" \
            ");\n  initial y = 'bx;\n  assign ok = 'bx;\nendmodule\n"

    @pytest.mark.parametrize("parser", ["tree-sitter", "keyword scanner"])
    def test_non_ansi_header_and_body_must_agree(self, parser):
        from mipiti_verify.languages import definitions as D

        with _parser_off() if parser == "keyword scanner" else _parser_on():
            if parser == "tree-sitter" and not D.tree_sitter_available("verilog"):
                pytest.skip("tree-sitter-language-pack is not installed")
            undeclared = "module m(a, y);\n  input a;\n  assign y = a;\nendmodule\n"
            with pytest.raises(DisableError, match="names y in its header without a port declaration"):
                mutate_verilog(undeclared, parse_mechanism("m.v::m"))
            unlisted = "module m(a);\n  input a;\n  output y;\n  assign y = a;\nendmodule\n"
            with pytest.raises(DisableError, match="declares y as a port in the body but does not name it"):
                mutate_verilog(unlisted, parse_mechanism("m.v::m"))
            twice = "module m(a);\n  input a;\n  input a;\nendmodule\n"
            with pytest.raises(DisableError, match="declared more than once"):
                mutate_verilog(twice, parse_mechanism("m.v::m"))
            expression = "module m(.a(x), y);\n  input x;\n  output y;\nendmodule\n"
            with pytest.raises(DisableError, match="not a plain identifier"):
                mutate_verilog(expression, parse_mechanism("m.v::m"))

    def test_port_less_module_stub_is_header_and_endmodule(self):
        out = mutate_verilog("module m;\n  initial $display(1);\nendmodule\n", parse_mechanism("m.v::m"))
        assert out == "module m;\nendmodule\n"

    def test_function_and_task_bodies_become_fatal(self):
        out = mutate_verilog(SV, parse_mechanism("g.sv::clamp"))
        assert '(input logic [W-1:0] v);\n  $fatal(1, "mipiti: mechanism disabled");\nendfunction' in out
        assert "return v > 8'd200" not in out
        out = mutate_verilog(SV, parse_mechanism("g.sv::task:check"))
        assert "input x;" in out and "$display(\"x\")" not in out
        assert '$fatal(1, "mipiti: mechanism disabled");\nendtask' in out

    def test_labelled_block_property_and_assert_are_removed(self):
        out = mutate_verilog(SV, parse_mechanism("g.sv::always:upd"))
        assert "always_ff" not in out and "y <= clamp" not in out and "assign ok" in out
        out = mutate_verilog(SV, parse_mechanism("g.sv::property:p_stable"))
        assert "property p_stable" not in out and "a_stable" not in out and "a_ok" in out
        out = mutate_verilog(SV, parse_mechanism("g.sv::assert:a_ok"))
        assert "a_ok" not in out and "a_stable" in out
        with pytest.raises(DisableError):
            mutate_verilog(SV, parse_mechanism("g.sv::assert:nope"))

    def test_bare_name_resolves_module_first(self):
        assert mutate_verilog(SV, parse_mechanism("g.sv::guard")).count("endmodule") == 1
        assert "$fatal" in mutate_verilog(SV, parse_mechanism("g.sv::clamp"))
        assert "always_ff" not in mutate_verilog(SV, parse_mechanism("g.sv::upd"))

    def test_vhdl_architecture_process_and_function(self):
        out = mutate_vhdl(VHDL, parse_mechanism("g.vhd::rtl"))
        assert "signal s : std_logic;\nbegin\nend architecture rtl;" in out
        assert "end function clamp;" in out
        out = mutate_vhdl(VHDL, parse_mechanism("g.vhd::process:upd"))
        assert "process" not in out and "y <= s;" in out
        out = mutate_vhdl(VHDL, parse_mechanism("g.vhd::clamp"))
        assert 'begin\n    assert false report "mipiti: mechanism disabled" severity failure;\n  end function clamp;' in out
        assert "r := 200" not in out
        with pytest.raises(DisableError):
            mutate_vhdl(VHDL, parse_mechanism("g.vhd::architecture:nope"))


# ---------------------------------------------------------------------------
# Restore, refusal, compile gate
# ---------------------------------------------------------------------------

class TestMutatedFile:
    def test_restored_byte_for_byte_even_when_the_block_raises(self, repo):
        f = repo / "a.go"
        original = b"package a\r\n\r\nfunc Guard() {}\r\n\xef\xbb\xbf"
        f.write_bytes(original)
        _commit_all(repo)
        digest = hashlib.sha256(original).hexdigest()
        with pytest.raises(RuntimeError):
            with mutated_file(repo, "a.go", b"mutated"):
                assert f.read_bytes() == b"mutated"
                raise RuntimeError("inside")
        assert hashlib.sha256(f.read_bytes()).hexdigest() == digest

    def test_refuses_a_file_with_uncommitted_changes(self, repo):
        f = repo / "a.go"
        f.write_text("package a\n")
        _commit_all(repo)
        f.write_text("package a\n// edited\n")
        with pytest.raises(DisableError, match="uncommitted"):
            with mutated_file(repo, "a.go", b"x"):
                pass
        assert f.read_text() == "package a\n// edited\n"

    def test_refuses_outside_a_checkout(self, tmp_path):
        (tmp_path / "a.go").write_text("package a\n")
        with pytest.raises(DisableError, match="git checkout"):
            with mutated_file(tmp_path, "a.go", b"x"):
                pass

    def test_a_failing_compile_check_is_an_error_with_the_reason(self, repo):
        from mipiti_verify.dependence import run_pair

        (repo / "go.mod").write_text("module example.com/x\n\ngo 1.21\n")
        (repo / "a.go").write_text(GO)
        _commit_all(repo)
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["go", "build"]:
                return subprocess.CompletedProcess(argv, 2, "", "./a.go:3: undefined: Limiter")
            return subprocess.CompletedProcess(argv, 1, "", "")

        record = run_pair(repo, "TestGuard", "a.go::Guard", runner=fake_run)
        assert record["status"] == "error"
        assert "does not compile" in record["note"] and "undefined: Limiter" in record["note"]
        assert (repo / "a.go").read_text() == GO
        assert not any(argv[:2] == ["go", "test"] for argv in calls)

    def test_a_passing_compile_check_runs_the_test_on_the_mutated_tree(self, repo):
        from mipiti_verify.dependence import run_dependence

        (repo / "go.mod").write_text("module example.com/x\n\ngo 1.21\n")
        (repo / "a.go").write_text(GO)
        _commit_all(repo)
        seen = {}

        def fake_run(argv, **kwargs):
            if argv[:2] == ["go", "build"]:
                seen["mutated"] = (repo / "a.go").read_text()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:2] == ["go", "test"]:
                seen["argv"] = argv
                return subprocess.CompletedProcess(argv, 1, "--- FAIL: TestGuard\nFAIL", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        summary = run_dependence(repo, [("TestGuard", "a.go::Guard")], runner=fake_run)
        assert 'panic("mipiti: mechanism disabled")' in seen["mutated"]
        assert seen["argv"][:5] == ["go", "test", "-count=1", "-run", "^TestGuard$"]
        assert summary["tests"][0]["fails_without"] == [{"mechanism": "a.go::Guard", "status": "failed"}]
        assert summary["runner"] == "go"
        assert (repo / "a.go").read_text() == GO

    def test_an_unsupported_language_is_a_reasoned_error(self, repo):
        from mipiti_verify.dependence import run_pair

        (repo / "Gemfile").write_text("")
        (repo / ".rspec").write_text("")
        (repo / "lib").mkdir()
        (repo / "lib" / "guard.rb").write_text("def guard; end\n")
        _commit_all(repo)
        record = run_pair(repo, "spec/guard_spec.rb::rejects", "lib/guard.rb::guard",
                          runner=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""))
        assert record["status"] == "error" and "cannot disable" in record["note"]


class TestNodeSetupFiles:
    def test_jest_registers_a_setup_file_that_mocks_the_module(self, tmp_path):
        from mipiti_verify.languages.adapters.node import ENV_SETUP

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "auth.js").write_text("module.exports = { requireToken() {} };\n")
        a = detect_adapter(tmp_path, "jest")
        with a.disable("src/auth.js::requireToken") as handle:
            setup = Path(handle.env[ENV_SETUP])
            text = setup.read_text()
            assert "jest.mock(" in text and (tmp_path / "src" / "auth.js").resolve().as_posix() in text
            assert 'out["requireToken"] = disabled' in text
            argv = a.select_argv("src/auth.test.js::rejects", handle.env)
            assert argv[argv.index("--setupFilesAfterEnv") + 1] == str(setup)
        assert not setup.exists()

    def test_vitest_extends_the_project_config_and_cleans_up(self, tmp_path):
        from mipiti_verify.languages.adapters.node import ENV_CONFIG

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "auth.ts").write_text("export class Auth { check() {} }\n")
        (tmp_path / "vitest.config.ts").write_text("export default {}\n")
        a = detect_adapter(tmp_path, "vitest")
        with a.disable("src/auth.ts::Auth.check") as handle:
            config = Path(handle.env[ENV_CONFIG])
            assert config.parent == tmp_path
            text = config.read_text()
            assert "mergeConfig" in text and "./vitest.config.ts" in text
            setup_text = Path(handle.env["MIPITI_NODE_SETUP_FILE"]).read_text()
            assert "vi.mock(" in setup_text and 'prototype["check"] = disabled' in setup_text
            assert "--config" in a.select_argv("src/auth.test.ts::x", handle.env)
        assert not config.exists()

    def test_mocha_requires_a_file_that_patches_the_export(self, tmp_path):
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "auth.js").write_text("module.exports = { requireToken() {} };\n")
        a = detect_adapter(tmp_path, "mocha")
        with a.disable("lib/auth.js::default") as handle:
            argv = a.select_argv("test/auth.js::rejects", handle.env)
            assert "--require" in argv
            assert 'out["default"] = disabled' in Path(handle.env["MIPITI_NODE_SETUP_FILE"]).read_text()

    def test_a_non_js_mechanism_is_refused(self, tmp_path):
        (tmp_path / "a.go").write_text("package a\n")
        a = detect_adapter(tmp_path, "jest")
        with pytest.raises(DisableError, match="JavaScript and TypeScript"):
            with a.disable("a.go::Guard"):
                pass


class TestReach:
    def test_reach_records_only_the_mechanism_file(self, tmp_path):
        from mipiti_verify.reach import run_reach

        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "guard.py").write_text("def f():\n    return 1\n")
        report = tmp_path / "lcov.info"

        class FakeAdapter:
            name = "fake"
            last_outcome = None

            def run_with_coverage(self, test_id, *, timeout, work_dir):
                from mipiti_verify.languages.adapters import Outcome
                self.last_outcome = Outcome("passed", 0)
                report.write_text("SF:app/guard.py\nDA:1,1\nDA:2,1\nend_of_record\nSF:app/other.py\nDA:1,1\nend_of_record\n")
                return report

        summary = run_reach(tmp_path, [("tests/test_g.py::test_a", "app/guard.py::f")], adapter=FakeAdapter())
        entry = summary["tests"][0]
        assert entry["status"] == "passed"
        assert entry["reached"] == [{"file": "app/guard.py", "lines": [1, 2]}]
        assert summary["totals"]["passed"] == 1

    def test_reach_budget_and_adapter_errors_carry_reasons(self, tmp_path):
        from mipiti_verify.reach import REASON_BUDGET_EXHAUSTED, run_reach

        class Failing:
            name = "fake"
            last_outcome = None

            def run_with_coverage(self, test_id, *, timeout, work_dir):
                raise AdapterError("cargo-llvm-cov is not installed")

        now = [0.0]

        def clock():
            now[0] += 100.0
            return now[0]

        summary = run_reach(tmp_path, [("a", "x.rs::f"), ("b", "x.rs::f")], adapter=Failing(),
                            total_timeout=150, clock=clock)
        assert summary["tests"][0]["status"] == "error"
        assert "cargo-llvm-cov" in summary["tests"][0]["reason"]
        assert summary["tests"][1]["reason"] == REASON_BUDGET_EXHAUSTED
        assert summary["not_run"] == 1

    def test_cli_attest_reach_writes_a_reach_record(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.attestation import ATTESTATION_DIR, statement_of
        from mipiti_verify.cli import main

        for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL", "GITHUB_SHA",
                    "MIPITI_ATTESTATION_PUBLIC_KEY"):
            monkeypatch.delenv(var, raising=False)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("a" * 40)
        (tmp_path / "guard.v").write_text("module guard(input a, output y);\n  assign y = ~a;\nendmodule\n")
        report = tmp_path / "cov.info"

        def fake_run(argv, **kwargs):
            report.write_text("SF:guard.v\nDA:2,3\nend_of_record\n")
            return subprocess.CompletedProcess(argv, 0, "", "")

        from unittest.mock import patch
        with patch("mipiti_verify.languages.adapters._common.subprocess.run", fake_run):
            result = CliRunner().invoke(main, [
                "attest-reach", "--project-root", str(tmp_path),
                "--run-cmd", "make sim TEST={test}", "--coverage-file", "cov.info",
                "--pair", "tb_guard=guard.v::guard",
            ])
        assert result.exit_code == 0, result.output
        path = next((tmp_path / ATTESTATION_DIR).glob("*-reach.json"))
        predicate = statement_of(path.read_text())["predicate"]
        assert predicate["kind"] == "reach"
        assert predicate["invocation"] == ["mipiti-verify", "attest-reach", "--runner", "command"]
        assert predicate["tests"][0]["reached"] == [{"file": "guard.v", "lines": [2]}]
        assert "1 reached their mechanism's file" in result.output
