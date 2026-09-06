"""Definition location across languages: parser path and fallbacks.

Every span below was checked against the grammar's own parse of the
fixture; the fallback expectations describe what the brace / indentation
heuristic can and cannot isolate, and that it says so (``scope="block"``).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mipiti_verify.attestation import locate_test_definitions, parse_junit
from mipiti_verify.definition_extract import extract_definition
from mipiti_verify.languages import definitions as D
from mipiti_verify.verifiers.tests import _reached_mechanism, mechanism_kinds, mechanism_line_span

# ---------------------------------------------------------------------------
# Fixtures: one realistic file per language
# ---------------------------------------------------------------------------

SOURCES = {
    "javascript": """import x from 'y';
function target(a) { return a; }
class Guard {
  check(req) { return !!req.user; }
  static make() { return new Guard(); }
}
const arrow = (x) => { return x; };
export default class Other { check() { return 1; } }
""",
    "typescript": """export function target(a: number): number { return a; }
export class Guard {
  private n = 1;
  check(req: Req): boolean { return !!req.user; }
}
interface Shape { area(): number; }
const arrow = (x: number) => x;
""",
    "go": """package main

func target(a int) int { return a }

type Guard struct {
\tName string
}

func (g *Guard) Check(r *Request) bool {
\treturn r.User != nil
}

type Shape interface { Area() float64 }
""",
    "rust": """fn target(a: u32) -> u32 { a }

pub struct Guard { pub n: u32 }

impl Guard {
    pub fn check(&self, r: &Req) -> bool { r.user.is_some() }
}

trait Shape { fn area(&self) -> f64; }
enum Kind { A, B }
""",
    "java": """package x;

public class Guard {
    private int n;
    public boolean check(Request r) { return r.user != null; }
    public static int target(int a) { return a; }
}
interface Shape { double area(); }
enum Kind { A, B }
""",
    "kotlin": """package x

fun target(a: Int): Int = a

class Guard(val n: Int) {
    fun check(r: Request): Boolean {
        return r.user != null
    }
}
object Single { fun go() = 1 }
interface Shape { fun area(): Double }
""",
    "c": """#include <stdio.h>

struct guard { int n; };

static int target(int a) {
    return a;
}

int check(struct guard *g) { return g->n; }
""",
    "cpp": """#include <string>

class Guard {
public:
    bool check(const Req& r) { return r.user; }
    static int target(int a);
};

int Guard::target(int a) { return a; }

struct Point { int x; };
namespace ns { int helper() { return 1; } }
""",
    "csharp": """namespace App {
    public class Guard {
        private int n;
        public bool Check(Request r) { return r.User != null; }
        public static int Target(int a) => a;
    }
    public struct Point { public int X; }
    public interface IShape { double Area(); }
}
""",
    "ruby": """class Guard
  def check(r)
    return true if r.user
    false
  end

  def self.target(a)
    a
  end
end

def target(a)
  a
end
module Util
  def helper; 1; end
end
""",
    "php": """<?php
namespace App;

function target($a) {
    return $a;
}

class Guard {
    private $n;
    public function check(Request $r): bool { return $r->user !== null; }
    public static function make(): Guard { return new Guard(); }
}
interface Shape { public function area(): float; }
""",
    "swift": """import Foundation

func target(_ a: Int) -> Int { return a }

class Guard {
    var n = 1
    func check(_ r: Request) -> Bool { return r.user != nil }
    static func make() -> Guard { return Guard() }
}
struct Point { var x: Int }
protocol Shape { func area() -> Double }
""",
    "systemverilog": """`timescale 1ns/1ps
module alu #(parameter W = 8) (
    input  logic [W-1:0] a, b,
    input  logic clk,
    output logic [W-1:0] y
);
    function automatic logic [W-1:0] add(input logic [W-1:0] x, y);
        return x + y;
    endfunction

    task automatic check(input logic [W-1:0] x);
        $display("%d", x);
    endtask

    always_ff @(posedge clk) begin : seq_logic
        y <= add(a, b);
    end

    always_comb begin : comb_logic
        y = a;
    end

    initial begin : init_blk
        y = '0;
    end

    property p_stable;
        @(posedge clk) $stable(a) |-> $stable(y);
    endproperty

    sequence s_req;
        a ##1 b;
    endsequence

    a_stable: assert property (p_stable) else $error("unstable");
    c_cov: cover property (p_stable);
endmodule

class Packet;
    int len;
    function new(); len = 0; endfunction
    function int size(); return len; endfunction
endclass

module top;
    alu #(.W(8)) u_alu(.a(), .b(), .clk(), .y());
endmodule
""",
    "verilog": """module counter(input clk, input rst, output reg [7:0] q);
    function [7:0] inc;
        input [7:0] v;
        begin
            inc = v + 1;
        end
    endfunction

    task show;
        begin
            $display("%d", q);
        end
    endtask

    always @(posedge clk) begin : seq_logic
        if (rst) q <= 0; else q <= inc(q);
    end

    initial begin : init_blk
        q = 0;
    end
endmodule
""",
    "vhdl": """library ieee;
use ieee.std_logic_1164.all;

entity alu is
    port (
        a, b : in  std_logic_vector(7 downto 0);
        clk  : in  std_logic;
        y    : out std_logic_vector(7 downto 0)
    );
end entity alu;

architecture rtl of alu is
    function add(x, y : std_logic_vector) return std_logic_vector is
    begin
        return x;
    end function add;

    procedure show(x : in std_logic_vector) is
    begin
        null;
    end procedure show;
begin
    seq_logic: process(clk)
    begin
        if rising_edge(clk) then
            y <= add(a, b);
        end if;
    end process seq_logic;

    comb: process(a)
    begin
        y <= a;
    end process;
end architecture rtl;
""",
}

# (language, kind, name, parser span, fallback span or None). A fallback
# ``None`` is a documented limit of the heuristic, not a wrong answer: the
# attestation then hashes the file and says so.
CASES = [
    ("javascript", "function", "target", (2, 2), (2, 2)),
    ("javascript", "class", "Guard", (3, 6), (3, 6)),
    ("javascript", "method", "Guard.check", (4, 4), (4, 4)),
    ("javascript", "function", "arrow", (7, 7), None),
    ("javascript", "method", "Other.check", (8, 8), (4, 4)),   # fallback: first `check`
    ("typescript", "function", "target", (1, 1), (1, 1)),
    ("typescript", "class", "Guard", (2, 5), (2, 5)),
    ("typescript", "method", "Guard.check", (4, 4), None),
    ("typescript", "class", "Shape", (6, 6), (6, 6)),
    ("go", "function", "target", (3, 3), (3, 3)),
    ("go", "class", "Guard", (5, 7), (5, 7)),
    ("go", "method", "Guard.Check", (9, 11), (9, 11)),
    ("go", "class", "Shape", (13, 13), None),
    ("rust", "function", "target", (1, 1), (1, 1)),
    ("rust", "class", "Guard", (3, 3), (3, 3)),
    ("rust", "method", "Guard.check", (6, 6), (6, 6)),
    ("rust", "class", "Shape", (9, 9), None),
    ("java", "function", "target", (6, 6), (6, 6)),
    ("java", "class", "Guard", (3, 7), (3, 7)),
    ("java", "method", "Guard.check", (5, 5), (5, 5)),
    ("java", "class", "Shape", (8, 8), (8, 8)),
    ("kotlin", "function", "target", (3, 3), None),
    ("kotlin", "class", "Guard", (5, 9), (5, 9)),
    ("kotlin", "method", "Guard.check", (6, 8), None),
    ("kotlin", "class", "Shape", (11, 11), (11, 11)),
    ("c", "function", "target", (5, 7), (5, 7)),
    ("c", "class", "guard", (3, 3), (3, 3)),
    ("c", "function", "check", (9, 9), (9, 9)),
    ("cpp", "function", "target", (9, 9), (6, 6)),            # fallback: the declaration line
    ("cpp", "class", "Guard", (3, 7), (3, 7)),
    ("cpp", "method", "Guard.check", (5, 5), (5, 5)),
    ("cpp", "method", "Guard.target", (9, 9), (6, 6)),
    ("cpp", "function", "helper", (12, 12), (12, 12)),
    ("csharp", "function", "Target", (5, 5), (5, 5)),
    ("csharp", "class", "Guard", (2, 6), (2, 6)),
    ("csharp", "method", "Guard.Check", (4, 4), (4, 4)),
    ("csharp", "class", "Point", (7, 7), (7, 7)),
    ("ruby", "function", "target", (12, 14), (12, 13)),        # fallback: indentation cuts `end`
    ("ruby", "class", "Guard", (1, 10), (1, 9)),
    ("ruby", "method", "Guard.check", (2, 5), (2, 4)),
    ("ruby", "method", "Guard.target", (7, 9), (12, 13)),      # fallback: first `target`
    ("ruby", "class", "Util", (15, 17), None),
    ("php", "function", "target", (4, 6), (4, 6)),
    ("php", "class", "Guard", (8, 12), (8, 12)),
    ("php", "method", "Guard.check", (10, 10), (10, 10)),
    ("php", "class", "Shape", (13, 13), (13, 13)),
    ("swift", "function", "target", (3, 3), (3, 3)),
    ("swift", "class", "Guard", (5, 9), (5, 9)),
    ("swift", "method", "Guard.check", (7, 7), (7, 7)),
    ("swift", "class", "Point", (10, 10), (10, 10)),
    ("swift", "class", "Shape", (11, 11), None),
]

# HDL: the keyword scanner recovers the same span as the grammar.
HDL_CASES = [
    ("systemverilog", "module", "alu", (2, 37)),
    ("systemverilog", "function", "add", (7, 9)),
    ("systemverilog", "task", "check", (11, 13)),
    ("systemverilog", "always", "seq_logic", (15, 17)),
    ("systemverilog", "always", "comb_logic", (19, 21)),
    ("systemverilog", "initial", "init_blk", (23, 25)),
    ("systemverilog", "property", "p_stable", (27, 29)),
    ("systemverilog", "sequence", "s_req", (31, 33)),
    ("systemverilog", "assert", "a_stable", (35, 35)),
    ("systemverilog", "assert", "c_cov", (36, 36)),
    ("systemverilog", "class", "Packet", (39, 43)),
    ("systemverilog", "method", "Packet.size", (42, 42)),
    ("systemverilog", "method", "Packet.new", (41, 41)),
    ("systemverilog", "module", "top", (45, 47)),
    ("verilog", "module", "counter", (1, 22)),
    ("verilog", "function", "inc", (2, 7)),
    ("verilog", "task", "show", (9, 13)),
    ("verilog", "always", "seq_logic", (15, 17)),
    ("verilog", "initial", "init_blk", (19, 21)),
    ("vhdl", "entity", "alu", (4, 10)),
    ("vhdl", "architecture", "rtl", (12, 34)),
    ("vhdl", "function", "add", (13, 16)),
    ("vhdl", "procedure", "show", (18, 21)),
    ("vhdl", "process", "seq_logic", (23, 28)),
    ("vhdl", "process", "comb", (30, 33)),
]


def _lines(src: str, start: int, end: int) -> str:
    return "\n".join(src.split("\n")[start - 1:end])


@pytest.fixture
def no_tree_sitter(monkeypatch):
    """Make the optional extra unimportable for the test."""
    monkeypatch.setitem(sys.modules, "tree_sitter_language_pack", None)
    D._get_parser.cache_clear()
    yield
    D._get_parser.cache_clear()


@pytest.fixture
def tree_sitter():
    D._get_parser.cache_clear()
    if not D.tree_sitter_available("javascript"):
        pytest.skip("tree-sitter-language-pack not installed")
    yield
    D._get_parser.cache_clear()


# ---------------------------------------------------------------------------
# language_of / hash_of
# ---------------------------------------------------------------------------

class TestLanguageOf:
    @pytest.mark.parametrize("path, language", [
        ("a/b.py", "python"), ("x.js", "javascript"), ("x.jsx", "javascript"),
        ("x.mjs", "javascript"), ("x.cjs", "javascript"), ("x.ts", "typescript"),
        ("x.tsx", "tsx"), ("x.go", "go"), ("x.rs", "rust"), ("x.java", "java"),
        ("x.kt", "kotlin"), ("x.c", "c"), ("x.h", "c"), ("x.cpp", "cpp"), ("x.cc", "cpp"),
        ("x.hpp", "cpp"), ("x.hh", "cpp"), ("x.cs", "csharp"), ("x.rb", "ruby"),
        ("x.php", "php"), ("x.swift", "swift"), ("x.v", "verilog"), ("x.vh", "verilog"),
        ("x.sv", "systemverilog"), ("x.svh", "systemverilog"), ("x.vhd", "vhdl"),
        ("x.vhdl", "vhdl"), ("rtl\\alu.SV", "systemverilog"), ("Makefile", ""),
        ("x.unknown", ""), ("", ""),
    ])
    def test_extension_maps_to_language(self, path, language):
        assert D.language_of(path) == language


class TestHashOf:
    def test_line_endings_and_trailing_whitespace_are_not_content(self):
        assert D.hash_of("def f():   \r\n    return 1\t\r\n") == D.hash_of("def f():\n    return 1\n")

    def test_content_changes_the_hash(self):
        assert D.hash_of("def f():\n    return 1") != D.hash_of("def f():\n    return 2")

    def test_leading_whitespace_is_content(self):
        assert D.hash_of("  x") != D.hash_of("x")


# ---------------------------------------------------------------------------
# locate: parser path
# ---------------------------------------------------------------------------

class TestLocateWithTreeSitter:
    @pytest.mark.parametrize("language, kind, name, span, _fallback", CASES,
                             ids=[f"{c[0]}-{c[1]}-{c[2]}" for c in CASES])
    def test_exact_symbol_span(self, tree_sitter, language, kind, name, span, _fallback):
        src = SOURCES[language]
        found = D.locate(src, kind, name, language=language)
        assert found is not None, f"{language} {kind} {name} not located"
        assert (found.start_line, found.end_line) == span
        assert found.text == _lines(src, *span)
        assert found.scope == "symbol"
        assert found.parser == "tree-sitter"

    @pytest.mark.parametrize("language, kind, name, span", HDL_CASES,
                             ids=[f"{c[0]}-{c[1]}-{c[2]}" for c in HDL_CASES])
    def test_hdl_kinds(self, tree_sitter, language, kind, name, span):
        src = SOURCES[language]
        found = D.locate(src, kind, name, language=language)
        assert found is not None
        assert (found.start_line, found.end_line) == span
        assert found.scope == "symbol"
        assert found.parser == "tree-sitter"

    def test_absent_name_falls_through_to_nothing(self, tree_sitter):
        assert D.locate(SOURCES["go"], "function", "nowhere", language="go") is None
        assert D.locate(SOURCES["vhdl"], "process", "nowhere", language="vhdl") is None

    def test_same_method_name_in_two_classes_resolves_per_class(self, tree_sitter):
        src = ("public class A {\n"
               "    public int check() { return 1; }\n"
               "}\n"
               "public class B {\n"
               "    public int check() { return 2; }\n"
               "}\n")
        a = D.locate(src, "method", "A.check", language="java")
        b = D.locate(src, "method", "B.check", language="java")
        assert (a.start_line, a.end_line) == (2, 2) and a.scope == "symbol"
        assert (b.start_line, b.end_line) == (5, 5) and b.scope == "symbol"

    def test_rust_attributes_belong_to_the_definition(self, tree_sitter):
        src = "#[test]\n#[ignore]\nfn it_works() {\n    assert!(true);\n}\n"
        found = D.locate(src, "function", "it_works", language="rust")
        assert (found.start_line, found.end_line) == (1, 5)
        assert found.text.startswith("#[test]")

    def test_export_wrapper_belongs_to_the_definition(self, tree_sitter):
        src = "export async function target(req) {\n  return req;\n}\n"
        found = D.locate(src, "function", "target", language="typescript")
        assert found.text.startswith("export async function target")
        assert found.end_line == 3

    def test_crlf_source_locates_the_same_lines(self, tree_sitter):
        src = SOURCES["go"].replace("\n", "\r\n")
        found = D.locate(src, "method", "Guard.Check", language="go")
        assert (found.start_line, found.end_line) == (9, 11)
        assert D.hash_of(found.text) == D.hash_of(_lines(SOURCES["go"], 9, 11))

    def test_python_still_uses_ast(self, tree_sitter):
        src = "@dec\ndef f():\n    pass\n\nclass C:\n    def f(self):\n        pass\n"
        top = D.locate(src, "function", "f", language="python")
        assert (top.start_line, top.end_line, top.parser) == (1, 3, "ast")
        method = D.locate(src, "method", "C.f", language="python")
        assert (method.start_line, method.end_line) == (6, 7)


# ---------------------------------------------------------------------------
# locate: fallbacks
# ---------------------------------------------------------------------------

class TestLocateWithoutTreeSitter:
    @pytest.mark.parametrize("language, kind, name, _span, fallback", CASES,
                             ids=[f"{c[0]}-{c[1]}-{c[2]}" for c in CASES])
    def test_block_heuristic_says_it_is_a_block(self, no_tree_sitter, language, kind, name,
                                                 _span, fallback):
        src = SOURCES[language]
        found = D.locate(src, kind, name, language=language)
        if fallback is None:
            assert found is None
            return
        assert (found.start_line, found.end_line) == fallback
        assert found.text == _lines(src, *fallback)
        assert found.scope == "block"
        assert found.parser == "lines"

    @pytest.mark.parametrize("language, kind, name, span", HDL_CASES,
                             ids=[f"{c[0]}-{c[1]}-{c[2]}" for c in HDL_CASES])
    def test_hdl_keyword_scanner_is_exact(self, no_tree_sitter, language, kind, name, span):
        src = SOURCES[language]
        found = D.locate(src, kind, name, language=language)
        assert found is not None
        assert (found.start_line, found.end_line) == span
        assert found.text == _lines(src, *span)
        assert found.scope == "symbol"
        assert found.parser == "keyword"

    def test_same_method_name_in_two_classes_resolves_to_the_first(self, no_tree_sitter):
        src = ("public class A {\n"
               "    public int check() { return 1; }\n"
               "}\n"
               "public class B {\n"
               "    public int check() { return 2; }\n"
               "}\n")
        b = D.locate(src, "method", "B.check", language="java")
        assert (b.start_line, b.end_line) == (2, 2)
        assert b.scope == "block"

    def test_python_is_unaffected(self, no_tree_sitter):
        src = "def f():\n    return 1\n"
        found = D.locate(src, "function", "f", language="python")
        assert found.parser == "ast" and found.scope == "symbol"

    def test_unknown_language_uses_python_then_lines(self, no_tree_sitter):
        found = D.locate("function target() {\n  return 1;\n}\n", "function", "target")
        assert (found.start_line, found.end_line, found.scope, found.parser) == (1, 3, "block", "lines")

    def test_invalid_python_falls_back_to_lines(self, no_tree_sitter):
        src = "def broken(:\n    pass\n\ndef target(x):\n    return x + 1\n"
        found = D.locate(src, "function", "target", language="python")
        assert found.text == "def target(x):\n    return x + 1"
        assert found.parser == "lines"

    def test_extract_definition_wrapper_accepts_a_language(self, no_tree_sitter):
        block = extract_definition(SOURCES["systemverilog"], "module", "top", language="systemverilog")
        assert block == _lines(SOURCES["systemverilog"], 45, 47)


# ---------------------------------------------------------------------------
# Attestation records scope and parser
# ---------------------------------------------------------------------------

JUNIT = """<testsuites><testsuite name="s">
  <testcase classname="auth" name="test_refuses" file="spec/auth.test.js"/>
  <testcase classname="rtl" name="tb_alu" file="rtl/alu_tb.sv"/>
</testsuite></testsuites>"""


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "auth.test.js").write_text(
        "function helper() {}\nfunction test_refuses() {\n  expect(guard()).toBe(false);\n}\n")
    (tmp_path / "rtl").mkdir()
    (tmp_path / "rtl" / "alu_tb.sv").write_text(
        "module tb;\n  task tb_alu();\n    $display(\"x\");\n  endtask\nendmodule\n")
    (tmp_path / "rtl" / "alu.sv").write_text(SOURCES["systemverilog"])
    (tmp_path / "report.xml").write_text(JUNIT)
    return tmp_path


def _entries(project: Path) -> dict:
    summary = parse_junit(project / "report.xml")
    locate_test_definitions(project, summary["tests"])
    return {t["name"]: t for t in summary["tests"]}


class TestAttestationScope:
    def test_parser_path_records_symbol_and_tree_sitter(self, tree_sitter, project):
        entries = _entries(project)
        js = entries["test_refuses"]
        assert js["definition_scope"] == "symbol" and js["parser"] == "tree-sitter"
        assert js["definition_sha256"] == D.hash_of(
            "function test_refuses() {\n  expect(guard()).toBe(false);\n}")
        sv = entries["tb_alu"]
        assert sv["definition_scope"] == "symbol" and sv["parser"] == "tree-sitter"

    def test_fallback_records_block_and_lines(self, no_tree_sitter, project):
        entries = _entries(project)
        js = entries["test_refuses"]
        assert js["definition_scope"] == "block" and js["parser"] == "lines"
        assert js["definition_sha256"] == D.hash_of(
            "function test_refuses() {\n  expect(guard()).toBe(false);\n}")
        sv = entries["tb_alu"]
        assert sv["definition_scope"] == "symbol" and sv["parser"] == "keyword"

    def test_file_scope_carries_no_parser(self, no_tree_sitter, project):
        (project / "spec" / "auth.test.js").write_text("module.exports = { test_refuses: 1 };\n")
        entries = _entries(project)
        js = entries["test_refuses"]
        assert js["definition_scope"] == "file"
        assert "parser" not in js


# ---------------------------------------------------------------------------
# Reach: the mechanism span in any language
# ---------------------------------------------------------------------------

class TestMechanismReach:
    def test_kind_is_read_from_the_mechanism_form(self):
        assert mechanism_kinds("module:alu") == (("module",), "alu")
        assert mechanism_kinds("always:seq_logic") == (("always",), "seq_logic")
        assert mechanism_kinds("Packet.size") == (("method", "class"), "Packet.size")
        assert mechanism_kinds("require_token")[0][:2] == ("function", "class")
        assert mechanism_kinds("require_token")[1] == "require_token"
        assert mechanism_kinds("nokind:x") == (D.MECHANISM_KIND_ORDER, "nokind:x")

    @pytest.mark.parametrize("symbol, span", [
        ("module:alu", (2, 37)),
        ("always:seq_logic", (15, 17)),
        ("alu", (2, 37)),
        ("seq_logic", (15, 17)),
        ("p_stable", (27, 29)),
        ("Packet.size", (42, 42)),
        ("add", (7, 9)),
        ("assert:a_stable", (35, 35)),
    ])
    def test_span_in_a_systemverilog_file(self, no_tree_sitter, project, symbol, span):
        assert mechanism_line_span(project, "rtl/alu.sv", symbol) == span

    def test_span_with_the_parser_agrees(self, tree_sitter, project):
        assert mechanism_line_span(project, "rtl/alu.sv", "always:seq_logic") == (15, 17)
        assert mechanism_line_span(project, "rtl/alu.sv", "Packet.size") == (42, 42)

    def test_reached_is_any_attested_line_inside_the_span(self, no_tree_sitter, project):
        hit = {"reached": [{"file": "rtl/alu.sv", "lines": [16]}]}
        miss = {"reached": [{"file": "rtl/alu.sv", "lines": [8, 20]}]}
        assert _reached_mechanism(hit, project, "rtl/alu.sv", "always:seq_logic") is True
        assert _reached_mechanism(miss, project, "rtl/alu.sv", "always:seq_logic") is False
        assert _reached_mechanism({}, project, "rtl/alu.sv", "always:seq_logic") is None
        assert _reached_mechanism(hit, project, "rtl/alu.sv", "module:nowhere") is None

    def test_suite_reach_never_establishes_reach(self, no_tree_sitter, project):
        entry = {"suite_reached": [{"file": "rtl/alu.sv", "lines": [16]}]}
        assert _reached_mechanism(entry, project, "rtl/alu.sv", "always:seq_logic") is None


class TestMechanismKindVocabulary:
    def test_one_tuple_everywhere(self):
        from mipiti_verify.languages import definitions as D
        from mipiti_verify.languages.adapters import _common as C
        from mipiti_verify.verifiers.tests import mechanism_kinds

        assert C.KINDS is D.MECHANISM_KINDS
        assert set(D.HDL_KINDS) < set(D.MECHANISM_KINDS)
        for kind in D.MECHANISM_KINDS:
            assert mechanism_kinds(f"{kind}:x") == ((kind,), "x")
            assert C.parse_mechanism(f"a/b.sv::{kind}:x").kind == kind
        assert mechanism_kinds("widget:x") == (D.MECHANISM_KIND_ORDER, "widget:x")

    def test_struct_and_impl_locate_as_class(self):
        from mipiti_verify.languages.definitions import locate

        src = "pub struct Limiter {\n    n: u32,\n}\n\nimpl Limiter {\n    pub fn allow(&self) -> bool { true }\n}\n"
        found = locate(src, "struct", "Limiter", language="rust")
        assert found is not None and found.start_line == 1
        assert locate(src, "class", "Limiter", language="rust").start_line == 1
