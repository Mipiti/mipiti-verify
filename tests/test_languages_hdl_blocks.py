"""The keyword-pair scanner: exact HDL blocks without a grammar.

The fixtures carry what trips a naive scanner: keywords inside comments
and strings, declarations that open no block (``extern``, DPI imports,
forward ``typedef class``, VHDL subprogram declarations), nested
``begin … end`` inside a labelled block, action blocks on assertions,
out-of-body class methods, and VHDL's case-insensitive names.
"""

from __future__ import annotations

import pytest

from mipiti_verify.languages import hdl_blocks as H

SV = """// module fake_in_comment ... endmodule
/* multi-line comment
   endfunction endclass */
`include "defs.svh"
import "DPI-C" function int c_add(input int a, b);
typedef class Fwd;
extern function void Ext::run();
module top #(parameter N = 4) (input logic clk);
    string s = "endmodule inside a string";
    function automatic int add(input int a, b);
        if (a) begin
            return a + b;
        end
        return b;
    endfunction
    seq: always_ff @(posedge clk) begin
        if (clk) begin : inner
            q <= 1;
        end
    end
    always_comb begin : comb_logic
        y = a;
    end
    initial q = 0;
    a_lbl: assert property (@(posedge clk) a |-> b) else begin
        $error("x");
    end
    c_lbl: cover property (p);
    p_lbl: assume property (@(posedge clk) a) else $error("y");
    case (q)
        2'd0: begin q <= 1; end
        default: q <= 0;
    endcase
endmodule
class Packet;
    function new(); endfunction
    extern function void print();
    function int size(); return 1; endfunction
    task run(); endtask
endclass
function void Packet::print();
    $display("p");
endfunction
"""

VHDL = """-- entity fake is
library ieee;
use ieee.std_logic_1164.all;
entity Alu is
  port (a : in std_logic; y : out std_logic);
end Alu;
architecture RTL of Alu is
  signal s : std_logic := '1';
  function add(x : std_logic) return std_logic;
  function add(x : std_logic) return std_logic is
  begin
    if x = '1' then
      return '0';
    end if;
    return x;
  end function add;
  component sub is
    port (p : in std_logic);
  end component;
begin
  u_sub: entity work.sub port map (p => a);
  SEQ_LOGIC: process(a)
    variable v : integer := 0;
  begin
    case v is
      when 0 => v := 1;
      when others => null;
    end case;
    for i in 0 to 3 loop
      v := v + 1;
    end loop;
    y <= a;
  end process SEQ_LOGIC;
  gen: for i in 0 to 1 generate
    u: entity work.sub port map (p => a);
  end generate gen;
  process (a) begin y <= a; end process;
end architecture RTL;
"""


def line(src: str, needle: str) -> int:
    """1-based line of the first line containing ``needle`` (must be unique)."""
    hits = [i + 1 for i, l in enumerate(src.split("\n")) if needle in l]
    assert len(hits) == 1, f"{needle!r} matched lines {hits}"
    return hits[0]


def last(src: str, needle: str) -> int:
    """1-based line of the last line containing ``needle`` (earlier ones are
    the comment / string decoys the fixture plants)."""
    hits = [i + 1 for i, l in enumerate(src.split("\n")) if needle in l]
    assert hits, f"{needle!r} not found"
    return hits[-1]


def blocks_by(blocks, kind, name=None):
    return [b for b in blocks if b.kind == kind and (name is None or b.name == name)]


class TestVerilogScanner:
    @pytest.fixture
    def blocks(self):
        return H.scan_verilog(SV)

    def test_comments_strings_and_declarations_open_nothing(self, blocks):
        assert blocks_by(blocks, "module", "fake_in_comment") == []
        assert [b.name for b in blocks_by(blocks, "module")] == ["top"]
        names = {(b.kind, b.name, b.owner) for b in blocks}
        assert ("function", "c_add", "") not in names       # DPI import
        assert ("function", "run", "Ext") not in names      # extern declaration
        assert ("class", "Fwd", "") not in names            # forward typedef
        assert ("function", "print", "") not in names       # extern inside the class

    def test_module_and_subprograms(self, blocks):
        top = blocks_by(blocks, "module", "top")[0]
        assert (top.start_line, top.end_line) == (line(SV, "module top"), last(SV, "endmodule"))
        add = blocks_by(blocks, "function", "add")[0]
        assert (add.start_line, add.end_line) == (line(SV, "function automatic int add"),
                                                  line(SV, "    endfunction"))
        assert blocks_by(blocks, "task", "run")[0].start_line == line(SV, "task run();")

    def test_labelled_always_prefix_form_spans_the_outer_block(self, blocks):
        seq = blocks_by(blocks, "always", "seq")[0]
        assert seq.start_line == line(SV, "seq: always_ff")
        # Ends at the outer ``end``, past the nested ``begin : inner … end``.
        assert seq.end_line == line(SV, "always_comb begin : comb_logic") - 1
        inner = blocks_by(blocks, "block", "inner")[0]
        assert seq.start_line < inner.start_line < inner.end_line < seq.end_line

    def test_begin_label_form_names_the_always(self, blocks):
        comb = blocks_by(blocks, "always", "comb_logic")[0]
        assert (comb.start_line, comb.end_line) == (line(SV, "always_comb begin : comb_logic"),
                                                    line(SV, "always_comb begin : comb_logic") + 2)

    def test_single_statement_initial_ends_at_its_semicolon(self, blocks):
        init = blocks_by(blocks, "initial")[0]
        assert init.name == ""
        assert (init.start_line, init.end_line) == (line(SV, "initial q = 0;"),) * 2

    def test_assertion_labels(self, blocks):
        a = blocks_by(blocks, "assert", "a_lbl")[0]
        assert a.start_line == line(SV, "a_lbl: assert")
        assert a.end_line == line(SV, "a_lbl: assert") + 2   # ``else begin … end`` action block
        c = blocks_by(blocks, "assert", "c_lbl")[0]
        assert (c.start_line, c.end_line) == (line(SV, "c_lbl: cover"),) * 2
        p = blocks_by(blocks, "assert", "p_lbl")[0]
        assert (p.start_line, p.end_line) == (line(SV, "p_lbl: assume"),) * 2

    def test_case_items_are_not_labels(self, blocks):
        assert all(b.name != "default" for b in blocks)
        case = blocks_by(blocks, "case")[0]
        assert (case.start_line, case.end_line) == (line(SV, "case (q)"), line(SV, "endcase"))

    def test_class_methods_and_out_of_body_definition(self, blocks):
        packet = blocks_by(blocks, "class", "Packet")[0]
        assert (packet.start_line, packet.end_line) == (line(SV, "class Packet;"), last(SV, "endclass"))
        new = blocks_by(blocks, "function", "new")[0]
        assert packet.start_line < new.start_line < packet.end_line
        out = blocks_by(blocks, "function", "print")[0]
        assert out.owner == "Packet"
        assert (out.start_line, out.end_line) == (line(SV, "function void Packet::print"),
                                                  len(SV.rstrip("\n").split("\n")))


class TestVerilogLocate:
    def test_method_inside_class_and_out_of_body(self):
        size = H.locate_block(SV, "method", "Packet.size", "systemverilog")
        assert (size.start_line, size.end_line) == (line(SV, "function int size"),) * 2
        assert size.scope == "symbol" and size.parser == "keyword"
        printed = H.locate_block(SV, "method", "Packet.print", "systemverilog")
        assert printed.start_line == line(SV, "function void Packet::print")

    def test_function_means_any_subprogram_but_task_is_strict(self):
        assert H.locate_block(SV, "task", "add", "systemverilog") is None
        run = H.locate_block(SV, "function", "run", "systemverilog")
        assert run is not None and run.start_line == line(SV, "task run();")
        assert H.locate_block(SV, "always", "seq", "systemverilog") is not None
        assert H.locate_block(SV, "initial", "seq", "systemverilog") is None

    def test_unnamed_blocks_are_never_matched_by_an_empty_name(self):
        assert H.locate_block(SV, "initial", "", "systemverilog") is None

    def test_text_is_the_exact_lines(self):
        found = H.locate_block(SV, "always", "comb_logic", "systemverilog")
        assert found.text == "    always_comb begin : comb_logic\n        y = a;\n    end"


class TestVhdlScanner:
    @pytest.fixture
    def blocks(self):
        return H.scan_vhdl(VHDL)

    def test_entity_and_architecture(self, blocks):
        ent = blocks_by(blocks, "entity", "Alu")[0]
        assert (ent.start_line, ent.end_line) == (line(VHDL, "entity Alu is"), line(VHDL, "end Alu;"))
        arch = blocks_by(blocks, "architecture", "RTL")[0]
        assert (arch.start_line, arch.end_line) == (line(VHDL, "architecture RTL of Alu is"),
                                                    line(VHDL, "end architecture RTL;"))

    def test_comment_and_instantiations_open_nothing(self, blocks):
        assert [b.name for b in blocks_by(blocks, "entity")] == ["Alu"]

    def test_subprogram_declaration_is_not_a_body(self, blocks):
        adds = blocks_by(blocks, "function", "add")
        assert len(adds) == 1
        assert (adds[0].start_line, adds[0].end_line) == (
            line(VHDL, "return std_logic is"), line(VHDL, "end function add;"))

    def test_component_declaration(self, blocks):
        comp = blocks_by(blocks, "component", "sub")[0]
        assert (comp.start_line, comp.end_line) == (line(VHDL, "component sub is"), line(VHDL, "end component;"))

    def test_labelled_process_spans_its_nested_statements(self, blocks):
        proc = blocks_by(blocks, "process", "SEQ_LOGIC")[0]
        assert (proc.start_line, proc.end_line) == (line(VHDL, "SEQ_LOGIC: process(a)"),
                                                    line(VHDL, "end process SEQ_LOGIC;"))
        case = blocks_by(blocks, "case")[0]
        loop = blocks_by(blocks, "loop")[0]
        assert proc.start_line < case.start_line < case.end_line < loop.start_line < loop.end_line < proc.end_line

    def test_unlabelled_process_and_generate(self, blocks):
        unlabelled = [b for b in blocks_by(blocks, "process") if b.name == ""]
        assert len(unlabelled) == 1
        assert unlabelled[0].start_line == line(VHDL, "process (a) begin")
        gen = blocks_by(blocks, "generate")[0]
        assert (gen.start_line, gen.end_line) == (line(VHDL, "gen: for i in 0 to 1 generate"),
                                                  line(VHDL, "end generate gen;"))


class TestVhdlLocate:
    def test_names_are_case_insensitive(self):
        found = H.locate_block(VHDL, "process", "seq_logic", "vhdl")
        assert found is not None and found.scope == "symbol"
        assert found.start_line == line(VHDL, "SEQ_LOGIC: process(a)")
        assert H.locate_block(VHDL, "entity", "ALU", "vhdl").start_line == line(VHDL, "entity Alu is")

    def test_function_is_the_body_not_the_declaration(self):
        found = H.locate_block(VHDL, "function", "add", "vhdl")
        assert found.start_line == line(VHDL, "return std_logic is")
        assert found.text.endswith("end function add;")

    def test_unknown_name_is_none(self):
        assert H.locate_block(VHDL, "process", "nowhere", "vhdl") is None
        assert H.locate_block(VHDL, "procedure", "add", "vhdl") is None


class TestUnknownLanguage:
    def test_both_scanners_are_tried(self):
        assert H.locate_block(SV, "module", "top", "").start_line == line(SV, "module top")
        assert H.locate_block(VHDL, "entity", "Alu", "").start_line == line(VHDL, "entity Alu is")
