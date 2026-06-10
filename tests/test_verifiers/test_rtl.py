"""Tests for RTL/Verilog verifiers."""

from pathlib import Path

import pytest

from mipiti_verify.verifiers.rtl import (
    ModuleExistsVerifier,
    ModuleInstantiatedVerifier,
    ParameterDefinedVerifier,
    PortExistsVerifier,
    RegisterResetVerifier,
    SignalExistsVerifier,
    SvaAssertionPresentVerifier,
)


@pytest.fixture
def rtl_file(project_root: Path) -> Path:
    """Create a representative SystemVerilog file with two modules."""
    f = project_root / "top.sv"
    f.write_text(
        """// Crypto peripheral
module crypto_core #(
    parameter KEY_WIDTH = 256,
    parameter DEPTH = 16
) (
    input  wire clk,
    input  wire rst_n,
    input  wire [KEY_WIDTH-1:0] key_in,
    output reg  [7:0] status,
    inout  wire sda
);

    localparam STATE_IDLE = 3'b000;

    wire busy;
    reg [KEY_WIDTH-1:0] key_reg;
    logic done;

    key_expand #(.WIDTH(KEY_WIDTH)) u_expand (
        .clk(clk),
        .key(key_reg)
    );

    fifo u_fifo (
        .clk(clk),
        .data(status)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg <= '0;
            status <= 8'h00;
        end else begin
            status <= status + 1;
        end
    end

    property p_key_cleared;
        @(posedge clk) !rst_n |-> (key_reg == 0);
    endproperty

    assert_key_cleared : assert property (p_key_cleared);

endmodule

module key_expand #(parameter WIDTH = 128) (
    input wire clk,
    input wire [WIDTH-1:0] key
);
    reg [WIDTH-1:0] round_key;
    wire shadow_only_here;

    always @(posedge clk) begin
        round_key <= key;
    end
endmodule
""",
        encoding="utf-8",
    )
    return f


@pytest.fixture
def legacy_file(project_root: Path) -> Path:
    """Create a Verilog file with non-ANSI (body-style) port declarations."""
    f = project_root / "legacy.v"
    f.write_text(
        """module legacy_adder (a, b, sum);
    input [3:0] a;
    input [3:0] b;
    output [4:0] sum;

    assign sum = a + b;
endmodule
""",
        encoding="utf-8",
    )
    return f


class TestModuleExists:
    def test_module_found(self, rtl_file, project_root):
        v = ModuleExistsVerifier()
        r = v.verify({"file": "top.sv", "name": "crypto_core"}, project_root)
        assert r.passed is True
        assert "line" in r.details

    def test_second_module_found(self, rtl_file, project_root):
        v = ModuleExistsVerifier()
        r = v.verify({"file": "top.sv", "name": "key_expand"}, project_root)
        assert r.passed is True

    def test_primitive_found(self, project_root):
        f = project_root / "prim.v"
        f.write_text("primitive mux_prim (out, sel, a, b);\nendprimitive\n")
        v = ModuleExistsVerifier()
        r = v.verify({"file": "prim.v", "name": "mux_prim"}, project_root)
        assert r.passed is True

    def test_program_found(self, project_root):
        f = project_root / "tb.sv"
        f.write_text("program test_prog;\nendprogram\n")
        v = ModuleExistsVerifier()
        r = v.verify({"file": "tb.sv", "name": "test_prog"}, project_root)
        assert r.passed is True

    def test_instantiated_but_not_declared(self, rtl_file, project_root):
        # 'fifo' appears as an instantiation, not as a declaration.
        v = ModuleExistsVerifier()
        r = v.verify({"file": "top.sv", "name": "fifo"}, project_root)
        assert r.passed is False

    def test_module_missing(self, rtl_file, project_root):
        v = ModuleExistsVerifier()
        r = v.verify({"file": "top.sv", "name": "nonexistent"}, project_root)
        assert r.passed is False
        assert "not declared" in r.details

    def test_file_missing(self, project_root):
        v = ModuleExistsVerifier()
        r = v.verify({"file": "missing.sv", "name": "crypto_core"}, project_root)
        assert r.passed is False

    def test_path_traversal(self, project_root):
        v = ModuleExistsVerifier()
        r = v.verify({"file": "../outside.sv", "name": "crypto_core"}, project_root)
        assert r.passed is False
        assert "escapes" in r.details


class TestModuleInstantiated:
    def test_plain_instantiation(self, rtl_file, project_root):
        v = ModuleInstantiatedVerifier()
        r = v.verify(
            {"file": "top.sv", "parent": "crypto_core", "child": "fifo"},
            project_root,
        )
        assert r.passed is True
        assert "line" in r.details

    def test_parameterized_instantiation(self, rtl_file, project_root):
        v = ModuleInstantiatedVerifier()
        r = v.verify(
            {"file": "top.sv", "parent": "crypto_core", "child": "key_expand"},
            project_root,
        )
        assert r.passed is True

    def test_instantiated_in_other_module_only(self, rtl_file, project_root):
        # fifo is instantiated in crypto_core, not in key_expand.
        v = ModuleInstantiatedVerifier()
        r = v.verify(
            {"file": "top.sv", "parent": "key_expand", "child": "fifo"},
            project_root,
        )
        assert r.passed is False

    def test_child_absent(self, rtl_file, project_root):
        v = ModuleInstantiatedVerifier()
        r = v.verify(
            {"file": "top.sv", "parent": "crypto_core", "child": "uart"},
            project_root,
        )
        assert r.passed is False

    def test_parent_not_found(self, rtl_file, project_root):
        v = ModuleInstantiatedVerifier()
        r = v.verify(
            {"file": "top.sv", "parent": "missing_mod", "child": "fifo"},
            project_root,
        )
        assert r.passed is False
        assert "missing_mod" in r.details

    def test_file_missing(self, project_root):
        v = ModuleInstantiatedVerifier()
        r = v.verify(
            {"file": "missing.sv", "parent": "a", "child": "b"},
            project_root,
        )
        assert r.passed is False


class TestPortExists:
    def test_ansi_input_port(self, rtl_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "module": "crypto_core", "port": "clk"},
            project_root,
        )
        assert r.passed is True
        assert "line" in r.details

    def test_ansi_port_with_direction(self, rtl_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "module": "crypto_core", "port": "status", "direction": "output"},
            project_root,
        )
        assert r.passed is True

    def test_inout_port(self, rtl_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "module": "crypto_core", "port": "sda", "direction": "inout"},
            project_root,
        )
        assert r.passed is True

    def test_non_ansi_port(self, legacy_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "legacy.v", "module": "legacy_adder", "port": "sum", "direction": "output"},
            project_root,
        )
        assert r.passed is True

    def test_direction_mismatch(self, rtl_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "module": "crypto_core", "port": "clk", "direction": "output"},
            project_root,
        )
        assert r.passed is False

    def test_port_in_other_module_only(self, rtl_file, legacy_file, project_root):
        # clk is a port of crypto_core, not of legacy_adder.
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "legacy.v", "module": "legacy_adder", "port": "clk"},
            project_root,
        )
        assert r.passed is False

    def test_invalid_direction(self, rtl_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "module": "crypto_core", "port": "clk", "direction": "sideways"},
            project_root,
        )
        assert r.passed is False
        assert "direction" in r.details

    def test_module_not_found(self, rtl_file, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "module": "missing_mod", "port": "clk"},
            project_root,
        )
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = PortExistsVerifier()
        r = v.verify(
            {"file": "missing.sv", "module": "m", "port": "p"},
            project_root,
        )
        assert r.passed is False


class TestParameterDefined:
    def test_parameter_found(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify({"file": "top.sv", "parameter": "KEY_WIDTH"}, project_root)
        assert r.passed is True
        assert "line" in r.details

    def test_localparam_found(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify({"file": "top.sv", "parameter": "STATE_IDLE"}, project_root)
        assert r.passed is True

    def test_module_scoped(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify(
            {"file": "top.sv", "parameter": "DEPTH", "module": "crypto_core"},
            project_root,
        )
        assert r.passed is True

    def test_defined_only_in_other_module(self, rtl_file, project_root):
        # DEPTH is a parameter of crypto_core, not key_expand.
        v = ParameterDefinedVerifier()
        r = v.verify(
            {"file": "top.sv", "parameter": "DEPTH", "module": "key_expand"},
            project_root,
        )
        assert r.passed is False

    def test_value_pattern_match(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify(
            {"file": "top.sv", "parameter": "KEY_WIDTH", "pattern": "^256$"},
            project_root,
        )
        assert r.passed is True
        assert "256" in r.details

    def test_value_pattern_mismatch(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify(
            {"file": "top.sv", "parameter": "KEY_WIDTH", "pattern": "^128$"},
            project_root,
        )
        assert r.passed is False
        assert "256" in r.details

    def test_module_not_found(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify(
            {"file": "top.sv", "parameter": "KEY_WIDTH", "module": "missing_mod"},
            project_root,
        )
        assert r.passed is False
        assert "missing_mod" in r.details

    def test_parameter_missing(self, rtl_file, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify({"file": "top.sv", "parameter": "NOT_THERE"}, project_root)
        assert r.passed is False

    def test_invalid_user_pattern_fails_closed(self, rtl_file, project_root):
        # Lookahead is rejected by RE2; the verifier must fail, not pass.
        v = ParameterDefinedVerifier()
        r = v.verify(
            {"file": "top.sv", "parameter": "KEY_WIDTH", "pattern": "(?=256)"},
            project_root,
        )
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = ParameterDefinedVerifier()
        r = v.verify({"file": "missing.sv", "parameter": "X"}, project_root)
        assert r.passed is False


class TestSignalExists:
    def test_wire_found(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify({"file": "top.sv", "name": "busy"}, project_root)
        assert r.passed is True
        assert "line" in r.details

    def test_reg_with_kind(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "key_reg", "kind": "reg"},
            project_root,
        )
        assert r.passed is True

    def test_logic_found(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "done", "kind": "logic"},
            project_root,
        )
        assert r.passed is True

    def test_kind_mismatch(self, rtl_file, project_root):
        # busy is a wire, not a reg.
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "busy", "kind": "reg"},
            project_root,
        )
        assert r.passed is False

    def test_module_scoped(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "round_key", "module": "key_expand"},
            project_root,
        )
        assert r.passed is True

    def test_declared_only_in_other_module(self, rtl_file, project_root):
        # shadow_only_here is declared in key_expand, not crypto_core.
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "shadow_only_here", "module": "crypto_core"},
            project_root,
        )
        assert r.passed is False

    def test_invalid_kind(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "busy", "kind": "tri_state"},
            project_root,
        )
        assert r.passed is False
        assert "kind" in r.details

    def test_module_not_found(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify(
            {"file": "top.sv", "name": "busy", "module": "missing_mod"},
            project_root,
        )
        assert r.passed is False

    def test_signal_missing(self, rtl_file, project_root):
        v = SignalExistsVerifier()
        r = v.verify({"file": "top.sv", "name": "ghost_signal"}, project_root)
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = SignalExistsVerifier()
        r = v.verify({"file": "missing.sv", "name": "busy"}, project_root)
        assert r.passed is False


class TestSvaAssertionPresent:
    def test_property_declaration(self, rtl_file, project_root):
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "top.sv", "name": "p_key_cleared"}, project_root)
        assert r.passed is True
        assert "line" in r.details

    def test_labelled_assert(self, rtl_file, project_root):
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "top.sv", "name": "assert_key_cleared"}, project_root)
        assert r.passed is True

    def test_assert_property_reference(self, project_root):
        f = project_root / "checks.sv"
        f.write_text(
            "module checks(input clk);\n"
            "    assert property (p_stable_output);\n"
            "endmodule\n"
        )
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "checks.sv", "name": "p_stable_output"}, project_root)
        assert r.passed is True

    def test_labelled_cover(self, project_root):
        f = project_root / "cov.sv"
        f.write_text("cov_reset_seen : cover property (@(posedge clk) !rst_n);\n")
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "cov.sv", "name": "cov_reset_seen"}, project_root)
        assert r.passed is True

    def test_ordinary_identifier_is_not_assertion(self, rtl_file, project_root):
        # busy exists as a signal but is not a property/assertion.
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "top.sv", "name": "busy"}, project_root)
        assert r.passed is False

    def test_assertion_missing(self, rtl_file, project_root):
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "top.sv", "name": "p_not_there"}, project_root)
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = SvaAssertionPresentVerifier()
        r = v.verify({"file": "missing.sv", "name": "p_x"}, project_root)
        assert r.passed is False


class TestRegisterReset:
    def test_async_reset_default_detection(self, rtl_file, project_root):
        # rst_n is detected by the default reset-name heuristic.
        v = RegisterResetVerifier()
        r = v.verify({"file": "top.sv", "signal": "key_reg"}, project_root)
        assert r.passed is True
        assert "line" in r.details

    def test_async_reset_custom_reset_param(self, rtl_file, project_root):
        v = RegisterResetVerifier()
        r = v.verify(
            {"file": "top.sv", "signal": "status", "reset": "rst_n"},
            project_root,
        )
        assert r.passed is True

    def test_sync_reset(self, project_root):
        f = project_root / "sync.v"
        f.write_text(
            "module sync_unit(input clk, input rst, input d, output reg q);\n"
            "    always @(posedge clk) begin\n"
            "        if (rst)\n"
            "            q <= 1'b0;\n"
            "        else\n"
            "            q <= d;\n"
            "    end\n"
            "endmodule\n"
        )
        v = RegisterResetVerifier()
        r = v.verify({"file": "sync.v", "signal": "q"}, project_root)
        assert r.passed is True

    def test_assigned_only_outside_reset_blocks(self, rtl_file, project_root):
        # round_key is assigned in an always block with no reset reference.
        v = RegisterResetVerifier()
        r = v.verify({"file": "top.sv", "signal": "round_key"}, project_root)
        assert r.passed is False

    def test_custom_reset_not_referenced(self, rtl_file, project_root):
        v = RegisterResetVerifier()
        r = v.verify(
            {"file": "top.sv", "signal": "key_reg", "reset": "soft_rst"},
            project_root,
        )
        assert r.passed is False

    def test_signal_never_assigned(self, rtl_file, project_root):
        v = RegisterResetVerifier()
        r = v.verify({"file": "top.sv", "signal": "busy"}, project_root)
        assert r.passed is False

    def test_comparison_is_not_assignment(self, project_root):
        f = project_root / "cmp.v"
        f.write_text(
            "module cmp_only(input clk, input rst, output reg flag);\n"
            "    reg other;\n"
            "    always @(posedge clk) begin\n"
            "        if (rst && flag == 1'b1)\n"
            "            other <= 1'b0;\n"
            "    end\n"
            "endmodule\n"
        )
        v = RegisterResetVerifier()
        r = v.verify({"file": "cmp.v", "signal": "flag"}, project_root)
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = RegisterResetVerifier()
        r = v.verify({"file": "missing.sv", "signal": "q"}, project_root)
        assert r.passed is False

    def test_path_traversal(self, project_root):
        v = RegisterResetVerifier()
        r = v.verify({"file": "../../outside.sv", "signal": "q"}, project_root)
        assert r.passed is False
        assert "escapes" in r.details


class TestRegistry:
    def test_all_rtl_types_registered(self):
        from mipiti_verify.verifiers import get_verifier

        for a_type in (
            "module_exists",
            "module_instantiated",
            "port_exists",
            "parameter_defined",
            "signal_exists",
            "sva_assertion_present",
            "register_reset",
        ):
            assert get_verifier(a_type) is not None, f"no verifier registered for {a_type}"
