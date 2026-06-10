"""RTL/Verilog verifiers: module_exists, module_instantiated, port_exists,
parameter_defined, signal_exists, sva_assertion_present, register_reset."""

from __future__ import annotations

import re2
from pathlib import Path

from . import (
    PathTraversalError,
    RegexTimeoutError,
    VerifierResult,
    register,
    resolve_content,
    safe_regex_search,
)

_PORT_DIRECTIONS = ("input", "output", "inout")
_SIGNAL_KINDS = ("wire", "reg", "logic", "bit")

# Default reset-signal detection when no explicit name is given:
# identifiers starting with rst/reset, case-insensitively
# (rst, rst_n, RESET, resetn, ...).
_DEFAULT_RESET_PATTERN = r"(?i)\b(rst|reset)\w*"


def _line_no(content: str, pos: int) -> int:
    """1-based line number of an absolute offset in ``content``."""
    return content[:pos].count("\n") + 1


def _module_slice(content: str, module_name: str) -> str | None:
    """Return the substring of ``content`` spanning the named module.

    The slice runs from the ``module``/``macromodule`` declaration to the
    first subsequent ``endmodule`` (end of file if none). Returns None when
    the module is not declared in ``content``.
    """
    name = re2.escape(module_name)
    start_match = re2.search(rf"\b(module|macromodule)\s+{name}\b", content)
    if not start_match:
        return None
    rest = content[start_match.start():]
    end_match = re2.search(r"\bendmodule\b", rest)
    if end_match:
        return rest[:end_match.end()]
    return rest


def _slice_offset(content: str, slice_text: str) -> int:
    """Absolute offset of a module slice within the full content."""
    pos = content.find(slice_text)
    return pos if pos >= 0 else 0


@register("module_exists")
class ModuleExistsVerifier:
    """Check that a Verilog/SystemVerilog module (or primitive/program) is declared."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        name = re2.escape(params["name"])
        pattern = rf"\b(module|macromodule|primitive|program)\s+{name}\b"
        match = re2.search(pattern, content)
        if match:
            line_no = _line_no(content, match.start())
            return VerifierResult(
                passed=True,
                details=f"Module '{params['name']}' declared at line {line_no}",
            )

        return VerifierResult(
            passed=False,
            details=f"Module '{params['name']}' not declared in {source}",
        )


@register("module_instantiated")
class ModuleInstantiatedVerifier:
    """Check that a module directly instantiates another module in its body."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        parent = params["parent"]
        child = params["child"]

        parent_slice = _module_slice(content, parent)
        if parent_slice is None:
            return VerifierResult(
                passed=False,
                details=f"Module '{parent}' not found in {source}",
            )

        child_esc = re2.escape(child)
        # Parameterized instantiation: child #(...) inst_name (...)
        # Plain instantiation:         child inst_name (...)
        patterns = [
            rf"\b{child_esc}\s*#\s*\(",
            rf"\b{child_esc}\s+\w+\s*\(",
        ]
        offset = _slice_offset(content, parent_slice)
        for pattern in patterns:
            match = re2.search(pattern, parent_slice)
            if match:
                line_no = _line_no(content, offset + match.start())
                return VerifierResult(
                    passed=True,
                    details=f"Module '{parent}' instantiates '{child}' at line {line_no}",
                )

        return VerifierResult(
            passed=False,
            details=f"Module '{parent}' does not instantiate '{child}' in {source}",
        )


@register("port_exists")
class PortExistsVerifier:
    """Check that a module declares a port (ANSI header or non-ANSI body style)."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        module = params["module"]
        port = params["port"]
        direction = params.get("direction")
        if direction is not None and direction not in _PORT_DIRECTIONS:
            return VerifierResult(
                passed=False,
                details=f"Invalid port direction {direction!r} (expected one of {', '.join(_PORT_DIRECTIONS)})",
            )

        module_slice = _module_slice(content, module)
        if module_slice is None:
            return VerifierResult(
                passed=False,
                details=f"Module '{module}' not found in {source}",
            )

        direction_alt = direction if direction else "(input|output|inout)"
        port_esc = re2.escape(port)
        # [^;)]* keeps the match inside one declaration, covering both
        # ANSI header ports and non-ANSI body declarations.
        pattern = rf"\b{direction_alt}\b[^;)]*\b{port_esc}\b"
        match = re2.search(pattern, module_slice)
        if match:
            offset = _slice_offset(content, module_slice)
            line_no = _line_no(content, offset + match.start())
            qualifier = f" ({direction})" if direction else ""
            return VerifierResult(
                passed=True,
                details=f"Port '{port}'{qualifier} declared in module '{module}' at line {line_no}",
            )

        qualifier = f" with direction '{direction}'" if direction else ""
        return VerifierResult(
            passed=False,
            details=f"Port '{port}'{qualifier} not declared in module '{module}' in {source}",
        )


@register("parameter_defined")
class ParameterDefinedVerifier:
    """Check that a parameter/localparam is declared, optionally matching its value."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        name = params["parameter"]
        module = params.get("module")
        value_pattern = params.get("pattern")

        if module:
            scope = _module_slice(content, module)
            if scope is None:
                return VerifierResult(
                    passed=False,
                    details=f"Module '{module}' not found in {source}",
                )
            scope_label = f"module '{module}'"
        else:
            scope = content
            scope_label = source

        name_esc = re2.escape(name)
        decl_pattern = rf"\b(parameter|localparam)\b[^;)]*\b{name_esc}\b"
        decl_match = re2.search(decl_pattern, scope)
        if not decl_match:
            return VerifierResult(
                passed=False,
                details=f"Parameter '{name}' not declared in {scope_label}",
            )

        offset = _slice_offset(content, scope) if module else 0
        line_no = _line_no(content, offset + decl_match.start())

        if not value_pattern:
            return VerifierResult(
                passed=True,
                details=f"Parameter '{name}' declared at line {line_no}",
            )

        value_match = re2.search(rf"\b{name_esc}\b\s*=\s*([^,;)\n]+)", scope)
        if not value_match:
            return VerifierResult(
                passed=False,
                details=f"Parameter '{name}' declared but no assigned value found in {scope_label}",
            )
        value = value_match.group(1).strip()

        try:
            match = safe_regex_search(value_pattern, value)
        except RegexTimeoutError as e:
            return VerifierResult(passed=False, details=f"Pattern check failed: {e}")

        if match:
            return VerifierResult(
                passed=True,
                details=f"Parameter '{name}' declared at line {line_no} with value '{value}' matching pattern",
            )
        return VerifierResult(
            passed=False,
            details=f"Parameter '{name}' value '{value}' does not match pattern '{value_pattern}'",
        )


@register("signal_exists")
class SignalExistsVerifier:
    """Check that a net/variable (wire, reg, logic, bit) is declared."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        name = params["name"]
        module = params.get("module")
        kind = params.get("kind")
        if kind is not None and kind not in _SIGNAL_KINDS:
            return VerifierResult(
                passed=False,
                details=f"Invalid signal kind {kind!r} (expected one of {', '.join(_SIGNAL_KINDS)})",
            )

        if module:
            scope = _module_slice(content, module)
            if scope is None:
                return VerifierResult(
                    passed=False,
                    details=f"Module '{module}' not found in {source}",
                )
            scope_label = f"module '{module}'"
        else:
            scope = content
            scope_label = source

        kind_alt = kind if kind else "(wire|reg|logic|bit)"
        name_esc = re2.escape(name)
        pattern = rf"\b{kind_alt}\b[^;]*\b{name_esc}\b"
        match = re2.search(pattern, scope)
        if match:
            offset = _slice_offset(content, scope) if module else 0
            line_no = _line_no(content, offset + match.start())
            qualifier = f" ({kind})" if kind else ""
            return VerifierResult(
                passed=True,
                details=f"Signal '{name}'{qualifier} declared at line {line_no}",
            )

        qualifier = f" of kind '{kind}'" if kind else ""
        return VerifierResult(
            passed=False,
            details=f"Signal '{name}'{qualifier} not declared in {scope_label}",
        )


@register("sva_assertion_present")
class SvaAssertionPresentVerifier:
    """Check that a named SystemVerilog assertion exists.

    Recognized forms: a ``property <name>`` declaration, a labelled
    ``<name> : assert|assume|cover`` statement, or an
    ``assert property (<name> ...)`` reference.
    """

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        name = re2.escape(params["name"])
        patterns = [
            rf"\bproperty\s+{name}\b",
            rf"\b{name}\s*:\s*(assert|assume|cover)\b",
            rf"\bassert\s+property\s*\(\s*{name}\b",
        ]
        for pattern in patterns:
            match = re2.search(pattern, content)
            if match:
                line_no = _line_no(content, match.start())
                return VerifierResult(
                    passed=True,
                    details=f"Assertion '{params['name']}' found at line {line_no}",
                )

        return VerifierResult(
            passed=False,
            details=f"Assertion '{params['name']}' not found in {source}",
        )


@register("register_reset")
class RegisterResetVerifier:
    """Check that a register is assigned on a reset path.

    Passes when some always block both references the reset signal and
    assigns the register.
    """

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        signal = params["signal"]
        reset = params.get("reset")
        if reset:
            reset_pattern = rf"\b{re2.escape(reset)}\b"
            reset_label = f"reset signal '{reset}'"
        else:
            reset_pattern = _DEFAULT_RESET_PATTERN
            reset_label = "a reset signal (rst*/reset*)"

        # Assignment to the signal (blocking or non-blocking); the trailing
        # [^=] excludes equality comparisons (==).
        assign_pattern = rf"\b{re2.escape(signal)}\b\s*(<=|=)[^=]"

        # Split content into always blocks: each runs from an always keyword
        # to the next always/initial/endmodule boundary (or EOF).
        boundary_pattern = r"\b(always(_ff|_comb|_latch)?|initial|endmodule)\b"
        boundaries = list(re2.finditer(boundary_pattern, content))
        for i, bound in enumerate(boundaries):
            if not bound.group(1).startswith("always"):
                continue
            start = bound.start()
            end = boundaries[i + 1].start() if i + 1 < len(boundaries) else len(content)
            block = content[start:end]

            if not re2.search(reset_pattern, block):
                continue
            assign_match = re2.search(assign_pattern, block)
            if assign_match:
                line_no = _line_no(content, start + assign_match.start())
                return VerifierResult(
                    passed=True,
                    details=f"Register '{signal}' assigned on a reset path at line {line_no}",
                )

        return VerifierResult(
            passed=False,
            details=(
                f"No always block in {source} both references {reset_label} "
                f"and assigns register '{signal}'"
            ),
        )
