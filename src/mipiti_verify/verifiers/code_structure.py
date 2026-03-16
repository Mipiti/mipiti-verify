"""Code structure verifiers: function_exists, class_exists, decorator_present, function_calls, import_present."""

from __future__ import annotations

import re
from pathlib import Path

from . import PathTraversalError, VerifierResult, register, safe_read_file, safe_regex_search


@register("function_exists")
class FunctionExistsVerifier:
    """Check that a function/method exists in a file (multi-language regex)."""

    # Patterns for common languages
    _PATTERNS = [
        r"\bdef\s+{name}\s*\(",           # Python
        r"\bfunction\s+{name}\s*\(",       # JavaScript/PHP
        r"\b(?:async\s+)?{name}\s*\(",     # Go / general
        r"\bfn\s+{name}\s*\(",             # Rust
        r"\bfunc\s+{name}\s*\(",           # Swift/Go
        r"\b(?:public|private|protected|static|async)\s+\w+\s+{name}\s*\(",  # Java/C#
    ]

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        name = re.escape(params["name"])

        for pattern_template in self._PATTERNS:
            pattern = pattern_template.format(name=name)
            match = re.search(pattern, content)
            if match:
                line_no = content[:match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Function '{params['name']}' found at line {line_no}",
                )

        return VerifierResult(passed=False, details=f"Function '{params['name']}' not found in {params['file']}")


@register("class_exists")
class ClassExistsVerifier:
    """Check that a class/struct/interface exists in a file."""

    _PATTERNS = [
        r"\bclass\s+{name}\b",             # Python/Java/JS/C#
        r"\bstruct\s+{name}\b",            # Rust/Go/C
        r"\binterface\s+{name}\b",         # Java/TS/Go
        r"\benum\s+{name}\b",              # Various
        r"\btype\s+{name}\s+struct\b",     # Go
    ]

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        name = re.escape(params["name"])

        for pattern_template in self._PATTERNS:
            pattern = pattern_template.format(name=name)
            match = re.search(pattern, content)
            if match:
                line_no = content[:match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Class '{params['name']}' found at line {line_no}",
                )

        return VerifierResult(passed=False, details=f"Class '{params['name']}' not found in {params['file']}")


@register("decorator_present")
class DecoratorPresentVerifier:
    """Check that a decorator is applied to a function."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        decorator = re.escape(params["decorator"])
        function = re.escape(params["function"])

        # Look for @decorator ... def function pattern
        pattern = rf"@{decorator}[^\n]*\n(?:\s*@[^\n]*\n)*\s*(?:async\s+)?def\s+{function}\s*\("
        match = re.search(pattern, content)
        if match:
            line_no = content[:match.start()].count("\n") + 1
            return VerifierResult(
                passed=True,
                details=f"Decorator @{params['decorator']} found on {params['function']} at line {line_no}",
            )

        return VerifierResult(
            passed=False,
            details=f"Decorator @{params['decorator']} not found on {params['function']} in {params['file']}",
        )


@register("function_calls")
class FunctionCallsVerifier:
    """Check that a function calls another function."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        caller = params["caller"]
        callee = params["callee"]

        # Find the caller function body
        caller_pattern = rf"(?:def|function|fn|func)\s+{re.escape(caller)}\s*\("
        caller_match = re.search(caller_pattern, content)
        if not caller_match:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' not found")

        # Get the function body (until next function definition at same indentation)
        rest = content[caller_match.start():]
        lines = rest.split("\n")
        if not lines:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' has no body")

        # Collect body lines (indented more than the function definition)
        body_lines = []
        first_indent = len(lines[0]) - len(lines[0].lstrip())
        for i, line in enumerate(lines[1:], 1):
            stripped = line.lstrip()
            if not stripped:
                body_lines.append(line)
                continue
            indent = len(line) - len(stripped)
            if indent <= first_indent and stripped and not stripped.startswith("#") and not stripped.startswith("//"):
                break
            body_lines.append(line)

        body = "\n".join(body_lines)
        callee_pattern = rf"\b{re.escape(callee)}\s*\("
        if re.search(callee_pattern, body):
            return VerifierResult(
                passed=True,
                details=f"Function '{caller}' calls '{callee}'",
            )

        return VerifierResult(passed=False, details=f"Function '{caller}' does not call '{callee}'")


@register("import_present")
class ImportPresentVerifier:
    """Check that a module is imported in a file."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        module = params["module"]

        # Python: import X, from X import ...
        # JS/TS: import ... from 'X', require('X')
        # Go: "X"
        # Rust: use X
        patterns = [
            rf"\bimport\s+{re.escape(module)}\b",
            rf"\bfrom\s+{re.escape(module)}\b",
            rf"\brequire\s*\(\s*['\"]{ re.escape(module)}['\"]\s*\)",
            rf"\bfrom\s+['\"]{ re.escape(module)}['\"]",
            rf'\buse\s+{re.escape(module)}\b',
        ]

        for pattern in patterns:
            if re.search(pattern, content):
                return VerifierResult(
                    passed=True,
                    details=f"Import of '{module}' found in {params['file']}",
                )

        return VerifierResult(passed=False, details=f"Import of '{module}' not found in {params['file']}")
