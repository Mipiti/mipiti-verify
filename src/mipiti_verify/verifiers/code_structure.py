"""Code structure verifiers: function_exists, class_exists, decorator_present, function_calls, import_present."""

from __future__ import annotations

import ast

import re2
from pathlib import Path

from . import PathTraversalError, VerifierResult, register, resolve_content, safe_regex_search


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
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        name = re2.escape(params["name"])

        for pattern_template in self._PATTERNS:
            pattern = pattern_template.format(name=name)
            match = re2.search(pattern, content)
            if match:
                line_no = content[:match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Function '{params['name']}' found at line {line_no}",
                )

        return VerifierResult(passed=False, details=f"Function '{params['name']}' not found in {source}")


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
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        name = re2.escape(params["name"])

        for pattern_template in self._PATTERNS:
            pattern = pattern_template.format(name=name)
            match = re2.search(pattern, content)
            if match:
                line_no = content[:match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Class '{params['name']}' found at line {line_no}",
                )

        return VerifierResult(passed=False, details=f"Class '{params['name']}' not found in {source}")


@register("decorator_present")
class DecoratorPresentVerifier:
    """Check that a decorator is applied to a function."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        decorator = re2.escape(params["decorator"])
        function = re2.escape(params["function"])

        # Look for @decorator ... def function pattern
        pattern = rf"@{decorator}[^\n]*\n(?:\s*@[^\n]*\n)*\s*(?:async\s+)?def\s+{function}\s*\("
        match = re2.search(pattern, content)
        if match:
            line_no = content[:match.start()].count("\n") + 1
            return VerifierResult(
                passed=True,
                details=f"Decorator @{params['decorator']} found on {params['function']} at line {line_no}",
            )

        return VerifierResult(
            passed=False,
            details=f"Decorator @{params['decorator']} not found on {params['function']} in {source}",
        )


@register("function_calls")
class FunctionCallsVerifier:
    """Check that a function calls another function.

    Python sources are analysed with the ``ast`` module: the caller's
    definition is located and its body walked for a call to the callee.
    This handles multi-line signatures, decorators, methods, and nested
    calls — cases a line-indentation body slice mishandles, because the
    closing line of a wrapped signature sits at the ``def``-level indent
    and would otherwise be mistaken for the end of the body. Bare calls
    (``callee(...)``) and attribute calls (``obj.callee(...)``) both count.

    Other languages fall back to a regex scan of the caller's body; that
    scan skips past the (possibly multi-line) signature by balancing the
    signature's parentheses before collecting body lines.
    """

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        caller = params["caller"]
        callee = params["callee"]

        if str(source).endswith(".py"):
            verdict = self._verify_python(content, caller, callee)
            if verdict is not None:
                return verdict
            # Unparseable Python falls through to the regex scan below.

        return self._verify_regex(content, caller, callee)

    @staticmethod
    def _verify_python(content: str, caller: str, callee: str) -> VerifierResult | None:
        """AST analysis. Returns a result, or None if the source will not
        parse (so the caller can fall back to the regex scan)."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return None

        found_caller = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == caller:
                found_caller = True
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        func = sub.func
                        name = getattr(func, "id", None) or getattr(func, "attr", None)
                        if name == callee:
                            return VerifierResult(
                                passed=True,
                                details=f"Function '{caller}' calls '{callee}'",
                            )
        if not found_caller:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' not found")
        return VerifierResult(passed=False, details=f"Function '{caller}' does not call '{callee}'")

    @staticmethod
    def _verify_regex(content: str, caller: str, callee: str) -> VerifierResult:
        """Regex fallback for non-Python languages."""
        caller_pattern = rf"(?:def|function|fn|func)\s+{re2.escape(caller)}\s*\("
        caller_match = re2.search(caller_pattern, content)
        if not caller_match:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' not found")

        # Skip past the (possibly multi-line) signature by balancing the
        # parentheses from the first '(' after the caller name.
        open_idx = content.find("(", caller_match.start())
        if open_idx == -1:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' has no signature")
        depth = 0
        i = open_idx
        while i < len(content):
            ch = content[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        # Body begins after the line that closes the signature.
        nl = content.find("\n", i)
        if nl == -1:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' has no body")

        # Collect body lines until a non-comment line dedents below the
        # first body line's indentation.
        body_lines = []
        ref_indent = None
        for line in content[nl + 1:].split("\n"):
            stripped = line.lstrip()
            if not stripped:
                body_lines.append(line)
                continue
            indent = len(line) - len(stripped)
            if ref_indent is None:
                ref_indent = indent
            elif indent < ref_indent and not stripped.startswith("#") and not stripped.startswith("//"):
                break
            body_lines.append(line)

        body = "\n".join(body_lines)
        callee_pattern = rf"\b{re2.escape(callee)}\s*\("
        if re2.search(callee_pattern, body):
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
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        module = params["module"]

        # Python: import X, from X import ...
        # JS/TS: import ... from 'X', require('X')
        # Go: "X"
        # Rust: use X
        patterns = [
            rf"\bimport\s+{re2.escape(module)}\b",
            rf"\bfrom\s+{re2.escape(module)}\b",
            rf"\brequire\s*\(\s*['\"]{ re2.escape(module)}['\"]\s*\)",
            rf"\bfrom\s+['\"]{ re2.escape(module)}['\"]",
            rf'\buse\s+{re2.escape(module)}\b',
        ]

        for pattern in patterns:
            if re2.search(pattern, content):
                return VerifierResult(
                    passed=True,
                    details=f"Import of '{module}' found in {source}",
                )

        return VerifierResult(passed=False, details=f"Import of '{module}' not found in {source}")
