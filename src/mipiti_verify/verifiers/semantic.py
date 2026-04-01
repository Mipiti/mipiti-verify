"""Semantic verifiers: parameter_validated, error_handled, middleware_registered, http_header_set.

These types rely heavily on Tier 2 for real verification.
Tier 1 just confirms structural presence (regex).
"""

from __future__ import annotations

import re
from pathlib import Path

from . import PathTraversalError, VerifierResult, register, resolve_content


@register("parameter_validated")
class ParameterValidatedVerifier:
    """Tier 1: Check function exists and references the parameter name."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")
        function = params["function"]
        parameter = params["parameter"]

        # Check function exists
        func_pattern = rf"(?:def|function|fn|func)\s+{re.escape(function)}\s*\("
        if not re.search(func_pattern, content):
            return VerifierResult(passed=False, details=f"Function '{function}' not found")

        # Check parameter is referenced (loose check)
        if re.search(re.escape(parameter), content):
            return VerifierResult(
                passed=True,
                details=f"Function '{function}' references parameter '{parameter}' (semantic verification needed)",
            )
        return VerifierResult(
            passed=False,
            details=f"Parameter '{parameter}' not referenced in {source}",
        )


@register("error_handled")
class ErrorHandledVerifier:
    """Tier 1: Check function has error handling constructs."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")
        function = params["function"]

        # Check function exists
        func_pattern = rf"(?:def|function|fn|func)\s+{re.escape(function)}\s*\("
        func_match = re.search(func_pattern, content)
        if not func_match:
            return VerifierResult(passed=False, details=f"Function '{function}' not found")

        # Check for error handling in the remainder of the file after the function
        rest = content[func_match.start():]
        error_patterns = [
            r"\btry\s*:",           # Python
            r"\btry\s*\{",          # JS/Java/C#
            r"\bcatch\s*\(",        # JS/Java
            r"\bexcept\s+",         # Python
            r"\.catch\s*\(",        # Promise.catch
            r"\bif\s+err\b",       # Go
            r"\bResult\s*<",       # Rust
            r"\bruntime\.recover",  # Go recover
        ]

        for pattern in error_patterns:
            if re.search(pattern, rest[:5000]):  # Check first ~5K chars of body
                return VerifierResult(
                    passed=True,
                    details=f"Function '{function}' has error handling (semantic verification needed)",
                )

        return VerifierResult(
            passed=False,
            details=f"No error handling found in '{function}'",
        )


@register("middleware_registered")
class MiddlewareRegisteredVerifier:
    """Tier 1: Check middleware name appears in file."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")
        middleware = params["middleware"]

        # Look for middleware registration patterns
        patterns = [
            rf"\.use\s*\(\s*{re.escape(middleware)}",      # Express.js app.use()
            rf"\.add_middleware\s*\(\s*{re.escape(middleware)}",  # FastAPI
            rf"middleware\s*=\s*\[.*{re.escape(middleware)}",     # Django/list-based
            rf"@{re.escape(middleware)}",                   # Decorator-based
            rf"{re.escape(middleware)}",                    # Plain reference
        ]

        for pattern in patterns:
            if re.search(pattern, content):
                return VerifierResult(
                    passed=True,
                    details=f"Middleware '{middleware}' found in {source} (semantic verification needed)",
                )

        return VerifierResult(
            passed=False,
            details=f"Middleware '{middleware}' not found in {source}",
        )


@register("http_header_set")
class HttpHeaderSetVerifier:
    """Tier 1: Check HTTP header name appears in file."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")
        header = params["header"]

        # Case-insensitive search for the header name
        if re.search(re.escape(header), content, re.IGNORECASE):
            return VerifierResult(
                passed=True,
                details=f"Header '{header}' referenced in {source} (semantic verification needed)",
            )
        return VerifierResult(
            passed=False,
            details=f"Header '{header}' not found in {source}",
        )
