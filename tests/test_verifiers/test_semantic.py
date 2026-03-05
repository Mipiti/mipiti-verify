"""Tests for semantic verifiers (Tier 1 structural checks)."""

from pathlib import Path

import pytest

from mipiti_verify.verifiers.semantic import (
    ErrorHandledVerifier,
    HttpHeaderSetVerifier,
    MiddlewareRegisteredVerifier,
    ParameterValidatedVerifier,
)


class TestParameterValidated:
    def test_parameter_referenced(self, python_file, project_root):
        v = ParameterValidatedVerifier()
        r = v.verify(
            {"file": "app.py", "function": "validate_input", "parameter": "data"},
            project_root,
        )
        assert r.passed is True

    def test_function_missing(self, python_file, project_root):
        v = ParameterValidatedVerifier()
        r = v.verify(
            {"file": "app.py", "function": "nonexistent", "parameter": "data"},
            project_root,
        )
        assert r.passed is False

    def test_parameter_not_referenced(self, project_root):
        f = project_root / "simple.py"
        f.write_text("def validate(x):\n    return True\n")
        v = ParameterValidatedVerifier()
        r = v.verify(
            {"file": "simple.py", "function": "validate", "parameter": "user_id"},
            project_root,
        )
        assert r.passed is False


class TestErrorHandled:
    def test_python_try_except(self, python_file, project_root):
        v = ErrorHandledVerifier()
        r = v.verify({"file": "app.py", "function": "validate_input"}, project_root)
        assert r.passed is True

    def test_js_try_catch(self, js_file, project_root):
        v = ErrorHandledVerifier()
        r = v.verify({"file": "server.js", "function": "handleAuth"}, project_root)
        assert r.passed is True

    def test_no_error_handling(self, project_root):
        f = project_root / "simple.py"
        f.write_text("def simple_func(x):\n    return x + 1\n")
        v = ErrorHandledVerifier()
        r = v.verify({"file": "simple.py", "function": "simple_func"}, project_root)
        assert r.passed is False

    def test_function_missing(self, project_root):
        f = project_root / "code.py"
        f.write_text("x = 1\n")
        v = ErrorHandledVerifier()
        r = v.verify({"file": "code.py", "function": "nonexistent"}, project_root)
        assert r.passed is False


class TestMiddlewareRegistered:
    def test_express_middleware(self, js_file, project_root):
        v = MiddlewareRegisteredVerifier()
        r = v.verify({"file": "server.js", "middleware": "helmet"}, project_root)
        assert r.passed is True

    def test_middleware_missing(self, js_file, project_root):
        v = MiddlewareRegisteredVerifier()
        r = v.verify({"file": "server.js", "middleware": "cors"}, project_root)
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = MiddlewareRegisteredVerifier()
        r = v.verify({"file": "missing.js", "middleware": "helmet"}, project_root)
        assert r.passed is False


class TestHttpHeaderSet:
    def test_header_found(self, js_file, project_root):
        v = HttpHeaderSetVerifier()
        r = v.verify({"file": "server.js", "header": "X-Frame-Options"}, project_root)
        assert r.passed is True

    def test_header_case_insensitive(self, js_file, project_root):
        v = HttpHeaderSetVerifier()
        r = v.verify({"file": "server.js", "header": "x-frame-options"}, project_root)
        assert r.passed is True

    def test_header_missing(self, js_file, project_root):
        v = HttpHeaderSetVerifier()
        r = v.verify({"file": "server.js", "header": "Content-Security-Policy"}, project_root)
        assert r.passed is False
