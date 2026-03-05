"""Tests for code structure verifiers."""

from pathlib import Path

import pytest

from mipiti_verify.verifiers.code_structure import (
    ClassExistsVerifier,
    DecoratorPresentVerifier,
    FunctionCallsVerifier,
    FunctionExistsVerifier,
    ImportPresentVerifier,
)


class TestFunctionExists:
    def test_python_function(self, python_file, project_root):
        v = FunctionExistsVerifier()
        r = v.verify({"file": "app.py", "name": "validate_input"}, project_root)
        assert r.passed is True
        assert "line" in r.details

    def test_python_function_missing(self, python_file, project_root):
        v = FunctionExistsVerifier()
        r = v.verify({"file": "app.py", "name": "nonexistent"}, project_root)
        assert r.passed is False

    def test_js_function(self, js_file, project_root):
        v = FunctionExistsVerifier()
        r = v.verify({"file": "server.js", "name": "handleAuth"}, project_root)
        assert r.passed is True

    def test_file_missing(self, project_root):
        v = FunctionExistsVerifier()
        r = v.verify({"file": "missing.py", "name": "foo"}, project_root)
        assert r.passed is False

    def test_method_found(self, python_file, project_root):
        v = FunctionExistsVerifier()
        r = v.verify({"file": "app.py", "name": "check_password"}, project_root)
        assert r.passed is True

    def test_rust_fn(self, project_root):
        f = project_root / "main.rs"
        f.write_text("fn validate_request(req: &Request) -> Result<(), Error> {\n    Ok(())\n}\n")
        v = FunctionExistsVerifier()
        r = v.verify({"file": "main.rs", "name": "validate_request"}, project_root)
        assert r.passed is True


class TestClassExists:
    def test_python_class(self, python_file, project_root):
        v = ClassExistsVerifier()
        r = v.verify({"file": "app.py", "name": "AuthService"}, project_root)
        assert r.passed is True

    def test_missing_class(self, python_file, project_root):
        v = ClassExistsVerifier()
        r = v.verify({"file": "app.py", "name": "MissingClass"}, project_root)
        assert r.passed is False

    def test_go_struct(self, project_root):
        f = project_root / "main.go"
        f.write_text("type AuthHandler struct {\n    db *sql.DB\n}\n")
        v = ClassExistsVerifier()
        r = v.verify({"file": "main.go", "name": "AuthHandler"}, project_root)
        assert r.passed is True

    def test_interface(self, project_root):
        f = project_root / "types.ts"
        f.write_text("interface UserService {\n    getUser(id: string): Promise<User>;\n}\n")
        v = ClassExistsVerifier()
        r = v.verify({"file": "types.ts", "name": "UserService"}, project_root)
        assert r.passed is True


class TestDecoratorPresent:
    def test_decorator_found(self, python_file, project_root):
        v = DecoratorPresentVerifier()
        r = v.verify(
            {"file": "app.py", "decorator": "require_auth", "function": "validate_input"},
            project_root,
        )
        assert r.passed is True

    def test_decorator_missing(self, python_file, project_root):
        v = DecoratorPresentVerifier()
        r = v.verify(
            {"file": "app.py", "decorator": "require_auth", "function": "check_password"},
            project_root,
        )
        assert r.passed is False

    def test_file_missing(self, project_root):
        v = DecoratorPresentVerifier()
        r = v.verify(
            {"file": "missing.py", "decorator": "foo", "function": "bar"},
            project_root,
        )
        assert r.passed is False


class TestFunctionCalls:
    def test_call_found(self, python_file, project_root):
        v = FunctionCallsVerifier()
        r = v.verify(
            {"file": "app.py", "caller": "process_request", "callee": "validate_input"},
            project_root,
        )
        assert r.passed is True

    def test_call_not_found(self, python_file, project_root):
        v = FunctionCallsVerifier()
        r = v.verify(
            {"file": "app.py", "caller": "process_request", "callee": "nonexistent"},
            project_root,
        )
        assert r.passed is False

    def test_caller_not_found(self, python_file, project_root):
        v = FunctionCallsVerifier()
        r = v.verify(
            {"file": "app.py", "caller": "missing_func", "callee": "validate_input"},
            project_root,
        )
        assert r.passed is False


class TestImportPresent:
    def test_python_import(self, python_file, project_root):
        v = ImportPresentVerifier()
        r = v.verify({"file": "app.py", "module": "os"}, project_root)
        assert r.passed is True

    def test_python_from_import(self, python_file, project_root):
        v = ImportPresentVerifier()
        r = v.verify({"file": "app.py", "module": "hashlib"}, project_root)
        assert r.passed is True

    def test_js_require(self, js_file, project_root):
        v = ImportPresentVerifier()
        r = v.verify({"file": "server.js", "module": "express"}, project_root)
        assert r.passed is True

    def test_import_missing(self, python_file, project_root):
        v = ImportPresentVerifier()
        r = v.verify({"file": "app.py", "module": "django"}, project_root)
        assert r.passed is False
