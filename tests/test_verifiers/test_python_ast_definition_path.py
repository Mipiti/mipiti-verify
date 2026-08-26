"""Python sources are decided by the parser, not by a regex.

``function_exists`` and ``class_exists`` both ask a question the Python
parser answers outright: a ``def`` / ``async def`` / ``class`` node with
this name is either in the tree or it is not. A comment, a docstring and
a string literal are structurally incapable of producing one, so the AST
path cannot be talked into a pass by prose, and formatting the patterns
did not anticipate cannot talk it into a miss.

The AST path is authoritative when it answers, so its answer is
terminal: a parsed file that holds no such node is a fail, not a hand-off
to the regex. It steps aside only when the source will not parse, and
then the pattern set decides — which is also the only path for Go,
TypeScript, Rust, C, Java and everything else.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mipiti_verify.verifiers.code_structure import (
    ClassExistsVerifier,
    FunctionExistsVerifier,
)


def _function(project_root: Path, source: str, name: str = "verify_token", filename: str = "auth.py"):
    (project_root / filename).write_text(source, encoding="utf-8")
    return FunctionExistsVerifier().verify({"file": filename, "name": name}, project_root)


def _klass(project_root: Path, source: str, name: str = "AuthService", filename: str = "svc.py"):
    (project_root / filename).write_text(source, encoding="utf-8")
    return ClassExistsVerifier().verify({"file": filename, "name": name}, project_root)


# --- The name appears, but nothing declares it ----------------------------

MENTION_ONLY_FUNCTION = (
    "# verify_token (see below) is the entry point\n"
    "\n"
    'DOC = """\n'
    "Callers should call verify_token before anything else.\n"
    '"""\n'
    "\n"
    'MSG = "please call verify_token first"\n'
    "\n"
    "def other(token):\n"
    '    """Delegates to verify_token in the auth module."""\n'
    "    return token\n"
)

MENTION_ONLY_CLASS = (
    "# class AuthService lives in the other module\n"
    "\n"
    'DOC = """\n'
    "The class AuthService is responsible for token checks.\n"
    '"""\n'
    "\n"
    'MSG = "see class AuthService for details"\n'
    "\n"
    "class Other:\n"
    '    """Wraps class AuthService."""\n'
    "    pass\n"
)


def test_function_named_only_in_comment_docstring_and_string_fails(project_root):
    r = _function(project_root, MENTION_ONLY_FUNCTION)
    assert r.passed is False, r.details
    assert "verify_token" in r.details


def test_class_named_only_in_comment_docstring_and_string_fails(project_root):
    r = _klass(project_root, MENTION_ONLY_CLASS)
    assert r.passed is False, r.details
    assert "AuthService" in r.details


def test_docstring_holding_a_verbatim_declaration_still_fails(project_root):
    """The parser sees a string, not a class — which is the whole point.

    A line-shape rule cannot tell a declaration quoted inside a
    docstring from one written in the file; the parser can.
    """
    source = 'DOC = """\nclass AuthService:\n    pass\n"""\n'
    r = _klass(project_root, source)
    assert r.passed is False, r.details


def test_docstring_holding_a_verbatim_def_still_fails(project_root):
    source = 'DOC = """\ndef verify_token(token):\n    return True\n"""\n'
    r = _function(project_root, source)
    assert r.passed is False, r.details


# --- Real definitions, reported at the right line -------------------------

FUNCTION_DEFINITIONS = [
    ("module_level", "def verify_token(token):\n    return True\n", 1),
    ("async_def", "async def verify_token(token):\n    return True\n", 1),
    (
        "after_a_mention",
        "# verify_token (see below) is the entry point\n\ndef verify_token(token):\n    return True\n",
        3,
    ),
    (
        "decorated",
        "@retry\n@trace\ndef verify_token(token):\n    return True\n",
        3,
    ),
    (
        "method_in_a_class",
        "class Auth:\n    def verify_token(self, token):\n        return True\n",
        2,
    ),
    (
        "async_method_in_a_class",
        "class Auth:\n    async def verify_token(self, token):\n        return True\n",
        2,
    ),
    (
        "nested_function",
        "def outer():\n    def verify_token(token):\n        return True\n    return verify_token\n",
        2,
    ),
    (
        "defined_under_a_conditional",
        "import sys\n\nif sys.version_info >= (3, 12):\n    def verify_token(token):\n        return True\n",
        4,
    ),
    (
        "signature_wrapped_across_lines",
        "def verify_token(\n    token: str,\n    *,\n    leeway: int = 30,\n) -> bool:\n    return True\n",
        1,
    ),
    ("bound_lambda", "verify_token = lambda token: True\n", 1),
]


@pytest.mark.parametrize(
    "source,line",
    [(s, ln) for _, s, ln in FUNCTION_DEFINITIONS],
    ids=[i for i, _, _ in FUNCTION_DEFINITIONS],
)
def test_function_definition_is_found_at_the_right_line(project_root, source, line):
    r = _function(project_root, source)
    assert r.passed is True, r.details
    assert f"line {line}" in r.details, r.details


CLASS_DECLARATIONS = [
    ("module_level", "class AuthService:\n    pass\n", 1),
    ("with_a_base", "class AuthService(Base):\n    pass\n", 1),
    (
        "after_a_mention",
        "# class AuthService (see below) is the entry point\n\nclass AuthService:\n    pass\n",
        3,
    ),
    ("decorated", "@dataclass\n@final\nclass AuthService:\n    token: str\n", 3),
    ("nested_in_a_class", "class Outer:\n    class AuthService:\n        pass\n", 2),
    (
        "nested_in_a_function",
        "def build():\n    class AuthService:\n        pass\n    return AuthService\n",
        2,
    ),
    (
        "declared_under_a_conditional",
        "import sys\n\nif sys.version_info >= (3, 12):\n    class AuthService:\n        pass\n",
        4,
    ),
    (
        "wrapped_base_list",
        "class AuthService(\n    Base,\n    Mixin,\n):\n    pass\n",
        1,
    ),
    ("enum_subclass", "class Status(enum.Enum):\n    OK = 1\n", 1),
]


@pytest.mark.parametrize(
    "source,line",
    [(s, ln) for _, s, ln in CLASS_DECLARATIONS],
    ids=[i for i, _, _ in CLASS_DECLARATIONS],
)
def test_class_declaration_is_found_at_the_right_line(project_root, source, line):
    name = "Status" if "class Status" in source else "AuthService"
    r = _klass(project_root, source, name=name)
    assert r.passed is True, r.details
    assert f"line {line}" in r.details, r.details


# --- Unparseable Python hands over to the pattern set ---------------------

BROKEN_TAIL = "\n\nthis file is not valid python (((\n"


def test_unparseable_python_falls_back_and_still_finds_a_function(project_root):
    """The fallback engages rather than erroring, and the regex decides."""
    source = "def verify_token(token):\n    return True\n" + BROKEN_TAIL
    r = _function(project_root, source)
    assert r.passed is True, r.details
    assert "line 1" in r.details


def test_unparseable_python_falls_back_and_still_finds_a_class(project_root):
    source = "class AuthService:\n    pass\n" + BROKEN_TAIL
    r = _klass(project_root, source)
    assert r.passed is True, r.details
    assert "line 1" in r.details


def test_unparseable_python_is_confirmed_unparseable():
    """Pin the premise of the two fallback tests above.

    If this source ever started parsing, those tests would silently stop
    exercising the fallback and start exercising the AST path.
    """
    import ast

    for source in (
        "def verify_token(token):\n    return True\n" + BROKEN_TAIL,
        "class AuthService:\n    pass\n" + BROKEN_TAIL,
    ):
        with pytest.raises(SyntaxError):
            ast.parse(source)


def test_unparseable_python_holding_only_a_mention_still_fails(project_root):
    """The fallback is the hardened pattern set, not the old one."""
    source = "MSG = 'the class AuthService checks tokens'" + BROKEN_TAIL
    r = _klass(project_root, source)
    assert r.passed is False, r.details


def test_content_with_a_null_byte_does_not_raise(project_root):
    """``ast.parse`` raises ValueError, not SyntaxError, on a null byte."""
    (project_root / "svc.py").write_bytes(b"class AuthService:\n    pass\n\x00\n")
    r = ClassExistsVerifier().verify({"file": "svc.py", "name": "AuthService"}, project_root)
    assert r.passed is True, r.details


# --- Non-Python sources keep the pattern path -----------------------------


def test_non_python_extension_is_decided_by_the_patterns(project_root):
    """A Go declaration has no AST path here and must still be found."""
    r = _klass(
        project_root,
        "type AuthService struct {\n\tdb *sql.DB\n}\n",
        filename="svc.go",
    )
    assert r.passed is True, r.details


def test_missing_file_param_never_reaches_the_ast_path(project_root):
    """An unnamed subject stays on the language-agnostic path.

    ``resolve_file_content`` labels a missing ``file`` param
    ``<no source>`` and returns no content, so the verifier reports the
    source as not found instead of parsing something it cannot identify.
    """
    r = ClassExistsVerifier().verify({"name": "AuthService"}, project_root)
    assert r.passed is False
    assert "not found" in r.details.lower()
