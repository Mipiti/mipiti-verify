"""``decorator_present`` passes on an application, never on an example.

The assertion claims two things at once: the decorator is written, and
the definition it sits against is the named function. A usage example in
a docstring or a fenced block in a README shows both, arranged exactly as
the real thing — which is why a Python source is decided by the parser
rather than by the shape of two adjacent lines.

Tier 1 is the only tier that decides whether the decorator is applied:
the tier-2 rubric asks whether the decorator provides meaningful security
enforcement, which presupposes it is there and gives the judge no
direction to check that it is attached to anything, and the runner
reports ``skipped`` for tier 2 when no provider is configured.

These tests are two-directional: every example-shaped subject must fail,
and every genuine application form must pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mipiti_verify.verifiers.code_structure import DecoratorPresentVerifier


def _verify(project_root: Path, filename: str, source: str, decorator="require_auth", function="validate_input"):
    (project_root / filename).write_text(source, encoding="utf-8")
    return DecoratorPresentVerifier().verify(
        {"file": filename, "decorator": decorator, "function": function}, project_root
    )


USAGE_DOCSTRING = (
    '"""Usage::\n'
    "\n"
    "    @require_auth\n"
    "    def validate_input(data):\n"
    "        ...\n"
    '"""\n'
)

README_FENCE = (
    "Apply the guard like this:\n"
    "\n"
    "```python\n"
    "@require_auth\n"
    "def validate_input(data):\n"
    "    ...\n"
    "```\n"
)


# --- Examples and mentions: none of these may satisfy the assertion -------

MENTIONS = [
    # The two shapes the previous pattern accepted, each reproduced
    # against the verifier before this change.
    ("module_docstring_usage_example", "auth.py", USAGE_DOCSTRING),
    ("readme_fenced_usage_example", "README.md", README_FENCE),
    (
        "function_docstring_usage_example",
        "auth.py",
        'def helper():\n    """Decorate as::\n\n        @require_auth\n        def validate_input(d): ...\n    """\n',
    ),
    (
        "string_literal_holding_the_pair",
        "auth.py",
        'TEMPLATE = "@require_auth\\ndef validate_input(data):\\n    pass"\n',
    ),
    (
        "commented_out_application",
        "auth.py",
        "# @require_auth\ndef validate_input(data):\n    pass\n",
    ),
    (
        "decorator_on_a_different_function",
        "auth.py",
        "@require_auth\ndef other(data):\n    pass\n\n\ndef validate_input(data):\n    pass\n",
    ),
    (
        "decorator_separated_by_a_statement",
        "auth.py",
        "@require_auth\nX = 1\n\n\ndef validate_input(data):\n    pass\n",
    ),
    (
        "similarly_named_decorator",
        "auth.py",
        "@require_auth_v2\ndef validate_input(data):\n    pass\n",
    ),
    (
        "decorator_applied_to_a_class_of_that_name",
        "auth.py",
        "@require_auth\nclass validate_input:\n    pass\n",
    ),
    ("function_is_undecorated", "auth.py", "def validate_input(data):\n    return True\n"),
    (
        "function_is_not_defined_at_all",
        "auth.py",
        "@require_auth\ndef check_password(p):\n    return True\n",
    ),
    (
        "prose_naming_both",
        "notes.md",
        "Remember to put @require_auth on def validate_input(data) before shipping.\n",
    ),
    (
        "python_example_quoted_in_a_ticket",
        "TICKET.md",
        "The handler should read:\n\n@require_auth\ndef validate_input(data):\n    pass\n",
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in MENTIONS], ids=[i for i, _, _ in MENTIONS]
)
def test_example_is_not_an_application(project_root, filename, source):
    r = _verify(project_root, filename, source)
    assert r.passed is False, f"an example satisfied the assertion: {r.details}"
    assert "require_auth" in r.details


# --- Applications: every one of these must be found -----------------------

APPLICATIONS = [
    ("bare", "auth.py", "@require_auth\ndef validate_input(data):\n    pass\n"),
    ("called", "auth.py", "@require_auth()\ndef validate_input(data):\n    pass\n"),
    (
        "called_with_arguments",
        "auth.py",
        '@require_auth(scope="admin", strict=True)\ndef validate_input(data):\n    pass\n',
    ),
    (
        "called_with_wrapped_arguments",
        "auth.py",
        "@require_auth(\n    scope='admin',\n    strict=True,\n)\ndef validate_input(data):\n    pass\n",
    ),
    (
        "called_with_nested_arguments",
        "auth.py",
        "@require_auth(scopes=(\"admin\", \"ops\"))\ndef validate_input(data):\n    pass\n",
    ),
    ("dotted", "auth.py", "@auth.require_auth\ndef validate_input(data):\n    pass\n"),
    (
        "dotted_and_called",
        "auth.py",
        "@app.auth.require_auth()\nasync def validate_input(data):\n    pass\n",
    ),
    (
        "on_a_method",
        "auth.py",
        "class Auth:\n    @require_auth\n    def validate_input(self, data):\n        pass\n",
    ),
    (
        "on_an_async_method_below_another_decorator",
        "auth.py",
        "class Auth:\n    @staticmethod\n    @require_auth\n    async def validate_input(data):\n        pass\n",
    ),
    (
        "on_a_nested_function",
        "auth.py",
        "def outer():\n    @require_auth\n    def validate_input(data):\n        pass\n",
    ),
    (
        "above_another_decorator",
        "auth.py",
        "@require_auth\n@trace\ndef validate_input(data):\n    pass\n",
    ),
    (
        "separated_by_a_comment",
        "auth.py",
        "@require_auth\n# the guard runs first\ndef validate_input(data):\n    pass\n",
    ),
    (
        "wrapped_signature",
        "auth.py",
        "@require_auth\ndef validate_input(\n    data: str,\n) -> bool:\n    return True\n",
    ),
    (
        "python_stub",
        "auth.pyi",
        "@require_auth\ndef validate_input(data: str) -> bool: ...\n",
    ),
    # Other languages keep the pattern path.
    (
        "typescript_method_decorator",
        "auth.ts",
        "  @require_auth()\n  async validate_input(data: string): Promise<void> {\n  }\n",
    ),
    (
        "java_annotation_on_its_own_line",
        "Auth.java",
        "    @require_auth\n    public boolean validate_input(String s) {\n        return true;\n    }\n",
    ),
    (
        "java_annotation_on_the_same_line",
        "Auth.java",
        "    @require_auth public boolean validate_input(String s) {\n        return true;\n    }\n",
    ),
    (
        "java_annotation_below_another",
        "Auth.java",
        "    @Override\n    @require_auth\n    public void validate_input(Request r) {\n    }\n",
    ),
    (
        "annotation_stack_where_another_entry_wraps_its_arguments",
        "Auth.java",
        '    @require_auth\n'
        '    @Retry(\n'
        '        attempts = 3,\n'
        '    )\n'
        "    public void validate_input(Request r) {\n    }\n",
    ),
    (
        "java_annotation_with_arguments",
        "Auth.java",
        '    @require_auth(scope = "admin")\n    public void validate_input(Request r) {\n    }\n',
    ),
    (
        "javascript_function_declaration",
        "server.js",
        "@require_auth\nfunction validate_input(req) {\n    return true;\n}\n",
    ),
    (
        "kotlin_function",
        "Auth.kt",
        "@require_auth\nfun validate_input(x: Int): Boolean {\n    return true\n}\n",
    ),
    (
        "csharp_allman_brace",
        "Auth.cs",
        "    @require_auth\n    public async Task<bool> validate_input(Request r)\n    {\n    }\n",
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in APPLICATIONS], ids=[i for i, _, _ in APPLICATIONS]
)
def test_application_is_found(project_root, filename, source):
    r = _verify(project_root, filename, source)
    assert r.passed is True, r.details
    assert "line" in r.details


DECORATOR_SPELLINGS = [
    # (decorator param, source, expected)
    ("final_segment_of_a_dotted_decorator", "require_auth", "@auth.require_auth\ndef validate_input(d):\n    pass\n", True),
    ("full_dotted_path", "auth.require_auth", "@auth.require_auth\ndef validate_input(d):\n    pass\n", True),
    (
        "full_dotted_path_of_a_called_decorator",
        "app.auth.require_auth",
        "@app.auth.require_auth(scope='x')\ndef validate_input(d):\n    pass\n",
        True,
    ),
    (
        "a_middle_segment_is_not_the_decorator",
        "auth",
        "@app.auth.require_auth\ndef validate_input(d):\n    pass\n",
        False,
    ),
    (
        "a_partial_dotted_path_is_not_the_decorator",
        "auth.require",
        "@app.auth.require_auth\ndef validate_input(d):\n    pass\n",
        False,
    ),
    (
        "a_prefix_of_the_identifier_is_not_the_decorator",
        "require",
        "@require_auth\ndef validate_input(d):\n    pass\n",
        False,
    ),
]


@pytest.mark.parametrize(
    "decorator,source,expected",
    [(d, s, e) for _, d, s, e in DECORATOR_SPELLINGS],
    ids=[i for i, _, _, _ in DECORATOR_SPELLINGS],
)
def test_decorator_name_matching_rule(project_root, decorator, source, expected):
    """The name matches the full dotted path or the final segment.

    The leading path is how the decorator was reached rather than part of
    its identity, so either spelling may be the one the assertion used.
    Matching is on whole segments, which is what the previous pattern's
    free-running tail did not require.
    """
    r = _verify(project_root, "auth.py", source, decorator=decorator)
    assert r.passed is expected, r.details


def test_reported_line_is_the_decorator(project_root):
    source = "# @require_auth (see below) guards the handler\n\n@require_auth\ndef validate_input(d):\n    pass\n"
    r = _verify(project_root, "auth.py", source)
    assert r.passed is True
    assert "line 3" in r.details


def test_undefined_function_says_so(project_root):
    r = _verify(project_root, "auth.py", "@require_auth\ndef other(d):\n    pass\n")
    assert r.passed is False
    assert "no definition of 'validate_input'" in r.details


# --- Unparseable Python hands over to the pattern set ---------------------

BROKEN_TAIL = "\n\nthis file is not valid python (((\n"


def test_unparseable_python_falls_back_and_still_finds_an_application(project_root):
    source = "@require_auth\ndef validate_input(data):\n    pass\n" + BROKEN_TAIL
    r = _verify(project_root, "auth.py", source)
    assert r.passed is True, r.details


def test_unparseable_python_still_refuses_a_separated_decorator(project_root):
    """The fallback is the hardened pattern set, not the old one."""
    source = "@require_auth\nX = 1\n\n\ndef validate_input(data):\n    pass\n" + BROKEN_TAIL
    r = _verify(project_root, "auth.py", source)
    assert r.passed is False, r.details


def test_unparseable_python_is_confirmed_unparseable():
    """Pin the premise of the two fallback tests above."""
    import ast

    with pytest.raises(SyntaxError):
        ast.parse("@require_auth\ndef validate_input(data):\n    pass\n" + BROKEN_TAIL)


def test_content_with_a_null_byte_does_not_raise(project_root):
    """``ast.parse`` raises ValueError, not SyntaxError, on a null byte."""
    (project_root / "auth.py").write_bytes(
        b"@require_auth\ndef validate_input(data):\n    pass\n\x00\n"
    )
    r = DecoratorPresentVerifier().verify(
        {"file": "auth.py", "decorator": "require_auth", "function": "validate_input"},
        project_root,
    )
    assert r.passed is True, r.details


def test_missing_file_param_never_reaches_the_ast_path(project_root):
    r = DecoratorPresentVerifier().verify(
        {"decorator": "require_auth", "function": "validate_input"}, project_root
    )
    assert r.passed is False
    assert "not found" in r.details.lower()


def test_a_second_definition_of_the_name_carries_the_decorator(project_root):
    """Every definition of the name is examined, not just the first."""
    source = "def validate_input(data):\n    pass\n\n\n@require_auth\ndef validate_input(data):\n    pass\n"
    r = _verify(project_root, "auth.py", source)
    assert r.passed is True, r.details
    assert "line 5" in r.details


def test_all_patterns_compile_under_re2():
    """Every pattern must be an RE2 pattern, not a Perl one."""
    import re2

    from mipiti_verify.verifiers.code_structure import _ANNOTATED_NON_PY, _ANNOTATED_PY

    for template in _ANNOTATED_PY + _ANNOTATED_NON_PY:
        re2.compile(
            template.replace("{decorator}", re2.escape("require_auth")).replace(
                "{name}", re2.escape("validate_input")
            )
        )
