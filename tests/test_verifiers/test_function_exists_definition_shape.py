"""``function_exists`` passes on a definition, never on a mention.

Tier 1 is the only tier that decides whether the named symbol exists: the
tier-2 rubric is handed the isolated definition and told that presence is
settled, so it judges the implementation rather than re-checking that the
symbol is there. A tier-1 pass therefore has to mean a definition was
written in the file, and the runner reports ``skipped`` for tier 2 when no
provider is configured, so nothing downstream re-examines the question.

A name followed by an open paren is a *call* shape and occurs in prose, in
comments, in docstrings and inside string literals as readily as in code.
These tests pin the two properties that separate a definition from a
mention: the definition starts its own line, and its parameter list is
followed by a body or by a declaration terminator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mipiti_verify.verifiers.code_structure import FunctionExistsVerifier


def _verify(project_root: Path, filename: str, source: str, name: str):
    (project_root / filename).write_text(source, encoding="utf-8")
    return FunctionExistsVerifier().verify({"file": filename, "name": name}, project_root)


# --- Definitions: every one of these must be found ------------------------

DEFINITIONS = [
    ("python_def", "auth.py", "def verify_token(token):\n    return True\n"),
    (
        "python_async_def",
        "auth.py",
        "async def verify_token(self, token: str) -> bool:\n    return True\n",
    ),
    (
        "python_default_value_with_call",
        "auth.py",
        "def verify_token(token, clock=time.time(), leeway: int = 30):\n    return True\n",
    ),
    ("go_function", "auth.go", "func verify_token(t string) bool {\n\treturn true\n}\n"),
    (
        "go_method_with_receiver",
        "server.go",
        "func (s *Server) verify_token(w http.ResponseWriter, r *http.Request) {\n"
        "\ts.check(r)\n"
        "}\n",
    ),
    (
        "go_method_named_return",
        "server.go",
        "func (s *Server) verify_token(id string) (err error) {\n\treturn nil\n}\n",
    ),
    (
        "swift_method",
        "Auth.swift",
        "    private func verify_token(x: Int) -> Bool {\n        return true\n    }\n",
    ),
    (
        "rust_fn",
        "auth.rs",
        "pub fn verify_token(req: &Request) -> Result<(), Error> {\n    Ok(())\n}\n",
    ),
    (
        "c_function",
        "auth.c",
        "int verify_token(const char *s) {\n    return 0;\n}\n",
    ),
    (
        "c_function_allman_brace",
        "auth.c",
        "int verify_token(const char *s)\n{\n    return 0;\n}\n",
    ),
    (
        "c_pointer_return",
        "auth.c",
        "static char *verify_token(void) {\n    return NULL;\n}\n",
    ),
    (
        "c_function_pointer_parameter",
        "auth.c",
        "int verify_token(void (*cb)(int), int n) {\n    return 0;\n}\n",
    ),
    ("c_prototype", "auth.h", "int verify_token(const char *s);\n"),
    (
        "java_method_with_modifiers",
        "Auth.java",
        "    public static boolean verify_token(String[] args) {\n        return true;\n    }\n",
    ),
    (
        "java_interface_declaration",
        "Auth.java",
        "public interface Auth {\n    boolean verify_token(Request r);\n}\n",
    ),
    (
        "java_abstract_declaration",
        "Auth.java",
        "    public abstract void verify_token(Request r);\n",
    ),
    (
        "java_long_modifier_chain",
        "Auth.java",
        "    public static final synchronized native strictfp void verify_token(int a) {\n    }\n",
    ),
    (
        "csharp_allman_brace",
        "Auth.cs",
        "        public async Task<Result> verify_token(Request r)\n        {\n        }\n",
    ),
    (
        "js_function",
        "server.js",
        "function verify_token(req, res) {\n    return true;\n}\n",
    ),
    (
        "js_class_method_shorthand",
        "server.js",
        "class Auth {\n    verify_token(req, res) {\n        return true;\n    }\n}\n",
    ),
    (
        "js_one_line_body",
        "server.js",
        "class Auth {\n    verify_token(req) { return true; }\n}\n",
    ),
    (
        "ts_method_with_return_type",
        "auth.ts",
        "  private async verify_token(req: Request): Promise<void> {\n  }\n",
    ),
    (
        "ts_interface_declaration",
        "auth.ts",
        "interface Auth {\n  verify_token(id: string): Promise<User>;\n}\n",
    ),
    (
        "ts_arrow_const",
        "auth.ts",
        "export const verify_token = (req: Request): boolean => {\n  return true;\n};\n",
    ),
    (
        "ts_arrow_const_default_parameter",
        "auth.ts",
        "const verify_token = (overrides: Partial<Opts> = {}): boolean => {\n  return true;\n};\n",
    ),
    (
        "multiline_signature_c",
        "auth.c",
        "static int verify_token(\n    const char *s,\n    size_t n)\n{\n    return 0;\n}\n",
    ),
    (
        "multiline_signature_go_receiver",
        "server.go",
        "func (s *Server) verify_token(\n"
        "\tw http.ResponseWriter,\n"
        "\tr *http.Request,\n"
        ") {\n"
        "}\n",
    ),
    (
        "multiline_signature_ts",
        "auth.ts",
        "  async verify_token(\n"
        "    req: Request,\n"
        "    res: Response,\n"
        "  ): Promise<void> {\n"
        "  }\n",
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in DEFINITIONS], ids=[i for i, _, _ in DEFINITIONS]
)
def test_definition_is_found(project_root, filename, source):
    r = _verify(project_root, filename, source, "verify_token")
    assert r.passed is True, r.details
    assert "line" in r.details


# --- Mentions: none of these may satisfy the assertion --------------------

MENTIONS = [
    ("readme_prose", "README.md", "The service calls verify_token (see below) first.\n"),
    (
        "readme_prose_trailing_semicolon",
        "README.md",
        "First verify_token (the guard) runs; then the handler runs.\n",
    ),
    (
        "readme_prose_with_braces",
        "README.md",
        "Returns verify_token (x) as {ok: true} on success.\n",
    ),
    ("markdown_heading", "README.md", "## verify_token (deprecated)\n\nUse the new one.\n"),
    (
        "markdown_line_ending_in_colon",
        "README.md",
        "Use verify_token (from auth.py) as follows:\n\n    example\n",
    ),
    ("markdown_bullet", "README.md", "- `verify_token (auth.py)` - checks the bearer token\n"),
    ("python_comment", "auth.py", "# we should add verify_token (later)\nX = 1\n"),
    ("c_comment", "auth.c", "/* call verify_token (soon) */\nint x;\n"),
    (
        "python_docstring",
        "auth.py",
        'def other():\n    """Delegates to verify_token (in auth.py)."""\n    return 1\n',
    ),
    ("string_literal", "auth.py", 'MSG = "please call verify_token (now) first"\n'),
    (
        "string_literal_with_semicolon",
        "server.js",
        'logger.info("ran verify_token (u); done");\n',
    ),
    ("json_string", "meta.json", '{"note": "verify_token (checks the jwt)"}\n'),
    ("changelog_entry", "CHANGELOG.md", "* Fixed verify_token (CVE-0000-1) to reject expiry.\n"),
    (
        "prose_before_an_unrelated_definition",
        "README.md",
        "Callers use verify_token (see below) for checks.\n\nfunction other(a) {\n}\n",
    ),
    ("call_in_condition", "server.js", "    if (verify_token(user)) {\n        ok();\n    }\n"),
    ("call_statement", "server.js", "        verify_token(user);\n"),
    ("call_assigned", "server.js", "    const ok = verify_token(user);\n"),
    ("call_in_python_body", "auth.py", "def other():\n    verify_token(user)\n"),
    ("attribute_call", "auth.py", "def other(self):\n    self.verify_token(u)\n"),
    ("import_only", "auth.py", "from other import verify_token\n"),
    # A modifier keyword, a noun and the name followed by a paren is
    # also the shape of an English sentence, so a modifier alone cannot
    # stand in for a definition.
    (
        "prose_naming_a_modifier",
        "README.md",
        "Use the public helper verify_token (auth.py) to check the token.\n",
    ),
    (
        "prose_naming_a_modifier_static",
        "README.md",
        "The static wrapper verify_token (see auth) is deprecated.\n",
    ),
    (
        "comment_naming_a_modifier",
        "auth.py",
        "# the private variant verify_token (internal) is not exported\nX = 1\n",
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in MENTIONS], ids=[i for i, _, _ in MENTIONS]
)
def test_mention_is_not_a_definition(project_root, filename, source):
    r = _verify(project_root, filename, source, "verify_token")
    assert r.passed is False, f"a mention satisfied the assertion: {r.details}"
    assert "verify_token" in r.details


def test_reported_line_is_the_definition_not_an_earlier_mention(project_root):
    """The line number in the details points at the definition."""
    source = (
        "# verify_token (see the helper below) is the entry point\n"
        "\n"
        "def verify_token(token):\n"
        "    return True\n"
    )
    r = _verify(project_root, "auth.py", source, "verify_token")
    assert r.passed is True
    assert "line 3" in r.details


def test_all_patterns_compile_under_re2():
    """Every pattern must be an RE2 pattern, not a Perl one.

    google-re2 is the engine at run time: no lookaround, no
    backreferences. A pattern that only compiles under ``re`` would fail
    closed at verification time instead of at import.
    """
    import re2

    for template in FunctionExistsVerifier._PATTERNS:
        re2.compile(template.replace("{name}", re2.escape("verify_token")))
