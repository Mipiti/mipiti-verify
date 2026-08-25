"""``function_calls`` passes on a call, never on a name in text.

A parseable Python source is decided by the parser and always has been.
The fallback every other language takes was not: it found the caller by a
keyword and a name — a shape a sentence produces — and then searched the
text that followed for the callee's name followed by a paren, which a
``// TODO``, a log message and a docstring all produce.

Tier 1 is the only tier that decides whether the call is there, and the
runner reports ``skipped`` for tier 2 when no provider is configured.

These tests are two-directional: a callee named in a comment or a string
must not count, a caller that is only mentioned must not lend its body to
the search, and every genuine call form must still be found.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mipiti_verify.verifiers.code_structure import (
    FunctionCallsVerifier,
    _blank_code_noise,
)


def _verify(project_root: Path, filename: str, source: str, caller="handleAuth", callee="encryptToken"):
    (project_root / filename).write_text(source, encoding="utf-8")
    return FunctionCallsVerifier().verify(
        {"file": filename, "caller": caller, "callee": callee}, project_root
    )


# --- Names in text: none of these may satisfy the assertion ---------------

MENTIONS = [
    (
        "callee_in_a_line_comment",
        "server.js",
        "function handleAuth(req, res) {\n    // TODO: call encryptToken(token) here\n    return null;\n}\n",
    ),
    (
        "callee_in_a_block_comment",
        "server.js",
        "function handleAuth(req, res) {\n    /* encryptToken(token) is not wired yet */\n    return null;\n}\n",
    ),
    (
        "callee_in_a_string_literal",
        "server.js",
        'function handleAuth(req, res) {\n    logger.info("next step: encryptToken(token)");\n}\n',
    ),
    (
        "callee_in_a_single_quoted_string",
        "auth.ts",
        "  handleAuth(req: Request): void {\n    const msg = 'encryptToken(t) pending';\n  }\n",
    ),
    (
        "callee_in_a_go_comment",
        "main.go",
        "func handleAuth(w http.ResponseWriter) {\n\t// encryptToken(t) goes here\n\treturn\n}\n",
    ),
    (
        "callee_in_a_c_comment",
        "auth.c",
        "int handleAuth(const char *s)\n{\n    /* encryptToken(s); */\n    return 0;\n}\n",
    ),
    (
        "caller_named_in_prose_lends_no_body",
        "README.md",
        "We call function handleAuth(req) whenever a request arrives.\n\n    encryptToken(req)\n",
    ),
    (
        "caller_named_in_a_comment_lends_no_body",
        "server.js",
        "// function handleAuth(req) used to live here\nfunction other(req) {\n    encryptToken(req);\n}\n",
    ),
    (
        "callee_only_in_another_function",
        "server.js",
        "function handleAuth(req) {\n    return null;\n}\n\nfunction other(req) {\n    encryptToken(req);\n}\n",
    ),
    (
        "caller_is_not_defined",
        "server.js",
        "function other(req) {\n    encryptToken(req);\n}\n",
    ),
    (
        "python_callee_in_a_docstring",
        "auth.py",
        'def handleAuth(req):\n    """Should call encryptToken(req) once wired."""\n    return None\n',
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in MENTIONS], ids=[i for i, _, _ in MENTIONS]
)
def test_mention_is_not_a_call(project_root, filename, source):
    r = _verify(project_root, filename, source)
    assert r.passed is False, f"a mention satisfied the assertion: {r.details}"


# --- Calls: every one of these must be found ------------------------------

CALLS = [
    ("js_bare_call", "server.js", "function handleAuth(req, res) {\n    encryptToken(req.token);\n}\n"),
    (
        "js_attribute_call",
        "server.js",
        "function handleAuth(req, res) {\n    crypto.encryptToken(req.token);\n}\n",
    ),
    (
        "js_call_beside_a_comment",
        "server.js",
        "function handleAuth(req, res) {\n    // guard first\n    encryptToken(req.token); // then encrypt\n}\n",
    ),
    (
        "ts_method",
        "auth.ts",
        "  private handleAuth(req: Request): void {\n    this.encryptToken(req.token);\n  }\n",
    ),
    (
        "ts_arrow_binding",
        "auth.ts",
        "const handleAuth = (req: Request): void => {\n  encryptToken(req.token);\n};\n",
    ),
    (
        "ts_template_literal_interpolation",
        "auth.ts",
        "function handleAuth(req) {\n  const url = `/session/${encryptToken(req)}`;\n  return url;\n}\n",
    ),
    (
        "go_function",
        "main.go",
        "func handleAuth(w http.ResponseWriter, r *http.Request) {\n\tencryptToken(r)\n}\n",
    ),
    (
        "go_multiline_signature",
        "main.go",
        "func handleAuth(\n\tw http.ResponseWriter,\n\tr *http.Request,\n) {\n\tencryptToken(r)\n}\n",
    ),
    (
        "go_method_with_receiver",
        "main.go",
        "func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {\n\tencryptToken(r)\n}\n",
    ),
    (
        "go_method_with_receiver_and_multiline_signature",
        "main.go",
        "func (s *Server) handleAuth(\n\tw http.ResponseWriter,\n\tr *http.Request,\n) {\n\tencryptToken(r)\n}\n",
    ),
    (
        "c_allman_brace",
        "auth.c",
        "int handleAuth(const char *s)\n{\n    encryptToken(s);\n    return 0;\n}\n",
    ),
    (
        "java_method",
        "Auth.java",
        "    public void handleAuth(Request r) {\n        encryptToken(r);\n    }\n",
    ),
    (
        "rust_function",
        "lib.rs",
        "pub fn handleAuth(req: &Request) -> Result<(), Error> {\n    encryptToken(req)?;\n    Ok(())\n}\n",
    ),
    ("python_module_level", "auth.py", "def handleAuth(req):\n    encryptToken(req)\n"),
    (
        "python_method",
        "auth.py",
        "class Auth:\n    def handleAuth(self, req):\n        self.encryptToken(req)\n",
    ),
    (
        "python_nested_function",
        "auth.py",
        "def outer():\n    def handleAuth(req):\n        encryptToken(req)\n    return handleAuth\n",
    ),
    (
        "python_async_method_with_wrapped_signature",
        "auth.py",
        "class Auth:\n    async def handleAuth(\n        self,\n        req: object,\n    ) -> None:\n        await self.encryptToken(req)\n",
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in CALLS], ids=[i for i, _, _ in CALLS]
)
def test_call_is_found(project_root, filename, source):
    r = _verify(project_root, filename, source)
    assert r.passed is True, r.details


def test_caller_found_only_in_prose_reports_the_caller_as_missing(project_root):
    r = _verify(
        project_root,
        "README.md",
        "We call function handleAuth(req) whenever a request arrives.\n\n    encryptToken(req)\n",
    )
    assert r.passed is False
    assert "Caller function 'handleAuth' not found" in r.details


# --- The blanker, judged on its own ---------------------------------------
#
# It is the piece that decides what counts as code, so what it leaves
# alone matters as much as what it removes.


BLANKING = [
    ("line_comment", "a();\n// b();\n", "b(", False),
    ("block_comment", "a();\n/* b(); */\nc();\n", "b(", False),
    ("hash_comment", "a()\n# b()\n", "b(", False),
    ("double_quoted_string", 'log("b()")\n', "b(", False),
    ("single_quoted_string", "log('b()')\n", "b(", False),
    ("triple_quoted_string", 'DOC = """\nb()\n"""\n', "b(", False),
    ("template_literal_text", "const s = `b() is next`;\n", "b(", False),
    # Left alone: these are code, and blanking them would hide a real
    # call or break the statement that carries the module path.
    ("c_preprocessor_include", "#include <openssl/evp.h>\n", "openssl/evp.h", True),
    ("c_preprocessor_conditional", "#ifdef DEBUG\nb();\n#endif\n", "b(", True),
    ("js_private_member_call", "class A {\n  f() {\n    this.#encrypt(t);\n  }\n}\n", "#encrypt(", True),
    ("shebang_line_is_not_code_either", "#!/usr/bin/env python\nb()\n", "b(", True),
    ("template_literal_interpolation", "const s = `/x/${encrypt(t)}`;\n", "encrypt(", True),
    ("code_outside_a_string", 'log("note"); encrypt(t);\n', "encrypt(", True),
]


@pytest.mark.parametrize(
    "source,needle,survives",
    [(s, n, k) for _, s, n, k in BLANKING],
    ids=[i for i, _, _, _ in BLANKING],
)
def test_blanker_removes_text_and_keeps_code(source, needle, survives):
    assert (needle in _blank_code_noise(source, "x.js")) is survives


def test_blanking_preserves_every_position_and_line(project_root):
    """Interiors are replaced with spaces, never deleted.

    The body slice reads indentation and the details report line
    numbers, so a blanker that shortened the text would move both.
    """
    source = 'function f() {\n    // a comment\n    log("text");\n}\n'
    blanked = _blank_code_noise(source, "server.js")
    assert len(blanked) == len(source)
    assert blanked.count("\n") == source.count("\n")
    for original, scrubbed in zip(source.split("\n"), blanked.split("\n")):
        assert len(original) == len(scrubbed)


def test_rust_lifetimes_are_not_string_delimiters():
    """``&'a str`` would otherwise pair with the next quote and blank
    the code between them."""
    source = "fn f<'a>(req: &'a Request) {\n    encrypt(req);\n}\n"
    assert "encrypt(" in _blank_code_noise(source, "lib.rs")
    assert "(req: &" in _blank_code_noise(source, "lib.rs")


def test_an_unterminated_quote_is_not_a_delimiter():
    """An apostrophe in prose closes nothing; pairing it with the next
    line's quote would blank whatever sits between them."""
    source = "// don't do this\nencrypt(t);\n"
    assert "encrypt(" in _blank_code_noise(source, "server.js")


def test_import_path_survives_when_strings_are_kept():
    """``import_present`` reads module paths out of string literals, so
    it blanks comments only."""
    source = "const h = require('helmet');\n"
    assert "helmet" in _blank_code_noise(source, "server.js", strings=False)
    assert "helmet" not in _blank_code_noise(source, "server.js", strings=True)


def test_a_comment_marker_inside_a_string_opens_no_comment():
    """The scanner recognises the literal first, so the rest of the
    file is not blanked away as a block comment."""
    source = 'const glob = "<dir>/*.sigstore";\nencrypt(t);\n'
    assert "encrypt(" in _blank_code_noise(source, "server.js")


def test_all_caller_patterns_compile_under_re2():
    """The caller is located with the shared definition-shape set, which
    must be RE2, not Perl."""
    import re2

    from mipiti_verify.verifiers.code_structure import _FUNCTION_DEFINITION_PATTERNS

    for template in _FUNCTION_DEFINITION_PATTERNS:
        re2.compile(template.replace("{name}", re2.escape("handleAuth")))
