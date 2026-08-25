"""``import_present`` passes on an import statement, never on a mention.

``import``, ``from`` and ``use`` are ordinary English words. The previous
pattern set asked for little more than one of them followed by the module
name, which a README sentence, a comment and a docstring all produce as
readily as a source file does.

Tier 1 is the only tier that decides whether the import is there: the
tier-2 rubric asks whether the imported module is *actively used*, a
question that presupposes the import exists, and the runner reports
``skipped`` for tier 2 when no provider is configured. So a tier-1 pass
has to mean an import statement is written in the file.

These tests are two-directional: every sentence-shaped subject must fail,
and every genuine import form across the languages the fallback covers
must pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mipiti_verify.verifiers.code_structure import ImportPresentVerifier


def _verify(project_root: Path, filename: str, source: str, module: str):
    (project_root / filename).write_text(source, encoding="utf-8")
    return ImportPresentVerifier().verify({"file": filename, "module": module}, project_root)


# --- Mentions: none of these may satisfy the assertion --------------------

MENTIONS = [
    # The four shapes the previous patterns accepted, each reproduced
    # against the verifier before this change.
    ("readme_use_as_a_verb", "README.md", "We use cryptography to sign every bundle.\n", "cryptography"),
    (
        "prose_from_as_a_preposition",
        "README.md",
        "This was copied from cryptography for speed.\n",
        "cryptography",
    ),
    ("comment_forbidding_the_import", "auth.py", "# do not import requests here\nX = 1\n", "requests"),
    (
        "docstring_from_as_a_preposition",
        "auth.py",
        'def load():\n    """Data comes from hashlib."""\n    return 1\n',
        "hashlib",
    ),
    # The same class of subject, in the other places a name gets written.
    ("string_literal", "auth.py", 'MSG = "please import requests first"\n', "requests"),
    (
        "block_comment_holding_a_real_import",
        "server.js",
        "/*\nimport express from 'express';\n*/\nconst app = 1;\n",
        "express",
    ),
    (
        "line_comment_holding_a_real_import",
        "server.js",
        "// import express from 'express';\nconst app = 1;\n",
        "express",
    ),
    ("markdown_bullet", "notes.md", "- import requests here for the retry fix\n", "requests"),
    ("changelog_entry", "CHANGELOG.md", "* Dropped the import requests dependency.\n", "requests"),
    ("prose_use_with_a_semicolon", "README.md", "You can use cryptography for signing; it is fast.\n", "cryptography"),
    ("sentence_starting_with_import", "README.md", "Import cryptography before you sign.\n", "cryptography"),
    ("json_string", "meta.json", '{"note": "we import requests in the worker"}\n', "requests"),
    # Naming a longer module does not import a shorter one's sibling, and
    # a prefix of an identifier is not a module path.
    ("prefix_of_a_longer_name", "auth.py", "import ostrich\n", "os"),
    ("import_of_a_parent_does_not_import_a_child", "auth.py", "import os\n", "os.path"),
    ("module_never_imported", "auth.py", "import os\nfrom hashlib import sha256\n", "django"),
]


@pytest.mark.parametrize(
    "filename,source,module",
    [(f, s, m) for _, f, s, m in MENTIONS],
    ids=[i for i, _, _, _ in MENTIONS],
)
def test_mention_is_not_an_import(project_root, filename, source, module):
    r = _verify(project_root, filename, source, module)
    assert r.passed is False, f"a mention satisfied the assertion: {r.details}"
    assert module in r.details


# --- Imports: every one of these must be found ----------------------------

IMPORTS = [
    # Python, decided by the parser.
    ("py_import", "app.py", "import os\n", "os"),
    ("py_import_dotted", "app.py", "import os.path\n", "os.path"),
    ("py_import_dotted_parent", "app.py", "import os.path\n", "os"),
    ("py_import_as", "app.py", "import numpy as np\n", "numpy"),
    ("py_import_dotted_as", "app.py", "import a.b as c\n", "a.b"),
    ("py_import_list", "app.py", "import os, sys\n", "sys"),
    ("py_from_import", "app.py", "from hashlib import sha256\n", "hashlib"),
    ("py_from_import_dotted", "app.py", "from cryptography.fernet import Fernet\n", "cryptography"),
    ("py_from_import_name", "app.py", "from jose import jwt\n", "jwt"),
    ("py_from_import_name_as_path", "app.py", "from jose import jwt\n", "jose.jwt"),
    ("py_relative_from", "app.py", "from .session import decode\n", "session"),
    ("py_relative_from_written_relative", "app.py", "from .session import decode\n", ".session"),
    ("py_relative_bare", "app.py", "from . import session\n", "session"),
    ("py_relative_parent", "app.py", "from ..services import billing\n", "services"),
    ("py_wrapped_from_import", "app.py", "from x import (\n    alpha,\n    beta,\n)\n", "beta"),
    ("py_import_under_a_conditional", "app.py", "if TYPE_CHECKING:\n    import requests\n", "requests"),
    ("py_import_inside_a_function", "app.py", "def f():\n    import requests\n    return requests\n", "requests"),
    (
        "py_dynamic_import",
        "app.py",
        "import importlib\nmod = importlib.import_module('crypto.sign')\n",
        "crypto.sign",
    ),
    ("py_dunder_import", "app.py", "mod = __import__('hashlib')\n", "hashlib"),
    # JavaScript and TypeScript.
    ("ts_named_import", "auth.ts", "import { sign } from 'crypto';\n", "crypto"),
    ("ts_default_import", "auth.ts", "import jwt from \"jsonwebtoken\";\n", "jsonwebtoken"),
    ("ts_namespace_import", "auth.ts", "import * as jwt from 'jsonwebtoken';\n", "jsonwebtoken"),
    ("ts_type_import", "auth.ts", "import type { User } from './types';\n", "./types"),
    (
        "ts_wrapped_named_import",
        "auth.ts",
        "import {\n  sign,\n  verify,\n} from 'node:crypto';\n",
        "node:crypto",
    ),
    ("ts_reexport", "index.ts", "export { sign } from './crypto';\n", "./crypto"),
    (
        "ts_default_and_wrapped_named_import",
        "auth.ts",
        "import verify, {\n  sign,\n} from '../util/verify';\n",
        "../util/verify",
    ),
    (
        "js_dynamic_import_wrapped",
        "auth.ts",
        "const { parse } = await import(\n  '../utils/webauthn'\n);\n",
        "../utils/webauthn",
    ),
    ("js_side_effect_import", "server.js", "import 'dotenv/config';\n", "dotenv/config"),
    ("js_require", "server.js", "const express = require('express');\n", "express"),
    ("js_require_double_quotes", "server.js", 'const helmet = require("helmet");\n', "helmet"),
    ("js_dynamic_import", "server.js", "const fs = await import('node:fs');\n", "node:fs"),
    # Go.
    ("go_single_import", "main.go", 'import "crypto/sha256"\n', "crypto/sha256"),
    (
        "go_import_block",
        "main.go",
        'import (\n\t"crypto/sha256"\n\t"net/http"\n)\n',
        "net/http",
    ),
    (
        "go_import_block_aliased",
        "main.go",
        'import (\n\tjson "encoding/json"\n)\n',
        "encoding/json",
    ),
    # Rust.
    ("rust_use", "lib.rs", "use hmac::Hmac;\n", "hmac::Hmac"),
    ("rust_use_prefix", "lib.rs", "use hmac::Hmac;\n", "hmac"),
    ("rust_use_group", "lib.rs", "use hmac::{Hmac, Mac};\n", "hmac"),
    ("rust_use_as", "lib.rs", "use hmac::Hmac as H;\n", "hmac"),
    ("rust_pub_use", "lib.rs", "pub use crate::auth::verify;\n", "crate::auth"),
    ("rust_pub_crate_use", "lib.rs", "pub(crate) use serde::Deserialize;\n", "serde"),
    ("rust_extern_crate", "lib.rs", "extern crate openssl;\n", "openssl"),
    # JVM and .NET.
    ("java_import", "Auth.java", "import java.security.MessageDigest;\n", "java.security"),
    ("java_wildcard_import", "Auth.java", "import java.util.*;\n", "java.util"),
    ("java_static_import", "Auth.java", "import static java.util.Objects.requireNonNull;\n", "java.util"),
    ("kotlin_import", "Auth.kt", "import kotlinx.serialization.json.Json\n", "kotlinx.serialization"),
    ("csharp_using", "Auth.cs", "using System.Security.Cryptography;\n", "System.Security.Cryptography"),
    ("csharp_using_alias", "Auth.cs", "using Crypto = System.Security.Cryptography;\n", "System.Security.Cryptography"),
    # C, C++, Objective-C.
    ("c_include_angle", "auth.c", "#include <openssl/evp.h>\n", "openssl/evp.h"),
    ("c_include_quoted", "auth.c", '#include "sha.h"\n', "sha.h"),
    ("c_include_prefix", "auth.c", "#include <openssl/evp.h>\n", "openssl"),
    ("objc_import", "Auth.m", "#import <Foundation/Foundation.h>\n", "Foundation/Foundation.h"),
    # Ruby, PHP, SystemVerilog, Swift.
    ("ruby_require", "auth.rb", "require 'openssl'\n", "openssl"),
    ("ruby_require_relative", "auth.rb", "require_relative 'session'\n", "session"),
    ("php_use", "Auth.php", "use App\\Security\\Signer;\n", "App"),
    ("systemverilog_package_import", "auth.sv", "import auth_pkg::*;\n", "auth_pkg"),
    ("swift_import", "Auth.swift", "import CryptoKit\n", "CryptoKit"),
    # Indentation is not a disqualifier.
    ("indented_import", "auth.go", '\timport "crypto/sha256"\n', "crypto/sha256"),
    ("import_with_trailing_comment", "auth.py", "import os  # noqa: F401\n", "os"),
]


@pytest.mark.parametrize(
    "filename,source,module",
    [(f, s, m) for _, f, s, m in IMPORTS],
    ids=[i for i, _, _, _ in IMPORTS],
)
def test_import_is_found(project_root, filename, source, module):
    r = _verify(project_root, filename, source, module)
    assert r.passed is True, r.details
    assert "line" in r.details


def test_reported_line_is_the_import_not_an_earlier_mention(project_root):
    source = "# we import requests in the worker, not here\n\nimport requests\n"
    r = _verify(project_root, "worker.py", source, "requests")
    assert r.passed is True
    assert "line 3" in r.details


# --- Unparseable Python hands over to the pattern set ---------------------

BROKEN_TAIL = "\n\nthis file is not valid python (((\n"


def test_unparseable_python_falls_back_and_still_finds_an_import(project_root):
    r = _verify(project_root, "auth.py", "import os\n" + BROKEN_TAIL, "os")
    assert r.passed is True, r.details


def test_unparseable_python_holding_only_a_mention_still_fails(project_root):
    """The fallback is the hardened pattern set, not the old one."""
    r = _verify(
        project_root, "auth.py", "MSG = 'we import requests in the worker'" + BROKEN_TAIL, "requests"
    )
    assert r.passed is False, r.details


def test_unparseable_python_is_confirmed_unparseable():
    """Pin the premise of the two fallback tests above."""
    import ast

    with pytest.raises(SyntaxError):
        ast.parse("import os\n" + BROKEN_TAIL)


def test_content_with_a_null_byte_does_not_raise(project_root):
    """``ast.parse`` raises ValueError, not SyntaxError, on a null byte."""
    (project_root / "auth.py").write_bytes(b"import os\n\x00\n")
    r = ImportPresentVerifier().verify({"file": "auth.py", "module": "os"}, project_root)
    assert r.passed is True, r.details


def test_missing_file_param_never_reaches_the_ast_path(project_root):
    r = ImportPresentVerifier().verify({"module": "os"}, project_root)
    assert r.passed is False
    assert "not found" in r.details.lower()


def test_a_comment_marker_inside_a_docstring_does_not_hide_the_file(project_root):
    """Comments are blanked for the pattern path; strings are not.

    A source that will not parse takes that path, and a ``/*`` written
    inside a docstring is not the start of a block comment. A scanner
    that did not recognise the docstring would blank from there to the
    next ``*/`` — the rest of the file, in a file that has none.
    """
    source = (
        'def helper():\n'
        '    """Paths are matched against ``<dir>/*.sigstore``."""\n'
        "\n"
        "import hashlib\n"
        + BROKEN_TAIL
    )
    r = _verify(project_root, "auth.py", source, "hashlib")
    assert r.passed is True, r.details


def test_a_preprocessor_include_survives_comment_blanking(project_root):
    """``#`` opens a comment in some languages and a directive in
    others. Blanking the directive would erase the import itself."""
    source = "/* the crypto layer */\n#include <openssl/evp.h>\n"
    r = _verify(project_root, "auth.c", source, "openssl/evp.h")
    assert r.passed is True, r.details

def test_all_patterns_compile_under_re2():
    """Every pattern must be an RE2 pattern, not a Perl one.

    google-re2 is the engine at run time: no lookaround, no
    backreferences. A pattern that only compiles under ``re`` would fail
    closed at verification time instead of at import.
    """
    import re2

    for template in ImportPresentVerifier._PATTERNS:
        re2.compile(template.replace("{module}", re2.escape("crypto.sign")))
