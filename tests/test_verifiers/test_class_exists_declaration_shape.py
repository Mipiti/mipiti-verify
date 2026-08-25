"""``class_exists`` passes on a declaration, never on a mention.

Tier 1 is the only tier that decides whether the named type exists: the
tier-2 rubric is handed the isolated declaration and told that presence
is settled, so it judges what the type contains rather than re-checking
that it is there. A tier-1 pass therefore has to mean a declaration was
written in the file, and the runner reports ``skipped`` for tier 2 when
no provider is configured, so nothing downstream re-examines the
question.

``class AuthService`` is an English noun phrase as readily as it is code,
and the same is true of the ``struct`` / ``interface`` / ``enum``
spellings, so the keyword and the name alone cannot stand for a
declaration. These tests pin the two properties that separate a
declaration from a mention: the declaration starts its own line,
preceded only by indentation and modifiers drawn from a fixed set, and
it is followed by something that opens or terminates it.

The cases run twice — once through ``verify()``, which is the contract,
and once against the raw pattern set. Python sources are decided by the
AST path inside ``verify()`` (see
``test_python_ast_definition_path.py``); running the patterns directly
keeps the regex layer pinned as well, since it stays the fallback for
Python that will not parse and the only path for every other language.
"""

from __future__ import annotations

from pathlib import Path

import re2
import pytest

from mipiti_verify.verifiers.code_structure import ClassExistsVerifier


def _verify(project_root: Path, filename: str, source: str, name: str):
    (project_root / filename).write_text(source, encoding="utf-8")
    return ClassExistsVerifier().verify({"file": filename, "name": name}, project_root)


def _regex_hit(source: str, name: str) -> bool:
    escaped = re2.escape(name)
    return any(
        re2.search(template.replace("{name}", escaped), source)
        for template in ClassExistsVerifier._PATTERNS
    )


# --- Declarations: every one of these must be found -----------------------

DECLARATIONS = [
    ("python_class", "svc.py", "class AuthService:\n    pass\n", "AuthService"),
    (
        "python_class_with_base",
        "svc.py",
        "class AuthService(BaseService):\n    def go(self):\n        return 1\n",
        "AuthService",
    ),
    (
        "python_decorated_class",
        "svc.py",
        "@dataclass\nclass AuthService:\n    token: str\n",
        "AuthService",
    ),
    (
        "python_nested_class",
        "svc.py",
        "class Outer:\n    class AuthService:\n        pass\n",
        "AuthService",
    ),
    (
        "python_wrapped_base_list",
        "svc.py",
        "class AuthService(\n    BaseService,\n    Mixin,\n):\n    pass\n",
        "AuthService",
    ),
    (
        "python_pep695_generic",
        "svc.py",
        "class AuthService[T]:\n    pass\n",
        "AuthService",
    ),
    (
        "python_trailing_comment",
        "svc.py",
        "class AuthService:  # checks bearer tokens\n    pass\n",
        "AuthService",
    ),
    (
        "java_class_extends_brace",
        "AuthService.java",
        "public class AuthService extends BaseService {\n    int calls;\n}\n",
        "AuthService",
    ),
    (
        "java_class_allman_brace",
        "AuthService.java",
        "public class AuthService extends BaseService\n{\n    int calls;\n}\n",
        "AuthService",
    ),
    (
        "java_generic_implements",
        "AuthService.java",
        "class AuthService<T> implements Bar {\n}\n",
        "AuthService",
    ),
    (
        "java_static_nested_class",
        "AuthService.java",
        "    private static final class AuthService {\n    }\n",
        "AuthService",
    ),
    (
        "java_annotation_type",
        "AuthService.java",
        "public @interface AuthService {\n    String value();\n}\n",
        "AuthService",
    ),
    (
        "csharp_sealed_partial",
        "AuthService.cs",
        "    public sealed partial class AuthService : IAuthService\n    {\n    }\n",
        "AuthService",
    ),
    (
        "csharp_abstract_generic_allman",
        "AuthService.cs",
        "internal abstract class AuthService<T> : Base<T>\n{\n}\n",
        "AuthService",
    ),
    (
        "ts_export_class",
        "svc.ts",
        "export class AuthService {\n  token = '';\n}\n",
        "AuthService",
    ),
    (
        "ts_export_default_class",
        "svc.ts",
        "export default class AuthService {\n  token = '';\n}\n",
        "AuthService",
    ),
    ("ts_interface", "svc.ts", "interface AuthService {\n  go(): void;\n}\n", "AuthService"),
    (
        "ts_export_interface_extends",
        "svc.ts",
        "export interface AuthService extends Base {\n  token: string;\n}\n",
        "AuthService",
    ),
    (
        "ts_generic_class_implements",
        "svc.ts",
        "class AuthService<T> implements Bar {\n  go(): void {}\n}\n",
        "AuthService",
    ),
    ("ts_empty_class_one_line", "svc.ts", "export class AuthService {}\n", "AuthService"),
    (
        "ts_declare_class",
        "svc.d.ts",
        "declare class AuthService {\n  token: string;\n}\n",
        "AuthService",
    ),
    (
        "rust_pub_struct",
        "svc.rs",
        "pub struct AuthService {\n    token: String,\n}\n",
        "AuthService",
    ),
    (
        "rust_generic_struct",
        "svc.rs",
        "struct AuthService<T> {\n    inner: T,\n}\n",
        "AuthService",
    ),
    ("rust_unit_struct", "svc.rs", "struct AuthService;\n", "AuthService"),
    ("rust_tuple_struct", "svc.rs", "pub struct AuthService(pub u32);\n", "AuthService"),
    (
        "rust_pub_crate_struct",
        "svc.rs",
        "pub(crate) struct AuthService<T> {\n    inner: T,\n}\n",
        "AuthService",
    ),
    (
        "rust_where_clause_struct",
        "svc.rs",
        "struct AuthService<T> where T: Copy {\n    inner: T,\n}\n",
        "AuthService",
    ),
    ("rust_enum", "svc.rs", "enum Status {\n    Ok,\n    Denied,\n}\n", "Status"),
    (
        "go_type_struct",
        "svc.go",
        "type AuthService struct {\n\tdb *sql.DB\n}\n",
        "AuthService",
    ),
    (
        "go_type_interface",
        "svc.go",
        "type AuthService interface {\n\tGo() error\n}\n",
        "AuthService",
    ),
    (
        "go_generic_struct",
        "svc.go",
        "type AuthService[T any] struct {\n\tinner T\n}\n",
        "AuthService",
    ),
    (
        "go_type_block_member",
        "svc.go",
        "type (\n\tAuthService struct {\n\t\tdb *sql.DB\n\t}\n)\n",
        "AuthService",
    ),
    ("go_empty_struct_one_line", "svc.go", "type AuthService struct{}\n", "AuthService"),
    ("c_struct", "svc.c", "struct AuthService {\n    int calls;\n};\n", "AuthService"),
    ("c_enum", "svc.c", "enum Status {\n    OK = 1,\n};\n", "Status"),
    ("c_forward_declaration", "svc.h", "struct AuthService;\n", "AuthService"),
    ("c_typedef_struct", "svc.h", "typedef struct AuthService AuthService;\n", "AuthService"),
    ("cpp_struct_one_line", "svc.hpp", "struct AuthService { int x, y; };\n", "AuthService"),
    ("cpp_scoped_enum", "svc.hpp", "enum class Status : uint8_t {\n    Ok,\n};\n", "Status"),
    (
        "kotlin_data_class",
        "Svc.kt",
        "data class AuthService(val token: String) {\n    fun go() {}\n}\n",
        "AuthService",
    ),
    (
        "scala_case_class",
        "Svc.scala",
        "case class AuthService(token: String) {\n  def go = 1\n}\n",
        "AuthService",
    ),
    (
        "swift_open_class",
        "Svc.swift",
        "open class AuthService: NSObject {\n    var token = \"\"\n}\n",
        "AuthService",
    ),
    ("tab_indented_class", "svc.ts", "\t\tclass AuthService {\n\t\t}\n", "AuthService"),
    (
        "brace_with_trailing_comment",
        "svc.ts",
        "class AuthService { // checks bearer tokens\n}\n",
        "AuthService",
    ),
    # A long base list wraps the way a formatter writes it.
    (
        "ts_interface_wrapped_extends",
        "svc.ts",
        "export interface AuthService\n"
        "  extends React.HTMLAttributes<HTMLElement>,\n"
        "    VariantProps<typeof variants> {\n"
        "  asChild?: boolean\n"
        "}\n",
        "AuthService",
    ),
    (
        "java_wrapped_extends_implements",
        "AuthService.java",
        "public class AuthService\n    extends BaseService\n    implements Bar {\n}\n",
        "AuthService",
    ),
    (
        "csharp_wrapped_base_list",
        "AuthService.cs",
        "internal class AuthService :\n    IFoo,\n    IBar\n{\n}\n",
        "AuthService",
    ),
    (
        "ts_one_line_body_with_extends",
        "svc.ts",
        "  class AuthService extends Error {}\n",
        "AuthService",
    ),
    ("python_one_line_pass", "svc.py", "class AuthService(Base): pass\n", "AuthService"),
    ("python_one_line_ellipsis", "svc.py", "class AuthService: ...\n", "AuthService"),
    (
        "python_base_built_by_a_call",
        "svc.py",
        'class AuthService(\n    namedtuple("AuthService", ("token", "org"))\n):\n    """A service."""\n',
        "AuthService",
    ),
]


@pytest.mark.parametrize(
    "filename,source,name",
    [(f, s, n) for _, f, s, n in DECLARATIONS],
    ids=[i for i, _, _, _ in DECLARATIONS],
)
def test_declaration_is_found(project_root, filename, source, name):
    r = _verify(project_root, filename, source, name)
    assert r.passed is True, r.details
    assert "line" in r.details


@pytest.mark.parametrize(
    "source,name",
    [(s, n) for _, _, s, n in DECLARATIONS],
    ids=[i for i, _, _, _ in DECLARATIONS],
)
def test_declaration_matches_the_pattern_layer(source, name):
    """The patterns alone must find every declaration.

    ``verify()`` decides Python through the AST, so without this the
    Python shapes would never exercise the regex that still has to
    handle them when a file does not parse.
    """
    assert _regex_hit(source, name) is True


# --- Mentions: none of these may satisfy the assertion --------------------

MENTIONS = [
    ("prose_sentence", "README.md", "The class AuthService is responsible for tokens.\n"),
    ("prose_leading_keyword", "README.md", "class AuthService validates every bearer token.\n"),
    (
        "prose_naming_a_modifier",
        "README.md",
        "The public class AuthService is the entry point.\n",
    ),
    (
        "prose_naming_a_modifier_abstract",
        "README.md",
        "An abstract class AuthService would be cleaner here.\n",
    ),
    (
        "prose_ending_in_a_semicolon",
        "README.md",
        "struct AuthService is declared in svc.h; see there.\n",
    ),
    (
        "prose_ending_in_a_colon",
        "README.md",
        "Use the class AuthService as follows:\n\n    example\n",
    ),
    (
        "prose_containing_braces",
        "README.md",
        "class AuthService returns {ok: true} on success.\n",
    ),
    ("markdown_heading", "README.md", "## class AuthService\n\nDocs follow.\n"),
    ("markdown_bullet", "README.md", "- class AuthService - checks the bearer token\n"),
    ("markdown_bullet_code_span", "README.md", "- `class AuthService` - checks the token\n"),
    ("markdown_numbered", "README.md", "1. class AuthService validates the token\n"),
    ("changelog_entry", "CHANGELOG.md", "* Fixed class AuthService to reject expired tokens.\n"),
    ("hash_comment", "svc.ts", "# the class AuthService lives elsewhere\nlet x = 1;\n"),
    ("slash_comment", "svc.ts", "// class AuthService handles auth\nlet x = 1;\n"),
    (
        "block_comment_body",
        "svc.c",
        "/*\n * class AuthService checks the token\n */\nint x;\n",
    ),
    (
        "docstring_prose",
        "svc.py",
        'def other():\n    """Delegates to class AuthService for checks."""\n    return 1\n',
    ),
    ("string_literal", "svc.py", 'MSG = "see class AuthService for details"\n'),
    ("string_literal_js", "svc.ts", 'logger.info("class AuthService failed to load");\n'),
    ("json_value", "meta.json", '{"note": "class AuthService handles auth"}\n'),
    ("json_key", "meta.json", '{\n  "class AuthService": {\n    "a": 1\n  }\n}\n'),
    ("yaml_list_item", "meta.yaml", "classes:\n  - class AuthService\n"),
    ("python_import", "svc.py", "from other import AuthService\n"),
    ("typescript_named_import", "svc.ts", "import { AuthService } from './other';\n"),
    ("type_annotation_parameter", "svc.py", "def f(svc: AuthService) -> None:\n    return None\n"),
    ("type_annotation_variable", "svc.ts", "let svc: AuthService = build();\n"),
    ("instantiation_python", "svc.py", "svc = AuthService()\n"),
    ("instantiation_new", "svc.ts", "const svc = new AuthService();\n"),
    ("isinstance_check", "svc.py", "def f(x):\n    return isinstance(x, AuthService)\n"),
    ("used_only_as_a_base", "svc.py", "class Other(AuthService):\n    pass\n"),
    ("referenced_in_a_list", "svc.py", "SERVICES = [AuthService, Other]\n"),
    ("longer_name_declared", "svc.py", "class AuthServiceFactory:\n    pass\n"),
    ("prefixed_name_declared", "svc.py", "class BaseAuthService:\n    pass\n"),
    ("go_name_glued_to_keyword", "svc.go", "type AuthServicestruct {\n}\n"),
    # A base-list clause is what lets a declaration wrap. These pin that
    # it cannot be used to walk out of a sentence and into a brace that
    # belongs to unrelated code below.
    (
        "prose_colon_then_a_later_brace",
        "README.md",
        "class AuthService: the token checker.\n\nfunction other() {\n}\n",
    ),
    (
        "prose_extends_then_a_later_brace",
        "README.md",
        "class AuthService extends the old design in ways that matter.\n"
        "\n"
        "function other() {\n}\n",
    ),
    (
        "prose_colon_then_an_object_literal",
        "README.md",
        "class AuthService: see below\n\nconst x = {a: 1};\n",
    ),
    ("prose_parenthetical", "README.md", "class AuthService (the old one) is deprecated.\n"),
    (
        "prose_wrapped_without_a_clause",
        "README.md",
        "class AuthService\n  is documented\n  here {\n",
    ),
    (
        "prose_parenthetical_then_colon",
        "README.md",
        "class AuthService (see the notes below):\n\n    example\n",
    ),
    (
        "prose_colon_then_a_sentence",
        "README.md",
        "class AuthService: the token checker for every request.\n",
    ),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in MENTIONS], ids=[i for i, _, _ in MENTIONS]
)
def test_mention_is_not_a_declaration(project_root, filename, source):
    r = _verify(project_root, filename, source, "AuthService")
    assert r.passed is False, f"a mention satisfied the assertion: {r.details}"
    assert "AuthService" in r.details


@pytest.mark.parametrize(
    "source", [s for _, _, s in MENTIONS], ids=[i for i, _, _ in MENTIONS]
)
def test_mention_matches_no_pattern(source):
    """No mention may satisfy the pattern layer either.

    ``verify()`` would catch the Python mentions through the AST, which
    would hide a regex that still accepts them on the fallback path.
    """
    assert _regex_hit(source, "AuthService") is False


ENUM_MENTIONS = [
    ("enum_prose", "README.md", "enum Status is the status enumeration used everywhere.\n"),
    ("enum_in_comment", "svc.c", "// enum Status lists every terminal state\nint x;\n"),
]


@pytest.mark.parametrize(
    "filename,source", [(f, s) for _, f, s in ENUM_MENTIONS], ids=[i for i, _, _ in ENUM_MENTIONS]
)
def test_enum_mention_is_not_a_declaration(project_root, filename, source):
    r = _verify(project_root, filename, source, "Status")
    assert r.passed is False, f"a mention satisfied the assertion: {r.details}"


def test_reported_line_is_the_declaration_not_an_earlier_mention(project_root):
    """The line number in the details points at the declaration."""
    source = (
        "// class AuthService (see below) is the entry point\n"
        "\n"
        "export class AuthService {\n"
        "  token = '';\n"
        "}\n"
    )
    r = _verify(project_root, "svc.ts", source, "AuthService")
    assert r.passed is True
    assert "line 3" in r.details


def test_all_patterns_compile_under_re2():
    """Every pattern must be an RE2 pattern, not a Perl one.

    google-re2 is the engine at run time: no lookaround, no
    backreferences. A pattern that only compiles under ``re`` would fail
    closed at verification time instead of at import.
    """
    for template in ClassExistsVerifier._PATTERNS:
        re2.compile(template.replace("{name}", re2.escape("AuthService")))
