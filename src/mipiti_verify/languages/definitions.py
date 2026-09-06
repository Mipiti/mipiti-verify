"""Resolve ``(file, kind, name)`` to the line span of one definition.

Every language gets the same answer shape: the 1-based inclusive line span,
the text of those lines, how exactly the span was isolated (``scope``) and
what found it (``parser``). The strategies, strongest first:

1. Python's ``ast`` for Python sources -- authoritative: a name the parser
   does not define is absent.
2. tree-sitter, through the optional ``tree-sitter-language-pack`` extra
   (``mipiti-verify[ast]``), for every other language with a grammar here.
   A hit isolates exactly the named definition, inside its owner for a
   ``Class.method`` name.
3. For Verilog, SystemVerilog and VHDL without a parser, a keyword-pair
   scanner (``module … endmodule``, ``label: process … end process``, …).
   A match is also exact: the name was read at the block's own start.
4. A brace / indentation block starting at the first line that looks like
   the definition. This cannot tell two same-named definitions apart, so it
   is reported as ``scope="block"``.

Sound in one direction only: the fallback never claims a span it did not
isolate, and the attestation names the strategy so a reader knows what a
``definition_sha256`` is a hash of.
"""

from __future__ import annotations

import ast
import hashlib
import re
from functools import lru_cache
from typing import NamedTuple, Optional

# Scope of a located span.
SCOPE_SYMBOL = "symbol"   # exactly the named definition
SCOPE_BLOCK = "block"     # a block starting at the first match of the name
SCOPE_FILE = "file"       # the whole file (nothing could be isolated)

# What isolated the span.
PARSER_AST = "ast"
PARSER_TREE_SITTER = "tree-sitter"
PARSER_KEYWORD = "keyword"
PARSER_LINES = "lines"


class Located(NamedTuple):
    start_line: int
    end_line: int
    text: str
    scope: str
    parser: str


# ---------------------------------------------------------------------------
# Languages
# ---------------------------------------------------------------------------

_EXTENSIONS = {
    "py": "python",
    "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "typescript", "tsx": "tsx",
    "go": "go",
    "rs": "rust",
    "java": "java",
    "kt": "kotlin", "kts": "kotlin",
    "c": "c", "h": "c",
    "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp", "hh": "cpp", "hxx": "cpp",
    "cs": "csharp",
    "rb": "ruby",
    "php": "php",
    "swift": "swift",
    "v": "verilog", "vh": "verilog",
    "sv": "systemverilog", "svh": "systemverilog",
    "vhd": "vhdl", "vhdl": "vhdl",
}

HDL_LANGUAGES = frozenset({"verilog", "systemverilog", "vhdl"})

# Kinds beyond function / class / method, all HDL. ``interface``, ``package``
# and ``program`` are Verilog-family compilation units alongside ``module``.
HDL_KINDS = (
    "module", "task", "always", "initial", "property", "sequence", "assert",
    "entity", "architecture", "process", "procedure",
    "interface", "package", "program",
)

# The order a bare ``file::name`` mechanism is tried in when no kind is given.
MECHANISM_KIND_ORDER = (
    "function", "class", "module", "entity", "task", "property", "sequence",
    "always", "initial", "assert", "architecture", "process", "procedure",
    "interface", "package", "program",
)


def language_of(path: str) -> str:
    """The language a file's extension names, or ``""``."""
    text = str(path or "").replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in text:
        return ""
    return _EXTENSIONS.get(text.rsplit(".", 1)[-1].lower(), "")


def hash_of(text: str) -> str:
    """SHA-256 over ``text`` with CRLF folded to LF and trailing whitespace
    stripped per line: line endings and trailing blanks are not content."""
    normalised = "\n".join(
        line.rstrip() for line in str(text).replace("\r\n", "\n").split("\n")
    )
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def _lines(content: str) -> list[str]:
    return content.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _slice(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1:end])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def locate(content: str, kind: str, name: str, *, language: str = "") -> Optional[Located]:
    """Locate ``name`` of ``kind`` in ``content`` written in ``language``.

    ``kind`` is ``function``, ``class``, ``method`` or one of ``HDL_KINDS``.
    A dotted ``Owner.leaf`` name resolves inside the owner (a class for a
    method, an enclosing class for a nested class, a SystemVerilog class for
    a function or task). ``language`` is a ``language_of`` value; unknown
    (``""``) means only Python (by trying to parse) and the block heuristics
    apply. ``None`` means nothing could be isolated.
    """
    if not content or not name or not kind:
        return None
    lines = _lines(content)
    text = "\n".join(lines)

    if language in ("python", ""):
        parsed, span = _python_span(text, kind, name)
        if parsed:
            if span is None:
                return None
            start, end = span
            return Located(start, end, _slice(lines, start, end), SCOPE_SYMBOL, PARSER_AST)
        if language == "python":
            # Not parseable as Python: the line heuristic is all that is left.
            return _lines_locate(lines, kind, name)

    if language and language in _TS_GRAMMARS:
        found = _tree_sitter_locate(text, lines, kind, name, language)
        if found is not None:
            return found

    if language in HDL_LANGUAGES or (not language and kind in HDL_KINDS):
        from . import hdl_blocks

        found = hdl_blocks.locate_block(text, kind, name, language)
        if found is not None:
            return found

    return _lines_locate(lines, kind, name)


# ---------------------------------------------------------------------------
# 1. Python ast
# ---------------------------------------------------------------------------

def _python_span(content: str, kind: str, name: str) -> tuple[bool, Optional[tuple[int, int]]]:
    """``(parsed, span)``: whether the source parsed as Python, and the span."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # ``MemoryError`` is the parser's own stack overflowing on deeply
        # nested source; the file is then not something ``ast`` can read.
        return False, None
    if kind in ("function", "method"):
        wanted: tuple = (ast.FunctionDef, ast.AsyncFunctionDef)
    elif kind == "class":
        wanted = (ast.ClassDef,)
    else:
        return True, None
    owner, _, leaf = name.rpartition(".")
    scope: ast.AST = tree
    if owner:
        holder = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == owner:
                holder = node
                break
        if holder is None:
            return True, None
        scope = holder
    for node in ast.walk(scope):
        if isinstance(node, wanted) and node.name == leaf:
            start = node.lineno
            for deco in getattr(node, "decorator_list", ()):
                start = min(start, deco.lineno)
            end = getattr(node, "end_lineno", None)
            if end is None:
                return True, None
            return True, (start, end)
    return True, None


# ---------------------------------------------------------------------------
# 2. tree-sitter
# ---------------------------------------------------------------------------

_IDENTIFIER_TYPES = frozenset({
    "identifier", "simple_identifier", "type_identifier", "constant", "name",
    "property_identifier", "field_identifier", "function_identifier",
    "task_identifier", "block_identifier",
})

_DECLARATOR_WRAPPERS = frozenset({
    "function_declarator", "pointer_declarator", "reference_declarator",
    "parenthesized_declarator", "array_declarator", "attributed_declarator",
})


class _Grammar(NamedTuple):
    functions: frozenset
    classes: frozenset
    methods: frozenset            # in addition to ``functions`` when an owner is named
    wrappers: frozenset           # parent types whose span extends the definition
    value_functions: frozenset    # ``value`` field types that make a declarator a function
    leading: frozenset            # preceding sibling types that belong to the definition
    require_body: bool            # class-kinds must carry a ``body`` field


def _g(functions, classes, methods=(), wrappers=(), value_functions=(), leading=(),
       require_body=False) -> _Grammar:
    return _Grammar(frozenset(functions), frozenset(classes), frozenset(methods),
                    frozenset(wrappers), frozenset(value_functions), frozenset(leading),
                    require_body)


_JS = _g(
    functions=("function_declaration", "generator_function_declaration", "method_definition"),
    classes=("class_declaration", "class", "abstract_class_declaration",
             "interface_declaration", "enum_declaration"),
    wrappers=("export_statement", "lexical_declaration", "variable_declaration"),
    value_functions=("arrow_function", "function_expression", "function",
                     "generator_function", "generator_function_expression"),
)

_TS_GRAMMARS: dict[str, _Grammar] = {
    "javascript": _JS,
    "typescript": _JS,
    "tsx": _JS,
    "go": _g(
        functions=("function_declaration", "method_declaration"),
        classes=("type_spec",),
        wrappers=("type_declaration",),
    ),
    "rust": _g(
        functions=("function_item", "function_signature_item"),
        classes=("struct_item", "enum_item", "trait_item", "union_item", "impl_item"),
        leading=("attribute_item",),
    ),
    "java": _g(
        functions=("method_declaration", "constructor_declaration"),
        classes=("class_declaration", "interface_declaration", "enum_declaration",
                 "record_declaration", "annotation_type_declaration"),
    ),
    "kotlin": _g(
        functions=("function_declaration",),
        classes=("class_declaration", "object_declaration"),
    ),
    "c": _g(
        functions=("function_definition",),
        classes=("struct_specifier", "union_specifier", "enum_specifier"),
        require_body=True,
    ),
    "cpp": _g(
        functions=("function_definition",),
        classes=("class_specifier", "struct_specifier", "union_specifier", "enum_specifier"),
        wrappers=("template_declaration",),
        require_body=True,
    ),
    "csharp": _g(
        functions=("method_declaration", "constructor_declaration", "local_function_statement"),
        classes=("class_declaration", "struct_declaration", "interface_declaration",
                 "record_declaration", "enum_declaration"),
    ),
    "ruby": _g(
        functions=("method", "singleton_method"),
        classes=("class", "module"),
    ),
    "php": _g(
        functions=("function_definition", "method_declaration"),
        classes=("class_declaration", "interface_declaration", "trait_declaration",
                 "enum_declaration"),
    ),
    "swift": _g(
        functions=("function_declaration", "protocol_function_declaration", "init_declaration"),
        classes=("class_declaration", "protocol_declaration"),
    ),
    # HDL grammars: the function / class tables serve ``function`` and
    # ``class`` kinds; the other kinds are in ``_HDL_KINDS`` below.
    "verilog": _g(
        functions=("function_declaration", "task_declaration"),
        classes=("class_declaration",),
    ),
    "systemverilog": _g(
        functions=("function_declaration", "task_declaration"),
        classes=("class_declaration",),
    ),
    "vhdl": _g(
        functions=("function_body", "procedure_body"),
        classes=(),
    ),
}

_TS_LANGUAGE_TAG = {"csharp": "csharp"}  # grammar tag differing from our name (none today)


@lru_cache(maxsize=None)
def _get_parser(language: str):
    """A tree-sitter parser for ``language``, or ``None`` when the optional
    extra is not installed or has no grammar for it."""
    try:
        from tree_sitter_language_pack import get_parser
    except Exception:  # noqa: BLE001 - absence of the extra, whatever its form
        return None
    try:
        return get_parser(_TS_LANGUAGE_TAG.get(language, language))
    except Exception:  # noqa: BLE001
        return None


def tree_sitter_available(language: str) -> bool:
    return _get_parser(language) is not None


def _walk(node):
    """Breadth-first, document-order traversal.

    Shallower definitions come first, so a bare name resolves to the
    outermost definition carrying it (a top-level function before a
    same-named method), as Python's ``ast.walk`` order does.
    """
    from collections import deque

    queue = deque([node])
    while queue:
        n = queue.popleft()
        yield n
        queue.extend(n.children)


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _first_child_of_types(node, types, *, named_only=True):
    for child in node.children:
        if child.type in types and (child.is_named or not named_only):
            return child
    return None


def _node_name(node, language: str) -> str:
    """The identifier a definition node declares, or ``""``."""
    if language in ("verilog", "systemverilog"):
        return _sv_name(node)
    if language == "vhdl":
        return _vhdl_name(node)
    if node.type in ("variable_declarator", "public_field_definition", "field_definition"):
        return _text(node.child_by_field_name("name"))
    if language in ("c", "cpp"):
        target = node.child_by_field_name("declarator")
        if target is None:
            target = node.child_by_field_name("name")
        while target is not None and target.type in _DECLARATOR_WRAPPERS:
            target = target.child_by_field_name("declarator")
        if target is None:
            return ""
        if target.type == "qualified_identifier":
            return _text(target.child_by_field_name("name"))
        if target.type in ("destructor_name", "operator_name", "template_function"):
            return _text(target)
        return _text(target)
    if language == "rust" and node.type == "impl_item":
        return _text(node.child_by_field_name("type"))
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named)
    named = node.child_by_field_name("designator")
    if named is not None:
        return _text(named)
    first = _first_child_of_types(node, _IDENTIFIER_TYPES)
    return _text(first)


def _owner_of(node, language: str) -> str:
    """The owner a definition names outside its body (Go receiver, C++
    ``Owner::name``), or ``""``."""
    if language == "go" and node.type == "method_declaration":
        receiver = node.child_by_field_name("receiver")
        if receiver is None:
            return ""
        for n in _walk(receiver):
            if n.type == "type_identifier":
                return _text(n)
        return ""
    if language in ("c", "cpp"):
        target = node.child_by_field_name("declarator")
        while target is not None and target.type in _DECLARATOR_WRAPPERS:
            target = target.child_by_field_name("declarator")
        if target is not None and target.type == "qualified_identifier":
            scope = target.child_by_field_name("scope")
            return _text(scope)
    if language in ("verilog", "systemverilog") and node.type in (
        "function_declaration", "task_declaration",
    ):
        # ``function void Packet::print();`` declares the method out of body.
        for n in _walk(node):
            if n.type in ("class_scope",):
                return _text(_first_child_of_types(n, ("simple_identifier",)))
    return ""


def _sv_name(node) -> str:
    t = node.type
    if t in ("module_declaration", "interface_declaration", "package_declaration",
             "program_declaration"):
        for child in node.children:
            if child.type.endswith("_header") or child.type in (
                "package_declaration", "interface_declaration",
            ):
                ident = _first_child_of_types(child, ("simple_identifier",))
                if ident is not None:
                    return _text(ident)
                for n in _walk(child):
                    if n.type == "simple_identifier":
                        return _text(n)
        named = node.child_by_field_name("name")
        if named is not None:
            return _text(named)
        ident = _first_child_of_types(node, ("simple_identifier",))
        return _text(ident)
    if t in ("function_declaration", "task_declaration", "class_constructor_declaration"):
        body = node
        for child in node.children:
            if child.type in ("function_body_declaration", "task_body_declaration"):
                body = child
                break
        for n in _walk(body):
            if n.type in ("function_identifier", "task_identifier"):
                return _text(n)
        named = body.child_by_field_name("name")
        if named is not None:
            return _text(named)
        if t == "class_constructor_declaration":
            return "new"
        return _text(_first_child_of_types(body, ("simple_identifier",)))
    if t in ("always_construct", "initial_construct", "final_construct"):
        return _sv_block_label(node)
    if t == "concurrent_assertion_item":
        first = next((c for c in node.children if c.is_named), None)
        if first is not None and first.type in ("simple_identifier", "block_identifier"):
            return _text(first)
        return ""
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named)
    return _text(_first_child_of_types(node, ("simple_identifier",)))


def _sv_block_label(node) -> str:
    """The ``begin : label`` of the first sequential block under ``node``."""
    for n in _walk(node):
        if n.type in ("seq_block", "par_block"):
            first = next((c for c in n.children if c.is_named), None)
            if first is not None and first.type in ("simple_identifier", "block_identifier"):
                return _text(first)
            return ""
    return ""


def _vhdl_name(node) -> str:
    if node.type == "process_statement":
        label = _first_child_of_types(node, ("label",))
        if label is None:
            return ""
        return _text(_first_child_of_types(label, ("identifier",)))
    for field in ("name", "designator"):
        named = node.child_by_field_name(field)
        if named is not None:
            return _text(named)
    return _text(_first_child_of_types(node, ("identifier",)))


# HDL kinds: node types per language and kind. ``function`` / ``class`` come
# from the grammar tables above.
_HDL_KINDS: dict[str, dict[str, tuple]] = {
    "verilog": {
        "module": ("module_declaration",),
        "interface": ("interface_declaration",),
        "package": ("package_declaration",),
        "program": ("program_declaration",),
        "task": ("task_declaration",),
        "always": ("always_construct",),
        "initial": ("initial_construct", "final_construct"),
        "property": ("property_declaration",),
        "sequence": ("sequence_declaration",),
        "assert": ("concurrent_assertion_item",),
    },
    "vhdl": {
        "entity": ("entity_declaration",),
        "architecture": ("architecture_body",),
        "process": ("process_statement",),
        "procedure": ("procedure_body",),
        "package": ("package_declaration", "package_body"),
    },
}
_HDL_KINDS["systemverilog"] = _HDL_KINDS["verilog"]


def _wanted_types(grammar: _Grammar, language: str, kind: str, owner: str):
    if kind in ("function", "method"):
        # In an HDL, ``function`` means any subprogram (a task or procedure
        # too): a test is nominated by name, not by which keyword declared
        # it. ``task`` and ``procedure`` stay strict.
        types = set(grammar.functions) | set(grammar.methods)
        if language in ("verilog", "systemverilog"):
            types.add("class_constructor_declaration")
        return types
    if kind == "class":
        return set(grammar.classes)
    table = _HDL_KINDS.get(language, {})
    return set(table.get(kind, ()))


def _is_definition(node, language: str, grammar: _Grammar, wanted: set) -> bool:
    if node.type in wanted:
        if grammar.require_body and node.type in grammar.classes:
            return node.child_by_field_name("body") is not None
        return True
    if node.type in ("variable_declarator", "public_field_definition", "field_definition") \
            and grammar.value_functions:
        value = node.child_by_field_name("value")
        return value is not None and value.type in grammar.value_functions
    return False


def _span_of(node, grammar: _Grammar) -> tuple[int, int]:
    outer = node
    while outer.parent is not None and outer.parent.type in grammar.wrappers:
        parent = outer.parent
        if parent.type in ("lexical_declaration", "variable_declaration", "type_declaration"):
            # Only a single-declarator statement is the definition itself.
            if sum(1 for c in parent.children if c.is_named and c.type not in ("comment",)) != 1:
                break
        outer = parent
    start = outer.start_point[0] + 1
    end = outer.end_point[0] + 1
    if outer.end_point[1] == 0 and end > start:
        end -= 1
    if grammar.leading:
        sibling = outer.prev_named_sibling
        while sibling is not None and sibling.type in grammar.leading:
            start = sibling.start_point[0] + 1
            sibling = sibling.prev_named_sibling
    return start, end


def _tree_sitter_locate(text: str, lines: list[str], kind: str, name: str,
                        language: str) -> Optional[Located]:
    grammar = _TS_GRAMMARS.get(language)
    parser = _get_parser(language)
    if grammar is None or parser is None:
        return None
    try:
        tree = parser.parse(text.encode("utf-8"))
    except Exception:  # noqa: BLE001 - a parser failure is "no parser", not an error
        return None
    root = tree.root_node
    owner, _, leaf = name.rpartition(".")
    if kind == "method" and not owner:
        kind = "function"
    wanted = _wanted_types(grammar, language, kind, owner)
    if not wanted:
        return None

    def matches(node) -> bool:
        return _is_definition(node, language, grammar, wanted) and _node_name(node, language) == leaf

    hit = None
    if owner:
        holders = [
            n for n in _walk(root)
            if _is_definition(n, language, grammar, set(grammar.classes))
            and _node_name(n, language) == owner
        ]
        for holder in holders:
            hit = next((n for n in _walk(holder) if n is not holder and matches(n)), None)
            if hit is not None:
                break
        if hit is None:
            hit = next((n for n in _walk(root) if matches(n) and _owner_of(n, language) == owner), None)
    else:
        hit = next((n for n in _walk(root) if matches(n)), None)
    if hit is None:
        return None
    start, end = _span_of(hit, grammar)
    end = min(end, len(lines))
    return Located(start, end, _slice(lines, start, end), SCOPE_SYMBOL, PARSER_TREE_SITTER)


# ---------------------------------------------------------------------------
# 4. Line heuristic (brace / indentation block)
# ---------------------------------------------------------------------------

_FUNCTION_LINE_PATTERNS = (
    r"\bdef\s+{name}\s*\(",
    r"\bfunction\s+{name}\s*\(",
    r"\bfn\s+{name}\s*\(",
    r"\bfunc\s+(?:\([^)]*\)\s*)?{name}\s*\(",
    r"\b(?:public|private|protected|static|async|final|override)\b[^;{{}}]*?\b{name}\s*\(",
    r"\b(?:async\s+)?{name}\s*\([^)]*\)\s*(?:=>|\{{)",
)

_CLASS_LINE_PATTERNS = (
    r"\bclass\s+{name}\b",
    r"\bstruct\s+{name}\b",
    r"\binterface\s+{name}\b",
    r"\benum\s+{name}\b",
    r"\btype\s+{name}\s+struct\b",
)


def _lines_locate(lines: list[str], kind: str, name: str) -> Optional[Located]:
    if kind in ("function", "method"):
        patterns = _FUNCTION_LINE_PATTERNS
    elif kind == "class":
        patterns = _CLASS_LINE_PATTERNS
    else:
        return None
    leaf = name.rsplit(".", 1)[-1]
    escaped = re.escape(leaf)
    for idx, line in enumerate(lines):
        for template in patterns:
            if re.search(template.format(name=escaped), line):
                block = block_from(lines, idx)
                end = idx + len(block.split("\n"))
                return Located(idx + 1, end, block, SCOPE_BLOCK, PARSER_LINES)
    return None


def block_from(lines: list[str], start: int) -> str:
    """Cut a block beginning at ``lines[start]``.

    If a ``{`` opens on the definition line (or the first following
    non-blank line), the block ends at its matching ``}``. Otherwise it ends
    before the next non-blank line indented at or above the definition's
    indentation (blank lines and deeper-indented lines belong to the block).
    """
    open_idx = None
    for j in range(start, min(start + 2, len(lines))):
        if "{" in lines[j]:
            open_idx = j
            break
        if j > start and lines[j].strip():
            break
    if open_idx is not None:
        depth = 0
        for j in range(open_idx, len(lines)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return "\n".join(lines[start:j + 1])
        return "\n".join(lines[start:])
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for j in range(start + 1, len(lines)):
        text = lines[j]
        if not text.strip():
            continue
        if len(text) - len(text.lstrip()) <= indent:
            end = j
            break
    block = lines[start:end]
    while block and not block[-1].strip():
        block.pop()
    return "\n".join(block)
