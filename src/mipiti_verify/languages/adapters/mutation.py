"""Source mutation for brace languages: Go, Rust, Java, Kotlin, C, C++,
C#, Swift.

A mechanism is disabled by replacing the body of its definition with a body
that aborts, so any test whose outcome rests on the mechanism cannot pass.
The rewrite is textual and local: only the body between the definition's
braces changes (or the expression body, where the language has one), and
the file is restored afterwards by the caller. A definition that cannot be
located, or whose body cannot be delimited, raises ``DisableError`` with
the reason; nothing is guessed.
"""

from __future__ import annotations

import re
from typing import Optional

from ._common import DISABLED_MESSAGE, DisableError, Mechanism, located_exactly, require_exact

ABORT_BODY = {
    "go": f'{{ panic("{DISABLED_MESSAGE}") }}',
    "rust": f'{{ panic!("{DISABLED_MESSAGE}") }}',
    "java": f'{{ throw new IllegalStateException("{DISABLED_MESSAGE}"); }}',
    "kotlin": f'{{ throw IllegalStateException("{DISABLED_MESSAGE}") }}',
    "csharp": f'{{ throw new System.InvalidOperationException("{DISABLED_MESSAGE}"); }}',
    "swift": f'{{ fatalError("{DISABLED_MESSAGE}") }}',
    "c": "{ abort(); }",
    "cpp": "{ abort(); }",
    "javascript": f'{{ throw new Error("{DISABLED_MESSAGE}"); }}',
    "typescript": f'{{ throw new Error("{DISABLED_MESSAGE}"); }}',
}

MUTATION_LANGUAGES = tuple(ABORT_BODY)

_CONTROL_WORDS = {
    "return", "if", "else", "while", "for", "switch", "case", "throw", "new",
    "await", "yield", "do", "try", "catch", "defer", "go", "match", "let",
    "var", "val", "const", "assert", "print", "println", "require",
}

_TYPE_KEYWORDS = {
    "class", "struct", "impl", "interface", "enum", "object", "trait",
    "record", "union", "protocol", "extension", "actor", "data",
}


# ---------------------------------------------------------------------------
# Lexical scanning that ignores strings and comments
# ---------------------------------------------------------------------------

def _skip_noise(content: str, i: int) -> int:
    """If ``content[i]`` opens a string or comment, return the index just
    past it; otherwise return ``i``."""
    n = len(content)
    ch = content[i]
    two = content[i:i + 2]
    if two == "//":
        j = content.find("\n", i)
        return n if j < 0 else j
    if two == "/*":
        j = content.find("*/", i + 2)
        return n if j < 0 else j + 2
    if ch in "\"'`":
        # Rust lifetimes ('a) and character literals share the quote; a
        # quote that does not close on the same line is treated as a
        # lifetime marker and skipped as a single character.
        quote = ch
        j = i + 1
        while j < n:
            c = content[j]
            if c == "\\" and quote != "`":
                j += 2
                continue
            if c == quote:
                return j + 1
            if c == "\n" and quote != "`":
                return i + 1
            j += 1
        return n
    return i


def match_brace(content: str, open_idx: int) -> int:
    """Index of the ``}`` matching the ``{`` at ``open_idx``, or -1."""
    depth = 0
    i = open_idx
    n = len(content)
    while i < n:
        j = _skip_noise(content, i)
        if j != i:
            i = j
            continue
        c = content[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def match_paren(content: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(content)
    while i < n:
        j = _skip_noise(content, i)
        if j != i:
            i = j
            continue
        c = content[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _next_significant(content: str, i: int, stop: int = -1) -> int:
    """Index of the next character that is not whitespace or a comment."""
    n = len(content) if stop < 0 else min(stop, len(content))
    while i < n:
        if content[i].isspace():
            i += 1
            continue
        if content[i:i + 2] in ("//", "/*"):
            i = _skip_noise(content, i)
            continue
        return i
    return -1


# ---------------------------------------------------------------------------
# Locating the definition
# ---------------------------------------------------------------------------

def _line_start(content: str, line_no: int) -> int:
    """Character offset of 1-based ``line_no``."""
    offset = 0
    for _ in range(line_no - 1):
        nl = content.find("\n", offset)
        if nl < 0:
            return len(content)
        offset = nl + 1
    return offset


def _external_span(content: str, kind: str, name: str, file: str = "") -> Optional[tuple[int, int]]:
    """A 1-based line span from the language layer when one is available:
    ``languages.definitions.locate`` (parser-exact where a parser is
    installed) when that module exists, else
    ``definition_extract.definition_line_span``."""
    try:
        from ..definitions import language_of as _language_of
        from ..definitions import locate  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        locate = None
    if locate is not None:
        try:
            wanted = "class" if kind in _TYPE_KEYWORDS else ("method" if "." in name else "function")
            found = locate(content, wanted, name, language=_language_of(file) if file else "")
            span = getattr(found, "span", None) or getattr(found, "lines", None) or found
            if isinstance(span, tuple) and len(span) >= 2:
                return int(span[0]), int(span[1])
            start = getattr(found, "start", None) or getattr(found, "start_line", None)
            end = getattr(found, "end", None) or getattr(found, "end_line", None)
            if start and end:
                return int(start), int(end)
        except Exception:  # noqa: BLE001
            pass
    try:
        from ...definition_extract import definition_line_span
    except Exception:  # noqa: BLE001
        return None
    try:
        return definition_line_span(content, "class" if kind in _TYPE_KEYWORDS else "function", name)
    except Exception:  # noqa: BLE001
        return None


def _definition_line_regexes(name: str, kind: str) -> list[str]:
    n = re.escape(name)
    if kind in _TYPE_KEYWORDS:
        return [
            rf"^[ \t]*(?:[\w@]+\s+)*(?:{'|'.join(sorted(_TYPE_KEYWORDS))})\s+{n}\b",
            rf"^[ \t]*impl\b[^{{]*\b{n}\b",
            rf"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|union)\s+{n}\b",
            rf"^[ \t]*type\s+{n}\s+(?:struct|interface)\b",
        ]
    return [
        rf"^[ \t]*(?:[\w@]+\s+)*(?:func|fn|fun|def|function)\s+(?:\([^)]*\)\s*)?(?:<[^>]*>\s*)?(?:[\w.]+\.)?{n}\s*[(<]",
        rf"^[ \t]*(?:[\w@<>\[\],.*&:?!]+\s+)*(?:[\w:]+::|[\w.]+\.)?{n}\s*(?:<[^>]*>)?\s*\(",
    ]


def _is_definition_line(line: str, name: str, kind: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.endswith(";"):
        return False
    first = re.split(r"[\s(]", stripped, 1)[0]
    if first in _CONTROL_WORDS:
        return False
    if stripped.startswith(("#", "//", "*", "/*", "@")) and not stripped.startswith("@Override"):
        # Preprocessor, comment, or a decorator line other than an
        # annotation that shares the line with the definition.
        if not re.search(rf"\b(?:fun|func|fn|def)\s+{re.escape(name)}\b", stripped):
            return False
    for pattern in _definition_line_regexes(name, kind):
        if re.search(pattern, line):
            return True
    return False


def _find_definition_line(content: str, name: str, kind: str, *, lo: int = 0, hi: int = -1) -> int:
    """0-based index of the line that defines ``name``, searching lines
    ``lo..hi``; -1 when absent."""
    lines = content.split("\n")
    if hi < 0 or hi > len(lines):
        hi = len(lines)
    for idx in range(lo, hi):
        if _is_definition_line(lines[idx], name, kind):
            return idx
    return -1


def _body_of_definition(content: str, def_line: int, name: str, kind: str, language: str) -> tuple[int, int, str]:
    """``(start, end, form)``: character offsets of the body to replace
    (``end`` exclusive) and whether it is a ``brace`` body, a Kotlin
    ``expr`` body (``= expr``) or a C# ``arrow`` body (``=> expr;``)."""
    line_off = _line_start(content, def_line + 1)
    line_end = content.find("\n", line_off)
    if line_end < 0:
        line_end = len(content)
    m = re.search(rf"\b{re.escape(name)}\b", content[line_off:line_end])
    if m is None:
        raise DisableError(f"{name} is not on its definition line")
    at = line_off + m.end()
    if kind in _TYPE_KEYWORDS:
        open_idx = content.find("{", at)
        if open_idx < 0:
            raise DisableError(f"{name} has no body")
        close = match_brace(content, open_idx)
        if close < 0:
            raise DisableError(f"the body of {name} has no closing brace")
        return open_idx, close + 1, "brace"
    # Skip generic parameters, then find the parameter list.
    nxt = _next_significant(content, at)
    if nxt >= 0 and content[nxt] == "<":
        depth = 0
        i = nxt
        while i < len(content):
            if content[i] == "<":
                depth += 1
            elif content[i] == ">":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        at = i + 1
    paren = content.find("(", at)
    if paren < 0:
        raise DisableError(f"{name} has no parameter list")
    close_paren = match_paren(content, paren)
    if close_paren < 0:
        raise DisableError(f"the parameter list of {name} does not close")
    i = close_paren + 1
    n = len(content)
    while i < n:
        j = _next_significant(content, i)
        if j < 0:
            break
        c = content[j]
        if c == "{":
            close = match_brace(content, j)
            if close < 0:
                raise DisableError(f"the body of {name} has no closing brace")
            return j, close + 1, "brace"
        if c == ";":
            raise DisableError(f"{name} is declared here but has no body")
        if content.startswith("=>", j) and language == "csharp":
            semi = _statement_end(content, j + 2)
            return j, semi + 1, "arrow"
        if c == "=" and language == "kotlin" and not content.startswith("==", j):
            end = _expression_end(content, j + 1)
            return j, end, "expr"
        if c == "(" :
            # A Swift/Kotlin trailing parenthesised clause (a closure type
            # or a call in a default value); step over it.
            k = match_paren(content, j)
            if k < 0:
                break
            i = k + 1
            continue
        if c == "@" or c.isalnum() or c in "_:->?![],.*&<>'":
            i = j + 1
            continue
        break
    raise DisableError(f"cannot delimit the body of {name}")


def _statement_end(content: str, i: int) -> int:
    n = len(content)
    while i < n:
        j = _skip_noise(content, i)
        if j != i:
            i = j
            continue
        c = content[i]
        if c == "(":
            i = match_paren(content, i) + 1
            if i <= 0:
                break
            continue
        if c == "{":
            i = match_brace(content, i) + 1
            if i <= 0:
                break
            continue
        if c == ";":
            return i
        i += 1
    raise DisableError("expression body does not end with ';'")


def _expression_end(content: str, i: int) -> int:
    """End of a Kotlin expression body: the end of the line the expression
    finishes on, following bracketed continuations."""
    n = len(content)
    while i < n:
        j = _skip_noise(content, i)
        if j != i:
            i = j
            continue
        c = content[i]
        if c == "(":
            i = match_paren(content, i) + 1
            if i <= 0:
                return n
            continue
        if c == "{":
            i = match_brace(content, i) + 1
            if i <= 0:
                return n
            continue
        if c == "\n":
            stripped = content[i + 1:].lstrip(" \t")
            # A continuation line starting with an operator or dot belongs
            # to the expression.
            if stripped[:1] in ("." , "?", "+", "-", "*", "/", "&", "|") and not stripped.startswith(("//", "/*")):
                i += 1
                continue
            return i
        i += 1
    return n


def _class_body(content: str, owner: str, file: str = "") -> tuple[int, int]:
    """Character range (open brace, close brace inclusive) of ``owner``'s
    body."""
    idx = _find_definition_line(content, owner, "class")
    if idx < 0:
        span = _external_span(content, "class", owner)
        if span is None:
            raise DisableError(f"{owner} is not defined in the file")
        idx = span[0] - 1
    line_off = _line_start(content, idx + 1)
    open_idx = content.find("{", line_off)
    if open_idx < 0:
        raise DisableError(f"{owner} has no body")
    close = match_brace(content, open_idx)
    if close < 0:
        raise DisableError(f"the body of {owner} has no closing brace")
    return open_idx, close


def _methods_in_body(content: str, open_idx: int, close_idx: int) -> list[tuple[int, int]]:
    """Body ranges of every method defined directly inside a class body."""
    bodies: list[tuple[int, int]] = []
    i = open_idx + 1
    saw_params = False
    while i < close_idx:
        j = _skip_noise(content, i)
        if j != i:
            i = j
            continue
        c = content[i]
        if c == "(":
            k = match_paren(content, i)
            if k < 0:
                break
            saw_params = True
            i = k + 1
            continue
        if c == ";":
            saw_params = False
        elif c == "{":
            k = match_brace(content, i)
            if k < 0:
                break
            if saw_params:
                bodies.append((i, k + 1))
            saw_params = False
            i = k + 1
            continue
        elif c == "=":
            # A field initializer; a method body never follows '='.
            saw_params = False
        i += 1
    return bodies


def _go_method_bodies(content: str, receiver: str) -> list[tuple[int, int]]:
    pattern = re.compile(
        rf"^func\s*\(\s*\w*\s*\*?\s*{re.escape(receiver)}(?:\[[^\]]*\])?\s*\)\s*\w+\s*\(", re.M)
    bodies = []
    for m in pattern.finditer(content):
        close_paren = match_paren(content, m.end() - 1)
        if close_paren < 0:
            continue
        open_idx = content.find("{", close_paren)
        if open_idx < 0:
            continue
        close = match_brace(content, open_idx)
        if close < 0:
            continue
        bodies.append((open_idx, close + 1))
    return bodies


def _with_stdlib(content: str, language: str) -> str:
    if language not in ("c", "cpp"):
        return content
    if re.search(r"^\s*#\s*include\s*<(?:stdlib\.h|cstdlib)>", content, re.M):
        return content
    return "#include <stdlib.h>\n" + content


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def mutate_source(content: str, mechanism: Mechanism, language: str = "") -> str:
    """``content`` with the mechanism's body replaced by the language's
    aborting body. Raises ``DisableError`` when the definition cannot be
    located or delimited, and when the language layer does not isolate
    it exactly (``scope == "symbol"``): a block-scope span may cover a
    different definition, and a mutation of the wrong block can still
    compile, which would attribute a test's outcome to the wrong
    mechanism."""
    language = language or mechanism.language
    body = ABORT_BODY.get(language)
    if body is None:
        raise DisableError(f"no source mutation is defined for {language or 'this language'}")
    kind = mechanism.kind or ""
    owner, leaf = mechanism.owner, mechanism.leaf
    if language == "go" and not kind and not owner and _find_definition_line(content, leaf, "function") < 0 \
            and _go_method_bodies(content, leaf):
        kind = "struct"
    exact: Optional[bool] = None
    if kind in _TYPE_KEYWORDS or (not kind and not owner and _looks_like_type(content, leaf)):
        kinds: tuple = ("class",)
        if language == "go":
            # A Go type's methods may live in a file that does not declare
            # the type: every method with that receiver must be isolated
            # exactly on its own, and at least one must exist.
            methods = re.findall(
                rf"^\s*func\s*\([^)]*\b{re.escape(leaf)}\s*\)\s*([A-Za-z_]\w*)\s*\(", content, re.M)
            if methods:
                exact = all(located_exactly(content, ("method",), f"{leaf}.{m}", "go") is True
                            for m in methods)
    elif owner:
        kinds = ("method",)
    else:
        kinds = ("function",)
    return require_exact(
        content, kinds, mechanism.name, language,
        lambda: _mutate_source(content, mechanism, language, body, kind),
        exact=exact,
    )


def _mutate_source(content: str, mechanism: Mechanism, language: str, body: str, kind: str) -> str:
    owner, leaf = mechanism.owner, mechanism.leaf
    if kind in _TYPE_KEYWORDS or (not kind and not owner and _looks_like_type(content, leaf)):
        if language == "go":
            ranges = _go_method_bodies(content, leaf)
            if not ranges:
                raise DisableError(f"{leaf} has no methods to disable")
        else:
            open_idx, close_idx = _class_body(content, leaf, mechanism.file)
            ranges = _methods_in_body(content, open_idx, close_idx)
            if not ranges:
                raise DisableError(f"{leaf} defines no method bodies to disable")
        return _with_stdlib(_replace_ranges(content, ranges, body), language)

    lo, hi = 0, -1
    if owner:
        if language == "go":
            ranges = [r for r in _go_method_bodies(content, owner)
                      if re.search(rf"\)\s*{re.escape(leaf)}\s*\(", content[max(0, r[0] - 200):r[0]])]
            if not ranges:
                raise DisableError(f"{owner}.{leaf} is not defined in the file")
            return _replace_ranges(content, ranges[:1], body)
        try:
            open_idx, close_idx = _class_body(content, owner, mechanism.file)
        except DisableError:
            # The owner is declared elsewhere (a C++ class whose methods are
            # defined out of line): the qualified name must be on the line.
            open_idx = close_idx = -1
        if open_idx >= 0:
            lo = content.count("\n", 0, open_idx)
            hi = content.count("\n", 0, close_idx) + 1
        else:
            qualified = re.compile(rf"\b{re.escape(owner)}\s*(?:::|\.)\s*{re.escape(leaf)}\s*\(")
            for idx, line in enumerate(content.split("\n")):
                if qualified.search(line) and _is_definition_line(line, leaf, "function"):
                    lo, hi = idx, idx + 1
                    break
            else:
                raise DisableError(f"{owner}.{leaf} is not defined in the file")
    def_line = _find_definition_line(content, leaf, "function", lo=lo, hi=hi)
    if def_line < 0:
        span = _external_span(content, "function", mechanism.name, mechanism.file)
        if span is None:
            raise DisableError(f"{mechanism.name} is not defined in the file")
        def_line = span[0] - 1
    start, end, form = _body_of_definition(content, def_line, leaf, "function", language)
    replacement = body
    if form == "expr":
        # Kotlin: `= expr` becomes a block body.
        replacement = body
    elif form == "arrow":
        # C#: `=> expr;` becomes a block body.
        replacement = body
    return _with_stdlib(content[:start] + replacement + content[end:], language)


def _looks_like_type(content: str, name: str) -> bool:
    return _find_definition_line(content, name, "class") >= 0 and \
        _find_definition_line(content, name, "function") < 0


def _replace_ranges(content: str, ranges: list[tuple[int, int]], body: str) -> str:
    out = content
    for start, end in sorted(ranges, reverse=True):
        out = out[:start] + body + out[end:]
    return out
