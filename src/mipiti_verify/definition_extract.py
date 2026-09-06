"""Isolate a named definition block from a source file.

The semantic tier judges the *body* of a symbol whose existence the structural
tier has already established. Handing the reviewer the whole file makes it
locate the symbol before judging it, which is a task it was never asked to do
and can fail at. This module cuts out just the definition so the reviewer's
only question is whether the body proves the stated aspect of the control.

Python sources are cut by ``ast`` (decorators included). Other languages fall
back to a line-based heuristic: the definition line is found with the same
multi-language patterns the structural tier uses, then the block extends to
the matching closing brace when the definition opens one, or to the next
non-blank line at the same or lower indentation otherwise.
"""

from __future__ import annotations

import ast
import re

# Keep the isolated block comfortably inside the reviewer's context budget.
MAX_DEFINITION_CHARS = 16000

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


def extract_definition(content: str, kind: str, name: str) -> str | None:
    """Return the definition block of ``name`` in ``content`` or ``None``.

    ``kind`` is ``"function"`` or ``"class"``. ``None`` means the block could
    not be isolated; the caller falls back to the enclosing file.
    """
    block = extract_definition_untruncated(content, kind, name)
    if block is None:
        return None
    if len(block) > MAX_DEFINITION_CHARS:
        block = block[:MAX_DEFINITION_CHARS] + "\n... (truncated)"
    return block


def extract_definition_untruncated(content: str, kind: str, name: str) -> str | None:
    """The whole definition block, however long.

    The reviewer's copy is bounded by ``MAX_DEFINITION_CHARS``; a hash taken
    over a definition must cover all of it, or two definitions that differ
    only past the cut would hash the same.
    """
    if not content or not name:
        return None
    span = definition_line_span(content, kind, name)
    if span is None:
        return None
    start, end = span
    return "\n".join(content.splitlines()[start - 1:end])


def definition_line_span(content: str, kind: str, name: str) -> tuple[int, int] | None:
    """1-based inclusive ``(start, end)`` line span of ``name``, or ``None``.

    ``kind`` is ``"function"`` or ``"class"``. A dotted ``Class.method`` name
    resolves to the method defined inside that class, so a method is not
    confused with a same-named function elsewhere in the file. Python is cut
    by ``ast``; other languages by the line heuristic the reviewer's copy
    already uses.
    """
    if not content or not name:
        return None
    parsed, span = _python_span(content, kind, name)
    if parsed:
        # The source is Python and the ast is authoritative: a name it does
        # not define is absent, and the line heuristic must not find a
        # look-alike that the parser did not.
        return span
    return _line_span_by_lines(content, kind, name.rsplit(".", 1)[-1])


def _python_span(content: str, kind: str, name: str) -> tuple[bool, tuple[int, int] | None]:
    """``(parsed, span)``: whether the source parsed as Python, and the span."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return False, None
    if kind == "function":
        wanted = (ast.FunctionDef, ast.AsyncFunctionDef)
    else:
        wanted = (ast.ClassDef,)
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


def _extract_python(content: str, kind: str, name: str) -> str | None:
    _, span = _python_span(content, kind, name)
    if span is None:
        return None
    start, end = span
    return "\n".join(content.splitlines()[start - 1:end])


def _extract_by_lines(content: str, kind: str, name: str) -> str | None:
    span = _line_span_by_lines(content, kind, name)
    if span is None:
        return None
    start, end = span
    return "\n".join(content.splitlines()[start - 1:end])


def _line_span_by_lines(content: str, kind: str, name: str) -> tuple[int, int] | None:
    escaped = re.escape(name)
    patterns = _FUNCTION_LINE_PATTERNS if kind == "function" else _CLASS_LINE_PATTERNS
    lines = content.splitlines()
    for idx, line in enumerate(lines):
        for template in patterns:
            if re.search(template.format(name=escaped), line):
                block = _block_from(lines, idx)
                return idx + 1, idx + len(block.split("\n"))
    return None


def _block_from(lines: list[str], start: int) -> str:
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
