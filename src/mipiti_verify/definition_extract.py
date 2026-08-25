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
    if not content or not name:
        return None
    block = _extract_python(content, kind, name)
    if block is None:
        block = _extract_by_lines(content, kind, name)
    if block is None:
        return None
    if len(block) > MAX_DEFINITION_CHARS:
        block = block[:MAX_DEFINITION_CHARS] + "\n... (truncated)"
    return block


def _extract_python(content: str, kind: str, name: str) -> str | None:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return None
    if kind == "function":
        wanted = (ast.FunctionDef, ast.AsyncFunctionDef)
    else:
        wanted = (ast.ClassDef,)
    for node in ast.walk(tree):
        if isinstance(node, wanted) and node.name == name:
            start = node.lineno
            for deco in getattr(node, "decorator_list", ()):
                start = min(start, deco.lineno)
            end = getattr(node, "end_lineno", None)
            if end is None:
                return None
            lines = content.splitlines()
            return "\n".join(lines[start - 1:end])
    return None


def _extract_by_lines(content: str, kind: str, name: str) -> str | None:
    escaped = re.escape(name)
    patterns = _FUNCTION_LINE_PATTERNS if kind == "function" else _CLASS_LINE_PATTERNS
    lines = content.splitlines()
    for idx, line in enumerate(lines):
        for template in patterns:
            if re.search(template.format(name=escaped), line):
                return _block_from(lines, idx)
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
