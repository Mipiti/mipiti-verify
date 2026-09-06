"""Isolate a named definition block from a source file.

The semantic tier judges the *body* of a symbol whose existence the structural
tier has already established. Handing the reviewer the whole file makes it
locate the symbol before judging it, which is a task it was never asked to do
and can fail at. This module cuts out just the definition so the reviewer's
only question is whether the body proves the stated aspect of the control.

The work is done by ``languages.definitions.locate``: Python by ``ast``, other
languages by tree-sitter when the optional ``ast`` extra is installed, HDL by
a keyword-pair scanner, and anything else by a brace / indentation block
starting at the definition line. These wrappers keep the older call shape.
"""

from __future__ import annotations

from typing import Optional

from .languages.definitions import Located, block_from, locate

# Keep the isolated block comfortably inside the reviewer's context budget.
MAX_DEFINITION_CHARS = 16000


def extract_definition(content: str, kind: str, name: str, *, language: str = "") -> str | None:
    """Return the definition block of ``name`` in ``content`` or ``None``.

    ``kind`` is ``"function"``, ``"class"``, ``"method"`` or an HDL kind.
    ``None`` means the block could not be isolated; the caller falls back
    to the enclosing file.
    """
    block = extract_definition_untruncated(content, kind, name, language=language)
    if block is None:
        return None
    if len(block) > MAX_DEFINITION_CHARS:
        block = block[:MAX_DEFINITION_CHARS] + "\n... (truncated)"
    return block


def extract_definition_untruncated(content: str, kind: str, name: str, *,
                                   language: str = "") -> str | None:
    """The whole definition block, however long.

    The reviewer's copy is bounded by ``MAX_DEFINITION_CHARS``; a hash taken
    over a definition must cover all of it, or two definitions that differ
    only past the cut would hash the same.
    """
    found = locate_definition(content, kind, name, language=language)
    return found.text if found is not None else None


def definition_line_span(content: str, kind: str, name: str, *,
                         language: str = "") -> tuple[int, int] | None:
    """1-based inclusive ``(start, end)`` line span of ``name``, or ``None``.

    A dotted ``Class.method`` name resolves to the method defined inside that
    class, so a method is not confused with a same-named function elsewhere
    in the file.
    """
    found = locate_definition(content, kind, name, language=language)
    return (found.start_line, found.end_line) if found is not None else None


def locate_definition(content: str, kind: str, name: str, *,
                      language: str = "") -> Optional[Located]:
    """``Located`` (span, text, scope, parser) for ``name``, or ``None``."""
    if not content or not name:
        return None
    return locate(content, kind, name, language=language)


def _extract_python(content: str, kind: str, name: str) -> str | None:
    return extract_definition_untruncated(content, kind, name, language="python")


def _extract_by_lines(content: str, kind: str, name: str) -> str | None:
    from .languages.definitions import _lines, _lines_locate

    found = _lines_locate(_lines(content), kind, name)
    return found.text if found is not None else None


def _block_from(lines: list[str], start: int) -> str:
    return block_from(lines, start)
