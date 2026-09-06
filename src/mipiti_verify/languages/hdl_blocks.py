"""Keyword-pair block scanner for Verilog, SystemVerilog and VHDL.

Used when no parser is installed. Hardware description languages close
every construct with a keyword (``endmodule``, ``endfunction``, ``end
process``), so a scanner that pairs openers with closers -- skipping
comments and strings, and nesting ``begin … end`` -- recovers the exact
extent of a named block without a grammar. A name is read at the block's
own start (``module alu``, ``seq_logic: process``, ``begin : init``), so a
match is exact: it cannot confuse two same-named blocks, because the block
it returns is the one whose header carried the name.

The scanner is deliberately conservative. Anything it cannot pair is
ignored rather than guessed, and a construct it does not know does not
disturb the pairing of the ones it does.
"""

from __future__ import annotations

import bisect
import re
from typing import NamedTuple, Optional


class Block(NamedTuple):
    kind: str          # module, function, task, class, property, sequence, always,
                       # initial, assert, block, entity, architecture, process,
                       # procedure, package, interface, program
    name: str          # label / declared name, "" when unnamed
    owner: str         # ``Packet`` for ``function void Packet::print``, else ""
    start_line: int    # 1-based inclusive
    end_line: int


class _Token(NamedTuple):
    text: str
    line: int
    is_word: bool


# ---------------------------------------------------------------------------
# Tokenising
# ---------------------------------------------------------------------------

def _strip(text: str, line_comment: str) -> str:
    """Blank out comments and strings, keeping every newline in place."""
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if text.startswith(line_comment, i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\" and line_comment == "//":
                    j += 1
                if j < n and text[j] == "\n":
                    break
                j += 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif ch == "'" and line_comment == "--" and i + 2 < n and text[i + 2] == "'" \
                and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_)]")):
            # A VHDL character literal; ``clk'event`` is an attribute, kept.
            out.append("   ")
            i += 3
        else:
            out.append(ch)
            i += 1
    return "".join(out)


_VERILOG_TOKEN = re.compile(r"\\\S+|`[A-Za-z_]\w*|[A-Za-z_$][A-Za-z0-9_$]*|\d[\w.]*|[();:#,@=.\[\]{}]")
_VHDL_TOKEN = re.compile(r"\\[^\\]*\\|[A-Za-z][A-Za-z0-9_]*|\d[\w.]*|[();:,.=<>]")


def _tokens(text: str, pattern: re.Pattern) -> list[_Token]:
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    tokens = []
    for m in pattern.finditer(text):
        raw = m.group(0)
        if raw.startswith("`"):
            continue
        line = bisect.bisect_right(starts, m.start())
        is_word = raw[0].isalpha() or raw[0] in "_$\\"
        tokens.append(_Token(raw, line, is_word))
    return tokens


# ---------------------------------------------------------------------------
# Verilog / SystemVerilog
# ---------------------------------------------------------------------------

_V_PAIRS = {
    "module": "endmodule", "macromodule": "endmodule",
    "interface": "endinterface", "package": "endpackage", "program": "endprogram",
    "function": "endfunction", "task": "endtask", "class": "endclass",
    "property": "endproperty", "sequence": "endsequence",
    "checker": "endchecker", "clocking": "endclocking", "covergroup": "endgroup",
    "case": "endcase", "casex": "endcase", "casez": "endcase", "randcase": "endcase",
    "generate": "endgenerate", "begin": "end", "fork": "join",
    "config": "endconfig", "primitive": "endprimitive", "specify": "endspecify",
    "table": "endtable",
}
_V_CLOSERS = {v: k for k, v in _V_PAIRS.items()}
_V_CLOSERS.update({"join_any": "fork", "join_none": "fork"})
_V_PROCEDURAL = {"always", "always_ff", "always_comb", "always_latch", "initial", "final"}
_V_ASSERTIONS = {"assert", "assume", "cover", "expect", "restrict"}
_V_KIND = {"macromodule": "module", "casex": "case", "casez": "case", "randcase": "case",
           "always_ff": "always", "always_comb": "always", "always_latch": "always",
           "final": "initial"}
_V_SKIP_PREV = {"extern", "pure", "import", "typedef", "virtual_interface"}


class _Frame:
    __slots__ = ("kind", "name", "owner", "start", "closer", "awaiting", "owns_begin")

    def __init__(self, kind, name, owner, start, closer, awaiting=False):
        self.kind = kind
        self.name = name
        self.owner = owner
        self.start = start
        self.closer = closer
        self.awaiting = awaiting    # procedural / assertion frame waiting for its statement
        self.owns_begin = False


def _v_declared_name(tokens: list[_Token], i: int) -> tuple[str, str]:
    """``(name, owner)`` declared by the keyword at ``tokens[i]``."""
    kw = tokens[i].text
    if kw in ("function", "task"):
        # The identifier just before ``(`` or ``;`` closes the header; a
        # ``Owner::name`` header names an out-of-body class method.
        last, owner = "", ""
        j = i + 1
        while j < len(tokens):
            t = tokens[j]
            if t.text in ("(", ";"):
                break
            if t.is_word:
                if (j + 2 < len(tokens) and tokens[j + 1].text == ":" and tokens[j + 2].text == ":"):
                    owner = t.text
                    j += 3
                    continue
                last = t.text
            j += 1
        return last, owner
    j = i + 1
    while j < len(tokens):
        t = tokens[j]
        if t.is_word and t.text not in ("automatic", "static", "virtual", "interface"):
            return t.text, ""
        if not t.is_word:
            break
        j += 1
    return "", ""


def scan_verilog(text: str) -> list[Block]:
    stripped = _strip(text, "//")
    tokens = _tokens(stripped, _VERILOG_TOKEN)
    blocks: list[Block] = []
    stack: list[_Frame] = []
    paren = 0
    i = 0
    n = len(tokens)

    def prev(k: int) -> str:
        return tokens[i - k].text if i - k >= 0 else ""

    def close(frame: _Frame, end_line: int) -> None:
        blocks.append(Block(frame.kind, frame.name, frame.owner, frame.start, end_line))

    while i < n:
        tok = tokens[i]
        word = tok.text
        if word == "(":
            paren += 1
        elif word == ")":
            paren = max(0, paren - 1)
        elif word == ";" and paren == 0:
            while stack and stack[-1].awaiting and not stack[-1].owns_begin:
                frame = stack.pop()
                close(frame, tok.line)
            if stack and stack[-1].kind == "assert" and stack[-1].owns_begin and \
                    not (i + 1 < n and tokens[i + 1].text == "else"):
                close(stack.pop(), tok.line)
        elif tok.is_word:
            lower = word
            if lower in _V_PAIRS and not (lower in ("function", "task", "class") and prev(1) in _V_SKIP_PREV) \
                    and not (lower == "property" and prev(1) in _V_ASSERTIONS) \
                    and not (lower == "interface" and i + 1 < n and tokens[i + 1].text == "class") \
                    and not (lower == "interface" and prev(1) == "virtual") \
                    and not (lower == "sequence" and prev(1) in _V_ASSERTIONS) \
                    and not (lower == "class" and prev(1) == "typedef"):
                if lower == "begin":
                    label = ""
                    if i + 2 < n and tokens[i + 1].text == ":" and tokens[i + 2].is_word:
                        label = tokens[i + 2].text
                    frame = _Frame("block", label, "", tok.line, "end")
                    if stack and stack[-1].awaiting and not stack[-1].owns_begin:
                        stack[-1].owns_begin = True
                        if not stack[-1].name:
                            stack[-1].name = label
                    stack.append(frame)
                else:
                    name, owner = _v_declared_name(tokens, i)
                    stack.append(_Frame(_V_KIND.get(lower, lower), name, owner, tok.line, _V_PAIRS[lower]))
            elif lower in _V_CLOSERS:
                opener = _V_CLOSERS[lower]
                # Pop to the nearest frame this closer pairs with; frames
                # left open above it were never closed and are dropped.
                idx = next((k for k in range(len(stack) - 1, -1, -1)
                            if stack[k].closer == _V_PAIRS[opener]), None)
                if idx is not None:
                    while len(stack) > idx + 1:
                        stack.pop()
                    frame = stack.pop()
                    close(frame, tok.line)
                    if lower == "end" and stack and stack[-1].owns_begin:
                        owner_frame = stack[-1]
                        if owner_frame.kind == "assert" and i + 1 < n and tokens[i + 1].text == "else":
                            owner_frame.owns_begin = False
                            owner_frame.awaiting = True
                        else:
                            close(stack.pop(), tok.line)
                    # ``end : label`` may follow; nothing to do with it.
            elif lower in _V_PROCEDURAL:
                label, start = "", tok.line
                if prev(1) == ":" and i - 2 >= 0 and tokens[i - 2].is_word:
                    label = tokens[i - 2].text
                    start = tokens[i - 2].line
                stack.append(_Frame(_V_KIND.get(lower, lower), label, "", start, "", awaiting=True))
            elif lower in _V_ASSERTIONS and prev(1) == ":" and i - 2 >= 0 and tokens[i - 2].is_word \
                    and paren == 0:
                stack.append(_Frame("assert", tokens[i - 2].text, "", tokens[i - 2].line, "", awaiting=True))
        i += 1
    blocks.sort(key=lambda b: (b.start_line, -b.end_line))
    return blocks


# ---------------------------------------------------------------------------
# VHDL
# ---------------------------------------------------------------------------

_VHDL_NAMED = {"entity", "architecture", "package", "component", "configuration",
               "context", "function", "procedure", "process", "block", "record",
               "units", "protected", "loop", "generate", "if", "case"}


def _vhdl_lookahead(tokens: list[_Token], i: int, stops: set[str]) -> str:
    depth = 0
    for j in range(i + 1, len(tokens)):
        t = tokens[j].text
        low = t.lower()
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
        elif depth == 0 and (low in stops or t == ";"):
            return low if low in stops else ";"
    return ""


def scan_vhdl(text: str) -> list[Block]:
    stripped = _strip(text, "--")
    tokens = _tokens(stripped, _VHDL_TOKEN)
    blocks: list[Block] = []
    stack: list[_Frame] = []
    i = 0
    n = len(tokens)

    def low(k: int) -> str:
        return tokens[k].text.lower() if 0 <= k < n else ""

    def next_name(k: int) -> str:
        j = k + 1
        while j < n and low(j) in ("body", "impure", "pure"):
            j += 1
        return tokens[j].text if j < n and tokens[j].is_word else ""

    def label_before(k: int) -> tuple[str, int]:
        if low(k - 1) == ":" and k - 2 >= 0 and tokens[k - 2].is_word:
            return tokens[k - 2].text, tokens[k - 2].line
        return "", tokens[k].line

    while i < n:
        tok = tokens[i]
        word = tok.text.lower()
        if not tok.is_word:
            i += 1
            continue
        after_end = low(i - 1) == "end" or (low(i - 2) == "end" and low(i - 1) in ("package", "protected"))
        if word == "end":
            # ``end [keyword] [name];`` -- everything up to the ``;`` belongs
            # to the closer, whether or not a frame is open to receive it.
            j = i + 1
            while j < n and tokens[j].text != ";":
                j += 1
            if stack:
                frame = stack.pop()
                blocks.append(Block(frame.kind, frame.name, frame.owner, frame.start,
                                    tokens[j].line if j < n else tok.line))
            i = j
        elif after_end:
            pass
        elif word == "entity":
            if low(i - 1) not in (":", "use") and _vhdl_lookahead(tokens, i, {"is"}) == "is":
                stack.append(_Frame("entity", next_name(i), "", tok.line, "end"))
        elif word == "architecture":
            stack.append(_Frame("architecture", next_name(i), "", tok.line, "end"))
        elif word == "process":
            label, start = label_before(i)
            if low(i - 1) == "postponed":
                label, start = label_before(i - 1)
            stack.append(_Frame("process", label, "", start, "end"))
        elif word in ("function", "procedure"):
            if _vhdl_lookahead(tokens, i, {"is"}) == "is":
                stack.append(_Frame(word, next_name(i), "", tok.line, "end"))
        elif word in ("package", "component", "configuration", "record", "units"):
            if word == "package" and low(i + 1) == "body":
                stack.append(_Frame("package", next_name(i), "", tok.line, "end"))
            elif word == "configuration" and low(i - 1) == "for":
                pass
            else:
                stack.append(_Frame(word, next_name(i) if word != "record" and word != "units" else "",
                                    "", tok.line, "end"))
        elif word == "context":
            if _vhdl_lookahead(tokens, i, {"is"}) == "is":
                stack.append(_Frame("context", next_name(i), "", tok.line, "end"))
        elif word == "protected":
            stack.append(_Frame("protected", "", "", tok.line, "end"))
        elif word == "block":
            label, start = label_before(i)
            stack.append(_Frame("block", label, "", start, "end"))
        elif word == "if":
            if _vhdl_lookahead(tokens, i, {"then", "generate"}) == "then":
                stack.append(_Frame("if", "", "", tok.line, "end"))
        elif word == "case":
            if _vhdl_lookahead(tokens, i, {"is", "generate"}) == "is":
                stack.append(_Frame("case", "", "", tok.line, "end"))
        elif word == "loop":
            stack.append(_Frame("loop", "", "", tok.line, "end"))
        elif word == "generate":
            stack.append(_Frame("generate", "", "", tok.line, "end"))
        i += 1
    blocks.sort(key=lambda b: (b.start_line, -b.end_line))
    return blocks


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def scan(text: str, language: str) -> list[Block]:
    if language == "vhdl":
        return scan_vhdl(text)
    if language in ("verilog", "systemverilog"):
        return scan_verilog(text)
    return scan_verilog(text) + scan_vhdl(text)


# ``function`` means any subprogram (a test is nominated by name, not by the
# keyword that declared it); ``task`` and ``procedure`` stay strict.
_KIND_ALIASES = {
    "function": ("function", "task", "procedure"),
    "method": ("function", "task"),
}


def locate_block(text: str, kind: str, name: str, language: str = ""):
    """The block of ``kind`` named ``name``, as a ``Located``, or ``None``.

    ``Owner.leaf`` names a function or task inside (or declared out of body
    for) the class ``Owner``. VHDL names compare case-insensitively.
    """
    from .definitions import PARSER_KEYWORD, SCOPE_SYMBOL, Located, _lines, _slice

    if not text or not name:
        return None
    lines = _lines(text)
    normalised = "\n".join(lines)
    blocks = scan(normalised, language)
    owner, _, leaf = name.rpartition(".")
    kinds = _KIND_ALIASES.get(kind, (kind,))
    fold = language == "vhdl"

    def same(a: str, b: str) -> bool:
        return a.lower() == b.lower() if fold else a == b

    hit: Optional[Block] = None
    if owner:
        holders = [b for b in blocks if b.kind == "class" and same(b.name, owner)]
        for holder in holders:
            hit = next((b for b in blocks if b.kind in kinds and same(b.name, leaf)
                        and holder.start_line <= b.start_line and b.end_line <= holder.end_line
                        and b is not holder), None)
            if hit is not None:
                break
        if hit is None:
            hit = next((b for b in blocks if b.kind in kinds and same(b.name, leaf)
                        and same(b.owner, owner)), None)
    else:
        hit = next((b for b in blocks if b.kind in kinds and b.name and same(b.name, leaf)), None)
    if hit is None:
        return None
    return Located(hit.start_line, hit.end_line, _slice(lines, hit.start_line, hit.end_line),
                   SCOPE_SYMBOL, PARSER_KEYWORD)
