"""Source mutation for hardware description languages.

Verilog / SystemVerilog: a ``module`` becomes a stub with the same header
whose outputs are driven to ``x``; a ``function`` or ``task`` body becomes
``$fatal``; a labelled ``always`` / ``initial`` block, a ``property``, a
``sequence`` or a labelled assertion is removed. VHDL: an ``architecture``
body is emptied (outputs undriven), a labelled ``process`` is removed, a
``function`` / ``procedure`` body becomes ``assert false ... severity
failure``.

Every rewrite is keyword-pair based over a comment- and string-masked copy
of the source, so offsets map back to the original text and nothing inside
a comment or string literal is ever matched. What cannot be delimited
raises ``DisableError`` with the reason.
"""

from __future__ import annotations

import re
from typing import Optional

from ._common import DISABLED_MESSAGE, DisableError, Mechanism

VERILOG_FATAL = f'$fatal(1, "{DISABLED_MESSAGE}");'
VHDL_FAIL = f'assert false report "{DISABLED_MESSAGE}" severity failure;'

_V_DIRECTIONS = ("input", "output", "inout", "ref")
_V_NET_WORDS = {"reg", "wire", "logic", "bit", "signed", "unsigned", "var", "tri",
                "tri0", "tri1", "wand", "wor", "integer", "int", "byte", "shortint",
                "longint", "real", "time", "supply0", "supply1", "const"}


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------

def _mask(content: str, line_comment: str, block: bool) -> str:
    """``content`` with comments and string literals replaced by spaces of
    the same length (newlines kept), so searches never match inside them."""
    out = []
    i, n = 0, len(content)
    while i < n:
        if content.startswith(line_comment, i):
            j = content.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if block and content.startswith("/*", i):
            j = content.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", content[i:j]))
            i = j
            continue
        if content[i] == '"':
            j = i + 1
            while j < n and content[j] != '"' and content[j] != "\n":
                j += 2 if content[j] == "\\" and not block is False else 1
            j = min(j + 1, n)
            out.append('"' + " " * max(0, j - i - 2) + ('"' if j - i >= 2 else ""))
            i = j
            continue
        out.append(content[i])
        i += 1
    return "".join(out)


def mask_verilog(content: str) -> str:
    return _mask(content, "//", True)


def mask_vhdl(content: str) -> str:
    return _mask(content, "--", False)


# ---------------------------------------------------------------------------
# Verilog / SystemVerilog
# ---------------------------------------------------------------------------

def _match_paren(masked: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(masked)):
        c = masked[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _find_keyword_end(masked: str, start: int, open_kw: str, close_kw: str) -> int:
    """Index just past the ``close_kw`` matching the ``open_kw`` at
    ``start``; nesting of the same pair is honoured."""
    pattern = re.compile(rf"\b({re.escape(open_kw)}|{re.escape(close_kw)})\b")
    depth = 0
    for m in pattern.finditer(masked, start):
        if m.group(1) == open_kw:
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.end()
    return -1


def _block_end(masked: str, begin_idx: int) -> int:
    """Index just past the ``end`` matching the ``begin`` at ``begin_idx``
    (``fork``/``join`` nest the same way)."""
    pattern = re.compile(r"\b(begin|end|fork|join(?:_any|_none)?)\b")
    depth = 0
    for m in pattern.finditer(masked, begin_idx):
        word = m.group(1)
        if word in ("begin", "fork"):
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.end()
    return -1


def _statement_end(masked: str, start: int) -> int:
    """Index just past the ``;`` that ends the statement starting at
    ``start``; parentheses and begin/end action blocks are stepped over."""
    depth_paren = 0
    depth_block = 0
    i = start
    n = len(masked)
    word = re.compile(r"\b(begin|end|fork|join(?:_any|_none)?)\b")
    while i < n:
        c = masked[i]
        if c == "(":
            depth_paren += 1
        elif c == ")":
            depth_paren -= 1
        elif c == ";" and depth_paren == 0 and depth_block == 0:
            return i + 1
        elif c.isalpha():
            m = word.match(masked, i)
            if m:
                if m.group(1) in ("begin", "fork"):
                    depth_block += 1
                else:
                    depth_block -= 1
                    if depth_block == 0 and depth_paren == 0:
                        # An action block closes the statement without a ';'
                        # when nothing follows it on the statement.
                        j = m.end()
                        k = re.match(r"\s*:\s*\w+", masked[j:])
                        if k:
                            j += k.end()
                        rest = masked[j:j + 40].lstrip()
                        if not rest.startswith("else"):
                            return j
                i = m.end()
                continue
        i += 1
    return -1


def _trailing_label(masked: str, at: int) -> int:
    m = re.match(r"\s*:\s*\w+", masked[at:])
    return at + m.end() if m else at


def _line_bounds(content: str, start: int, end: int) -> tuple[int, int]:
    """Widen ``[start, end)`` to whole lines when the removed text is
    alone on them, so removal leaves no blank stub lines."""
    ls = content.rfind("\n", 0, start) + 1
    le = content.find("\n", end)
    le = len(content) if le < 0 else le + 1
    if content[ls:start].strip() == "" and content[end:le].strip() == "":
        return ls, le
    return start, end


def _remove(content: str, start: int, end: int) -> str:
    s, e = _line_bounds(content, start, end)
    return content[:s] + content[e:]


def _verilog_ports(header: str) -> list[tuple[str, str, str]]:
    """``(direction, net kind, name)`` per port of an ANSI header."""
    m = re.search(r"\(", header)
    if m is None:
        return []
    open_idx = m.start()
    # A parameter list comes first: `module m #(...) (...)`.
    hash_idx = header.find("#")
    if 0 <= hash_idx < open_idx:
        close = _match_paren(header, open_idx)
        open_idx = header.find("(", close + 1)
        if open_idx < 0:
            return []
    close = _match_paren(header, open_idx)
    if close < 0:
        raise DisableError("module port list does not close")
    body = header[open_idx + 1:close]
    chunks, depth, cur = [], 0, []
    for c in body:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            chunks.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    chunks.append("".join(cur))
    ports: list[tuple[str, str, str]] = []
    direction = ""
    net = ""
    for chunk in chunks:
        text = chunk.strip()
        if not text:
            continue
        text = re.sub(r"=.*$", "", text, flags=re.S).strip()
        words = re.findall(r"\[[^\]]*\]|[\w$]+", text)
        if not words:
            continue
        if words[0] in _V_DIRECTIONS:
            direction = words[0]
            net = ""
            words = words[1:]
        names = [w for w in words if not w.startswith("[")]
        kinds = [w for w in names if w in _V_NET_WORDS]
        if kinds:
            net = kinds[0]
        idents = [w for w in names if w not in _V_NET_WORDS]
        if not idents:
            continue
        ports.append((direction, net, idents[-1]))
    return ports


def _verilog_module(content: str, masked: str, name: str) -> str:
    m = re.search(rf"\bmodule\s+{re.escape(name)}\b", masked)
    if m is None:
        raise DisableError(f"module {name} is not defined in the file")
    semi = masked.find(";", m.end())
    if semi < 0:
        raise DisableError(f"the header of module {name} does not end")
    end = _find_keyword_end(masked, m.start(), "module", "endmodule")
    if end < 0:
        raise DisableError(f"module {name} has no endmodule")
    header = content[m.start():semi + 1]
    ports = _verilog_ports(masked[m.start():semi + 1])
    if not any(d for d, _, _ in ports):
        raise DisableError(
            f"module {name} declares its ports in the non-ANSI style; only "
            f"an ANSI header can be stubbed")
    lines = [header]
    for direction, net, port in ports:
        if direction != "output":
            continue
        if net in ("reg", "logic", "bit", "integer", "int", "byte", "shortint", "longint", "var"):
            lines.append(f"  initial {port} = 'bx;")
        else:
            lines.append(f"  assign {port} = 'bx;")
    lines.append("endmodule")
    return content[:m.start()] + "\n".join(lines) + content[end:]


def _verilog_routine(content: str, masked: str, kind: str, name: str) -> str:
    m = re.search(rf"\b{kind}\b[^;]*?\b{re.escape(name)}\b\s*[;(]", masked)
    if m is None:
        raise DisableError(f"{kind} {name} is not defined in the file")
    semi = masked.find(";", m.start())
    # An ANSI port list may run past the name; the header ends at the first
    # ';' after the closing parenthesis.
    paren = masked.find("(", m.start(), semi if semi > 0 else None)
    if paren >= 0:
        close = _match_paren(masked, paren)
        semi = masked.find(";", close)
    if semi < 0:
        raise DisableError(f"the header of {kind} {name} does not end")
    end = _find_keyword_end(masked, m.start(), kind, f"end{kind}")
    if end < 0:
        raise DisableError(f"{kind} {name} has no end{kind}")
    end_kw = masked.rfind(f"end{kind}", semi, end)
    body_start = semi + 1
    b = re.search(r"\bbegin\b", masked[body_start:end_kw])
    if b is not None:
        # Non-ANSI declarations sit between the header and 'begin'; keep them.
        body_start = body_start + b.start()
    return content[:body_start] + "\n  " + VERILOG_FATAL + "\n" + content[end_kw:]


def _verilog_labelled_block(content: str, masked: str, label: str) -> Optional[str]:
    m = re.search(rf"\bbegin\s*:\s*{re.escape(label)}\b", masked)
    if m is None:
        return None
    heads = list(re.finditer(r"\b(always(?:_ff|_comb|_latch)?|initial|final)\b", masked[:m.start()]))
    if not heads:
        raise DisableError(f"block {label} is not an always or initial block")
    head = heads[-1]
    end = _block_end(masked, m.start())
    if end < 0:
        raise DisableError(f"block {label} has no matching end")
    end = _trailing_label(masked, end)
    return _remove(content, head.start(), end)


def _verilog_property(content: str, masked: str, kind: str, name: str) -> Optional[str]:
    m = re.search(rf"\b{kind}\s+{re.escape(name)}\b", masked)
    if m is None:
        return None
    end = _find_keyword_end(masked, m.start(), kind, f"end{kind}")
    if end < 0:
        raise DisableError(f"{kind} {name} has no end{kind}")
    out = _remove(content, m.start(), end)
    # Every assertion that instantiates it goes too, or the file no longer
    # elaborates.
    masked2 = mask_verilog(out)
    pattern = re.compile(
        rf"(?:\b\w+\s*:\s*)?\b(?:assert|assume|cover|restrict)\s+(?:property|sequence)\s*\(\s*{re.escape(name)}\b")
    while True:
        m2 = pattern.search(masked2)
        if m2 is None:
            break
        stmt_end = _statement_end(masked2, m2.start())
        if stmt_end < 0:
            raise DisableError(f"an assertion of {name} does not end")
        out = _remove(out, m2.start(), stmt_end)
        masked2 = mask_verilog(out)
    return out


def _verilog_assert(content: str, masked: str, label: str) -> Optional[str]:
    m = re.search(rf"\b{re.escape(label)}\s*:\s*(?:assert|assume|cover|restrict)\b", masked)
    if m is None:
        return None
    end = _statement_end(masked, m.start())
    if end < 0:
        raise DisableError(f"assertion {label} does not end")
    return _remove(content, m.start(), end)


def mutate_verilog(content: str, mechanism: Mechanism) -> str:
    masked = mask_verilog(content)
    name = mechanism.name
    kind = mechanism.kind
    if kind == "module":
        return _verilog_module(content, masked, name)
    if kind in ("function", "task"):
        return _verilog_routine(content, masked, kind, name)
    if kind in ("always", "initial"):
        out = _verilog_labelled_block(content, masked, name)
        if out is None:
            raise DisableError(f"no labelled block {name} in the file")
        return out
    if kind in ("property", "sequence"):
        out = _verilog_property(content, masked, kind, name)
        if out is None:
            raise DisableError(f"{kind} {name} is not defined in the file")
        return out
    if kind == "assert":
        out = _verilog_assert(content, masked, name)
        if out is None:
            raise DisableError(f"no assertion labelled {name} in the file")
        return out
    if kind:
        raise DisableError(f"{kind} is not a Verilog construct this adapter can disable")
    # No kind given: the first construct of that name, most structural first.
    if re.search(rf"\bmodule\s+{re.escape(name)}\b", masked):
        return _verilog_module(content, masked, name)
    for routine in ("function", "task"):
        if re.search(rf"\b{routine}\b[^;]*?\b{re.escape(name)}\b\s*[;(]", masked):
            return _verilog_routine(content, masked, routine, name)
    for pkind in ("property", "sequence"):
        out = _verilog_property(content, masked, pkind, name)
        if out is not None:
            return out
    out = _verilog_labelled_block(content, masked, name)
    if out is not None:
        return out
    out = _verilog_assert(content, masked, name)
    if out is not None:
        return out
    raise DisableError(f"{name} names no module, function, task, property, sequence, labelled block or assertion in the file")


# ---------------------------------------------------------------------------
# VHDL
# ---------------------------------------------------------------------------

_VHDL_TOKEN = re.compile(r"[A-Za-z_]\w*|[^\w\s]", re.I)
_VHDL_SIMPLE_OPENERS = {"case", "loop", "block", "generate", "process", "record", "units",
                        "component", "architecture", "package", "configuration", "protected"}


def _vhdl_tokens(masked: str, start: int) -> list[tuple[str, int, int]]:
    return [(m.group(0).lower(), m.start(), m.end()) for m in _VHDL_TOKEN.finditer(masked, start)]


def _routine_has_body(tokens: list, i: int) -> bool:
    """Whether the function/procedure at ``tokens[i]`` is a body (an ``is``
    before the next ``;`` outside parentheses)."""
    depth = 0
    for word, _, _ in tokens[i + 1:]:
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
        elif depth == 0 and word == ";":
            return False
        elif depth == 0 and word == "is":
            return True
    return False


def _vhdl_walk(masked: str, start: int):
    """Yield ``(token, start, end, depth_after)`` from ``start``; depth
    counts every construct that an ``end`` closes."""
    tokens = _vhdl_tokens(masked, start)
    depth = 0
    i = 0
    while i < len(tokens):
        word, s, e = tokens[i]
        prev = tokens[i - 1][0] if i > 0 else ""
        if word == "end":
            depth -= 1
        elif word in ("function", "procedure"):
            if prev not in ("end",) and _routine_has_body(tokens, i):
                depth += 1
        elif word == "entity":
            if prev not in ("end",) and i + 2 < len(tokens) and tokens[i + 2][0] == "is":
                depth += 1
        elif word == "if":
            if prev != "end":
                # `if ... generate` is closed by `end generate`, counted there.
                j = i + 1
                is_generate = False
                while j < len(tokens) and tokens[j][0] not in ("then", ";"):
                    if tokens[j][0] == "generate":
                        is_generate = True
                        break
                    j += 1
                if not is_generate:
                    depth += 1
        elif word in _VHDL_SIMPLE_OPENERS:
            if prev not in ("end",) and not (word == "component" and prev == ":") \
                    and not (word == "process" and prev == "postponed" and i >= 2 and tokens[i - 2][0] == "end"):
                depth += 1
        yield word, s, e, depth
        i += 1


def _vhdl_construct_end(masked: str, start: int) -> tuple[int, int]:
    """``(end keyword start, index just past the closing ';')`` of the
    construct opening at ``start``."""
    end_at = -1
    for word, s, e, depth in _vhdl_walk(masked, start):
        if end_at >= 0:
            if word == ";":
                return end_at, e
            continue
        if word == "end" and depth == 0:
            end_at = s
    raise DisableError("construct does not close")


def _vhdl_own_begin(masked: str, start: int) -> int:
    """Offset of the ``begin`` that opens the statement part of the
    construct starting at ``start`` (nested bodies skipped)."""
    for word, s, e, depth in _vhdl_walk(masked, start):
        if word == "begin" and depth == 1:
            return s
        if depth <= 0 and word == "end":
            break
    raise DisableError("construct has no begin")


def _vhdl_architecture(content: str, masked: str, name: str) -> str:
    m = re.search(rf"\barchitecture\s+{re.escape(name)}\s+of\b", masked, re.I)
    if m is None:
        raise DisableError(f"architecture {name} is not defined in the file")
    begin = _vhdl_own_begin(masked, m.start())
    end_kw, _ = _vhdl_construct_end(masked, m.start())
    return content[:begin + len("begin")] + "\n" + content[end_kw:]


def _vhdl_process(content: str, masked: str, label: str) -> str:
    m = re.search(rf"\b{re.escape(label)}\s*:\s*(?:postponed\s+)?process\b", masked, re.I)
    if m is None:
        raise DisableError(f"no process labelled {label} in the file")
    proc = re.search(r"\bprocess\b", masked[m.start():], re.I)
    _, end = _vhdl_construct_end(masked, m.start() + proc.start())
    return _remove(content, m.start(), end)


def _vhdl_routine(content: str, masked: str, name: str) -> str:
    pattern = re.compile(rf"\b(?:(?:pure|impure)\s+)?(function|procedure)\s+(?:\"[^\"]*\"|{re.escape(name)})\b", re.I)
    for m in pattern.finditer(masked):
        head = m.start()
        tokens = _vhdl_tokens(masked, head)
        if not _routine_has_body(tokens, 0):
            continue
        begin = _vhdl_own_begin(masked, head)
        end_kw, _ = _vhdl_construct_end(masked, head)
        return content[:begin + len("begin")] + "\n    " + VHDL_FAIL + "\n  " + content[end_kw:]
    raise DisableError(f"no function or procedure body named {name} in the file")


def mutate_vhdl(content: str, mechanism: Mechanism) -> str:
    masked = mask_vhdl(content)
    name = mechanism.name
    kind = mechanism.kind
    if kind == "architecture":
        return _vhdl_architecture(content, masked, name)
    if kind == "process":
        return _vhdl_process(content, masked, name)
    if kind in ("function", "procedure"):
        return _vhdl_routine(content, masked, name)
    if kind == "entity":
        raise DisableError("an entity is disabled through its architecture; name the architecture")
    if kind:
        raise DisableError(f"{kind} is not a VHDL construct this adapter can disable")
    if re.search(rf"\barchitecture\s+{re.escape(name)}\s+of\b", masked, re.I):
        return _vhdl_architecture(content, masked, name)
    if re.search(rf"\b{re.escape(name)}\s*:\s*(?:postponed\s+)?process\b", masked, re.I):
        return _vhdl_process(content, masked, name)
    return _vhdl_routine(content, masked, name)
