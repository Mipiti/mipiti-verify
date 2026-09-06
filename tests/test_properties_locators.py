"""Property-based checks over definition location.

The locators read whatever a repository holds: source in a dozen languages,
generated files, binary that happens to carry a source extension. Whatever
the input, ``locate`` answers or declines, and an answer is a span of the
file whose text is the file's own lines and carries the name it was asked
for. ``hash_of`` is a hash of content, not of line endings or trailing
blanks. The HDL keyword scanner pairs what it can and drops the rest, and
what it emits is properly nested.
"""

from __future__ import annotations

import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mipiti_verify.languages import definitions as D
from mipiti_verify.languages import hdl_blocks

LANGUAGES = sorted(set(D._EXTENSIONS.values())) + [""]
KINDS = ("function", "class", "method") + D.HDL_KINDS
NAMES = ("f", "m", "X", "guard", "Owner.f", "alu", "seq", "rtl", "p", "new")

# Fragments that look like the languages' own structure, so the generated
# text reaches the parsers' and scanners' interesting paths, not only their
# rejections.
FRAGMENTS = (
    "def f(x):\n", "    return x\n", "class X:\n", "    def f(self): pass\n", "@dec\n",
    "function f() {", "func f() {", "fn f() {", "func (o Owner) f() {", "}", "{", "}\n",
    "public class X {", "void f() {", "struct X {", "impl X {", "type X struct {",
    "module m(a, y);", "module m #(parameter W = 8) (input a, output y);", "endmodule",
    "input a;", "output reg y;", "always @(posedge clk) begin : seq", "end", "begin", "begin : blk",
    "function automatic int f(input int v);", "endfunction", "task t;", "endtask",
    "property p;", "endproperty", "a_ok: assert property (p);", "class X;", "endclass",
    "function void X::f();", "initial begin", "fork", "join", "generate", "endgenerate",
    "entity alu is", "end entity;", "architecture rtl of alu is", "begin", "end architecture rtl;",
    "seq : process (clk)", "end process seq;", "function f(v : integer) return integer is",
    "end function f;", "procedure p is", "end procedure;", "if x then", "end if;",
    "-- comment begin end\n", "// comment { module\n", "/* end */", '"string { end"', "'x'",
    "\n", "\n\n", " ", "\t", ";", "(", ")", "[", "]", "<", ">", ":", ".", "::", "\r\n",
)

fragments = st.lists(st.sampled_from(FRAGMENTS), max_size=40).map("".join)
free_text = st.text(max_size=400)
binaryish = st.binary(max_size=300).map(lambda b: b.decode("latin-1"))
with_nul = st.tuples(free_text, st.integers(0, 3)).map(lambda t: t[0] + "\0" * t[1] + t[0][::-1])
long_lines = st.tuples(
    st.text(alphabet=string.printable, min_size=1, max_size=20), st.integers(200, 900),
).map(lambda t: (t[0] * t[1]) + "\n" + (t[0] * t[1]))
unbalanced = st.lists(st.sampled_from(("{", "}", "begin", "end", "(", ")", "endmodule", "module m;",
                                      "end process;", "end;", "\n", "x")), max_size=60).map(" ".join)

content = st.one_of(fragments, free_text, binaryish, with_nul, long_lines, unbalanced)

FAST = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@FAST
@given(content=content, kind=st.sampled_from(KINDS), name=st.sampled_from(NAMES),
       language=st.sampled_from(LANGUAGES))
def test_locate_never_raises_and_a_span_is_the_files_own_lines(content, kind, name, language):
    found = D.locate(content, kind, name, language=language)
    if found is None:
        return
    lines = D._lines(content)
    assert 1 <= found.start_line <= found.end_line <= len(lines)
    assert found.text == "\n".join(lines[found.start_line - 1:found.end_line])
    leaf = name.rpartition(".")[2]
    if language == "vhdl":
        assert leaf.lower() in found.text.lower()
    else:
        assert leaf in found.text
    assert found.scope in (D.SCOPE_SYMBOL, D.SCOPE_BLOCK, D.SCOPE_FILE)
    assert found.parser in (D.PARSER_AST, D.PARSER_TREE_SITTER, D.PARSER_KEYWORD, D.PARSER_LINES)


@FAST
@given(text=st.text(max_size=300), pad=st.sampled_from(("", " ", "\t", " \t ")))
def test_hash_of_ignores_line_endings_and_trailing_whitespace(text, pad):
    base = D.hash_of(text)
    crlf = text.replace("\r\n", "\n").replace("\n", "\r\n")
    assert D.hash_of(crlf) == base
    padded = "\n".join(line + pad for line in text.replace("\r\n", "\n").split("\n"))
    assert D.hash_of(padded) == base
    assert D.hash_of(text) == base  # idempotent: hashing is a pure function of content


@FAST
@given(text=st.text(alphabet=string.ascii_letters + string.digits + " \n", min_size=1, max_size=200),
       data=st.data())
def test_hash_of_changes_when_a_non_whitespace_byte_changes(text, data):
    positions = [i for i, ch in enumerate(text) if not ch.isspace()]
    if not positions:
        return
    i = data.draw(st.sampled_from(positions))
    replacement = data.draw(st.sampled_from([c for c in string.ascii_letters + string.digits if c != text[i]]))
    changed = text[:i] + replacement + text[i + 1:]
    assert D.hash_of(changed) != D.hash_of(text)


def _properly_nested(blocks) -> bool:
    """Blocks either nest or are disjoint; a crossing pair would mean the
    scanner's depth accounting went inconsistent."""
    open_stack: list = []
    for b in sorted(blocks, key=lambda b: (b.start_line, -b.end_line)):
        while open_stack and open_stack[-1].end_line < b.start_line:
            open_stack.pop()
        if open_stack and b.end_line > open_stack[-1].end_line:
            return False
        open_stack.append(b)
    return True


@FAST
@given(content=content, language=st.sampled_from(("verilog", "systemverilog", "vhdl", "")))
def test_hdl_scanner_never_raises_and_its_blocks_nest(content, language):
    blocks = hdl_blocks.scan(content, language)
    n = len(D._lines(content))
    for b in blocks:
        assert 1 <= b.start_line <= b.end_line <= max(n, 1)
        assert isinstance(b.kind, str) and isinstance(b.name, str)
    if language:
        assert _properly_nested(blocks)
    for kind in KINDS:
        for name in NAMES:
            hdl_blocks.locate_block(content, kind, name, language)
