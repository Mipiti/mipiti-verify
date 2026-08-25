"""Code structure verifiers: function_exists, class_exists, decorator_present, function_calls, import_present."""

from __future__ import annotations

import ast

import re2
from pathlib import Path

from . import PathTraversalError, VerifierResult, register, resolve_file_content, safe_regex_search


# --- Definition-shape building blocks (FunctionExistsVerifier) ---
#
# The predicate these compose is "a definition of this name is written
# here", not "this name appears here". A name followed by an open paren
# is a *call* shape, and it occurs in prose, comments, docstrings and
# string literals as readily as in code, so it cannot stand for a
# definition on its own. Two properties separate a definition from a
# mention, and every general pattern below requires both:
#
#   1. The definition starts its own line, preceded only by indentation,
#      modifiers and a return type. A mention sits inside a sentence, a
#      quoted string, or a condition such as ``if (name(x)) {``.
#   2. The parameter list is followed by a body or a declaration
#      terminator: an opening brace, a complete one-line body, or a
#      semicolon closing the line. Prose carries on with ordinary words
#      and ends with a full stop.
#
# RE2 is the engine (linear time, no lookaround, no backreferences), so
# these are expressed with negated character classes rather than
# assertions, and each class stops at the delimiters that bound a
# signature. Notably a parameter list may not run past its own closing
# paren, which is what stops a scan started in prose from borrowing a
# brace further down the file.

# A parameter list: one level of nesting for default values, casts and
# function-pointer types. Newlines are allowed, so a signature that
# wraps across lines still matches; '(' and ')' are excluded from the
# unnested branch so the scan can never run past its own closing paren.
_PARAMS = r"\((?:[^;{}()]|\([^;{}()]*\))*\)"

# What may sit between the closing paren and the body: a return type,
# generics, a throws clause, cv-qualifiers. Never crosses a line.
_TAIL = r"[^;{}\n]*"

# One modifier or return-type token preceding the name on the same line.
_MODS = r"(?:[\w$@.<>,:\[\]*&?~-]+[ \t]+)"

# Pointer sigils and a ``Class::`` / ``obj.`` qualifier before the name.
_QUAL = r"[*&]{0,4}(?:[\w$]+(?:::|\.))*"

# The parameter list of a function bound to a name (see the last entry
# in ``_PATTERNS``). Looser than ``_PARAMS`` because it must admit
# destructuring and default values -- ``({ retries = 3 })`` -- yet it
# still cannot run past its own closing paren, and it is only ever
# reached after a line that already reads ``<name> = ``.
_BOUND_PARAMS = r"\((?:[^()]|\([^()]*\))*\)"

# End of line, allowing a trailing comment.
_EOL = r"[ \t]*(?://[^\n]*|/\*[^\n]*|#[^\n]*)?$"

# Start of line, allowing indentation.
_HEAD = r"(?m)^[ \t]*"


# --- Type-declaration building blocks (ClassExistsVerifier) ---
#
# Same predicate, same two properties, applied to type declarations: a
# declaration starts its own line and is followed by something that
# opens or terminates it — a brace, a Python colon, or a semicolon.
# ``class AuthService`` on its own is an English noun phrase as much as
# it is code, which is why none of the patterns below stop at the name.

# The declaration keywords. ``@interface`` is a Java annotation type;
# ``enum class`` / ``enum struct`` are C++ scoped enumerations.
_TYPE_KW = r"(?:class|struct|@?interface|enum(?:[ \t]+(?:class|struct))?)"

# Modifiers that may precede the keyword. An explicit, bounded set, and
# deliberately not ``\w+``: an arbitrary word in front of the keyword is
# also the shape of an English sentence ("the abstract class Session is
# deprecated"), which is exactly what these patterns exist to exclude.
_TYPE_MODS = (
    r"(?:(?:export[ \t]+default|export|declare|default|public|private|"
    r"protected|internal|abstract|final|sealed|static|partial|open|data|"
    r"case|inner|typedef|extern|unsafe|pub\((?:crate|super|self|"
    r"in[^()\n]*)\)|pub)[ \t]+){0,6}"
)

# Generic parameters attached directly to the name: ``<T>``, ``<K, V>``,
# ``<Vec<u8>>``, and the bracket form Go and PEP 695 use.
_GENERICS = r"(?:<[^;{}<>\n]*(?:<[^;{}<>\n]*>[^;{}<>\n]*)*>|\[[^\[\]\n]*\])?"

# What introduces a base list: ``extends`` / ``implements`` / ``where``,
# or one of ``:`` ``<`` ``(``. Another explicit set, for the same reason
# the modifiers are one -- without it, "class Session returns {ok} on
# success" reads as a declaration with a one-line body. The keyword
# branch may start on the next line, which is where a formatter puts a
# long clause.
_INHERIT_HEAD = r"(?:(?:[ \t]*\n)?[ \t]*(?:extends|implements|where)\b|[ \t]*[:<(])"

# The clause itself, confined to one line.
_INHERIT = r"(?:" + _INHERIT_HEAD + r"[^;{}\n]*)?"

# The clause allowed to wrap, as a long ``extends`` list does. Only a
# clause that actually began may continue, and every continuation line
# has to be non-empty, so a scan that started in running text cannot
# cross a paragraph break to reach a brace further down.
_INHERIT_ML = r"(?:" + _INHERIT_HEAD + r"[^;{}\n]*(?:\n[ \t]*[^\s;{}][^;{}\n]*){0,3})?"

# A Python base-class list. Structured rather than "anything up to the
# colon", so it may wrap across lines the way a formatter writes it
# while still refusing a sentence that happens to end in a colon. Two
# levels of nesting, which is what a base built by a call needs.
_PY_BASES = r"(?:\((?:[^();{}]|\((?:[^();{}]|\([^();{}]*\))*\))*\))?"


# --- The function-definition pattern set ---------------------------------
#
# Held at module level because three types need it. ``function_exists``
# asks whether a definition is present; ``decorator_present`` and
# ``function_calls`` both have to find a named definition before they can
# say anything about what decorates it or what it calls, and a weaker
# notion of "found" there reopens the same hole in a different type.
#
# The keyword-led entries are exact for the languages that name their
# definitions. The bodies below them carry the definition-shape
# requirement described above, and are kept separate from their ``_HEAD``
# anchor so a caller that needs an unanchored copy — a decorator and its
# target written on one line — can compose one.

_FUNC_KEYWORD_PATTERNS = [
    r"\bdef\s+{name}\s*\(",            # Python
    r"\bfunction\s+{name}\s*\(",       # JavaScript/PHP
    r"\bfn\s+{name}\s*\(",             # Rust
    r"\bfunc\s+{name}\s*\(",           # Swift/Go
]

# There is no Java/C# entry keyed on a modifier keyword alone. A
# modifier, a word and the name followed by a paren is also the shape of
# an English sentence ("the static wrapper verify_token (see auth) is
# deprecated"), so it cannot stand for a definition. Those languages are
# covered by the bodies below, which read the modifiers as leading tokens
# and still require a body or a declaration terminator.
_FUNC_DEF_BODIES = [
    # Go method with a receiver: the receiver sits between `func` and the
    # name, so the `func {name}` entry above cannot see it.
    r"func\s*\([^()\n]*\)\s*{name}\s*\(",
    # Body opening at end of line, brace on the signature line or on its
    # own (Allman): C, C++, Java, C#, Go, Kotlin, Swift, and JS/TS
    # class-method and object-literal shorthand.
    _MODS + r"{0,8}" + _QUAL + r"{name}[ \t]*" + _PARAMS + _TAIL + r"(?:\n[ \t]*)?\{" + _EOL,
    # Complete one-line body. The tail must be whitespace only: an
    # opening brace that is neither at end of line nor preceded directly
    # by the parameter list is a brace in running text.
    _MODS + r"{0,8}" + _QUAL + r"{name}[ \t]*" + _PARAMS + r"[ \t]*\{[^\n]*\}",
    # Declaration closing the line: a C/C++/Objective-C prototype, a Java
    # interface method, a C# expression-bodied member. A leading return
    # type is required, which is what keeps a bare `name(arg);` call
    # statement from reading as a prototype.
    _MODS + r"{1,8}" + _QUAL + r"{name}[ \t]*" + _PARAMS + _TAIL + r"(?:;|=>)" + _EOL,
    # Declaration whose return type is annotated after the parameter list
    # instead of before the name (TypeScript interfaces).
    _QUAL + r"{name}[ \t]*" + _PARAMS + r"[ \t]*:" + _TAIL + r";" + _EOL,
    # The name is bound to a function value rather than declared: arrow
    # functions and class-property arrows in JS/TS, `var f = function`,
    # Go `var f = func`, Python `f = lambda`. The right-hand side must
    # itself begin a function, so a name bound to the result of a call
    # that happens to take a callback (`const xs = ys.map(y => y.z)`) is
    # not a definition.
    r"(?:(?:export|public|private|protected|static|final|readonly|const|let|var)[ \t]+){0,4}"
    + _QUAL
    + r"{name}\b[ \t]*(?::[^=\n]{0,120})?=[ \t]*(?:async[ \t]+)?"
    + r"(?:function\b|func\b|lambda\b|[A-Za-z_$][\w$]*[ \t]*=>|"
    + _BOUND_PARAMS
    + r"[ \t]*(?::[^=\n]{0,120})?=>)",
]

# Ordered; the first match wins.
_FUNCTION_DEFINITION_PATTERNS = _FUNC_KEYWORD_PATTERNS + [
    _HEAD + body for body in _FUNC_DEF_BODIES
]

# Modifiers that may precede a keyword-led definition on its own line.
# A fixed set, never ``\w+``: an arbitrary word in front of the keyword
# is the shape of a sentence, which is the whole point of anchoring.
_DEF_LEAD = (
    r"(?:(?:export[ \t]+default|export|default|async|public|private|"
    r"protected|internal|static|final|open|suspend|inline|const|let|var|"
    r"pub\((?:crate|super|self)\)|pub)[ \t]+){0,4}"
)

# The same set for a caller whose *body* is about to be read, with the
# keyword entries anchored to the start of a line as well. A keyword and
# a name and a paren is decisive enough for "this function exists
# somewhere in this file", including inside a one-line object literal.
# It is not decisive enough to hand a body to a search: "we call function
# handleAuth(req) on every request" is a sentence, and the lines
# following it are prose, not statements.
_CALLER_DEFINITION_PATTERNS = [
    _HEAD + _DEF_LEAD + pattern for pattern in _FUNC_KEYWORD_PATTERNS
] + [_HEAD + body for body in _FUNC_DEF_BODIES]


def _is_python_source(source: str) -> bool:
    """Whether the resolved source is a Python file.

    Selection is by extension, not by trying the parser on any content:
    a parse that happens to succeed on something that is not Python
    would make the AST path authoritative over a language it cannot
    read, and its answer is terminal. ``resolve_file_content`` refuses a
    platform ``target`` and labels a missing ``file`` param
    ``<no source>``, so an unnamed subject never reaches here and keeps
    the language-agnostic regex path.

    A ``.pyi`` stub is Python and parses as Python, and this is the one
    notion of "Python source" the module has: the types that decide a
    Python source with the parser all read it from here, and a second,
    subtly different notion in one of them is how they drift apart.
    """
    return str(source).endswith((".py", ".pyi"))


# --- Blanking comments and string literals --------------------------------
#
# The pattern paths read text that has no parser behind it, so a comment
# and a string literal are indistinguishable from code to them. Both are
# places where a name is *mentioned* rather than used, and both are where
# the false passes this module exists to prevent come from: a callee
# named in a ``// TODO``, an import written inside a block comment.
#
# The blanker replaces the *interior* of comments and string literals
# with spaces and leaves everything else — delimiters, newlines, column
# positions, file length — exactly where it was, so offsets, line numbers
# and the indentation the body slice reads are all preserved.
#
# It is a scanner, not a parser, and it is language-agnostic by
# necessity: one function serves every language the fallback paths cover.
# What that costs is stated at each rule below, and the failure mode is
# chosen: blanking only ever removes text, so a rule that fires where it
# should not can hide a real occurrence (a miss) but cannot manufacture
# one (a false pass).

# ``#`` opens a comment in Python, Ruby, shell and YAML, and opens a
# preprocessor or compiler directive in C, C++, Objective-C and C#. A
# directive is code and must survive — ``#include <openssl/evp.h>`` is an
# import, and blanking it would break the very check that reads it.
_DIRECTIVE_KEYWORDS = frozenset(
    {
        "include", "import", "define", "undef", "if", "ifdef", "ifndef",
        "elif", "else", "endif", "pragma", "error", "warning", "line",
        "region", "endregion", "using", "nullable", "load", "r",
    }
)


def _blank_code_noise(content: str, source: str, strings: bool = True) -> str:
    """Blank comment and string-literal interiors, preserving positions.

    ``strings=False`` blanks comments only, for a caller whose subject
    lives inside a string literal — an import path is written as
    ``require('x')``, so blanking string interiors would erase the thing
    being looked for.

    String literals are *recognised* either way, and only the blanking is
    conditional: a comment marker inside a string is not a comment, and a
    scanner that did not know it was inside one would take the ``/*`` in
    a docstring for the start of a block comment and blank everything up
    to the next ``*/`` — most of the file, in a file that has no such
    thing.
    """
    chars = list(content)
    n = len(content)
    # Rust writes lifetimes with a single quote (``&'a str``), so a
    # single quote there is not a delimiter and pairing it with the next
    # one would blank live code. Rust char literals hold one character,
    # which is too small to hold a call or an import path, so nothing is
    # lost by leaving them alone.
    single_quotes_delimit = not str(source).endswith(".rs")

    def blank(start: int, end: int) -> None:
        for k in range(max(start, 0), min(end, n)):
            if chars[k] != "\n":
                chars[k] = " "

    def line_end(start: int) -> int:
        idx = content.find("\n", start)
        return n if idx == -1 else idx

    i = 0
    while i < n:
        ch = content[i]
        pair = content[i : i + 2]
        triple = content[i : i + 3]

        if pair == "//":
            end = line_end(i)
            blank(i + 2, end)
            i = end
            continue

        if pair == "/*":
            end = content.find("*/", i + 2)
            end = n if end == -1 else end
            blank(i + 2, end)
            i = min(end + 2, n)
            continue

        if ch == "#" and (i == 0 or content[i - 1] in " \t\n\r"):
            # A JS/TS private member (``this.#decrypt(x)``) is reached
            # through a dot, so it never satisfies the preceding-space
            # test; a directive is excluded by keyword. The keyword has
            # to sit directly against the ``#``, which is how a
            # directive is written and is not how a comment is: ``#if``
            # is a directive, ``# if we ever need this`` is a comment.
            k = i + 1
            while k < n and (content[k].isalnum() or content[k] == "_"):
                k += 1
            word = content[i + 1 : k].lower()
            if word not in _DIRECTIVE_KEYWORDS and content[i + 1 : i + 2] != "!":
                end = line_end(i)
                blank(i + 1, end)
                i = end
                continue
            i = k
            continue

        if triple in ('"""', "'''"):
            end = content.find(triple, i + 3)
            end = n if end == -1 else end
            if strings:
                blank(i + 3, end)
            i = min(end + 3, n)
            continue

        if ch == '"' or ch == "`" or (ch == "'" and single_quotes_delimit):
            i = _blank_string(content, i, ch, blank if strings else None, n)
            continue

        i += 1

    return "".join(chars)


def _blank_string(content: str, start: int, quote: str, blank, n: int) -> int:
    """Skip one string literal, blanking its interior if asked.

    ``blank`` is None when the caller keeps string contents, in which
    case the literal is only stepped over — which the scanner has to do
    either way, so that a comment marker inside a string is not read as
    a comment.

    A quote that does not close on the same line is not treated as a
    delimiter at all — an apostrophe in prose, a stray quote in a
    language this scanner does not know. Backtick strings may span
    lines, because that is what a template literal is for, and the
    interpolations inside one are left intact: ``${verify(x)}`` is code,
    and blanking it would hide a real call.
    """
    segment = start + 1
    j = start + 1
    while j < n:
        c = content[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n" and quote != "`":
            return start + 1
        if quote == "`" and c == "$" and content[j + 1 : j + 2] == "{":
            if blank is not None:
                blank(segment, j)
            depth = 0
            k = j + 1
            while k < n:
                if content[k] == "{":
                    depth += 1
                elif content[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            j = min(k + 1, n)
            segment = j
            continue
        if c == quote:
            if blank is not None:
                blank(segment, j)
            return j + 1
        j += 1
    # Unterminated at end of file: nothing to pair it with.
    return start + 1


@register("function_exists")
class FunctionExistsVerifier:
    """Check that a function/method is DEFINED in a file.

    Tier 1 is the only tier that decides whether the symbol exists: the
    tier-2 rubric is told the symbol is in front of it and judges the
    implementation, not the presence. So a match here has to be a
    definition, and a name quoted in prose, a comment, a docstring or a
    string literal must not satisfy it.

    Python is decided by ``ast``; every other language, and Python that
    will not parse, by the patterns below.
    """

    # Ordered; the first match wins. The keyword-led entries are exact
    # for the languages that name their definitions, and the general
    # entries below them carry the definition-shape requirement
    # described above for the languages that do not. Shared with
    # ``decorator_present`` and ``function_calls``, which both have to
    # locate a definition before they can judge anything about it.
    _PATTERNS = _FUNCTION_DEFINITION_PATTERNS

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_file_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        if _is_python_source(source):
            verdict = self._verify_python(content, params["name"], source)
            if verdict is not None:
                return verdict
            # Unparseable Python falls through to the regex scan below.

        name = re2.escape(params["name"])

        for pattern_template in self._PATTERNS:
            # str.replace, not str.format: these patterns contain literal
            # braces and bounded repeats, which format() would treat as
            # fields and which doubling every brace would make unreadable.
            pattern = pattern_template.replace("{name}", name)
            match = re2.search(pattern, content)
            if match:
                line_no = content[:match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Function '{params['name']}' defined at line {line_no}",
                )

        return VerifierResult(
            passed=False,
            details=f"No definition of function '{params['name']}' found in {source}",
        )

    @staticmethod
    def _verify_python(content: str, name: str, source: str) -> VerifierResult | None:
        """AST analysis. Returns a result, or None if the source will not
        parse (so the caller can fall back to the regex scan).

        For Python the regex patterns approximate a question the parser
        answers outright: a ``def`` / ``async def`` node with this name
        is either in the tree or it is not, and a comment, a docstring
        or a string literal cannot produce one. The walk covers the
        whole tree, so a method, a nested function or a conditionally
        defined one is found at whatever depth it sits, which is the
        file-wide reach the regex scan has.
        """
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError):
            # ValueError is what content with a null byte raises and
            # RecursionError what a literal nested past the interpreter's
            # limit raises. All three say the same thing here: this
            # content will not parse, so the regex scan decides.
            return None

        lines = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                lines.append(node.lineno)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                node.value, ast.Lambda
            ):
                # A name bound to a lambda is a definition, the same way
                # the last regex pattern treats a name bound to a
                # function value.
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if (isinstance(target, ast.Name) and target.id == name) or (
                        isinstance(target, ast.Attribute) and target.attr == name
                    ):
                        lines.append(node.lineno)

        if lines:
            # ``ast.walk`` is breadth-first, so take the earliest line to
            # report the first definition in the file as the regex does.
            return VerifierResult(
                passed=True,
                details=f"Function '{name}' defined at line {min(lines)}",
            )

        return VerifierResult(
            passed=False,
            details=f"No definition of function '{name}' found in {source}",
        )


@register("class_exists")
class ClassExistsVerifier:
    """Check that a class/struct/interface is DECLARED in a file.

    Tier 1 is the only tier that decides whether the type exists: the
    tier-2 rubric is told the type's existence is settled and judges
    what the declaration contains, not whether it is there. So a match
    here has to be a declaration, and a type named in prose, in a
    comment, in a docstring or inside a string literal must not satisfy
    it.

    Python is decided by ``ast``; every other language, and Python that
    will not parse, by the patterns below.
    """

    # Ordered; the first match wins. Every entry carries the
    # declaration-shape requirement described above the building
    # blocks: the declaration starts its own line, preceded only by
    # indentation and modifiers drawn from a fixed set, and is followed
    # by something that opens or terminates it.
    _PATTERNS = [
        # Body opening at end of line, brace on the declaration line or
        # on its own (Allman): C, C++, Java, C#, TS/JS, Rust, Kotlin,
        # Scala, Swift, PHP. A long base list may wrap in between.
        _HEAD + _TYPE_MODS + _TYPE_KW + r"[ \t]+{name}\b" + _GENERICS + _INHERIT_ML
        + r"[ \t]*(?:\n[ \t]*)?\{" + _EOL,
        # Python. The base list is structured rather than "anything up
        # to a colon", so a sentence ending in a colon cannot stand in
        # for one, and it has to sit against the name the way the
        # language writes it rather than after a space, which is where a
        # sentence puts a parenthetical. A one-line body is admitted
        # only as ``pass`` or ``...``: anything else after the colon is
        # indistinguishable from a sentence continuing.
        _HEAD + r"class[ \t]+{name}\b" + _GENERICS + _PY_BASES
        + r"[ \t]*:(?:[ \t]+(?:pass|\.\.\.))?" + _EOL,
        # Declaration closing the line: a C forward declaration, a C
        # ``typedef``, a Rust unit or tuple struct. The tail is narrow
        # here — generics, a tuple body, one trailing identifier — so
        # that a sentence which happens to end in a semicolon does not
        # read as a declaration.
        _HEAD + _TYPE_MODS + _TYPE_KW + r"[ \t]+{name}\b" + _GENERICS
        + r"(?:\([^;{}\n]*\))?(?:[ \t]+[\w$]+)?[ \t]*;" + _EOL,
        # Complete one-line body. The brace must follow the name, its
        # generics and at most one base-list clause: a brace reached
        # across ordinary words is a brace in running text.
        _HEAD + _TYPE_MODS + _TYPE_KW + r"[ \t]+{name}\b" + _GENERICS + _INHERIT
        + r"[ \t]*\{[^\n]*\}",
        # Go. ``type`` is optional so a member of a ``type (...)`` block
        # is found too, and the literal ``struct`` / ``interface``
        # keyword has to follow the name.
        _HEAD + r"(?:type[ \t]+)?{name}\b" + _GENERICS + r"[ \t]*(?:struct|interface)\b[ \t]*"
        + r"(?:\{" + _EOL + r"|\{[^\n]*\})",
    ]

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_file_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        if _is_python_source(source):
            verdict = self._verify_python(content, params["name"], source)
            if verdict is not None:
                return verdict
            # Unparseable Python falls through to the regex scan below.

        name = re2.escape(params["name"])

        for pattern_template in self._PATTERNS:
            # str.replace, not str.format: these patterns contain literal
            # braces and bounded repeats, which format() would treat as
            # fields and which doubling every brace would make unreadable.
            pattern = pattern_template.replace("{name}", name)
            match = re2.search(pattern, content)
            if match:
                line_no = content[:match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Class '{params['name']}' found at line {line_no}",
                )

        return VerifierResult(passed=False, details=f"Class '{params['name']}' not found in {source}")

    @staticmethod
    def _verify_python(content: str, name: str, source: str) -> VerifierResult | None:
        """AST analysis. Returns a result, or None if the source will not
        parse (so the caller can fall back to the regex scan).

        For Python the regex patterns approximate a question the parser
        answers outright: a ``ClassDef`` node with this name is either in
        the tree or it is not, and a comment, a docstring or a string
        literal cannot produce one. The walk covers the whole tree, so a
        nested class is found at whatever depth it sits, which is the
        file-wide reach the regex scan has.
        """
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError):
            # ValueError is what content with a null byte raises and
            # RecursionError what a literal nested past the interpreter's
            # limit raises. All three say the same thing here: this
            # content will not parse, so the regex scan decides.
            return None

        lines = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == name
        ]
        if lines:
            # ``ast.walk`` is breadth-first, so take the earliest line to
            # report the first declaration in the file as the regex does.
            return VerifierResult(
                passed=True,
                details=f"Class '{name}' found at line {min(lines)}",
            )

        return VerifierResult(passed=False, details=f"Class '{name}' not found in {source}")


# --- Decorator-application building blocks (DecoratorPresentVerifier) ---
#
# The predicate is "this decorator is applied to this function", which is
# two claims: the decorator is written, and the definition it sits
# against is the named one. A usage example in a docstring or a fenced
# block in a README shows both, arranged exactly as the real thing, which
# is why the pattern path is not what decides a Python source.
#
# What the patterns add over "the name appears, then the name appears" is
# the definition shape: the target has to be a definition of the function
# by the same standard ``function_exists`` applies, and only annotations,
# comments and blank lines may sit between the two.

# A decorator's argument list. Three levels of nesting — a decorator
# argument built by a call whose own argument is a call is ordinary in
# every framework that uses decorators — and allowed to wrap across
# lines the way a formatter writes a long one, which the previous
# ``[^\n]*`` tail handled only by accident, when the arguments happened
# to fit on the decorator's own line.
_DEC_ARGS = r"(?:\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?"

# The decorator itself, starting its own line: ``@name``, ``@name(...)``,
# ``@a.name`` and ``@a.name(...)``.
_DEC_HEAD = _HEAD + r"@{decorator}\b(?:\.[\w.$]+)?" + _DEC_ARGS

# Between a decorator on its own line and the definition it applies to,
# only further annotations, comments and blank lines may sit. A statement
# in between means the decorator is not applied to that definition.
#
# Another annotation is admitted as a whole annotation — a name and its
# argument list — rather than as a line beginning with ``@``, so a
# decorator stack in which one entry wraps its arguments across lines
# (which is most stacks of any size) does not break the chain.
_DEC_OTHER = r"[ \t]*@[\w$]+(?:\.[\w$]+)*" + _DEC_ARGS + _EOL + r"\n"
_DEC_FILLER = r"[ \t]*(?://[^\n]*|#[^\n]*)?\n"
_DEC_GAP = r"\n(?:" + _DEC_OTHER + r"|" + _DEC_FILLER + r")*[ \t]*"

# The Python target, spelled out rather than taken from the keyword set
# so that ``async def`` is reachable directly after the gap.
_PY_DEF_TARGET = r"(?:async[ \t]+)?def[ \t]+{name}[ \t]*\("


def _annotated_definition_patterns(python: bool) -> list[str]:
    """The decorator-application pattern set for one kind of source.

    ``@x`` followed by ``def f(...)`` is Python. A Python source is
    decided by the parser, so the only way that spelling reaches these
    patterns is in a file that is not Python — a README, a design note, a
    ticket — where it is a quotation of code rather than code, and the
    file has no decorated ``f`` of its own. The ``def`` target is
    therefore offered only for a Python source, which by the time it gets
    here means Python that would not parse. Every other language's
    definition shapes stay available to every source.
    """
    targets = [_PY_DEF_TARGET] if python else []
    targets += [p for p in _FUNC_KEYWORD_PATTERNS if not p.startswith(r"\bdef")]
    targets += _FUNC_DEF_BODIES

    patterns = []
    for target in targets:
        # The decorator on its own line, the definition below it.
        patterns.append(_DEC_HEAD + _EOL + _DEC_GAP + target)
        # Both on one line, which is how Java and Kotlin often write an
        # annotation: ``@Override public void handle() {``.
        patterns.append(_DEC_HEAD + r"[ \t]+" + target)
    return patterns


_ANNOTATED_PY = _annotated_definition_patterns(python=True)
_ANNOTATED_NON_PY = _annotated_definition_patterns(python=False)


def _decorator_path(expr: ast.expr) -> str | None:
    """The dotted path a decorator expression names, or None.

    ``@x`` → ``x``; ``@x(...)`` → ``x``; ``@a.b.x`` → ``a.b.x``;
    ``@a.x(...)`` → ``a.x``. Anything else — a subscript, a call on a
    call, a lambda — has no name to compare and returns None.
    """
    if isinstance(expr, ast.Call):
        expr = expr.func
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
        return ".".join(reversed(parts))
    return None


def _decorator_matches(expr: ast.expr, decorator: str) -> bool:
    """Whether a decorator expression is the named decorator.

    The name matches the decorator's full dotted path or its final
    segment: ``require_auth`` is satisfied by ``@require_auth``,
    ``@require_auth(scope="admin")`` and ``@auth.require_auth``, since the
    leading path is how the decorator was reached rather than part of its
    identity, and an assertion may reasonably spell either. The match is
    on whole segments, so ``require_auth`` is not satisfied by
    ``@require_auth_v2`` — which the previous pattern accepted, its tail
    being free to run on through the rest of the identifier.
    """
    path = _decorator_path(expr)
    if path is None:
        return False
    return path == decorator or path.rsplit(".", 1)[-1] == decorator


@register("decorator_present")
class DecoratorPresentVerifier:
    """Check that a decorator is APPLIED to a function in a file.

    Tier 1 is the only tier that decides whether the decorator is
    applied: the tier-2 rubric asks whether the decorator provides
    meaningful security enforcement, which presupposes it is there, and
    the runner reports ``skipped`` for tier 2 when no provider is
    configured. So a match here has to be an application, and a usage
    example in a docstring, a comment or a fenced block must not satisfy
    it.

    Python is decided by ``ast``; every other language, and Python that
    will not parse, by the patterns above.
    """

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_file_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        is_python = _is_python_source(source)
        if is_python:
            verdict = self._verify_python(
                content, params["decorator"], params["function"], source
            )
            if verdict is not None:
                return verdict
            # Unparseable Python falls through to the pattern scan below.

        scrubbed = _blank_code_noise(content, source)
        decorator = re2.escape(params["decorator"])
        function = re2.escape(params["function"])

        for template in _ANNOTATED_PY if is_python else _ANNOTATED_NON_PY:
            # str.replace, not str.format: these patterns contain literal
            # braces and bounded repeats, which format() would treat as
            # fields and which doubling every brace would make unreadable.
            pattern = template.replace("{decorator}", decorator).replace("{name}", function)
            match = re2.search(pattern, scrubbed)
            if match:
                line_no = scrubbed[: match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=(
                        f"Decorator @{params['decorator']} found on "
                        f"{params['function']} at line {line_no}"
                    ),
                )

        return VerifierResult(
            passed=False,
            details=(
                f"Decorator @{params['decorator']} not found on "
                f"{params['function']} in {source}"
            ),
        )

    @staticmethod
    def _verify_python(
        content: str, decorator: str, function: str, source: str
    ) -> VerifierResult | None:
        """AST analysis. Returns a result, or None if the source will not
        parse (so the caller can fall back to the pattern scan).

        The parser holds the decorator list against the definition it
        belongs to, so "applied to" is read off the tree rather than
        inferred from two things being written near each other. The walk
        covers the whole tree, so a decorated method or a decorated
        nested function is found at whatever depth it sits.
        """
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError):
            # ValueError is what content with a null byte raises and
            # RecursionError what a literal nested past the interpreter's
            # limit raises. All three say the same thing here: this
            # content will not parse, so the pattern scan decides.
            return None

        defined = False
        lines = []
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function
            ):
                defined = True
                for expr in node.decorator_list:
                    if _decorator_matches(expr, decorator):
                        lines.append(getattr(expr, "lineno", node.lineno))

        if lines:
            return VerifierResult(
                passed=True,
                details=f"Decorator @{decorator} found on {function} at line {min(lines)}",
            )

        if not defined:
            return VerifierResult(
                passed=False,
                details=(
                    f"Decorator @{decorator} not found on {function} in {source}: "
                    f"no definition of '{function}'"
                ),
            )

        return VerifierResult(
            passed=False,
            details=f"Decorator @{decorator} not found on {function} in {source}",
        )


@register("function_calls")
class FunctionCallsVerifier:
    """Check that a function calls another function.

    Python sources are analysed with the ``ast`` module: every definition
    of the caller's name in the tree is located — at module level, as a
    method, or nested inside another function — and its body walked for a
    call to the callee. This handles multi-line signatures, decorators,
    methods, and nested calls — cases a line-indentation body slice
    mishandles, because the closing line of a wrapped signature sits at
    the ``def``-level indent and would otherwise be mistaken for the end
    of the body. Bare calls (``callee(...)``) and attribute calls
    (``obj.callee(...)``) both count.

    Other languages fall back to a pattern scan of the caller's body.
    Two things bound what that scan will accept. The caller has to be
    found by the definition shape ``function_exists`` requires, not by a
    keyword and a name, so a caller "found" in a sentence cannot lend its
    body to the search. And the search runs over a copy of the source
    with comment and string-literal interiors blanked, so a callee named
    in a comment about work still to do, or quoted in a log message, is
    not a call.
    """

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_file_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        caller = params["caller"]
        callee = params["callee"]

        if _is_python_source(source):
            verdict = self._verify_python(content, caller, callee)
            if verdict is not None:
                return verdict
            # Unparseable Python falls through to the regex scan below.

        return self._verify_regex(content, caller, callee, source)

    @staticmethod
    def _verify_python(content: str, caller: str, callee: str) -> VerifierResult | None:
        """AST analysis. Returns a result, or None if the source will not
        parse (so the caller can fall back to the regex scan)."""
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError):
            # ValueError is what content with a null byte raises and
            # RecursionError what a literal nested past the interpreter's
            # limit raises. All three say the same thing here: this
            # content will not parse, so the regex scan decides.
            return None

        found_caller = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == caller:
                found_caller = True
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        func = sub.func
                        name = getattr(func, "id", None) or getattr(func, "attr", None)
                        if name == callee:
                            return VerifierResult(
                                passed=True,
                                details=f"Function '{caller}' calls '{callee}'",
                            )
        if not found_caller:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' not found")
        return VerifierResult(passed=False, details=f"Function '{caller}' does not call '{callee}'")

    @staticmethod
    def _verify_regex(content: str, caller: str, callee: str, source: str) -> VerifierResult:
        """Regex fallback for non-Python languages.

        Runs over a copy of the source whose comment and string-literal
        interiors have been blanked, so neither the caller's definition
        nor the call can be found in text that is not code. Blanking
        preserves every position and every newline, so the indentation
        the body slice reads is the file's own.
        """
        scrubbed = _blank_code_noise(content, source)

        # The caller has to be DEFINED, by the definition shape
        # ``function_exists`` requires and with every entry anchored to
        # the start of a line: a caller matched in prose hands the search
        # whatever text follows it as if it were a body.
        escaped = re2.escape(caller)
        caller_match = None
        for template in _CALLER_DEFINITION_PATTERNS:
            caller_match = re2.search(template.replace("{name}", escaped), scrubbed)
            if caller_match:
                break
        if not caller_match:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' not found")

        # Skip past the (possibly multi-line) signature by balancing the
        # parentheses from the first '(' after the caller's name. The
        # search starts at the name rather than at the start of the
        # match, because a Go method's match starts at ``func`` and the
        # first paren after that opens the receiver, not the parameters.
        name_idx = scrubbed.find(caller, caller_match.start())
        if name_idx == -1:
            name_idx = caller_match.start()
        open_idx = scrubbed.find("(", name_idx + len(caller))
        if open_idx == -1:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' has no signature")
        depth = 0
        i = open_idx
        while i < len(scrubbed):
            ch = scrubbed[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        # Body begins after the line that closes the signature.
        nl = scrubbed.find("\n", i)
        if nl == -1:
            return VerifierResult(passed=False, details=f"Caller function '{caller}' has no body")

        # Collect body lines until a non-comment line dedents below the
        # first body line's indentation.
        body_lines = []
        ref_indent = None
        for line in scrubbed[nl + 1:].split("\n"):
            stripped = line.lstrip()
            if not stripped:
                body_lines.append(line)
                continue
            indent = len(line) - len(stripped)
            if ref_indent is None:
                ref_indent = indent
            elif indent < ref_indent and not stripped.startswith("#") and not stripped.startswith("//"):
                break
            body_lines.append(line)

        body = "\n".join(body_lines)
        callee_pattern = rf"\b{re2.escape(callee)}\s*\("
        if re2.search(callee_pattern, body):
            return VerifierResult(
                passed=True,
                details=f"Function '{caller}' calls '{callee}'",
            )

        return VerifierResult(passed=False, details=f"Function '{caller}' does not call '{callee}'")


# --- Import-statement building blocks (ImportPresentVerifier) ---
#
# ``import``, ``from`` and ``use`` are ordinary English words, and a
# pattern that asks for one of them followed by the module name asks for
# a shape prose produces: a README sentence about what a project uses, a
# comment saying where something was copied from, a comment forbidding an
# import, a docstring naming where data comes from.
#
# What separates an import statement from a sentence containing the same
# words is that the statement occupies its own line and ends where the
# statement ends — at a semicolon, at end of line, or at a quoted module
# path. Every pattern below is anchored at the start of a line and
# terminated, or is a call whose argument is the quoted module path.
# None of them will match a module name simply because it is mentioned.
#
# Modifier prefixes are drawn from fixed keyword sets, never ``\w+``: an
# arbitrary word in front of a keyword is the shape of an English
# sentence, which is what these patterns exist to exclude.

# What may follow the module name and still be the same module path:
# dotted segments (``import a.b`` satisfies ``a``) and Java's wildcard.
# The leading ``\b`` is what stops ``os`` matching ``import ostrich``.
_MODULE_TAIL = r"\b(?:\.[\w$]+)*(?:\.\*)?"

# Names already listed before the one being looked for, in a
# comma-separated import list, and the rest of the list after it.
_IMPORT_LIST_HEAD = r"(?:[\w.$]+(?:[ \t]+as[ \t]+[\w.$]+)?[ \t]*,[ \t]*)*"
_IMPORT_LIST_TAIL = r"(?:[ \t]*,[^\n]*)?"

# A relative-import prefix: ``from .x import y``, ``from .. import z``.
_REL_DOTS = r"\.{0,8}"

_IMPORT_PATTERNS = [
    # Python, Kotlin, Java, Swift, Dart, Haskell, Elixir: an import
    # statement occupying its own line and ending there.
    _HEAD + r"import[ \t]+(?:static[ \t]+)?" + _IMPORT_LIST_HEAD
    + r"{module}" + _MODULE_TAIL + r"(?:[ \t]+as[ \t]+[\w.$]+)?"
    + _IMPORT_LIST_TAIL + r"[ \t]*;?" + _EOL,
    # Python ``from`` import, where the module is the package imported
    # from. The ``import`` keyword has to follow on the same line, which
    # is what a sentence beginning "from cryptography ..." does not do.
    _HEAD + r"from[ \t]+" + _REL_DOTS + r"{module}" + _MODULE_TAIL + r"[ \t]+import\b",
    # Python ``from`` import, where the module is one of the names being
    # imported: ``from jose import jwt``.
    _HEAD + r"from[ \t]+" + _REL_DOTS + r"[\w.$]*[ \t]+import[ \t]+" + _IMPORT_LIST_HEAD
    + r"{module}\b(?:[ \t]+as[ \t]+[\w.$]+)?" + _IMPORT_LIST_TAIL + r"[ \t]*;?" + _EOL,
    # The same, with the parenthesised list a formatter writes when it
    # wraps. Bounded by the list's own closing paren.
    _HEAD + r"from[ \t]+" + _REL_DOTS + r"[\w.$]*[ \t]+import[ \t]*\([^()]*\b{module}\b",
    # JS/TS ES module: ``import x from 'M'``, ``import * as x from "M"``,
    # ``export { x } from 'M'``.
    _HEAD + r"(?:import|export)\b[^;\n]*\bfrom[ \t]*['\"]{module}['\"]",
    # The same with the brace list wrapped across lines, which is where
    # a formatter puts a list of any length. A default binding may
    # precede the list and an ``as`` clause may follow it, but neither
    # may cross a line: the braces are what is allowed to wrap.
    _HEAD + r"(?:import|export)\b[^;{}\n]*\{[^{}]*\}[^;{}\n]*\bfrom[ \t]*['\"]{module}['\"]",
    # Side-effect import of a bare module path: ``import 'M';``.
    _HEAD + r"(?:@?import)[ \t]*['\"]{module}['\"]",
    # A call whose argument is the quoted module path. Not anchored to a
    # line, because it is an expression: ``const x = require('M')``,
    # ``await import('M')``. Whitespace inside the call may include
    # newlines, which is where a formatter puts a long specifier; the
    # quotes and the closing paren bound the scan either way.
    r"\b(?:require|import|require_relative|importlib\.import_module|__import__)"
    + r"\s*\(\s*['\"]{module}['\"]\s*\)",
    # Ruby's parenthesis-free form.
    _HEAD + r"require(?:_relative)?[ \t]+['\"]{module}['\"]",
    # Go, single import and import block. The block's contents are
    # bounded by its own closing paren, so the scan cannot run past it.
    _HEAD + r"import[ \t]+(?:[\w.]+[ \t]+)?[`\"]{module}[`\"]",
    _HEAD + r"import[ \t]*\([^()]*[`\"]{module}[`\"]",
    # Rust and PHP ``use``. After the module path only a path
    # continuation may follow before the semicolon, which is what keeps a
    # sentence that begins with the word from reading as a statement
    # merely because it ends in one.
    _HEAD + r"(?:pub(?:\((?:crate|super|self|in[^()\n]*)\))?[ \t]+)?use[ \t]+"
    + r"(?:crate::|self::|super::|::)?{module}"
    + r"(?:::[\w:{}*, \t]*|\\[\w\\]*)?[ \t]*;",
    # Rust ``extern crate``.
    _HEAD + r"extern[ \t]+crate[ \t]+{module}\b[^;\n]*;",
    # C# ``using``, including the alias form.
    _HEAD + r"using[ \t]+(?:static[ \t]+)?(?:[\w.]+[ \t]*=[ \t]*)?{module}"
    + _MODULE_TAIL + r"[ \t]*;",
    # C, C++ and Objective-C preprocessor include.
    _HEAD + r"#[ \t]*(?:include|import)[ \t]*[<\"]{module}(?:[./][^>\"\n]*)?[>\"]",
    # SystemVerilog package import.
    _HEAD + r"import[ \t]+{module}::[\w*]+[ \t]*;",
]


def _module_covers(claim: str, imported: str) -> bool:
    """Whether an import of ``imported`` imports ``claim``.

    A dotted path covers itself and everything under it: ``import a.b``
    imports ``a.b``, and it also brings in ``a``, so an assertion naming
    ``a`` is satisfied. The reverse does not hold — ``import a`` does not
    satisfy an assertion naming ``a.b``, which claims strictly more.
    """
    return claim == imported or imported.startswith(claim + ".")


@register("import_present")
class ImportPresentVerifier:
    """Check that a module is IMPORTED in a file.

    Tier 1 is the only tier that decides whether the import is there:
    the tier-2 rubric asks whether the imported module is actively used,
    which presupposes it is imported, and the runner reports ``skipped``
    for tier 2 when no provider is configured. So a match here has to be
    an import statement, and a module named in prose, in a comment, in a
    docstring or inside a string literal must not satisfy it.

    Python is decided by ``ast``; every other language, and Python that
    will not parse, by the patterns above.
    """

    _PATTERNS = _IMPORT_PATTERNS

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content, source = resolve_file_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        module = params["module"]

        if _is_python_source(source):
            verdict = self._verify_python(content, module, source)
            if verdict is not None:
                return verdict
            # Unparseable Python falls through to the pattern scan below.

        # Comments are blanked; string literals are not. A module path is
        # written as a string in half these languages — ``require('M')``,
        # a Go import block, an ES module specifier — so blanking string
        # interiors would erase the thing being looked for.
        scrubbed = _blank_code_noise(content, source, strings=False)
        escaped = re2.escape(module)

        for template in self._PATTERNS:
            # str.replace, not str.format: these patterns contain literal
            # braces and bounded repeats, which format() would treat as
            # fields and which doubling every brace would make unreadable.
            match = re2.search(template.replace("{module}", escaped), scrubbed)
            if match:
                line_no = scrubbed[: match.start()].count("\n") + 1
                return VerifierResult(
                    passed=True,
                    details=f"Import of '{module}' found at line {line_no} in {source}",
                )

        return VerifierResult(passed=False, details=f"Import of '{module}' not found in {source}")

    @staticmethod
    def _verify_python(content: str, module: str, source: str) -> VerifierResult | None:
        """AST analysis. Returns a result, or None if the source will not
        parse (so the caller can fall back to the pattern scan).

        An ``Import`` or ``ImportFrom`` node is either in the tree or it
        is not, and no comment, docstring or string literal can produce
        one. What each node satisfies:

        * ``import a.b`` and ``import a.b as c`` satisfy ``a.b`` and
          ``a``, not ``a.b.c``. The alias is a local name, not a module,
          so it satisfies nothing on its own.
        * ``from a.b import c`` satisfies ``a.b`` and ``a``. It also
          satisfies ``c``, which is the reading the previous patterns
          had — ``from jose import jwt`` is how a submodule is commonly
          imported — and ``a.b.c``, which is the same import spelled in
          full.
        * ``from .x import y`` satisfies ``x``, ``.x``, ``y`` and
          ``.x.y``: the module written relative to the package is still
          the module the assertion names, and either spelling may be the
          one the assertion used.
        * ``importlib.import_module("a.b")`` and ``__import__("a.b")``
          with a literal argument satisfy the same set as ``import a.b``.
          A computed argument names no module and satisfies nothing.
        """
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, RecursionError):
            # ValueError is what content with a null byte raises and
            # RecursionError what a literal nested past the interpreter's
            # limit raises. All three say the same thing here: this
            # content will not parse, so the pattern scan decides.
            return None

        def found(line: int) -> VerifierResult:
            return VerifierResult(
                passed=True,
                details=f"Import of '{module}' found at line {line} in {source}",
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _module_covers(module, alias.name):
                        return found(node.lineno)

            elif isinstance(node, ast.ImportFrom):
                written = "." * (node.level or 0) + (node.module or "")
                if node.module and _module_covers(module, node.module):
                    return found(node.lineno)
                if node.level and module == written:
                    return found(node.lineno)
                prefix = written if written.endswith(".") else written + "."
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if module == alias.name or module == prefix + alias.name:
                        return found(node.lineno)

            elif isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name in ("import_module", "__import__") and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        if _module_covers(module, first.value):
                            return found(node.lineno)

        return VerifierResult(passed=False, details=f"Import of '{module}' not found in {source}")
