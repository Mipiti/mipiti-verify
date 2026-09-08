"""Formal verification of the sound-witness engine: the flagged set is a
superset of what is unsafe.

The engine behind ``sink_default_deny`` and ``typed_boundary`` reports one
thing: over a declared scope, every site where a value reaches a declared
sink takes a form the declaration admits. That claim is only worth
something in one direction -- the flagged set must CONTAIN every unsafe
site. A false alarm costs a reviewer an allowlist entry; a missed site
makes the witness a lie.

This checker states that direction over a grammar of small programs, one
per construct the engine must see through, in Python (its own parser), a
tree-sitter language and a hardware description language. Each program
declares its own ground truth -- the sites that are unsafe by
construction -- and the checker asserts:

  S1  every ground-truth site is flagged                      (soundness)
  S2  the verdict is PASS exactly on the programs whose ground truth is
      empty and whose scope the engine can read                (usefulness)
  S3  a refusal says which of the fixed refusal reasons it is  (no silent
      pass through an unreadable scope, a vacuous sink list, or a stale
      allowlist entry)

and then self-validates: each of the engine's four enumeration features
(alias tracking, wrapper discovery, escape hatches, stores to a named
target) is switched off in turn, and the harness FAILS unless the mutant
loses a site S1 requires. A property no mutant can break is a property
that was never being checked.

Usage:
    python formal/check_sound.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple

_ROOT = Path(os.path.dirname(os.path.abspath(__file__))).parent
sys.path.insert(0, str(_ROOT / "src"))

from mipiti_verify.languages.definitions import tree_sitter_available  # noqa: E402
from mipiti_verify.verifiers.sound import (  # noqa: E402
    FEATURE_ALIASES,
    FEATURE_ASSIGN_SINKS,
    FEATURE_ESCAPES,
    FEATURE_WRAPPERS,
    MODE_DEFAULT_DENY,
    MODE_TYPED_BOUNDARY,
    SinkEngine,
    _engine_params,
    flagged_sites,
)

_ALL_SAFE = ["literal", "named_constant", "literal_concat", "parameter_binding"]


class Case:
    """One program, its ground truth, and what the engine must say about it.

    ``unsafe`` is the set of ``file:line`` sites that are unsafe by
    construction of the program -- written by the author of the fixture,
    never read back from the engine. ``expect`` is the verdict; ``refusal``
    is a phrase a refusal must state. ``needs`` names the enumeration
    features without which the ground truth cannot be reached, which is what
    the self-validation pass uses.
    """

    def __init__(self, label, files, params, *, mode=MODE_DEFAULT_DENY, unsafe=(),
                 expect="fail", refusal="", needs=(), language=""):
        self.label = label
        self.files = files
        self.params = params
        self.mode = mode
        self.unsafe = set(unsafe)
        self.expect = expect
        self.refusal = refusal
        self.needs = tuple(needs)
        self.language = language


def _sink(callee, **kw):
    return dict(callee=callee, **kw)


# ---------------------------------------------------------------------------
# The grammar of programs
# ---------------------------------------------------------------------------

_PY_SINKS = [_sink("execute", positions=[0])]


def _cases() -> List[Case]:
    cases: List[Case] = [
        Case(
            "python: a literal at the guarded position",
            {"src/a.py": "def go(conn):\n    conn.execute(\"SELECT 1\")\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            expect="pass",
        ),
        Case(
            "python: a name bound once at module scope to a literal",
            {"src/a.py": "Q = \"SELECT 1\"\n\ndef go(conn):\n    conn.execute(Q)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal", "named_constant"],
             "property": "Every statement is a constant."},
            expect="pass",
        ),
        Case(
            "python: a name rebound elsewhere is not a constant",
            {"src/a.py": "Q = \"SELECT 1\"\n\ndef reset(v):\n    global Q\n    Q = v\n\n"
                         "def go(conn):\n    conn.execute(Q)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal", "named_constant"],
             "property": "Every statement is a constant."},
            unsafe={"src/a.py:8"},
        ),
        Case(
            "python: concatenation with a variable operand",
            {"src/a.py": "def go(conn, name):\n    conn.execute(\"SELECT \" + name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal", "literal_concat"],
             "property": "No statement is built from data."},
            unsafe={"src/a.py:2"},
        ),
        Case(
            "python: a template with an expression part",
            {"src/a.py": "def go(conn, uid):\n    conn.execute(f\"SELECT {uid}\")\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": _ALL_SAFE,
             "property": "No statement is built from data."},
            unsafe={"src/a.py:2"},
        ),
        Case(
            "python: data bound beside a literal statement",
            {"src/a.py": "def go(conn, uid):\n    conn.execute(\"SELECT ?\", (uid,))\n"},
            {"scope": ["src/a.py"], "sinks": [_sink("execute")],
             "safe_forms": ["literal", "parameter_binding"],
             "property": "Data is bound, never interpolated."},
            expect="pass",
        ),
        Case(
            "python: a guarded keyword position",
            {"src/a.py": "def go(conn, uid):\n    conn.execute(sql=uid)\n"},
            {"scope": ["src/a.py"], "sinks": [_sink("execute", positions=["sql"])],
             "safe_forms": ["literal"], "property": "The sql keyword is a literal."},
            unsafe={"src/a.py:2"},
        ),
        Case(
            "python: reached through an import alias",
            {"src/a.py": "from db import execute as run_it\n\ndef go(name):\n    run_it(name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:4"}, needs=(FEATURE_ALIASES,),
        ),
        Case(
            "python: reached through an assignment alias",
            {"src/a.py": "def go(conn, name):\n    runner = conn.execute\n    runner(name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:3"}, needs=(FEATURE_ALIASES,),
        ),
        Case(
            "python: a wrapper forwarding a parameter into a guarded position",
            {"src/a.py": "def query(conn, sql):\n    conn.execute(sql)\n\n"
                         "def go(conn, name):\n    query(conn, name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:2", "src/a.py:5"}, needs=(FEATURE_WRAPPERS,),
        ),
        Case(
            "python: a wrapper two levels deep",
            {"src/a.py": "def query(conn, sql):\n    conn.execute(sql)\n\n"
                         "def outer(conn, sql):\n    query(conn, sql)\n\n"
                         "def go(conn, name):\n    outer(conn, name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:2", "src/a.py:5", "src/a.py:8"}, needs=(FEATURE_WRAPPERS,),
        ),
        Case(
            "python: a name resolved by reflection",
            {"src/a.py": "def go(conn, name):\n    conn.execute(\"SELECT 1\")\n"
                         "    return getattr(conn, name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:3"}, needs=(FEATURE_ESCAPES,),
        ),
        Case(
            "python: the sink handed on as a value",
            {"src/a.py": "def go(conn):\n    conn.execute(\"SELECT 1\")\n    return conn.execute\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:3"}, needs=(FEATURE_ESCAPES,),
        ),
        Case(
            "python: a reviewed exception",
            {"src/a.py": "def go(conn, name):\n    conn.execute(name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal.",
             "allowlist": [{"file": "src/a.py", "site": "2", "callee": "execute",
                            "reason": "the caller passes a value from a closed enum",
                            "reviewed_by": "a.reviewer"}]},
            expect="pass",
        ),
        Case(
            "python: an exception that matches no flagged site",
            {"src/a.py": "def go(conn):\n    conn.execute(\"SELECT 1\")\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal.",
             "allowlist": [{"file": "src/a.py", "site": "9", "callee": "execute",
                            "reason": "reviewed once", "reviewed_by": "a.reviewer"}]},
            refusal="matches no flagged site",
        ),
        Case(
            "python: a site whose arguments could not be read",
            {"src/a.py": "def go(conn):\n    conn.execute()\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:2"},
        ),
        Case(
            "scope: matches no file",
            {"src/a.py": "x = 1\n"},
            {"scope": ["nothing/**/*.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            refusal="scope matched no files",
        ),
        Case(
            "scope: a file whose extension names no language",
            {"src/a.py": "x = 1\n", "src/notes.txt": "nothing to parse\n"},
            {"scope": ["src"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            refusal="unclassifiable file in scope",
        ),
        Case(
            "scope: a file the parser rejects",
            {"src/a.py": "def go(conn:\n    conn.execute(\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            refusal="unparsed",
        ),
        Case(
            "scope: an entry that climbs out of the checkout",
            {"src/a.py": "x = 1\n"},
            {"scope": ["../elsewhere/*.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            refusal="scope refused",
        ),
        Case(
            "vacuity: a declared sink that does not occur",
            {"src/a.py": "def go(conn):\n    conn.commit()\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "property": "Every statement is a literal."},
            refusal="do not occur in scope",
        ),
        Case(
            "typed_boundary: every value built through a declared constructor",
            {"src/a.py": "from safe import SafeSql\n\nQ = SafeSql.literal(\"SELECT 1\")\n\n"
                         "def go(conn):\n    conn.execute(Q)\n"
                         "    conn.execute(SafeSql.literal(\"SELECT 2\"))\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "boundary_type": "SafeSql",
             "constructors": ["SafeSql.literal"],
             "property": "The driver accepts only SafeSql."},
            mode=MODE_TYPED_BOUNDARY, expect="pass",
        ),
        Case(
            "typed_boundary: a value that is not a construction",
            {"src/a.py": "from safe import SafeSql\n\ndef go(conn, raw):\n    conn.execute(raw)\n"
                         "    conn.execute(SafeSql.literal(\"SELECT 1\"))\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "boundary_type": "SafeSql",
             "constructors": ["SafeSql.literal"],
             "property": "The driver accepts only SafeSql."},
            mode=MODE_TYPED_BOUNDARY, unsafe={"src/a.py:4"},
        ),
        Case(
            "typed_boundary: a construction from something that is not a literal",
            {"src/a.py": "from safe import SafeSql\n\ndef go(conn, raw):\n"
                         "    conn.execute(SafeSql.literal(raw))\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "boundary_type": "SafeSql",
             "constructors": ["SafeSql.literal"],
             "property": "The driver accepts only SafeSql."},
            mode=MODE_TYPED_BOUNDARY, unsafe={"src/a.py:4"},
        ),
        Case(
            "python: a wrapper the check cannot see, declared",
            {"src/a.py": "from helpers import query\n\ndef go(conn, name):\n    query(conn, name)\n"},
            {"scope": ["src/a.py"], "sinks": _PY_SINKS, "safe_forms": ["literal"],
             "wrappers": ["query"],
             "property": "Every statement is a literal."},
            unsafe={"src/a.py:4"},
        ),
        Case(
            "python: a constructor sink",
            {"src/a.py": "from db import Query\n\ndef go(name):\n    return Query(name)\n"},
            {"scope": ["src/a.py"], "sinks": [_sink("Query", kind="constructor", positions=[0])],
             "safe_forms": ["literal"], "property": "Every query is a literal."},
            unsafe={"src/a.py:4"},
        ),
    ]

    if tree_sitter_available("javascript"):
        cases += [
            Case(
                "javascript: a template literal with a substitution",
                {"src/a.js": "function go(db, name) {\n  db.query(`SELECT ${name}`);\n}\n"},
                {"scope": ["src/a.js"], "sinks": [_sink("query", positions=[0])],
                 "safe_forms": ["literal", "literal_concat"],
                 "property": "No statement is built from data."},
                unsafe={"src/a.js:2"}, language="javascript",
            ),
            Case(
                "javascript: a literal template",
                {"src/a.js": "function go(db) {\n  db.query(`SELECT 1`);\n}\n"},
                {"scope": ["src/a.js"], "sinks": [_sink("query", positions=[0])],
                 "safe_forms": ["literal", "literal_concat"],
                 "property": "No statement is built from data."},
                expect="pass", language="javascript",
            ),
        ]

    if tree_sitter_available("rust"):
        cases += [
            Case(
                "rust: a macro sink",
                {"src/a.rs": "fn go(name: &str) {\n    query!(name);\n}\n"},
                {"scope": ["src/a.rs"], "sinks": [_sink("query", kind="macro", positions=[0])],
                 "safe_forms": ["literal"], "property": "Every statement is a literal."},
                unsafe={"src/a.rs:2"}, language="rust",
            ),
        ]

    if tree_sitter_available("go"):
        cases += [
            Case(
                "go: a constant at the guarded position",
                {"src/a.go": "package a\n\nconst Q = \"SELECT 1\"\n\n"
                             "func Run(db *DB) {\n\tdb.Query(Q)\n}\n"},
                {"scope": ["src/a.go"], "sinks": [_sink("Query", positions=[0])],
                 "safe_forms": ["literal", "named_constant"],
                 "property": "Every statement is a constant."},
                expect="pass", language="go",
            ),
            Case(
                "go: a parameter at the guarded position",
                {"src/a.go": "package a\n\nfunc Run(db *DB, name string) {\n\tdb.Query(name)\n}\n"},
                {"scope": ["src/a.go"], "sinks": [_sink("Query", positions=[0])],
                 "safe_forms": ["literal", "named_constant"],
                 "property": "Every statement is a constant."},
                unsafe={"src/a.go:4"}, language="go",
            ),
        ]

    if tree_sitter_available("systemverilog"):
        cases += [
            Case(
                "systemverilog: a store to a named target from a literal",
                {"rtl/a.sv": "module m (input logic clk);\n  logic [7:0] cfg_reg;\n"
                             "  always_ff @(posedge clk) begin\n    cfg_reg <= 8'h00;\n"
                             "  end\nendmodule\n"},
                {"scope": ["rtl/a.sv"], "sinks": [_sink("cfg_reg", kind="assign")],
                 "safe_forms": ["literal", "named_constant"],
                 "property": "The configuration register takes only constants."},
                expect="pass", language="systemverilog",
            ),
            Case(
                "systemverilog: a store to a named target from a signal",
                {"rtl/a.sv": "module m (input logic clk, input logic [7:0] key_in);\n"
                             "  logic [7:0] cfg_reg;\n"
                             "  always_ff @(posedge clk) begin\n    cfg_reg <= key_in;\n"
                             "  end\nendmodule\n"},
                {"scope": ["rtl/a.sv"], "sinks": [_sink("cfg_reg", kind="assign")],
                 "safe_forms": ["literal", "named_constant"],
                 "property": "The configuration register takes only constants."},
                unsafe={"rtl/a.sv:4"}, needs=(FEATURE_ASSIGN_SINKS,), language="systemverilog",
            ),
            Case(
                "systemverilog: an instantiation port driven by a signal",
                {"rtl/a.sv": "module m (input logic clk, input logic [7:0] key_in);\n"
                             "  aes_core u_aes (.clk(clk), .key_in(key_in));\n"
                             "endmodule\n"},
                {"scope": ["rtl/a.sv"], "sinks": [_sink("aes_core", kind="instantiate",
                                                        positions=["key_in"])],
                 "safe_forms": ["literal", "named_constant"],
                 "property": "The key port is tied to a constant."},
                unsafe={"rtl/a.sv:2"}, language="systemverilog",
            ),
        ]

    if tree_sitter_available("vhdl"):
        cases += [
            Case(
                "vhdl: a signal assignment from a declared constant",
                {"rtl/a.vhd": "library ieee;\nuse ieee.std_logic_1164.all;\n\n"
                              "entity guard is\n  port (clk : in std_logic);\nend entity;\n\n"
                              "architecture rtl of guard is\n"
                              "  constant DEFAULT : std_logic_vector(7 downto 0) := \"00000000\";\n"
                              "  signal cfg_reg : std_logic_vector(7 downto 0);\n"
                              "begin\n  cfg_reg <= DEFAULT;\nend architecture;\n"},
                {"scope": ["rtl/a.vhd"], "sinks": [_sink("cfg_reg", kind="assign")],
                 "safe_forms": ["literal", "named_constant"],
                 "property": "The configuration register takes only constants."},
                expect="pass", language="vhdl",
            ),
        ]
    return cases


# ---------------------------------------------------------------------------
# Running one case
# ---------------------------------------------------------------------------

def _materialise(files: dict) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _run(case: Case, features: frozenset):
    root = _materialise(case.files)
    try:
        spec, problem = _engine_params(case.params, case.mode)
        if spec is None:
            return None, problem
        report = SinkEngine(root, spec, features=features).run()
        return report, ""
    finally:
        shutil.rmtree(root, ignore_errors=True)


def check_cases(cases: List[Case]) -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    for case in cases:
        report, problem = _run(case, frozenset())
        checked += 1
        if report is None:
            violations.append(f"S0 {case.label}: params refused ({problem})")
            continue
        flagged = flagged_sites(report)
        missed = sorted(case.unsafe - flagged)
        if missed:
            violations.append(f"S1 {case.label}: unsafe site(s) not flagged: {missed}")
        checked += 1
        if report.passed != (case.expect == "pass"):
            violations.append(
                f"S2 {case.label}: expected {case.expect.upper()}, got "
                f"{'PASS' if report.passed else 'FAIL'} ({report.details.splitlines()[0]})")
        if case.refusal:
            checked += 1
            if case.refusal not in report.details:
                violations.append(
                    f"S3 {case.label}: refusal does not state {case.refusal!r} "
                    f"({report.details.splitlines()[0]})")
    return checked, violations


def check_self_validation(cases: List[Case]) -> Tuple[int, List[str]]:
    """Each enumeration feature, switched off, must lose a site S1 requires."""
    violations: List[str] = []
    checked = 0
    features = (FEATURE_ALIASES, FEATURE_WRAPPERS, FEATURE_ESCAPES, FEATURE_ASSIGN_SINKS)
    caught: dict = {f: 0 for f in features}
    for feature in features:
        for case in cases:
            if feature not in case.needs:
                continue
            checked += 1
            report, _problem = _run(case, frozenset({feature}))
            if report is None:
                continue
            if case.unsafe - flagged_sites(report):
                caught[feature] += 1
            else:
                violations.append(
                    f"R {case.label}: still flags every unsafe site with {feature!r} "
                    f"disabled, so the case does not exercise it")
    for feature in features:
        checked += 1
        if not caught[feature]:
            violations.append(
                f"R {feature!r}: no case loses a site when it is disabled; the "
                f"feature is not covered by any program in the grammar")
    return checked, violations


def main() -> int:
    print("=" * 70)
    print("SOUND WITNESS ENGINE")
    print("=" * 70)
    cases = _cases()
    languages = sorted({c.language or "python" for c in cases})
    print(f"\nPrograms: {len(cases)} across {', '.join(languages)}")

    all_pass = True
    count, violations = check_cases(cases)
    print(f"S1-S3 superset, verdict, refusal ({count} checks): ", end="")
    if violations:
        all_pass = False
        print(f"FAILED ({len(violations)})")
        for v in violations:
            print(f"  {v}")
    else:
        print("VERIFIED")

    count, violations = check_self_validation(cases)
    caught = count - len(violations)
    print(f"Regression self-validation ({count} checks): ", end="")
    if violations:
        all_pass = False
        print(f"FAILED ({len(violations)})")
        for v in violations:
            print(f"  {v}")
    else:
        print(f"{caught}/{count} caught")

    print(f"\n{'=' * 70}")
    if not all_pass:
        print("SOUND WITNESS PROPERTIES: FAILED")
        return 1
    print("ALL SOUND WITNESS PROPERTIES VERIFIED")
    print(f"{'=' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
