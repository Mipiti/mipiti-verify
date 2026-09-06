"""Formal verification of the runner adapters and the language layer.

``attest-dependence`` disables a mechanism by rewriting its source for one
test run. That is the one place this package writes into a checkout, so
the properties that make it safe are checked exhaustively -- every adapter
that mutates, every language it mutates, every fixture -- against the real
code, driven through the same entry point the command uses:

  A1  restore is identity: after ``mutated_file`` exits, normally or by an
      exception raised inside the block, the file's bytes hash to what they
      hashed to before
  A2  a mutation changes the file, and the change is confined to the lines
      of the definition the mechanism names (plus the documented extras:
      the ``stdlib.h`` include a C abort needs, and the assertions that
      instantiate a removed property)
  A3  the compile check runs before the test, on the mutated tree; a check
      that fails is an ``error`` outcome and the test runner is never
      invoked
  A4  a file with uncommitted changes, or outside a checkout, is refused
      as ``error`` and its bytes are never rewritten
  A5  definition location agrees between the parser and the fallback: for
      every fixture the parser isolates the named definition
      (``scope="symbol"``); with the parser made unavailable, the fallback
      either declines or reports a block (``scope="block"``), except for
      the HDL keyword scanner, which reads the name at the block's own
      start and so reports ``symbol``; where the fallback claims a span it
      is the documented one
  A6  the coverage readers agree: one table of executed lines, written in
      every accepted format (coverage.py JSON with and without contexts,
      LCOV, Cobertura, JaCoCo, a per-test directory), reads back as the
      same line sets from both readers
  A7  outcome mapping is total and closed: for every adapter and every
      exit status in a representative set, the outcome is one of
      ``passed`` / ``failed`` / ``error``, and it is the one the adapter's
      documented table gives; and in suite mode, every JUnit status a
      report can carry (passed, failed, error, skipped) and a test absent
      from the report map to the documented outcome and reason

Fixture sources are the ones the unit tests use, imported from them, so
there is one set of representative programs.

Usage:
    python formal/check_adapters.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple
from unittest.mock import patch

_ROOT = Path(os.path.dirname(os.path.abspath(__file__))).parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from mipiti_verify.languages import definitions as D  # noqa: E402
from mipiti_verify.languages.adapters import (  # noqa: E402
    OUTCOME_ERROR, OUTCOME_FAILED, OUTCOME_PASSED, DisableError, _all_adapters,
    detect_adapter, parse_mechanism,
)
from mipiti_verify.languages.adapters._common import mutated_file  # noqa: E402
from mipiti_verify.languages.adapters.hdl import mutate_verilog, mutate_vhdl  # noqa: E402
from mipiti_verify.languages.adapters.mutation import mutate_source  # noqa: E402
from mipiti_verify.languages.adapters import checks as checks_mod  # noqa: E402
from mipiti_verify.languages.adapters import coverage_read  # noqa: E402
from mipiti_verify.coverage_readers import read_coverage  # noqa: E402
from mipiti_verify.dependence import run_pair  # noqa: E402

from tests.test_adapters_registry import (  # noqa: E402
    C, CPP, CSHARP, GO, JAVA, KOTLIN, RUST, SV, SWIFT, VHDL,
)
from tests.test_languages_definitions import CASES, HDL_CASES, SOURCES  # noqa: E402

OUTCOMES = frozenset({OUTCOME_PASSED, OUTCOME_FAILED, OUTCOME_ERROR})


# ---------------------------------------------------------------------------
# Fixtures: one file per mutation language
# ---------------------------------------------------------------------------

FIXTURES: dict[str, tuple[str, str]] = {
    # language: (file name, source)
    "go": ("a.go", GO),
    "rust": ("a.rs", RUST),
    "java": ("A.java", JAVA),
    "kotlin": ("a.kt", KOTLIN),
    "c": ("a.c", C),
    "cpp": ("a.cpp", CPP),
    "csharp": ("a.cs", CSHARP),
    "swift": ("a.swift", SWIFT),
    "systemverilog": ("g.sv", SV),
    "vhdl": ("g.vhd", VHDL),
}

# Bytes the text fixtures cannot express: CRLF, a BOM, a trailing partial
# line. Restore must be byte-exact, not text-exact.
BYTES_FIXTURE = ("bytes.go", b"package a\r\n\r\nfunc Guard() {}\r\n\xef\xbb\xbf")

# A2 cases: (language, mechanism, 1-based inclusive line span the change
# must stay within, extra lines the documented behaviour may also touch,
# (kind, name) the parser locates for the cross-check).
MUTATION_CASES = [
    ("go", "a.go::Guard", (3, 8), (), ("function", "Guard")),
    ("go", "a.go::Limiter.Allow", (10, 10), (), ("method", "Limiter.Allow")),
    ("go", "a.go::Limiter", (10, 10), (), ("method", "Limiter.Allow")),
    ("rust", "a.rs::guard", (1, 3), (), ("function", "guard")),
    ("rust", "a.rs::Limiter.allow", (5, 5), (), ("method", "Limiter.allow")),
    ("rust", "a.rs::impl:Limiter", (5, 5), (), ("method", "Limiter.allow")),
    ("java", "A.java::guard", (3, 5), (), ("function", "guard")),
    ("java", "A.java::A.other", (7, 7), (), ("method", "A.other")),
    ("java", "A.java::class:A", (3, 7), (), ("class", "A")),
    ("kotlin", "a.kt::guard", (2, 2), (), ("function", "guard")),
    ("kotlin", "a.kt::A.other", (3, 5), (), ("method", "A.other")),
    ("c", "a.c::guard", (1, 3), (), ("function", "guard")),
    ("cpp", "a.cpp::Guard.check", (2, 4), (), ("method", "Guard.check")),
    ("csharp", "a.cs::Guard.Check", (2, 2), (), ("method", "Guard.Check")),
    ("csharp", "a.cs::Other", (3, 3), (), ("function", "Other")),
    ("swift", "a.swift::guardToken", (1, 3), (), ("function", "guardToken")),
    ("swift", "a.swift::L.allow", (4, 4), (), ("method", "L.allow")),
    ("systemverilog", "g.sv::module:guard", (1, 26), (), ("module", "guard")),
    ("systemverilog", "g.sv::clamp", (8, 10), (), ("function", "clamp")),
    ("systemverilog", "g.sv::task:check", (11, 16), (), ("task", "check")),
    ("systemverilog", "g.sv::always:upd", (17, 19), (), ("always", "upd")),
    # Removing a property also removes the assertions that instantiate it,
    # or the file no longer elaborates; the instantiation is on line 24.
    ("systemverilog", "g.sv::property:p_stable", (21, 23), (24,), ("property", "p_stable")),
    ("systemverilog", "g.sv::assert:a_ok", (25, 25), (), ("assert", "a_ok")),
    ("vhdl", "g.vhd::rtl", (2, 18), (), ("architecture", "rtl")),
    ("vhdl", "g.vhd::process:upd", (11, 16), (), ("process", "upd")),
    ("vhdl", "g.vhd::clamp", (3, 8), (), ("function", "clamp")),
]

# A3 / A4: which adapters disable which fixture language by mutation.
ADAPTERS_BY_LANGUAGE: dict[str, tuple[str, ...]] = {
    "go": ("go",),
    "rust": ("cargo",),
    "java": ("maven", "gradle"),
    "kotlin": ("maven", "gradle"),
    "csharp": ("dotnet",),
    "c": ("command",),
    "cpp": ("command",),
    "swift": ("command",),
    "systemverilog": ("command", "pytest"),
    "vhdl": ("command", "pytest"),
}
DRIVE_MECHANISM: dict[str, str] = {
    "go": "a.go::Guard", "rust": "a.rs::guard", "java": "A.java::guard",
    "kotlin": "a.kt::guard", "csharp": "a.cs::Other", "c": "a.c::guard",
    "cpp": "a.cpp::Guard.check", "swift": "a.swift::guardToken",
    "systemverilog": "g.sv::clamp", "vhdl": "g.vhd::clamp",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=formal@example.invalid", "-c", "user.name=formal",
         "-c", "commit.gpgsign=false", *args],
        cwd=root, check=True, capture_output=True,
    )


def _repo(files: dict[str, bytes]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="mipiti-formal-"))
    _git(root, "init", "-q")
    for name, data in files.items():
        (root / name).write_bytes(data)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "fixture")
    return root


def _all_fixture_files() -> dict[str, bytes]:
    files = {name: src.encode("utf-8") for name, src in FIXTURES.values()}
    files[BYTES_FIXTURE[0]] = BYTES_FIXTURE[1]
    return files


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mutate(language: str, source: str, mechanism: str) -> str:
    mech = parse_mechanism(mechanism)
    if language in ("verilog", "systemverilog"):
        return mutate_verilog(source, mech)
    if language == "vhdl":
        return mutate_vhdl(source, mech)
    return mutate_source(source, mech, language)


def _changed_lines(original: str, mutated: str) -> set:
    """1-based lines of ``original`` that the edit touched: everything
    outside the longest common prefix and suffix of the line lists."""
    a, b = original.split("\n"), mutated.split("\n")
    p = 0
    while p < min(len(a), len(b)) and a[p] == b[p]:
        p += 1
    s = 0
    while s < min(len(a), len(b)) - p and a[-1 - s] == b[-1 - s]:
        s += 1
    return set(range(p + 1, len(a) - s + 1))


class _ParserOff:
    """Context: the optional parser extra is unimportable."""

    def __enter__(self):
        self._patch = patch.dict(sys.modules, {"tree_sitter_language_pack": None})
        self._patch.__enter__()
        D._get_parser.cache_clear()
        return self

    def __exit__(self, *exc):
        self._patch.__exit__(*exc)
        D._get_parser.cache_clear()
        return False


# ---------------------------------------------------------------------------
# A1  restore is identity
# ---------------------------------------------------------------------------

def check_a1() -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    root = _repo(_all_fixture_files())
    try:
        for name, data in _all_fixture_files().items():
            path = root / name
            before = _sha(path.read_bytes())

            # Normal exit.
            with mutated_file(root, name, b"// replaced\n"):
                if path.read_bytes() == data:
                    violations.append(f"A1: {name}: the block did not see the mutated bytes")
            checked += 1
            if _sha(path.read_bytes()) != before:
                violations.append(f"A1: {name}: bytes differ after a normal exit")

            # Exception raised inside the block.
            try:
                with mutated_file(root, name, b"// replaced\n"):
                    raise RuntimeError("inside the block")
            except RuntimeError:
                pass
            else:
                violations.append(f"A1: {name}: the exception raised inside the block was swallowed")
            checked += 1
            if _sha(path.read_bytes()) != before:
                violations.append(f"A1: {name}: bytes differ after an exception inside the block")

            # The tree is clean again, as git sees it.
            status = subprocess.run(["git", "status", "--porcelain", "--", name], cwd=root,
                                    capture_output=True, text=True).stdout.strip()
            checked += 1
            if status:
                violations.append(f"A1: {name}: git reports the file changed after restore: {status!r}")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return checked, violations


# ---------------------------------------------------------------------------
# A2  a mutation changes the file, within the definition's lines
# ---------------------------------------------------------------------------

def check_a2() -> Tuple[int, List[str], List[str]]:
    violations: List[str] = []
    unestablished: List[str] = []
    checked = 0
    for language, mechanism, span, extras, (kind, name) in MUTATION_CASES:
        file, source = FIXTURES[language]
        try:
            mutated = _mutate(language, source, mechanism)
        except DisableError as e:
            violations.append(f"A2: {mechanism}: mutation refused: {e}")
            continue
        checked += 1
        if mutated == source:
            violations.append(f"A2: {mechanism}: the mutation left the file unchanged")
            continue
        # The C abort needs <stdlib.h>; the include is prepended when the
        # file lacks it. Documented, and outside any span by construction.
        compare = mutated
        if language in ("c", "cpp") and mutated.startswith("#include <stdlib.h>\n") \
                and not source.startswith("#include <stdlib.h>\n"):
            compare = mutated[len("#include <stdlib.h>\n"):]
        changed = _changed_lines(source, compare)
        allowed = set(range(span[0], span[1] + 1)) | set(extras)
        if not changed:
            violations.append(f"A2: {mechanism}: could not attribute the change to any line")
        stray = sorted(changed - allowed)
        if stray:
            violations.append(f"A2: {mechanism}: the change touched lines {stray} outside {span} + {list(extras)}")

        # Cross-check the table against the parser: the span the table
        # allows lies inside the definition the parser isolates.
        checked += 1
        lang = D.language_of(file)
        if D.tree_sitter_available(lang):
            located = D.locate(source, kind, name, language=lang)
            if located is None or located.scope != D.SCOPE_SYMBOL:
                violations.append(f"A2: {mechanism}: the parser did not isolate {kind} {name}")
            elif not (located.start_line <= span[0] and span[1] <= located.end_line):
                violations.append(
                    f"A2: {mechanism}: table span {span} is not inside the parser's "
                    f"({located.start_line}, {located.end_line})")
        else:
            unestablished.append(f"A2 parser cross-check for {mechanism}")
    return checked, violations, unestablished


# ---------------------------------------------------------------------------
# A3  compile check before test run; a failing check is error, no run
# A4  a dirty file is refused, never rewritten
# ---------------------------------------------------------------------------

def _drive(root: Path, adapter_name: str, mechanism: str, check_reason: str,
           log: list, runner_rc: int = 1) -> dict:
    """Run one pair through the real ``run_pair`` with a recording compile
    check and a recording test runner."""
    file = mechanism.split("::", 1)[0]
    path = root / file

    def fake_check(language, project_root, rel_file, *, runner=None, work_dir=None):
        log.append(("check", path.read_bytes()))
        return check_reason

    def fake_runner(argv, **kwargs):
        log.append(("run", path.read_bytes()))
        return subprocess.CompletedProcess(argv, runner_rc, "", "")

    adapter = detect_adapter(root, override=adapter_name, run_cmd="sim {test}", runner=fake_runner)
    with patch.object(checks_mod, "compile_check", fake_check):
        return run_pair(root, "the_test", mechanism, adapter=adapter)


def check_a3_a4() -> Tuple[int, int, List[str]]:
    violations: List[str] = []
    a3 = a4 = 0
    root = _repo(_all_fixture_files())
    try:
        for language, adapters in ADAPTERS_BY_LANGUAGE.items():
            file, source = FIXTURES[language]
            path = root / file
            original = source.encode("utf-8")
            mechanism = DRIVE_MECHANISM[language]
            mutated_expected = _mutate(language, source, mechanism).encode("utf-8")
            for adapter_name in adapters:
                where = f"{adapter_name}/{mechanism}"

                # A3, passing check: check first, on the mutated tree; then
                # the run, still on the mutated tree; then restored. The fake
                # runner exits with the status the adapter maps to ``failed``.
                failing_status = min(OUTCOME_TABLE[adapter_name][3])
                log: list = []
                record = _drive(root, adapter_name, mechanism, "", log, runner_rc=failing_status)
                a3 += 1
                kinds = [k for k, _ in log]
                if kinds != ["check", "run"]:
                    violations.append(f"A3: {where}: expected [check, run], saw {kinds}")
                for k, seen in log:
                    if seen != mutated_expected:
                        violations.append(f"A3: {where}: the {k} step did not see the mutated tree")
                if record["status"] != OUTCOME_FAILED:
                    violations.append(f"A3: {where}: a run exiting {failing_status} after a passing check recorded {record['status']!r}")
                if path.read_bytes() != original:
                    violations.append(f"A3: {where}: file not restored after the run")

                # A3, failing check: error, the reason carried, no run.
                log = []
                record = _drive(root, adapter_name, mechanism, "undefined: Limiter", log)
                a3 += 1
                if record["status"] != OUTCOME_ERROR:
                    violations.append(f"A3: {where}: a failing compile check recorded {record['status']!r}")
                if "does not compile" not in record.get("note", "") or "undefined: Limiter" not in record.get("note", ""):
                    violations.append(f"A3: {where}: the compile failure reason is not on the record: {record.get('note')!r}")
                if [k for k, _ in log] != ["check"]:
                    violations.append(f"A3: {where}: expected only [check], saw {[k for k, _ in log]}")
                if path.read_bytes() != original:
                    violations.append(f"A3: {where}: file not restored after a failing check")

                # A4, dirty file: refused before anything runs, bytes untouched.
                dirty = original + b"\n// uncommitted edit\n"
                path.write_bytes(dirty)
                log = []
                record = _drive(root, adapter_name, mechanism, "", log, runner_rc=failing_status)
                a4 += 1
                if record["status"] != OUTCOME_ERROR or "uncommitted" not in record.get("note", ""):
                    violations.append(f"A4: {where}: a dirty file was not refused: {record}")
                if log:
                    violations.append(f"A4: {where}: {[k for k, _ in log]} ran on a dirty file")
                if path.read_bytes() != dirty:
                    violations.append(f"A4: {where}: the dirty file's bytes were rewritten")
                path.write_bytes(original)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    # A4, outside a checkout: refused, bytes untouched.
    loose = Path(tempfile.mkdtemp(prefix="mipiti-formal-loose-"))
    try:
        (loose / "a.go").write_text(GO)
        log = []
        record = _drive(loose, "go", "a.go::Guard", "", log)
        a4 += 1
        if record["status"] != OUTCOME_ERROR or "git checkout" not in record.get("note", ""):
            violations.append(f"A4: outside a checkout was not refused: {record}")
        if log or (loose / "a.go").read_text() != GO:
            violations.append("A4: outside a checkout: something ran or the file changed")
    finally:
        shutil.rmtree(loose, ignore_errors=True)
    return a3, a4, violations


# ---------------------------------------------------------------------------
# A5  definition location: parser vs fallback
# ---------------------------------------------------------------------------

PYTHON_SOURCE = (
    "import os\n\n"
    "def target(a):\n"
    "    return a\n\n"
    "class Guard:\n"
    "    def check(self, r):\n"
    "        return r\n"
)
PYTHON_CASES = [
    ("python", "function", "target", (3, 4)),
    ("python", "class", "Guard", (6, 8)),
    ("python", "method", "Guard.check", (7, 8)),
]


def check_a5() -> Tuple[int, List[str], List[str]]:
    violations: List[str] = []
    unestablished: List[str] = []
    checked = 0
    limits = 0

    def source_of(language: str) -> str:
        return PYTHON_SOURCE if language == "python" else SOURCES[language]

    # Parser arm.
    parser_seen: dict = {}
    rows = [(l, k, n, s, f) for (l, k, n, s, f) in CASES] \
        + [(l, k, n, s, s) for (l, k, n, s) in HDL_CASES] \
        + [(l, k, n, s, s) for (l, k, n, s) in PYTHON_CASES]
    for language, kind, name, span, _ in rows:
        where = f"{language} {kind} {name}"
        if language != "python" and not D.tree_sitter_available(language):
            unestablished.append(f"A5 parser arm for {where}")
            continue
        checked += 1
        found = D.locate(source_of(language), kind, name, language=language)
        if found is None:
            violations.append(f"A5: {where}: the parser found nothing")
            continue
        parser_seen[(language, kind, name)] = found
        if found.scope != D.SCOPE_SYMBOL:
            violations.append(f"A5: {where}: parser scope is {found.scope!r}, not symbol")
        expected_parser = D.PARSER_AST if language == "python" else D.PARSER_TREE_SITTER
        if found.parser != expected_parser:
            violations.append(f"A5: {where}: located by {found.parser!r}, not {expected_parser!r}")
        if (found.start_line, found.end_line) != span:
            violations.append(f"A5: {where}: parser span {(found.start_line, found.end_line)} != {span}")

    # Fallback arm.
    with _ParserOff():
        for language, kind, name, span, fallback in rows:
            where = f"{language} {kind} {name}"
            checked += 1
            found = D.locate(source_of(language), kind, name, language=language)
            if fallback is None:
                if found is not None:
                    violations.append(f"A5: {where}: the fallback claimed {(found.start_line, found.end_line)} where it is documented to decline")
                continue
            if found is None:
                violations.append(f"A5: {where}: the fallback found nothing; documented {fallback}")
                continue
            if (found.start_line, found.end_line) != tuple(fallback):
                violations.append(f"A5: {where}: fallback span {(found.start_line, found.end_line)} != documented {fallback}")
            if language == "python":
                if found.scope != D.SCOPE_SYMBOL or found.parser != D.PARSER_AST:
                    violations.append(f"A5: {where}: Python is located by ast regardless of the extra; saw {found.scope}/{found.parser}")
            elif language in D.HDL_LANGUAGES:
                if found.scope != D.SCOPE_SYMBOL or found.parser != D.PARSER_KEYWORD:
                    violations.append(f"A5: {where}: the keyword scanner reports {found.scope}/{found.parser}, not symbol/keyword")
            else:
                if found.scope != D.SCOPE_BLOCK or found.parser != D.PARSER_LINES:
                    violations.append(f"A5: {where}: the block fallback reports {found.scope}/{found.parser}, not block/lines")
            if fallback[0] != span[0]:
                limits += 1  # a documented limit of the heuristic, not a disagreement found here
            elif (language, kind, name) in parser_seen and parser_seen[(language, kind, name)].start_line != found.start_line:
                violations.append(f"A5: {where}: parser and fallback start on different lines")
    return checked, violations, unestablished, limits


# ---------------------------------------------------------------------------
# A6  coverage readers agree across formats
# ---------------------------------------------------------------------------

LINE_TABLE: dict[str, set] = {
    "src/a.py": {3, 4, 7},
    "src/b.py": {10},
}
UNHIT: dict[str, set] = {"src/a.py": {5}, "src/b.py": {11}}


def _coverage_fixtures(root: Path) -> dict[str, Path]:
    def da(file: str) -> str:
        hit = "".join(f"DA:{n},1\n" for n in sorted(LINE_TABLE[file]))
        miss = "".join(f"DA:{n},0\n" for n in sorted(UNHIT[file]))
        return f"SF:{file}\n{hit}{miss}end_of_record\n"

    lcov = "".join(da(f) for f in LINE_TABLE)
    coveragepy = {"files": {f: {"executed_lines": sorted(v), "missing_lines": sorted(UNHIT[f])}
                            for f, v in LINE_TABLE.items()}}
    contexts = {"files": {f: {"executed_lines": sorted(v),
                              "contexts": {str(n): ["tests/test_x.py::test_one|run"] for n in sorted(v)}}
                          for f, v in LINE_TABLE.items()}}
    cobertura = '<?xml version="1.0"?>\n<coverage><sources><source>.</source></sources><packages><package name="src">' + "".join(
        f'<classes><class filename="{f}"><lines>'
        + "".join(f'<line number="{n}" hits="1"/>' for n in sorted(v))
        + "".join(f'<line number="{n}" hits="0"/>' for n in sorted(UNHIT[f]))
        + "</lines></class></classes>" for f, v in LINE_TABLE.items()
    ) + "</package></packages></coverage>\n"
    jacoco = '<?xml version="1.0"?>\n<report name="r"><package name="src">' + "".join(
        f'<sourcefile name="{f.split("/", 1)[1]}">'
        + "".join(f'<line nr="{n}" mi="0" ci="1"/>' for n in sorted(v))
        + "".join(f'<line nr="{n}" mi="1" ci="0"/>' for n in sorted(UNHIT[f]))
        + "</sourcefile>" for f, v in LINE_TABLE.items()
    ) + "</package></report>\n"

    out = {}
    for name, text in (("coveragepy.json", json.dumps(coveragepy)), ("contexts.json", json.dumps(contexts)),
                       ("lcov.info", lcov), ("cobertura.xml", cobertura), ("jacoco.xml", jacoco)):
        (root / name).write_text(text)
        out[name] = root / name
    per_test = root / "per-test"
    per_test.mkdir()
    (per_test / "tests__test_x.py__test_one.info").write_text(lcov)
    out["per-test/"] = per_test
    return out


def check_a6() -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    root = Path(tempfile.mkdtemp(prefix="mipiti-formal-cov-"))
    try:
        fixtures = _coverage_fixtures(root)
        for name, path in fixtures.items():
            checked += 1
            report = read_coverage(path, root)
            got = {f: set(v) for f, v in report.all_lines().items()}
            if got != LINE_TABLE:
                violations.append(f"A6: read_coverage({name}) -> {got}, table {LINE_TABLE}")
            if path.is_dir():
                continue
            checked += 1
            fallback = {f: set(v) for f, v in coverage_read.executed_lines(path, root).items()}
            if fallback != LINE_TABLE:
                violations.append(f"A6: executed_lines({name}) -> {fallback}, table {LINE_TABLE}")
        # Attribution: the contexts export and the per-test directory name the
        # test; the aggregate formats attribute nothing.
        for name in ("contexts.json", "per-test/"):
            checked += 1
            report = read_coverage(fixtures[name], root)
            if not report.attributed:
                violations.append(f"A6: {name} attributes lines to a test but the reader reports none")
        for name in ("coveragepy.json", "lcov.info", "cobertura.xml", "jacoco.xml"):
            checked += 1
            if read_coverage(fixtures[name], root).attributed:
                violations.append(f"A6: aggregate {name} was read as attributing lines to a test")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return checked, violations


# ---------------------------------------------------------------------------
# A7  outcome mapping: total over exit statuses, closed over outcomes
# ---------------------------------------------------------------------------

EXIT_STATUSES = (0, 1, 2, 4, 5, 101, 124, 137)

# Per adapter: (stdout that evidences a completed passing run, stdout that
# evidences a completed failing run, exit statuses that are ``failed`` when
# the failing evidence is present, exit statuses that are ``failed`` with
# no output at all). Every other status is ``error``. An adapter whose
# runner reports counts (mocha, rspec, jest, vitest) needs the counts to
# call a run complete; an exit status alone is the run not happening.
OUTCOME_TABLE: dict[str, tuple[str, str, frozenset, frozenset]] = {
    "pytest": ("", "", frozenset({1}), frozenset({1})),
    "go": ("ok  \texample.com/x\t0.01s\n", "--- FAIL: TestGuard\nFAIL\n", frozenset({1}), frozenset({1})),
    "cargo": ("running 1 test\ntest ok\n", "running 1 test\ntest FAILED\n", frozenset({101}), frozenset({101})),
    "maven": ("Tests run: 1, Failures: 0\n", "Tests run: 1, Failures: 1\n", frozenset({1}), frozenset({1})),
    "gradle": ("", "1 test completed, 1 failed\n", frozenset({1}), frozenset({1})),
    "dotnet": ("Passed!  - Failed: 0\n", "Failed!  - Failed: 1\n", frozenset({1}), frozenset({1})),
    "jest": ("Tests:       1 passed, 1 total\n", "Tests:       1 failed, 1 total\n", frozenset({1}), frozenset()),
    "vitest": (" Test Files  1 passed (1)\n      Tests  1 passed (1)\n",
               " Test Files  1 failed (1)\n      Tests  1 failed (1)\n", frozenset({1}), frozenset()),
    "mocha": ("  1 passing (5ms)\n", "  1 passing (5ms)\n  1 failing\n",
              frozenset(s for s in EXIT_STATUSES if s != 0), frozenset()),
    "rspec": ("1 example, 0 failures\n", "2 examples, 1 failure\n", frozenset({1}), frozenset()),
    "phpunit": ("OK (1 test, 1 assertion)\n", "FAILURES!\nTests: 1, Assertions: 1, Failures: 1.\n",
                frozenset({1, 2}), frozenset({1, 2})),
    "command": ("", "", frozenset({1}), frozenset({1})),
}
# Adapters that cannot call an exit status of 0 a pass without counts.
PASS_NEEDS_EVIDENCE = frozenset({"mocha"})
# Adapters that call a non-zero exit ``failed`` only with a failing count:
# mocha's exit status is the number of failures, so the count is the verdict.
# The other count-reporting runners (jest, vitest, rspec) take the exit
# status once any summary shows the run completed.
FAIL_NEEDS_FAIL_EVIDENCE = frozenset({"mocha"})


# Suite mode: the outcome a nominated test takes from the suite's JUnit
# report. A skipped or absent test produced no outcome, so it is ``error``
# with a reason (unknown to the verifier); an errored test did not pass.
JUNIT_OUTCOME_TABLE: dict = {
    "passed": (OUTCOME_PASSED, ""),
    "failed": (OUTCOME_FAILED, ""),
    "error": (OUTCOME_ERROR, ""),
    "skipped": (OUTCOME_ERROR, "skipped under mutation"),
    None: (OUTCOME_ERROR, "not in report"),
    "": (OUTCOME_ERROR, "not in report"),
    "unknown-status": (OUTCOME_ERROR, "not in report"),
}


def check_a7() -> Tuple[int, List[str]]:
    from mipiti_verify.dependence import suite_outcome

    violations: List[str] = []
    checked = 0
    for status, expected in JUNIT_OUTCOME_TABLE.items():
        checked += 1
        got = suite_outcome(status)
        if got[0] not in OUTCOMES:
            violations.append(f"A7: suite status {status!r} -> {got[0]!r}, outside {sorted(OUTCOMES)}")
        elif got != expected:
            violations.append(f"A7: suite status {status!r} -> {got!r}, documented {expected!r}")
    root = Path(tempfile.mkdtemp(prefix="mipiti-formal-a7-"))
    try:
        names = {cls.name: cls for cls in _all_adapters()}
        missing = sorted(set(names) - set(OUTCOME_TABLE))
        if missing:
            violations.append(f"A7: adapters without an outcome table: {missing}")
        for name, (pass_out, fail_out, failed_with, failed_bare) in OUTCOME_TABLE.items():
            if name not in names:
                violations.append(f"A7: outcome table names no adapter {name!r}")
                continue
            adapter = names[name](root, run_cmd="sim {test}")
            for code in EXIT_STATUSES:
                for label, stdout in (("no output", ""), ("pass evidence", pass_out), ("fail evidence", fail_out)):
                    checked += 1
                    outcome = adapter.classify(code, stdout, "")
                    if outcome.status not in OUTCOMES:
                        violations.append(f"A7: {name} exit {code} ({label}) -> {outcome.status!r}, outside {sorted(OUTCOMES)}")
                        continue
                    if code == 0:
                        # Exit 0 is a pass; a counts runner with no counts at
                        # all did not run.
                        expected = OUTCOME_ERROR if (name in PASS_NEEDS_EVIDENCE and label == "no output") else OUTCOME_PASSED
                    elif label == "no output":
                        expected = OUTCOME_FAILED if code in failed_bare else OUTCOME_ERROR
                    elif label == "fail evidence":
                        expected = OUTCOME_FAILED if code in failed_with else OUTCOME_ERROR
                    else:  # a completed run's summary with no failing count
                        expected = (OUTCOME_FAILED if code in failed_with and name not in FAIL_NEEDS_FAIL_EVIDENCE
                                    else OUTCOME_ERROR)
                    if outcome.status != expected:
                        violations.append(f"A7: {name} exit {code} ({label}) -> {outcome.status!r}, documented {expected!r}")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return checked, violations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _report(label: str, count: int, violations: List[str]) -> bool:
    print(f"{label} ({count} checks): ", end="")
    if violations:
        print(f"FAILED ({len(violations)})")
        for v in violations:
            print(f"  {v}")
        return False
    print("VERIFIED")
    return True


def main() -> int:
    print("=" * 70)
    print("RUNNER ADAPTERS AND LANGUAGE LAYER")
    print("=" * 70)
    if shutil.which("git") is None:
        print("git is required: the mutation gate asks git whether the tree is clean")
        return 1
    parser = D.tree_sitter_available("go")
    print(f"\nFixture languages: {len(FIXTURES)}; adapters: {len(_all_adapters())}; "
          f"parser extra: {'installed' if parser else 'not installed'}\n")

    all_pass = True
    unestablished: List[str] = []

    c, v = check_a1()
    all_pass &= _report("A1 restore is identity", c, v)

    c, v, u = check_a2()
    all_pass &= _report("A2 mutation confined to the definition", c, v)
    unestablished += u

    a3, a4, v = check_a3_a4()
    all_pass &= _report("A3 compile check gates the run", a3, [x for x in v if x.startswith("A3")])
    all_pass &= _report("A4 dirty or unversioned file refused", a4, [x for x in v if x.startswith("A4")])

    c, v, u, limits = check_a5()
    all_pass &= _report("A5 parser and fallback agree", c, v)
    unestablished += u
    if limits:
        print(f"  ({limits} rows where the block heuristic is documented to land on a same-named "
              f"declaration elsewhere; checked against the documented span, not the parser's)")

    c, v = check_a6()
    all_pass &= _report("A6 coverage readers agree across formats", c, v)

    c, v = check_a7()
    all_pass &= _report("A7 outcome mapping total and closed", c, v)

    print(f"\n{'=' * 70}")
    if not all_pass:
        print("ADAPTER PROPERTIES: FAILED")
        return 1
    if unestablished:
        print(f"ADAPTER PROPERTIES VERIFIED EXCEPT {len(unestablished)} parser-arm checks "
              f"NOT ESTABLISHED (tree-sitter-language-pack not installed)")
        print(f"{'=' * 70}")
        return 0
    print("ALL ADAPTER PROPERTIES VERIFIED")
    print(f"  Mutation languages: {len(FIXTURES)}; adapters: {len(OUTCOME_TABLE)}")
    print(f"{'=' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
