"""Sound witnesses: ``sink_default_deny`` and ``typed_boundary``.

Both types state something about EVERY site in a declared scope, which is
what separates them from a scan (which finds a form) and from a test
(which drives one path). The statement is decided by one engine,
parameterised entirely by the assertion's params: which callees are
sinks, which positions of a sink are guarded, which static forms of a
value are safe, which sites a reviewer has excepted and why. Nothing is
inferred from a name, a path or a description.

``sink_default_deny``
    Over every source file in ``scope``, every site of a declared sink
    receives, at each guarded position, only a form the safe-form
    vocabulary accepts -- decided from the value written there, and for a
    data structure from every element it was written with -- or is an
    allowlisted site with a reviewed reason.
    Every site the engine could not classify counts as a violation. A
    scope that matches nothing, a file it cannot read, parse or name a
    language for, and a declared sink that never occurs are refusals: the
    witness is sound modulo the declared sink list and never vacuous.

``typed_boundary``
    Every guarded sink position in ``scope`` receives a value whose static
    form is a construction of ``boundary_type`` through one of the
    declared ``constructors``, and every construction site of that type
    in scope receives only literal or named-constant arguments or is
    allowlisted. Construction tracking is by name; a signed construction
    statement from a compile-checked probe upgrades it.

Sound in one direction only: the engine over-approximates. A callee is
matched by its leaf name on any receiver; an alias, a partial application
and a wrapper that forwards a parameter into a guarded position are sinks
too; a value escaping into reflection, dynamic evaluation, a macro body or
a function pointer is a violation.

A pass is returned only when every file the scope names was read and every
site in it was classified, so anything that leaves part of the scope
unexamined is a refusal and never a caveat on a pass: a file with no
parser for its language, a link in the region a scope entry searches, a
scope larger than the run can hold, and a forwarding chain that had not
closed when the discovery budget ran out. An allowlist excepts a site the
run flagged; it never excuses a part of the scope the run did not read,
it is bounded by the sites the run examined, and a run whose every
flagged site is an exception -- with no value anywhere in the scope
admitted by form -- has decided nothing mechanically and is a refusal
too.

Each language is read through ``languages.calls``: Python by its own
``ast``, every other tabled grammar (Verilog, SystemVerilog and VHDL
included) by tree-sitter. There is no third strategy. The parser used is
recorded per file.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Optional

from . import (
    SOUNDNESS_BY_CONSTRUCTION,
    SOUNDNESS_OVER_APPROXIMATION,
    PathTraversalError,
    VerifierResult,
    register,
    resolve_scope_files,
)
from ..languages import calls as C
from ..languages.definitions import hash_of, language_of

MODE_DEFAULT_DENY = "sink_default_deny"
MODE_TYPED_BOUNDARY = "typed_boundary"

# The types whose subject is a SCOPE of files rather than one file. Read by
# the runner (which loads their tier-2 source as an inventory, not a file)
# and by the tier-2 template contract, so the two never drift apart.
SCOPE_TYPES = frozenset({MODE_DEFAULT_DENY, MODE_TYPED_BOUNDARY})

# Every file in a scope is read by a parser that reads the language's
# grammar. There is no third strategy: a file this build cannot parse is a
# refusal, so no verdict rests on a search that saw a name without seeing
# what was handed to it.
PARSER_AST = "ast"
PARSER_TREE_SITTER = "tree-sitter"

# Grammars tried in order for a language whose first grammar rejects a
# file: SystemVerilog is a superset of Verilog, so a ``.v`` file the
# Verilog grammar cannot read may still parse cleanly.
_GRAMMAR_FALLBACKS = {"verilog": ("verilog", "systemverilog")}

# Self-validation seam for ``formal/check_sound.py``: an engine feature
# named here is switched off, and the checker asserts that the flagged set
# then stops being a superset of the ground truth. Empty in every
# production run; nothing else reads it.
_DISABLED_FOR_SELF_VALIDATION: frozenset = frozenset()
FEATURE_ALIASES = "aliases"
FEATURE_WRAPPERS = "wrappers"
FEATURE_ESCAPES = "escapes"
FEATURE_ASSIGN_SINKS = "assign_sinks"

_PYTHON_ESCAPES: dict = {
    "eval": 0, "exec": 0, "compile": 0, "getattr": 1, "setattr": 1, "delattr": 1,
    "__import__": 0, "import_module": 0,
}
_PYTHON_SHELL_CALLS = frozenset({"run", "call", "check_call", "check_output", "Popen", "getoutput",
                                 "getstatusoutput"})

# How many hops of wrapper discovery the fixed point runs before it gives
# up. Each round re-walks every file in scope, so a bound that grows with
# the file count is a bound only in principle. A forwarding chain deeper
# than this is a modelling problem, and the run says so rather than
# spending the CI job on it -- or, worse, stopping short of closure and
# reporting a pass over sites it never enumerated.
_MAX_WRAPPER_ROUNDS = 12

_MAX_LISTED_LINES = 200

# The details string is a submitted field with a fixed size limit on the
# receiving side, and one oversized row rejects the whole batch it travels
# in -- every other assertion's result with it. The counts and the refusal
# reasons are the load-bearing part and are bounded by construction; the
# per-site listing is a convenience, so it is what gives way, and the line
# that replaces it says how many sites were left out.
_MAX_DETAILS_CHARS = 4000

# Room kept back for the line that reports how many sites were left out, so
# the omission is always stated inside the budget rather than being the
# thing that overruns it.
_OMISSION_ROOM = 100

# How many reviewed exceptions one witness may carry. Each entry is a
# reviewer's statement about one site, so the list is short by nature; a
# list past this length is not one a person went through site by site, and
# it is also the one part of the params whose size the reasons reported
# back would otherwise follow.
_MAX_ALLOWLIST_ENTRIES = 500

# How many reasons a refusal states before it reports the rest as a count.
# A malformed submission can hold one reason per entry, and the refusal is
# a submitted field with a size limit of its own.
_MAX_PROBLEMS_REPORTED = 20


def _refusal(problems: list) -> str:
    """The reasons a submission cannot be evaluated, as one bounded string."""
    shown = problems[:_MAX_PROBLEMS_REPORTED]
    rest = len(problems) - len(shown)
    text = "; ".join(shown)
    if rest > 0:
        text += f"; ... ({rest} further reason(s) not listed)"
    return _within_details_bound(text)


def _within_details_bound(text: str) -> str:
    """``text`` cut to the size the receiving side accepts.

    Every detail string a verdict carries passes through here, so no input
    -- a scope of any width, a params list of any length, a parser's own
    message -- can produce a row that rejects the batch it is submitted in.
    """
    if len(text) <= _MAX_DETAILS_CHARS:
        return text
    marker = "\n... (truncated to the submitted-field bound)"
    return text[:_MAX_DETAILS_CHARS - len(marker)] + marker


def _os_reason(error: OSError) -> str:
    """Why a filesystem read failed, without where the checkout sits.

    The string form of an ``OSError`` carries the absolute path the call
    failed on. This verdict is submitted and stored, and every path it
    reports elsewhere is repository-relative, so the reason is taken from
    the error alone and the path is named separately by the caller.
    """
    return error.strerror or type(error).__name__


def _parser_counts(parser_by_file: dict) -> str:
    """How many files each parser read, as a bounded summary.

    The per-file map stays in the structured facts, where a reader can
    index it. Naming every file here would make the length of a submitted
    verdict grow with the size of the scope.
    """
    counts: dict = {}
    for parser in parser_by_file.values():
        counts[parser] = counts.get(parser, 0) + 1
    return f"{len(parser_by_file)} file(s); " + ("; ".join(
        f"{name}={n}" for name, n in sorted(counts.items())) or "none")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass
class SinkSpec:
    callee: str                 # declared name: a leaf or a dotted path
    kind: str = C.KIND_CALL
    positions: Optional[tuple] = None   # None = every position is guarded
    declared: bool = True       # False for a discovered wrapper or alias
    origin: str = "declared"    # declared | wrapper | alias | declared_wrapper

    @property
    def leaf(self) -> str:
        return self.callee.rsplit(".", 1)[-1]

    def guards(self, index: int, name: str) -> bool:
        if self.positions is None:
            return True
        return index in self.positions or (name != "" and name in self.positions)


# The sink kinds whose declared name denotes something CALLED. A store to a
# named target and an instantiated module are named again at every read of
# them, so the two rules that read a bare occurrence of a sink's name --
# rebinding it to an alias, and passing it on as a value -- are stated over
# these kinds only. Reading a signal is not an escape.
CALLABLE_KINDS = frozenset({C.KIND_CALL, C.KIND_CONSTRUCTOR, C.KIND_MACRO})


def _callable_names(sinks: dict) -> set:
    """Every name under which a callable sink may be reached: its declared
    name and the leaf that name ends in."""
    out: set = set()
    for name, spec in sinks.items():
        if spec.kind in CALLABLE_KINDS:
            out.add(name)
            out.add(spec.leaf)
    return {n for n in out if n}


@dataclass
class ArgRecord:
    index: int
    name: str
    guarded: bool
    form: str
    reason: str
    boundary: str = ""
    allowlisted: str = ""       # the reviewed reason when allowlisted
    # Whether the value is a data structure written at the site (an array,
    # list, tuple, map or dictionary literal), and the static form of each
    # element it was written with. A form is proved from the value itself:
    # being a structure is what makes the elements the thing to judge, and
    # an argument's position never licenses either.
    aggregate: bool = False
    elements: tuple = dc_field(default_factory=tuple)


@dataclass
class SiteRecord:
    file: str
    line: int
    kind: str
    callee: str                 # leaf
    path: str                   # dotted path as written
    args: list = dc_field(default_factory=list)
    declared: bool = True
    note: str = ""              # escape / construction wording
    category: str = "sink"      # sink | escape | construction | related

    @property
    def flagged_args(self) -> list:
        return [a for a in self.args if a.guarded and a.form in (C.FORM_VIOLATION, C.FORM_UNCLASSIFIABLE)]


@dataclass
class FileReport:
    file: str
    language: str
    parser: str
    sites: list = dc_field(default_factory=list)
    escapes: list = dc_field(default_factory=list)
    constructions: list = dc_field(default_factory=list)
    related: list = dc_field(default_factory=list)
    references: int = 0
    constructor_references: int = 0
    unparsed: str = ""
    aliases: dict = dc_field(default_factory=dict)
    wrappers: dict = dc_field(default_factory=dict)
    receiver_unknown: int = 0


@dataclass
class EngineSpec:
    mode: str
    scope: list
    sinks: list
    safe_forms: tuple
    allowlist: list
    wrappers: list
    boundary_type: str = ""
    constructors: tuple = ()


@dataclass
class EngineReport:
    passed: bool
    details: str
    facts: dict
    evidence_hash: str
    files: list
    problems: list
    spec: Optional[EngineSpec] = None


# ---------------------------------------------------------------------------
# Params
# ---------------------------------------------------------------------------

def _engine_params(params: dict, mode: str):
    """``(EngineSpec, problem)``: the validated params, or the reason they
    cannot be evaluated. Read here and only here, so the parameter set the
    engine consumes is the one the catalogue declares."""
    problems: list = []
    scope = params.get("scope")
    if isinstance(scope, str):
        scope = [scope]
    if not isinstance(scope, list) or not scope or not all(isinstance(s, str) and s.strip() for s in scope):
        problems.append("'scope' must be a non-empty list of repository-relative globs, directories or files")
        scope = []
    sinks_raw = params.get("sinks")
    sinks: list = []
    if not isinstance(sinks_raw, list) or not sinks_raw:
        problems.append("'sinks' must be a non-empty list of {callee, kind?, positions?}")
    else:
        for i, item in enumerate(sinks_raw):
            if isinstance(item, str):
                item = {"callee": item}
            if not isinstance(item, dict) or not str(item.get("callee") or "").strip():
                problems.append(f"sinks[{i}] names no callee")
                continue
            kind = str(item.get("kind") or C.KIND_CALL)
            if kind not in C.SINK_KINDS:
                problems.append(f"sinks[{i}] kind {kind!r} is not one of {list(C.SINK_KINDS)}")
                continue
            positions = item.get("positions")
            pos: Optional[tuple] = None
            if positions is not None:
                if not isinstance(positions, list) or not positions or not all(
                        (isinstance(p, int) and not isinstance(p, bool) and p >= 0)
                        or (isinstance(p, str) and p.strip()) for p in positions):
                    problems.append(f"sinks[{i}] positions must be a non-empty list of indexes or names")
                    continue
                pos = tuple(p if isinstance(p, int) else p.strip() for p in positions)
            callee = str(item["callee"]).strip().replace("::", ".").replace("->", ".")
            sinks.append(SinkSpec(callee=callee, kind=kind, positions=pos))
    safe_forms: tuple = ()
    boundary_type = ""
    constructors: tuple = ()
    if mode == MODE_DEFAULT_DENY:
        forms = params.get("safe_forms")
        if not isinstance(forms, list) or not forms or not all(isinstance(f, str) for f in forms):
            problems.append(f"'safe_forms' must be a non-empty subset of {list(C.SAFE_FORMS)}")
        else:
            unknown = [f for f in forms if f not in C.SAFE_FORMS]
            if unknown:
                problems.append(f"'safe_forms' names forms outside the vocabulary: {unknown}")
            safe_forms = tuple(dict.fromkeys(f for f in forms if f in C.SAFE_FORMS))
    else:
        boundary_type = str(params.get("boundary_type") or "").strip()
        if not boundary_type:
            problems.append("'boundary_type' must name the type the sinks accept")
        ctors = params.get("constructors")
        if not isinstance(ctors, list) or not ctors or not all(isinstance(c, str) and c.strip() for c in ctors):
            problems.append("'constructors' must be a non-empty list of constructor names")
        else:
            constructors = tuple(dict.fromkeys(
                c.strip().replace("::", ".").replace("->", ".") for c in ctors))
    allowlist_raw = params.get("allowlist")
    allowlist: list = []
    if allowlist_raw is not None:
        if not isinstance(allowlist_raw, list):
            problems.append("'allowlist' must be a list of {file, site, callee, reason, reviewed_by}")
        elif len(allowlist_raw) > _MAX_ALLOWLIST_ENTRIES:
            problems.append(
                f"'allowlist' carries {len(allowlist_raw)} entries; a reviewed exception list is "
                f"bounded at {_MAX_ALLOWLIST_ENTRIES}, so narrow the scope or fix the sites")
        else:
            for i, entry in enumerate(allowlist_raw):
                if not isinstance(entry, dict):
                    problems.append(f"allowlist[{i}] is not an object")
                    continue
                file_ = str(entry.get("file") or "").strip().replace("\\", "/")
                site = entry.get("site")
                try:
                    line = int(str(site).strip())
                except (TypeError, ValueError):
                    line = 0
                callee = str(entry.get("callee") or "").strip().replace("::", ".").replace("->", ".")
                reason = str(entry.get("reason") or "").strip()
                reviewer = str(entry.get("reviewed_by") or "").strip()
                if not file_ or line <= 0 or not callee:
                    problems.append(f"allowlist[{i}] must name file, site (a line number) and callee")
                    continue
                if not reason or not reviewer:
                    problems.append(f"allowlist[{i}] ({file_}:{line} {callee}) has no reason or no reviewed_by")
                    continue
                allowlist.append({"file": file_, "site": line, "callee": callee,
                                  "reason": reason, "reviewed_by": reviewer})
    wrappers_raw = params.get("wrappers")
    wrappers: list = []
    if wrappers_raw is not None:
        if not isinstance(wrappers_raw, list) or not all(isinstance(w, str) and w.strip() for w in wrappers_raw):
            problems.append("'wrappers' must be a list of callee names")
        else:
            wrappers = [w.strip().replace("::", ".").replace("->", ".") for w in wrappers_raw]
    if problems:
        return None, _refusal(problems)
    return EngineSpec(mode=mode, scope=[s.strip() for s in scope], sinks=sinks, safe_forms=safe_forms,
                      allowlist=allowlist, wrappers=wrappers, boundary_type=boundary_type,
                      constructors=constructors), ""


# ---------------------------------------------------------------------------
# Python backend
# ---------------------------------------------------------------------------

def _py_leaf(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _py_path(node) -> str:
    parts: list = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = _py_path(node.func)
        if inner:
            parts.append(inner + "()")
    return ".".join(reversed(parts))


def _py_is_literal(node) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_py_is_literal(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and _py_is_literal(k) and _py_is_literal(v)
                   for k, v in zip(node.keys, node.values))
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    return False


class _PythonBackend:
    parser = PARSER_AST

    def __init__(self, rel: str, content: str, features: frozenset) -> None:
        self.rel = rel
        self.features = features
        self.tree = ast.parse(content)
        self.parents: dict = {}
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
        self.bindings = self._binding_counts()
        self.constants = self._constants()

    # -- bindings ---------------------------------------------------------
    def _binding_counts(self) -> dict:
        counts: dict = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                counts[node.id] = counts.get(node.id, 0) + 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                counts[node.name] = counts.get(node.name, 0) + 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    name = (alias.asname or alias.name).split(".")[0]
                    counts[name] = counts.get(name, 0) + 1
        return counts

    def _scope_level(self, node) -> bool:
        parent = self.parents.get(node)
        while parent is not None:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return False
            if isinstance(parent, (ast.Module, ast.ClassDef)):
                return True
            parent = self.parents.get(parent)
        return True

    def _constants(self) -> dict:
        out: dict = {}
        for node in ast.walk(self.tree):
            targets: list = []
            value = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                targets, value = [node.targets[0]], node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                targets, value = [node.target], node.value
            if not targets or value is None or not self._scope_level(node):
                continue
            name = targets[0].id
            if self.bindings.get(name, 0) != 1:
                continue
            if _py_is_literal(value):
                out[name] = C.Form(C.FORM_NAMED_CONSTANT, f"'{name}' is bound once to a literal", "")
        return out

    def aliases(self, leaves: set) -> dict:
        if FEATURE_ALIASES in self.features:
            return {}
        aliases: dict = {}
        changed = True
        rounds = 0
        while changed and rounds < 8:
            changed = False
            rounds += 1
            known = set(leaves) | set(aliases)
            for node in ast.walk(self.tree):
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.asname and alias.name in known and alias.asname not in known:
                            aliases[alias.asname] = aliases.get(alias.name, alias.name)
                            changed = True
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        leaf = alias.name.rsplit(".", 1)[-1]
                        if alias.asname and leaf in known and alias.asname not in known:
                            aliases[alias.asname] = aliases.get(leaf, leaf)
                            changed = True
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    value = node.value
                    if value is None or len(targets) != 1 or not isinstance(targets[0], ast.Name):
                        continue
                    source = None
                    if isinstance(value, (ast.Name, ast.Attribute)):
                        source = _py_leaf(value)
                    elif isinstance(value, ast.Call) and _py_leaf(value.func) == "partial" and value.args:
                        source = _py_leaf(value.args[0])
                    alias_name = targets[0].id
                    if source in known and alias_name not in known and alias_name != source:
                        aliases[alias_name] = aliases.get(source, source)
                        changed = True
        return aliases

    # -- sites ------------------------------------------------------------
    def references(self, leaves: set) -> int:
        count = 0
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and _py_leaf(node) in leaves:
                count += 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    if alias.name.rsplit(".", 1)[-1] in leaves or (alias.asname or "") in leaves:
                        count += 1
        return count

    def _classify(self, node, boundary: dict) -> C.Form:
        if _py_is_literal(node):
            if isinstance(node, ast.JoinedStr):
                return C.Form(C.FORM_LITERAL, "f-string without expression parts", "")
            return C.Form(C.FORM_LITERAL, type(node).__name__, "")
        if isinstance(node, ast.JoinedStr):
            return C.Form(C.FORM_VIOLATION, "f-string with an expression part", "")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            forms = [self._classify(node.left, boundary), self._classify(node.right, boundary)]
            if all(f.form in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT) for f in forms):
                return C.Form(C.FORM_LITERAL_CONCAT, "concatenation of safe operands", "")
            bad = next(f for f in forms if f.form not in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT))
            return C.Form(C.FORM_VIOLATION, f"concatenation with an unsafe operand ({bad.reason})", "")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return C.Form(C.FORM_VIOLATION, "%-formatting", "")
        if isinstance(node, ast.Name):
            if node.id in self.constants:
                return self.constants[node.id]
            if boundary and node.id in boundary.get("bound", {}):
                return C.Form(C.FORM_CONSTRUCTED, f"'{node.id}' is bound once to a construction", boundary["type"])
            return C.Form(C.FORM_VIOLATION, f"identifier '{node.id}' is not a named constant", "")
        if isinstance(node, ast.Attribute):
            return C.Form(C.FORM_VIOLATION, f"attribute '{_py_path(node)}' is not a named constant", "")
        if isinstance(node, ast.Call):
            leaf, path = _py_leaf(node.func), _py_path(node.func)
            if boundary and (leaf in boundary.get("constructors", set()) or path in boundary.get("constructors", set())):
                return C.Form(C.FORM_CONSTRUCTED, f"built through {path or leaf}", boundary["type"])
            return C.Form(C.FORM_VIOLATION, f"call to {path or leaf or 'a value'}", "")
        if isinstance(node, ast.Starred):
            return C.Form(C.FORM_VIOLATION, "unpacked positional arguments", "")
        if isinstance(node, (ast.Tuple, ast.List, ast.Dict, ast.Set)):
            # A data structure written at the site: an unadmitted value at a
            # guarded position, carrying the form of each element it was
            # written with. An element reaches the sink inside the structure,
            # so it is the elements that decide, never the container.
            if isinstance(node, ast.Dict):
                parts = [n for pair in zip(node.keys, node.values) for n in pair]
            else:
                parts = list(node.elts)
            elements = tuple(
                self._classify(p, boundary) if p is not None
                else C.Form(C.FORM_VIOLATION, "unpacked into a dictionary", "")
                for p in parts)
            return C.Form(C.FORM_VIOLATION, f"{type(node).__name__} expression", "", True, elements)
        return C.Form(C.FORM_VIOLATION, f"{type(node).__name__} expression", "")

    def _bound_constructions(self, ctors: set) -> dict:
        bound: dict = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                    and isinstance(node.value, ast.Call):
                name = node.targets[0].id
                leaf, path = _py_leaf(node.value.func), _py_path(node.value.func)
                if (leaf in ctors or path in ctors) and self.bindings.get(name, 0) == 1:
                    bound[name] = True
        return bound

    def _arguments(self, call) -> list:
        args: list = []
        for i, a in enumerate(call.args):
            args.append((i, "", a))
        base = len(call.args)
        for j, kw in enumerate(call.keywords):
            args.append((base + j, kw.arg or "**", kw.value))
        return args

    def analyse(self, sinks: dict, boundary: dict) -> FileReport:
        report = FileReport(self.rel, "python", self.parser)
        boundary = dict(boundary)
        if boundary:
            boundary["bound"] = self._bound_constructions(boundary.get("constructors", set()))
        callee_nodes: set = set()
        alias_sources: set = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                callee_nodes.add(id(node.func))
                leaf, path = _py_leaf(node.func), _py_path(node.func)
                spec = _match_sink(sinks, leaf, path, (C.KIND_CALL, C.KIND_CONSTRUCTOR, C.KIND_MACRO))
                if spec is not None:
                    site = SiteRecord(self.rel, node.lineno, spec.kind, leaf, path, declared=spec.declared)
                    for index, name, expr in self._arguments(node):
                        guarded = spec.guards(index, name)
                        if name == "**":
                            form = C.Form(C.FORM_VIOLATION, "unpacked keyword arguments", "")
                        else:
                            form = self._classify(expr, boundary)
                        site.args.append(ArgRecord(index, name, guarded, form.form, form.reason,
                                                   form.boundary, aggregate=form.aggregate, elements=form.elements))
                    report.sites.append(site)
                    if isinstance(node.func, ast.Attribute) and not isinstance(node.func.value, ast.Name):
                        report.receiver_unknown += 1
                elif boundary and (leaf in boundary.get("constructors", set()) or path in boundary.get("constructors", set())):
                    site = SiteRecord(self.rel, node.lineno, C.KIND_CONSTRUCTOR, leaf, path,
                                      category="construction", note=f"construction of {boundary['type']}")
                    for index, name, expr in self._arguments(node):
                        form = self._classify(expr, {})
                        if form.form not in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT):
                            form = C.Form(C.FORM_VIOLATION, f"construction from a non-literal ({form.reason})", "")
                        site.args.append(ArgRecord(index, name, True, form.form, form.reason))
                    report.constructions.append(site)
                elif FEATURE_ESCAPES not in self.features:
                    self._escape(node, leaf, path, report)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and FEATURE_ASSIGN_SINKS not in self.features:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if value is None:
                    continue
                for target in targets:
                    leaf, path = _py_leaf(target), _py_path(target)
                    spec = _match_sink(sinks, leaf, path, (C.KIND_ASSIGN,))
                    if spec is None:
                        continue
                    site = SiteRecord(self.rel, node.lineno, C.KIND_ASSIGN, leaf, path, declared=spec.declared)
                    form = self._classify(value, boundary)
                    site.args.append(ArgRecord(0, "", spec.guards(0, ""), form.form, form.reason,
                                               form.boundary, aggregate=form.aggregate, elements=form.elements))
                    report.sites.append(site)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if value is not None and len(targets) == 1 and isinstance(targets[0], ast.Name):
                    if isinstance(value, (ast.Name, ast.Attribute)):
                        alias_sources.add(id(value))
                    elif isinstance(value, ast.Call) and _py_leaf(value.func) == "partial" and value.args:
                        alias_sources.add(id(value.args[0]))
        # A sink named as a value rather than called escapes the check.
        if FEATURE_ESCAPES not in self.features:
            leaves = {s.leaf for s in sinks.values() if s.kind in CALLABLE_KINDS}
            for node in ast.walk(self.tree):
                if not isinstance(node, (ast.Name, ast.Attribute)) or _py_leaf(node) not in leaves:
                    continue
                if id(node) in callee_nodes or id(node) in alias_sources:
                    continue
                if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                    continue
                parent = self.parents.get(node)
                if isinstance(parent, ast.Attribute) and parent.value is node:
                    continue
                if isinstance(node, ast.Attribute) and isinstance(parent, ast.Call) and parent.func is node:
                    continue
                report.escapes.append(SiteRecord(
                    self.rel, node.lineno, "escape", _py_leaf(node), _py_path(node), category="escape",
                    note="sink escapes as a value",
                    args=[ArgRecord(0, "", True, C.FORM_VIOLATION, "sink escapes as a value")]))
        report.references = self.references({s.leaf for s in sinks.values()})
        if boundary:
            report.constructor_references = self.references(
                {c.rsplit(".", 1)[-1] for c in boundary.get("constructors", set())})
        report.sites.extend(self._related(sinks))
        return report

    def _related(self, sinks: dict) -> list:
        """Calls into the receivers the declared sinks live on (``subprocess.*``
        for a declared ``subprocess.run``; the module a bare sink was
        imported from), declared or not, for the reviewer's inventory."""
        receivers: set = set()
        leaves = {s.leaf for s in sinks.values() if s.declared}
        for spec in sinks.values():
            if spec.declared and "." in spec.callee:
                receivers.add(spec.callee.rsplit(".", 1)[0])
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(a.name in leaves for a in node.names):
                    receivers.add(node.module)
        out: list = []
        if not receivers:
            return out
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                path = _py_path(node.func)
                leaf = _py_leaf(node.func)
                if leaf in leaves:
                    continue
                receiver = path.rsplit(".", 1)[0] if "." in path else ""
                if receiver and any(receiver == r or receiver.endswith("." + r) or r.endswith("." + receiver)
                                    for r in receivers):
                    out.append(SiteRecord(self.rel, node.lineno, C.KIND_CALL, leaf, path, category="related",
                                          note="call into a sink's receiver (undeclared)"))
        return out

    def _escape(self, node, leaf: str, path: str, report: FileReport) -> None:
        index = _PYTHON_ESCAPES.get(leaf)
        args = self._arguments(node)
        if index is not None:
            target = next((a for a in args if a[0] == index and a[1] == ""), None)
            if target is None or not _py_is_literal(target[2]):
                form = self._classify(target[2], {}) if target is not None else C.Form(C.FORM_VIOLATION, "no argument", "")
                if form.form not in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT):
                    report.escapes.append(SiteRecord(
                        self.rel, node.lineno, "escape", leaf, path, category="escape",
                        note=f"{path or leaf} with a non-literal name ({form.reason})",
                        args=[ArgRecord(index, "", True, C.FORM_VIOLATION, form.reason)]))
            return
        if leaf in _PYTHON_SHELL_CALLS:
            shell = next((kw for kw in node.keywords if kw.arg == "shell"), None)
            if shell is not None and isinstance(shell.value, ast.Constant) and shell.value.value is True:
                first = node.args[0] if node.args else None
                form = self._classify(first, {}) if first is not None else C.Form(C.FORM_VIOLATION, "no command", "")
                if form.form not in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT):
                    report.escapes.append(SiteRecord(
                        self.rel, node.lineno, "escape", leaf, path, category="escape",
                        note=f"{path or leaf} with shell=True and a non-literal command ({form.reason})",
                        args=[ArgRecord(0, "", True, C.FORM_VIOLATION, form.reason)]))

    def wrappers(self, sinks: dict) -> dict:
        """Functions that forward a parameter into a guarded position of a
        sink: each is a sink itself, every position guarded."""
        if FEATURE_WRAPPERS in self.features:
            return {}
        found: dict = {}
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {a.arg for a in node.args.args + node.args.posonlyargs + node.args.kwonlyargs}
            if node.args.vararg:
                params.add(node.args.vararg.arg)
            if node.args.kwarg:
                params.add(node.args.kwarg.arg)
            params.discard("self")
            params.discard("cls")
            if not params or node.name in sinks:
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                spec = _match_sink(sinks, _py_leaf(inner.func), _py_path(inner.func),
                                   (C.KIND_CALL, C.KIND_CONSTRUCTOR, C.KIND_MACRO))
                if spec is None:
                    continue
                for index, name, expr in self._arguments(inner):
                    if spec.guards(index, name) and any(
                            isinstance(n, ast.Name) and n.id in params for n in ast.walk(expr)):
                        found[node.name] = SinkSpec(node.name, C.KIND_CALL, None, declared=False, origin="wrapper")
                        break
                if node.name in found:
                    break
        return found


# ---------------------------------------------------------------------------
# tree-sitter backend
# ---------------------------------------------------------------------------

class _TreeSitterBackend:
    parser = PARSER_TREE_SITTER

    def __init__(self, rel: str, language: str, root, table: C.CallTable, features: frozenset) -> None:
        self.rel = rel
        self.language = language
        self.root = root
        self.table = table
        self.features = features
        self.constants = C.constant_bindings(root, table, lambda n, b: C.classify_value(n, table, {}, b))
        self.counts = C.binding_counts(root, table)

    def aliases(self, leaves: set) -> dict:
        if FEATURE_ALIASES in self.features:
            return {}
        return C.alias_bindings(self.root, self.table, set(leaves))

    def references(self, leaves: set) -> int:
        count = 0
        for n in C.walk(self.root):
            if n.type in self.table.identifiers and not any(c.is_named for c in n.children) \
                    and C.text(n).strip() in leaves:
                count += 1
        return count

    def _bound_constructions(self, ctors: set) -> dict:
        bound: dict = {}
        t = self.table
        for node in C.walk(self.root):
            found = None
            if node.type in t.declarations:
                found = C.declaration_of(node, t)
            elif node.type in t.assignments:
                pair = C.assignment_of(node, t)
                found = (pair[0], pair[1][0]) if pair and pair[1] else None
            if found is None:
                continue
            name_node, value = found
            value = C._unwrap(value, t)
            if value.type in t.calls or value.type in t.constructors:
                callee = C.callee_of(value, t)
                leaf, path = C.leaf_name(callee, t), C.path_name(callee, t)
                name = C.leaf_name(name_node, t)
                if (leaf in ctors or path in ctors) and self.counts.get(name, 0) == 1:
                    bound[name] = True
        return bound

    def analyse(self, sinks: dict, boundary: dict) -> FileReport:
        t = self.table
        report = FileReport(self.rel, self.language, self.parser)
        boundary = dict(boundary)
        if boundary:
            boundary["bound"] = self._bound_constructions(boundary.get("constructors", set()))
        callee_ids: set = set()
        alias_sources: set = set()
        leaves = {s.leaf for s in sinks.values()}
        for node in C.walk(self.root):
            nt = node.type
            if nt in t.calls or nt in t.constructors or nt in t.macros:
                callee = C.callee_of(node, t)
                if callee is not None:
                    for n in C.walk(callee):
                        callee_ids.add(n.id)
                leaf, path = C.leaf_name(callee, t), C.path_name(callee, t)
                if nt in t.calls and t.hdl and node.parent is not None and node.parent.type in t.calls:
                    continue  # the call wrapper and its inner call share a site
                kinds = (C.KIND_CONSTRUCTOR,) if nt in t.constructors else \
                    (C.KIND_MACRO,) if nt in t.macros else (C.KIND_CALL, C.KIND_CONSTRUCTOR, C.KIND_MACRO)
                spec = _match_sink(sinks, leaf, path, kinds)
                if spec is not None:
                    site = SiteRecord(self.rel, C.line_of(node), spec.kind, leaf, path, declared=spec.declared)
                    for arg in C.arguments_of(node, t):
                        form = C.classify_value(arg.node, t, self.constants, boundary)
                        site.args.append(ArgRecord(arg.index, arg.name, spec.guards(arg.index, arg.name),
                                                   form.form, form.reason, form.boundary,
                                                   aggregate=form.aggregate, elements=form.elements))
                    report.sites.append(site)
                    if callee is not None and C.named_children(callee) and not all(
                            n.type in t.identifiers for n in C.walk(callee)
                            if n.is_named and n.id != callee.id):
                        report.receiver_unknown += 1
                    continue
                if boundary and (leaf in boundary.get("constructors", set()) or path in boundary.get("constructors", set())):
                    site = SiteRecord(self.rel, C.line_of(node), C.KIND_CONSTRUCTOR, leaf, path,
                                      category="construction", note=f"construction of {boundary['type']}")
                    for arg in C.arguments_of(node, t):
                        form = C.classify_value(arg.node, t, self.constants, {})
                        if form.form not in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT):
                            form = C.Form(C.FORM_VIOLATION, f"construction from a non-literal ({form.reason})", "")
                        site.args.append(ArgRecord(arg.index, arg.name, True, form.form, form.reason))
                    report.constructions.append(site)
                    continue
                if FEATURE_ESCAPES not in self.features:
                    self._escape(node, callee, leaf, path, report)
            elif nt in t.assignments and FEATURE_ASSIGN_SINKS not in self.features:
                pair = C.assignment_of(node, t)
                if pair is None:
                    continue
                target, values = pair
                leaf, path = C.leaf_name(target, t), C.path_name(target, t)
                spec = _match_sink(sinks, leaf, path, (C.KIND_ASSIGN,))
                if spec is None:
                    continue
                site = SiteRecord(self.rel, C.line_of(node), C.KIND_ASSIGN, leaf, path, declared=spec.declared)
                for index, value in enumerate(values):
                    form = C.classify_value(value, t, self.constants, boundary)
                    site.args.append(ArgRecord(index, "", spec.guards(index, ""), form.form, form.reason,
                                               form.boundary, aggregate=form.aggregate, elements=form.elements))
                report.sites.append(site)
            elif nt in t.instantiations:
                found = C.instantiation_of(node, t)
                if found is None:
                    continue
                type_node, args = found
                leaf, path = C.leaf_name(type_node, t), C.path_name(type_node, t)
                spec = _match_sink(sinks, leaf, path, (C.KIND_INSTANTIATE,))
                if spec is None:
                    continue
                site = SiteRecord(self.rel, C.line_of(node), C.KIND_INSTANTIATE, leaf, path, declared=spec.declared)
                for arg in args:
                    form = C.classify_value(arg.node, t, self.constants, boundary)
                    site.args.append(ArgRecord(arg.index, arg.name, spec.guards(arg.index, arg.name),
                                               form.form, form.reason, form.boundary,
                                               aggregate=form.aggregate, elements=form.elements))
                report.sites.append(site)
            elif nt in t.macro_definitions and FEATURE_ESCAPES not in self.features:
                name = C.field(node, "name")
                body = C.field(node, "value")
                body_text = C.text(body) if body is not None else ""
                for leaf in sorted(leaves):
                    if re.search(rf"\b{re.escape(leaf)}\b", body_text):
                        report.escapes.append(SiteRecord(
                            self.rel, C.line_of(node), "escape", leaf, C.text(name).strip() if name else "",
                            category="escape", note=f"macro body names sink '{leaf}'",
                            args=[ArgRecord(0, "", True, C.FORM_VIOLATION, f"macro body names sink '{leaf}'")]))
                        break
            if nt in t.declarations or nt in t.assignments or nt in t.aliases:
                found = C.declaration_of(node, t) if nt in t.declarations else None
                if found is None and nt in t.assignments:
                    pair = C.assignment_of(node, t)
                    found = (pair[0], pair[1][0]) if pair and pair[1] else None
                if found is not None:
                    value = C._unwrap(found[1], t)
                    if C._is_member_reference(value, t):
                        for n in C.walk(value):
                            alias_sources.add(n.id)
        if FEATURE_ESCAPES not in self.features:
            self._value_escapes(sinks, callee_ids, alias_sources, report)
        report.references = self.references(leaves)
        if boundary:
            report.constructor_references = self.references(
                {c.rsplit(".", 1)[-1] for c in boundary.get("constructors", set())})
        report.sites.extend(self._related(sinks))
        return report

    def _escape(self, node, callee, leaf: str, path: str, report: FileReport) -> None:
        t = self.table
        if callee is not None and callee.type in t.variable_callee:
            report.escapes.append(SiteRecord(
                self.rel, C.line_of(node), "escape", leaf, path, category="escape",
                note="call through a variable (dynamic dispatch)",
                args=[ArgRecord(0, "", True, C.FORM_VIOLATION, "call through a variable")]))
            return
        index = t.escapes.get(leaf)
        if index is None:
            return
        args = C.arguments_of(node, t)
        target = next((a for a in args if a.index == index), None)
        if target is None:
            form = C.Form(C.FORM_VIOLATION, "no argument", "")
        else:
            form = C.classify_value(target.node, t, self.constants, {})
        if form.form not in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT):
            report.escapes.append(SiteRecord(
                self.rel, C.line_of(node), "escape", leaf, path, category="escape",
                note=f"{path or leaf} with a non-literal argument ({form.reason})",
                args=[ArgRecord(index, "", True, C.FORM_VIOLATION, form.reason)]))

    def _value_escapes(self, sinks: dict, callee_ids: set, alias_sources: set, report: FileReport) -> None:
        t = self.table
        if t.hdl:
            # In a hardware description every occurrence of a name is a read
            # of the thing it names; there is no value to pass on.
            return
        leaves = {s.leaf for s in sinks.values() if s.kind in CALLABLE_KINDS}
        definition_names: set = set()
        for _node, name, _params in C.definition_nodes(self.root, self.language):
            definition_names.add(name)
        for n in C.walk(self.root):
            if n.type not in t.identifiers or any(c.is_named for c in n.children):
                continue
            name = C.text(n).strip()
            if name not in leaves or n.id in callee_ids or n.id in alias_sources:
                continue
            if C.is_import_context(n, t):
                continue
            parent = n.parent
            # The declaring occurrence of a wrapper's own name, or a field /
            # member name on a receiver chain, is not a value escape.
            if parent is not None and (parent.type in t.declarations or parent.type in t.constants
                                       or parent.type in ("function_declaration", "function_definition",
                                                          "method_declaration", "function_item",
                                                          "function_declarator", "method", "function_body",
                                                          "procedure_body", "function_body_declaration",
                                                          "task_body_declaration", "name_of_instance",
                                                          "param_assignment", "class_declaration")):
                continue
            if name in definition_names and parent is not None and parent.type not in t.argument_lists \
                    and parent.type not in t.argument_wrappers:
                continue
            if parent is not None and parent.type in t.assignments:
                pair = C.assignment_of(parent, t)
                if pair is not None and pair[0].id == n.id:
                    continue
            report.escapes.append(SiteRecord(
                self.rel, C.line_of(n), "escape", name, name, category="escape",
                note="sink escapes as a value",
                args=[ArgRecord(0, "", True, C.FORM_VIOLATION, "sink escapes as a value")]))

    def _related(self, sinks: dict) -> list:
        t = self.table
        receivers = {s.callee.rsplit(".", 1)[0] for s in sinks.values() if s.declared and "." in s.callee}
        leaves = {s.leaf for s in sinks.values() if s.declared}
        out: list = []
        if not receivers:
            return out
        for node in C.walk(self.root):
            if node.type in t.calls or node.type in t.constructors:
                callee = C.callee_of(node, t)
                leaf, path = C.leaf_name(callee, t), C.path_name(callee, t)
                if leaf in leaves or "." not in path:
                    continue
                receiver = path.rsplit(".", 1)[0]
                if any(receiver == r or receiver.endswith("." + r) or r.endswith("." + receiver) for r in receivers):
                    out.append(SiteRecord(self.rel, C.line_of(node), C.KIND_CALL, leaf, path, category="related",
                                          note="call into a sink's receiver (undeclared)"))
        return out

    def wrappers(self, sinks: dict) -> dict:
        if FEATURE_WRAPPERS in self.features:
            return {}
        t = self.table
        found: dict = {}
        for node, name, params in C.definition_nodes(self.root, self.language):
            if not name or not params or name in sinks:
                continue
            for inner in C.walk(node):
                if inner.id == node.id:
                    continue
                spec = None
                args: list = []
                if inner.type in t.calls or inner.type in t.constructors or inner.type in t.macros:
                    callee = C.callee_of(inner, t)
                    spec = _match_sink(sinks, C.leaf_name(callee, t), C.path_name(callee, t),
                                       (C.KIND_CALL, C.KIND_CONSTRUCTOR, C.KIND_MACRO))
                    args = C.arguments_of(inner, t) if spec else []
                elif inner.type in t.assignments and FEATURE_ASSIGN_SINKS not in self.features:
                    pair = C.assignment_of(inner, t)
                    if pair is not None:
                        spec = _match_sink(sinks, C.leaf_name(pair[0], t), C.path_name(pair[0], t), (C.KIND_ASSIGN,))
                        args = [C.Argument(i, "", v) for i, v in enumerate(pair[1])] if spec else []
                elif inner.type in t.instantiations:
                    pair = C.instantiation_of(inner, t)
                    if pair is not None:
                        spec = _match_sink(sinks, C.leaf_name(pair[0], t), C.path_name(pair[0], t),
                                           (C.KIND_INSTANTIATE,))
                        args = pair[1] if spec else []
                if spec is None:
                    continue
                if any(spec.guards(a.index, a.name) and C.mentions(a.node, params, t) for a in args):
                    found[name] = SinkSpec(name, C.KIND_CALL, None, declared=False, origin="wrapper")
                    break
        return found


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _match_sink(sinks: dict, leaf: str, path: str, kinds: tuple) -> Optional[SinkSpec]:
    """The sink a callee names: by full dotted path when the declaration
    carries one, else by leaf on any receiver. A leaf-declared sink matches
    ``x.y.leaf`` (over-approximate); a path-declared sink matches a path
    that ends with it."""
    if not leaf:
        return None
    best = None
    for spec in sinks.values():
        if spec.kind not in kinds and not (spec.origin in ("wrapper", "alias") and C.KIND_CALL in kinds):
            continue
        if "." in spec.callee:
            if path == spec.callee or path.endswith("." + spec.callee):
                return spec
            continue
        if spec.leaf == leaf and best is None:
            best = spec
    return best


def _parse_backend(rel: str, language: str, content: str, features: frozenset):
    """``(backend, problem)`` for one file. A language with a parser whose
    parser rejects the file is a problem, never a silent fallback."""
    if language == "python":
        try:
            return _PythonBackend(rel, content, features), ""
        except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
            return None, f"unparsed: {rel} ({type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''})"
    table = C.table_for(language)
    if table is None:
        # No call grammar for this language in this build. Sites could still
        # be located by name, but the arguments at them could not be read,
        # and the sites the name search missed would not be counted at all.
        # A scope this build cannot read is a refusal, never a pass with a
        # caveat attached.
        return None, (
            f"unparsed: {rel} (this build reads no call grammar for {language}; "
            f"narrow the scope to the languages it reads)")
    from ..languages.definitions import get_parser

    tried = 0
    for grammar in _GRAMMAR_FALLBACKS.get(language, (language,)):
        parser = get_parser(grammar)
        if parser is None:
            continue
        tried += 1
        try:
            tree = parser.parse(content.encode("utf-8"))
        except Exception as e:  # noqa: BLE001 - a parser crash is "unparsed"
            return None, f"unparsed: {rel} ({type(e).__name__})"
        if not tree.root_node.has_error:
            return _TreeSitterBackend(rel, language, tree.root_node, C.table_for(grammar) or table, features), ""
    if tried:
        return None, f"unparsed: {rel} (the {language} grammar reports syntax errors)"
    return None, (
        f"unparsed: {rel} (no {language} parser is installed, so the arguments at its sites "
        f"cannot be read; install the 'ast' extra of this package, or narrow the scope to "
        f"the languages this install reads)")


def _signed_notes(project_root: Path, spec: EngineSpec) -> dict:
    """What signed statements in the checkout say about this witness's
    residuals, as assumption lines.

    Two residuals can be upgraded by evidence the customer's own build
    produces: that a value of the boundary type cannot be built from a
    non-literal (a probe the toolchain refused to compile), and that a named
    reviewer stands behind the allowlisted sites at this commit. Neither
    decides the verdict -- both state, in the facts a reader sees, whether
    the residual is carried on the author's word or on a signed statement.
    """
    notes: dict = {}
    if spec.mode != MODE_TYPED_BOUNDARY and not spec.allowlist:
        return notes
    entries: list = []
    try:
        from .tests import (
            KIND_ALLOWLIST_REVIEW,
            KIND_CONSTRUCTION,
            load_verified_statements,
            statement_kind,
        )

        statements, _problems, _commit = load_verified_statements(project_root)
        entries = [(statement_kind(st), (st.get("predicate") or {}), prov)
                   for st, prov in statements]
    except Exception:  # noqa: BLE001 - a checkout with no readable attestation says so
        entries = []
        KIND_CONSTRUCTION, KIND_ALLOWLIST_REVIEW = "construction", "allowlist-review"

    if spec.mode == MODE_TYPED_BOUNDARY:
        witness = ""
        for kind, predicate, provenance in entries:
            if kind != KIND_CONSTRUCTION or predicate.get("outcome") != "passed":
                continue
            if str(predicate.get("boundary_type") or "") != spec.boundary_type:
                continue
            probes = len(predicate.get("tests") or [])
            witness = (f"a construction statement ({provenance}) records "
                       f"{probes} probe(s) the toolchain refused to compile")
            break
        notes["by_construction"] = (
            f"construction of {spec.boundary_type} is tracked by name; "
            + (witness or "no signed construction statement covers this type at this commit"))

    if spec.allowlist:
        wanted = {(e["file"], e["site"], e["callee"]) for e in spec.allowlist}
        review = ""
        for kind, predicate, provenance in entries:
            if kind != KIND_ALLOWLIST_REVIEW:
                continue
            covered = {
                (str(t.get("file") or ""), int(t.get("site") or 0), str(t.get("callee") or ""))
                for t in (predicate.get("tests") or []) if isinstance(t, dict)
            }
            if wanted <= covered:
                review = f"an allowlist review statement ({provenance}) covers every entry"
                break
        notes["allowlist_provenance"] = (
            f"{len(spec.allowlist)} reviewed exception(s), their content inside the "
            f"evidence hash; "
            + (review or "no signed allowlist review covers them at this commit"))
    return notes


# Reports already computed in this process, keyed by everything the report
# is a statement about: the mode, the engine features, the evidence hash
# (every file's content and the whole declaration) and the signed
# statements the run folds into its residual lines. Bounded, and small:
# within one invocation the same witness is evaluated twice (a verdict,
# then the inventory a semantic review is asked about), and a scope is
# parsed once for both.
_REPORT_CACHE: "OrderedDict[tuple, EngineReport]" = OrderedDict()
_REPORT_CACHE_MAX = 32


def _remember(key: tuple, report: "EngineReport") -> None:
    _REPORT_CACHE[key] = report
    _REPORT_CACHE.move_to_end(key)
    while len(_REPORT_CACHE) > _REPORT_CACHE_MAX:
        _REPORT_CACHE.popitem(last=False)


class SinkEngine:
    """One run of the default-deny check over a scope."""

    def __init__(self, project_root: Path, spec: EngineSpec, *, features: Optional[frozenset] = None) -> None:
        self.root = project_root.resolve()
        self.spec = spec
        self.features = features if features is not None else _DISABLED_FOR_SELF_VALIDATION

    # -- scope --------------------------------------------------------------
    def _scope(self):
        """``(files, problem)``: the files in scope with their language and
        content, or the reason the scope cannot be read."""
        try:
            paths = resolve_scope_files(self.root, self.spec.scope)
        except PathTraversalError as e:
            return [], f"scope refused: {e}"
        except ValueError as e:
            return [], f"scope refused: {e}"
        except OSError as e:
            return [], f"scope unreadable: {_os_reason(e)}"
        if not paths:
            return [], "scope matched no files"
        out: list = []
        for p in paths:
            rel = p.relative_to(self.root).as_posix()
            language = language_of(rel)
            if not language:
                return [], f"unclassifiable file in scope: {rel} (no language for its extension; make the scope exact)"
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                return [], f"unreadable file in scope: {rel} ({_os_reason(e)})"
            out.append((rel, language, content))
        return out, ""

    # -- run --------------------------------------------------------------
    def run(self) -> EngineReport:
        spec = self.spec
        files, problem = self._scope()
        facts: dict = {"files": 0, "sites": 0, "safe_by_form": {}, "allowlisted": 0, "violations": 0,
                       "unclassifiable": 0, "stale_allowlist": 0, "wrappers_discovered": 0,
                       "parser_by_file": {}, "assumptions": {}, "escapes": 0, "constructions": 0}
        if problem:
            return EngineReport(False, _within_details_bound(f"{spec.mode} FAIL: {problem}"),
                                facts, "", [], [problem], spec)
        evidence_hash = self._evidence_hash(files)
        signed = _signed_notes(self.root, spec)
        # The scope is read on every call, so the report is always a
        # statement about the files as they are now. Parsing them again to
        # reach a report already computed for exactly this content is not:
        # the key below covers every file's content, the whole declaration
        # and the signed statements, so a hit is the same statement about
        # the same bytes.
        cache_key = (spec.mode, self.features, evidence_hash,
                     json.dumps(signed, sort_keys=True))
        cached = _REPORT_CACHE.get(cache_key)
        if cached is not None:
            return cached
        backends: list = []
        for rel, language, content in files:
            backend, err = _parse_backend(rel, language, content, self.features)
            if err:
                facts["parser_by_file"][rel] = "none"
                return EngineReport(False, _within_details_bound(f"{spec.mode} FAIL: {err}"),
                                    facts, evidence_hash, [], [err], spec)
            backends.append(backend)
            facts["parser_by_file"][rel] = backend.parser
        facts["files"] = len(files)

        # Sinks: declared, declared wrappers, then discovered wrappers to a
        # fixed point across the scope; aliases are per file.
        sinks: dict = {s.callee: s for s in spec.sinks}
        for w in spec.wrappers:
            if w not in sinks:
                sinks[w] = SinkSpec(w, C.KIND_CALL, None, declared=True, origin="declared_wrapper")
        boundary: dict = {}
        if spec.mode == MODE_TYPED_BOUNDARY:
            boundary = {"type": spec.boundary_type, "constructors": set(spec.constructors)}
        discovered: dict = {}
        settled = False
        for _round in range(_MAX_WRAPPER_ROUNDS):
            grew = False
            for backend in backends:
                per_file = dict(sinks)
                for alias in backend.aliases(_callable_names(per_file)):
                    per_file[alias] = SinkSpec(alias, C.KIND_CALL, None, declared=False, origin="alias")
                for name, wrapper in backend.wrappers(per_file).items():
                    if name not in sinks:
                        sinks[name] = wrapper
                        discovered[name] = wrapper
                        grew = True
            if not grew:
                settled = True
                break
        if not settled:
            # The sink set was still growing when the budget ran out, so the
            # scope holds a forwarding chain deeper than this many hops and
            # the enumeration is not closed. An unclosed sink set means sites
            # that were never looked at, which is a refusal.
            problem = (
                f"the chain of functions forwarding into a declared sink is deeper than "
                f"{_MAX_WRAPPER_ROUNDS} hops, so the sink set did not close over this scope; "
                f"declare the outermost of them in 'wrappers', or narrow the scope")
            facts["files"] = len(files)
            return EngineReport(False, _within_details_bound(f"{spec.mode} FAIL: {problem}"),
                                facts, evidence_hash, [], [problem], spec)
        facts["wrappers_discovered"] = len(discovered)

        reports: list = []
        for backend in backends:
            per_file = dict(sinks)
            aliases = backend.aliases(_callable_names(per_file))
            for alias in aliases:
                per_file[alias] = SinkSpec(alias, C.KIND_CALL, None, declared=False, origin="alias")
            report = backend.analyse(per_file, boundary)
            report.aliases = aliases
            report.wrappers = {n: w for n, w in discovered.items()}
            reports.append(report)

        # Classification under the declared vocabulary.
        safe = set(spec.safe_forms) if spec.mode == MODE_DEFAULT_DENY else set()
        for report in reports:
            for site in report.sites:
                if site.category != "sink":
                    continue
                guarded = [a for a in site.args if a.guarded]
                if not guarded:
                    # The site reaches the sink but the reader saw nothing at
                    # a guarded position: no argument was read, or none sits
                    # where the declaration guards. Unread is not safe -- the
                    # site is unclassifiable and needs a reviewed exception.
                    site.args.append(ArgRecord(
                        0, "", True, C.FORM_UNCLASSIFIABLE,
                        "no guarded argument could be read at this site"))
                    guarded = [site.args[-1]]
                for a in guarded:
                    if spec.mode == MODE_TYPED_BOUNDARY:
                        if a.form == C.FORM_CONSTRUCTED and a.boundary == spec.boundary_type:
                            continue
                        if a.form == C.FORM_UNCLASSIFIABLE:
                            continue
                        a.form, a.reason = C.FORM_VIOLATION, f"not a construction of {spec.boundary_type} ({a.reason})"
                        continue
                    if a.form in safe or a.form == C.FORM_UNCLASSIFIABLE:
                        continue
                    if a.form in (C.FORM_LITERAL, C.FORM_NAMED_CONSTANT, C.FORM_LITERAL_CONCAT):
                        # A safe form the assertion did not admit.
                        a.form, a.reason = C.FORM_VIOLATION, f"{a.form} is not an admitted safe form ({a.reason})"
                        continue
                    if C.FORM_PARAMETER_BINDING in safe and a.aggregate:
                        # A data structure written at the site, judged by what
                        # it was written with: every element must itself be a
                        # form this assertion admits, since an element reaches
                        # the sink inside the structure exactly as a value at
                        # the position does. A structure holding a value built
                        # from anything else -- an interpolation, a name that
                        # is not a constant, a call, a nested structure -- is a
                        # violation, and so is one no element could be read
                        # from: whether the callee treats such a value as data
                        # or as the statement it runs is a fact about the
                        # callee, which this engine does not read. An operator
                        # whose sink takes bound values one per argument names
                        # the statement position in ``positions`` instead, so
                        # the data positions are not guarded at all.
                        admitted = safe - {C.FORM_PARAMETER_BINDING}
                        unadmitted = next((e for e in a.elements if e.form not in admitted), None)
                        if a.elements and unadmitted is None:
                            seen = tuple(dict.fromkeys(e.form for e in a.elements))
                            a.form, a.reason = C.FORM_PARAMETER_BINDING, (
                                f"a data structure whose {len(a.elements)} element(s) are each an "
                                f"admitted form ({', '.join(seen)})")
                            continue
                        detail = (f"holds {unadmitted.reason}" if unadmitted is not None
                                  else "was written with no element this build could read")
                        a.form, a.reason = C.FORM_VIOLATION, (
                            f"a data structure at a guarded position that {detail}; name the "
                            f"statement position in 'positions' if the callee takes bound data here")
                        continue
                    if a.form != C.FORM_VIOLATION:
                        a.form, a.reason = C.FORM_VIOLATION, f"{a.form} is not an admitted safe form ({a.reason})"

        # Allowlist: every entry must match a flagged site, inside scope.
        scope_files = {r.file for r in reports}
        flagged: list = []
        for report in reports:
            for site in report.sites:
                if site.category == "sink" and site.flagged_args:
                    flagged.append(site)
            for site in report.escapes:
                flagged.append(site)
            for site in report.constructions:
                if site.flagged_args:
                    flagged.append(site)
        stale: list = []
        allowlisted_sites = 0
        for entry in spec.allowlist:
            if entry["file"] not in scope_files:
                stale.append(f"{entry['file']}:{entry['site']} {entry['callee']} (file not in scope)")
                continue
            matched = False
            for site in flagged:
                if site.file == entry["file"] and site.line == entry["site"] and \
                        entry["callee"] in (site.callee, site.path):
                    for a in site.args:
                        if a.guarded and a.form in (C.FORM_VIOLATION, C.FORM_UNCLASSIFIABLE) and not a.allowlisted:
                            a.allowlisted = f"{entry['reason']} (reviewed by {entry['reviewed_by']})"
                    matched = True
                    allowlisted_sites += 1
            if not matched:
                stale.append(f"{entry['file']}:{entry['site']} {entry['callee']} (matches no flagged site)")

        # Counts.
        violations: list = []
        unclassifiable: list = []
        safe_by_form: dict = {}
        sites_total = 0
        escapes_total = 0
        constructions_total = 0
        receiver_unknown = 0
        references = 0
        constructor_references = 0
        for report in reports:
            receiver_unknown += report.receiver_unknown
            references += report.references
            constructor_references += report.constructor_references
            for site in report.sites:
                if site.category != "sink":
                    continue
                sites_total += 1
                for a in site.args:
                    if not a.guarded:
                        continue
                    if a.allowlisted:
                        continue
                    if a.form == C.FORM_VIOLATION:
                        violations.append(f"{site.file}:{site.line} {site.path or site.callee} arg[{a.name or a.index}] {a.reason}")
                    elif a.form == C.FORM_UNCLASSIFIABLE:
                        unclassifiable.append(f"{site.file}:{site.line} {site.path or site.callee} {a.reason}")
                    else:
                        safe_by_form[a.form] = safe_by_form.get(a.form, 0) + 1
            for site in report.escapes:
                escapes_total += 1
                for a in site.args:
                    if a.allowlisted:
                        continue
                    violations.append(f"{site.file}:{site.line} {site.path or site.callee} escape: {site.note}")
            for site in report.constructions:
                constructions_total += 1
                for a in site.args:
                    if a.allowlisted:
                        continue
                    if a.form == C.FORM_VIOLATION:
                        violations.append(f"{site.file}:{site.line} {site.path or site.callee} construction arg[{a.name or a.index}] {a.reason}")
                    elif a.form == C.FORM_UNCLASSIFIABLE:
                        unclassifiable.append(f"{site.file}:{site.line} {site.path or site.callee} construction {a.reason}")
                    else:
                        safe_by_form[a.form] = safe_by_form.get(a.form, 0) + 1
        violations.sort()
        unclassifiable.sort()
        stale.sort()
        facts.update({
            "sites": sites_total,
            "safe_by_form": dict(sorted(safe_by_form.items())),
            "allowlisted": allowlisted_sites,
            "violations": len(violations),
            "unclassifiable": len(unclassifiable),
            "stale_allowlist": len(stale),
            "escapes": escapes_total,
            "constructions": constructions_total,
            "references": references,
            "sinks_declared": sorted(s.callee for s in spec.sinks),
            "wrappers_declared": sorted(spec.wrappers),
            "wrappers_found": sorted(discovered),
            "assumptions": {
                "sink_identification": (
                    f"sound modulo the declared sink list: {len(spec.sinks)} declared sink(s), "
                    f"{len(spec.wrappers)} declared wrapper(s), {len(discovered)} discovered wrapper(s)"),
                "name_based_dispatch": (
                    f"a callee is matched by name on any receiver; {receiver_unknown} site(s) on a receiver "
                    f"whose type is not read; a differently named method fronting a sink is visible only "
                    f"through 'wrappers'"),
                "wrapper_closure": "wrappers discovered by fixpoint within the scope",
                "value_forms": (
                    "every form is decided from the value written at the site, never from the "
                    "position it sits in; a data structure is admitted only where every element "
                    "it was written with is itself an admitted form. What a callee then does "
                    "with a value it accepts is a property of the callee and is not read here"),
                "review_exceptions": (
                    f"{allowlisted_sites} site(s) stand on a reviewed exception rather than on a "
                    f"form the run admitted; a run in which no site was admitted by form "
                    f"establishes nothing and is refused"),
                "metaprogramming": f"{escapes_total} escape site(s) (reflection, dynamic evaluation, macro bodies, sinks as values) counted as violations unless allowlisted",
                "parser_fidelity": "; ".join(
                    f"{parser}:{sum(1 for p in facts['parser_by_file'].values() if p == parser)}"
                    for parser in (PARSER_AST, PARSER_TREE_SITTER)),
            },
        })
        facts["assumptions"].update(signed)
        problems: list = []
        if sites_total == 0 and references == 0:
            problems.append("declared sinks do not occur in scope (no site and no reference to their names)")
        if spec.mode == MODE_TYPED_BOUNDARY and constructions_total == 0 and constructor_references == 0:
            problems.append(f"declared constructors of {spec.boundary_type} do not occur in scope")
        # An exception excepts a site the run examined and flagged; it is a
        # reviewer's statement, not a thing the run established. A run whose
        # every flagged site is an exception, with no value anywhere in the
        # scope admitted by form, has mechanically decided nothing -- the
        # same vacuity as a scope the declared sinks never occur in, reached
        # by excepting the sites instead of by missing them.
        if allowlisted_sites and not safe_by_form:
            problems.append(
                f"every site this run flagged is a reviewed exception ({allowlisted_sites}) and no "
                f"value at a guarded position was admitted by form, so the run establishes nothing "
                f"over this scope")
        # The exception list is bounded by the sites it excepts: an entry
        # beyond that count cannot be pointing at a site this run examined,
        # and a list nobody could have reviewed site by site is not a
        # reviewed list.
        examined = sites_total + escapes_total + constructions_total
        if len(spec.allowlist) > examined:
            problems.append(
                f"{len(spec.allowlist)} reviewed exception(s) over {examined} site(s) examined; an "
                f"exception names a site this run flagged, so the list cannot be longer than the "
                f"sites in scope")
        passed = not violations and not unclassifiable and not stale and not problems
        details = self._render(passed, facts, violations, unclassifiable, stale, problems)
        report = EngineReport(passed, details, facts, evidence_hash, reports, problems, spec)
        _remember(cache_key, report)
        return report

    def _evidence_hash(self, files: list) -> str:
        spec = self.spec
        payload = {
            "files": [[rel, hash_of(content)] for rel, _lang, content in files],
            "allowlist": sorted(json.dumps(e, sort_keys=True) for e in spec.allowlist),
            "sinks": sorted(json.dumps({"callee": s.callee, "kind": s.kind, "positions": s.positions}, sort_keys=True)
                            for s in spec.sinks),
            "safe_forms": list(spec.safe_forms),
            "wrappers": sorted(spec.wrappers),
            "boundary_type": spec.boundary_type,
            "constructors": list(spec.constructors),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _render(self, passed: bool, facts: dict, violations: list, unclassifiable: list,
                stale: list, problems: list) -> str:
        spec = self.spec
        head = f"{spec.mode} {'PASS' if passed else 'FAIL'}"
        counts = (
            f"files={facts['files']} sites={facts['sites']} safe_by_form={json.dumps(facts['safe_by_form'], sort_keys=True)} "
            f"allowlisted={facts['allowlisted']} violations={facts['violations']} "
            f"unclassifiable={facts['unclassifiable']} stale_allowlist={facts['stale_allowlist']} "
            f"wrappers_discovered={facts['wrappers_discovered']}"
        )
        if spec.mode == MODE_TYPED_BOUNDARY:
            counts += f" constructions={facts['constructions']}"
        lines = [f"{head}: {counts}"]
        if problems:
            lines.append("refused: " + "; ".join(problems))
        lines.append("parsers: " + _parser_counts(facts["parser_by_file"]))
        lines.append("assumptions: " + "; ".join(f"{k}: {v}" for k, v in facts["assumptions"].items()))
        head_len = sum(len(ln) + 1 for ln in lines)
        listing: list = []
        listed = 0
        omitted = 0
        budget = _MAX_DETAILS_CHARS - head_len
        for label, items in (("violations", violations), ("unclassifiable", unclassifiable), ("stale allowlist", stale)):
            if not items:
                continue
            listing.append(f"{label}:")
            for item in items:
                line = f"  {item}"
                if listed >= _MAX_LISTED_LINES or budget - len(line) - 1 < _OMISSION_ROOM:
                    omitted += 1
                    continue
                listing.append(line)
                budget -= len(line) + 1
                listed += 1
        if omitted:
            listing.append(f"  ... ({omitted} further site(s) not listed; the counts above are complete)")
        # The listing gives way first, above; this is the backstop for the
        # head itself, whose length follows the declaration (the refusal
        # reasons, the assumptions) rather than the scope.
        return _within_details_bound("\n".join(lines + listing))


def flagged_sites(report: EngineReport) -> set:
    """``{"<file>:<line>"}`` for every site the run counts against the
    witness: a guarded argument of an unsafe or unreadable form, an escape,
    and a construction from something other than a literal or a named
    constant. Allowlisted sites are excluded -- they are the reviewed
    exceptions, counted separately. This is the flagged SET the soundness
    argument is stated over (it must contain every unsafe site); the counts
    in ``facts`` are its size by category.
    """
    out: set = set()
    for fr in report.files:
        for site in list(fr.sites) + list(fr.escapes) + list(fr.constructions):
            if site.category == "related":
                continue
            for a in site.args:
                if a.guarded and not a.allowlisted and a.form in (C.FORM_VIOLATION,
                                                                  C.FORM_UNCLASSIFIABLE):
                    out.add(f"{site.file}:{site.line}")
                    break
    return out


# ---------------------------------------------------------------------------
# Inventory for the semantic tier
# ---------------------------------------------------------------------------

def _form_word(a: ArgRecord) -> str:
    form = a.form if a.form != C.FORM_CONSTRUCTED else f"constructed:{a.boundary}"
    word = f"arg[{a.name or a.index}] {form}"
    if a.reason and a.form in (C.FORM_VIOLATION, C.FORM_UNCLASSIFIABLE):
        word += f" ({a.reason})"
    if a.allowlisted:
        word += f" [allowlisted: {a.allowlisted}]"
    if not a.guarded:
        word += " [unguarded position]"
    return word


def render_inventory(report: EngineReport, *, limit_chars: int = 14000) -> str:
    """The sink inventory tier 1 built, as the source the semantic tier
    reviews: every site of a declared or discovered sink with each
    argument's form, every undeclared call into the sinks' receivers,
    every construction site of the boundary type, every allowlisted site
    with its reason, and a facts block with the counts and the parser per
    file. The semantic tier never re-scans; it judges whether the declared
    sinks are the sinks through which the property could be violated."""
    spec = report.spec
    lines: list = []
    if spec is None:
        return report.details
    lines.append(f"--- Sink inventory ({report.facts.get('files', 0)} file(s) in scope) ---")
    lines.append("declared sinks: " + ", ".join(
        f"{s.callee} ({s.kind}; positions: {'all' if s.positions is None else list(s.positions)})"
        for s in spec.sinks))
    if spec.wrappers:
        lines.append("declared wrappers: " + ", ".join(spec.wrappers))
    if report.facts.get("wrappers_found"):
        lines.append("discovered wrappers (forward a parameter into a guarded position): "
                     + ", ".join(report.facts["wrappers_found"]))
    if spec.mode == MODE_DEFAULT_DENY:
        lines.append("admitted safe forms: " + ", ".join(spec.safe_forms))
    else:
        lines.append(f"boundary type: {spec.boundary_type}; constructors: " + ", ".join(spec.constructors))
    lines.append("")
    lines.append("sites (* = declared or discovered sink; each guarded argument's static form):")
    sites: list = []
    related: list = []
    escapes: list = []
    constructions: list = []
    for fr in report.files:
        for s in fr.sites:
            (sites if s.category == "sink" else related).append(s)
        escapes.extend(fr.escapes)
        constructions.extend(fr.constructions)
    for s in sorted(sites, key=lambda x: (x.file, x.line, x.path)):
        args = "; ".join(_form_word(a) for a in s.args) or "no arguments"
        lines.append(f"  {s.file}:{s.line}  * {s.path or s.callee} [{s.kind}]  {args}")
    if not sites:
        lines.append("  (none)")
    lines.append("")
    lines.append("other calls into the sinks' receivers or modules (undeclared; a sink of the same effect here is a gap):")
    for s in sorted(related, key=lambda x: (x.file, x.line, x.path)):
        lines.append(f"  {s.file}:{s.line}    {s.path or s.callee}")
    if not related:
        lines.append("  (none)")
    if spec.mode == MODE_TYPED_BOUNDARY or constructions:
        lines.append("")
        lines.append(f"construction sites of {spec.boundary_type or 'the boundary type'}:")
        for s in sorted(constructions, key=lambda x: (x.file, x.line, x.path)):
            args = "; ".join(_form_word(a) for a in s.args) or "no arguments"
            lines.append(f"  {s.file}:{s.line}  {s.path or s.callee}  {args}")
        if not constructions:
            lines.append("  (none)")
    if escapes:
        lines.append("")
        lines.append("escape sites (violations unless allowlisted):")
        for s in sorted(escapes, key=lambda x: (x.file, x.line, x.path)):
            note = s.note + (f" [allowlisted: {s.args[0].allowlisted}]" if s.args and s.args[0].allowlisted else "")
            lines.append(f"  {s.file}:{s.line}  {s.path or s.callee}  {note}")
    if spec.allowlist:
        lines.append("")
        lines.append("allowlisted sites and their reviewed reasons:")
        for e in spec.allowlist:
            lines.append(f"  {e['file']}:{e['site']} {e['callee']}: {e['reason']} (reviewed by {e['reviewed_by']})")
    text = "\n".join(lines)
    if len(text) > limit_chars:
        text = text[:limit_chars] + "\n... (inventory truncated; the counts below cover the whole scope)"
    return text


def render_facts(report: EngineReport, extra: Optional[list] = None) -> str:
    """The ``--- Facts (established by the mechanical tier) ---`` block."""
    facts = report.facts
    lines = [
        "--- Facts (established by the mechanical tier) ---",
        f"verdict: {'PASS' if report.passed else 'FAIL'}",
        f"files in scope: {facts.get('files', 0)}; sites: {facts.get('sites', 0)}; "
        f"safe by form: {json.dumps(facts.get('safe_by_form', {}), sort_keys=True)}; "
        f"allowlisted: {facts.get('allowlisted', 0)}; violations: {facts.get('violations', 0)}; "
        f"unclassifiable: {facts.get('unclassifiable', 0)}; stale allowlist entries: {facts.get('stale_allowlist', 0)}; "
        f"escape sites: {facts.get('escapes', 0)}; wrappers discovered: {facts.get('wrappers_discovered', 0)}",
        "parsers: " + _parser_counts(facts.get("parser_by_file", {})),
    ]
    for key, value in (facts.get("assumptions") or {}).items():
        lines.append(f"{key}: {value}")
    for line in extra or []:
        lines.append(line)
    return "\n".join(lines)


def run_engine(params: dict, project_root: Path, mode: str) -> EngineReport:
    """Evaluate the params of a sound-witness assertion over a checkout.

    Reads the scope every time it is called: the report is a statement about
    the files as they are now, and a remembered one would be a statement
    about the files as they were.
    """
    spec, problem = _engine_params(params, mode)
    if spec is None:
        return EngineReport(False, _within_details_bound(f"{mode} FAIL: {problem}"), {}, "", [], [problem], None)
    return SinkEngine(project_root, spec).run()


def to_result(report: EngineReport) -> VerifierResult:
    """The engine's report as a verifier verdict."""
    return _to_result(report)


def _to_result(report: EngineReport) -> VerifierResult:
    return VerifierResult(
        passed=report.passed,
        details=report.details,
        evidence_hash=report.evidence_hash,
        facts=dict(report.facts),
    )


@register("sink_default_deny", soundness=SOUNDNESS_OVER_APPROXIMATION)
class SinkDefaultDenyVerifier:
    """Every site of a declared sink in scope receives only an admitted
    safe form at each guarded position, or is a reviewed exception."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        return _to_result(run_engine(params, project_root, MODE_DEFAULT_DENY))


@register("typed_boundary", soundness=SOUNDNESS_BY_CONSTRUCTION)
class TypedBoundaryVerifier:
    """Every guarded sink position in scope receives a construction of the
    boundary type through a declared constructor, and every construction
    site receives only literal or named-constant arguments."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        return _to_result(run_engine(params, project_root, MODE_TYPED_BOUNDARY))
