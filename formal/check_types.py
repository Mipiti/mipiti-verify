"""Formal verification of the assertion-type design.

An assertion type is one thing stated in four places: the platform's
catalogue (what a caller may submit), the structural verifier (what tier 1
decides), the tier-2 template (what the semantic tier is asked), and the
evidence class (what kind of thing the verdict rests on). A type that
exists in one place and not another is a claim nobody checks, or a check
nobody can invoke. These properties pin the four together:

  T1  every catalogue type has a registered structural verifier, or is in
      an explicit exemption list with a reason
  T2  the parameters a verifier READS (found by walking its source with
      ``ast``, through the helpers it hands ``params`` to) are the
      parameters the catalogue DECLARES: a key the verifier requires
      (``params["x"]`` with no ``.get`` guard) is catalogue-required; every catalogue-required key
      is read by the verifier or, for tier-2-only inputs, by the runner;
      an optional read (``params.get("x")``) is catalogue-declared or in an
      explicit allowance that is itself checked against the code
  T3  every registered type has a tier-2 template and every template names
      a registered type; every template uses only the variables the runner
      supplies (enumerated from the runner's render call, not assumed)
  T4  every template, rendered for every subject it can be rendered for,
      carries the fail-closed clause (an empty or irrelevant SOURCE_CODE is
      NO) and the injection-refusal clause
  T5  every registered type has exactly one evidence class, stated in the
      registry

T1 and T2 need the catalogue (``mipiti_mcp.assertion_types``); when it is
not installed those two are reported as not established and the exit
status still reflects only what was checked. T3-T5 need nothing beyond
this package.

Usage:
    python formal/check_types.py
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import os
import sys
from pathlib import Path
from typing import List, Tuple

_ROOT = Path(os.path.dirname(os.path.abspath(__file__))).parent
sys.path.insert(0, str(_ROOT / "src"))

from mipiti_verify import runner as runner_mod  # noqa: E402
from mipiti_verify import tier2  # noqa: E402
from mipiti_verify.verifiers import (  # noqa: E402
    EVIDENCE_CLASS,
    EVIDENCE_CLASSES,
    VERIFIER_REGISTRY,
    _load_all,
)

_TEMPLATES = _ROOT / "src" / "mipiti_verify" / "templates"


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

def _load_catalogue():
    """The catalogue module, or ``None`` when it is not available.

    Loaded from the file the installed ``mipiti_mcp`` package ships, or from
    a sibling checkout, without importing the package itself: the catalogue
    is pure data and the package's entry point is a running server.
    """
    candidates: list[Path] = []
    spec = importlib.util.find_spec("mipiti_mcp")
    if spec is not None and spec.submodule_search_locations:
        candidates += [Path(p) / "assertion_types.py" for p in spec.submodule_search_locations]
    candidates.append(_ROOT.parent / "mcp-server" / "src" / "mipiti_mcp" / "assertion_types.py")
    for path in candidates:
        if path.is_file():
            module_spec = importlib.util.spec_from_file_location("_assertion_catalogue", path)
            module = importlib.util.module_from_spec(module_spec)
            sys.modules[module_spec.name] = module  # dataclasses resolve annotations via sys.modules
            module_spec.loader.exec_module(module)  # type: ignore[union-attr]
            return module
    return None


# T1: catalogue types with no structural verifier, each with its reason.
# Empty: every catalogue type is verified structurally. A type added here
# must say why a structural verdict cannot exist for it.
READ_ONLY_EXEMPT: dict[str, str] = {}

# T2: keys a verifier reads that the catalogue does not declare for the
# type, each with the reason the read is legitimate. Every entry is checked
# against the code: the key must actually be read, or the allowance is
# stale and the check fails.
OPTIONAL_READ_ALLOWANCE: dict[str, dict[str, str]] = {
    "*": {
        # The subject switch. Read by the shared content resolvers on every
        # type: honoured where the catalogue declares it, refused elsewhere.
        "target": "subject switch read by the shared resolver; refused where undeclared",
        # Content the platform attaches beside ``target``; never authored.
        "target_content": "platform-attached content for a target; never a caller param",
    },
    "test_attested": {
        "pattern": "accepted alias for 'test' from the earlier test-file form",
        "mechanism": "optional '<file>::<symbol>' reference that the reach and dependence facts are computed against",
    },
}

# T2: catalogue-required keys that the structural verifier does not read
# because they are inputs to the semantic tier. Each must be read by the
# runner's tier-2 source loader, which is checked.
RUNNER_READ_REQUIRED: dict[str, set] = {
    "file_hash": {"scope_file"},
}


# ---------------------------------------------------------------------------
# Reading parameter accesses out of the source
# ---------------------------------------------------------------------------

class _ParamReads(ast.NodeVisitor):
    """Keys read from any name bound as ``params``: subscripts (required)
    and ``.get`` calls (optional), plus the helper functions ``params`` is
    passed on to."""

    def __init__(self) -> None:
        self.required: set = set()
        self.optional: set = set()
        self.forwarded: set = set()

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Name) and node.value.id == "params":
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                self.required.add(node.slice.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if (isinstance(f, ast.Attribute) and f.attr == "get"
                and isinstance(f.value, ast.Name) and f.value.id == "params"
                and node.args and isinstance(node.args[0], ast.Constant)):
            self.optional.add(node.args[0].value)
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if isinstance(arg, ast.Name) and arg.id == "params":
                if isinstance(f, ast.Name):
                    self.forwarded.add(f.id)
                elif isinstance(f, ast.Attribute):
                    self.forwarded.add(f.attr)
        self.generic_visit(node)


def _function_reads(tree: ast.AST) -> dict[str, _ParamReads]:
    out: dict[str, _ParamReads] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            reads = _ParamReads()
            reads.visit(node)
            out[node.name] = reads
    return out


def _class_reads(cls_node: ast.ClassDef) -> _ParamReads:
    reads = _ParamReads()
    reads.visit(cls_node)
    return reads


def _verifier_param_reads() -> dict[str, tuple[set, set]]:
    """``{type: (required keys, optional keys)}`` per registered verifier,
    following ``params`` through helper functions in the verifiers package
    to a fixed point."""
    import mipiti_verify.verifiers as pkg

    helpers: dict[str, _ParamReads] = {}
    modules = [pkg] + [
        sys.modules[f"{pkg.__name__}.{m}"]
        for m in ("file_based", "code_structure", "config", "dependencies", "tests", "semantic", "rtl")
    ]
    trees: dict[str, ast.AST] = {}
    for mod in modules:
        tree = ast.parse(inspect.getsource(mod))
        trees[mod.__name__] = tree
        helpers.update(_function_reads(tree))

    def closure(reads: _ParamReads) -> tuple[set, set]:
        required, optional = set(reads.required), set(reads.optional)
        seen, todo = set(), set(reads.forwarded)
        while todo:
            name = todo.pop()
            if name in seen or name not in helpers:
                continue
            seen.add(name)
            h = helpers[name]
            required |= h.required
            optional |= h.optional
            todo |= h.forwarded
        # A key the code both subscripts and ``.get``s is guarded: the
        # ``.get`` is how absence is handled before the subscript runs, so
        # the subscript is not a requirement on the caller.
        return required - optional, optional

    out: dict[str, tuple[set, set]] = {}
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for deco in node.decorator_list:
                if (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Name)
                        and deco.func.id == "register" and deco.args
                        and isinstance(deco.args[0], ast.Constant)):
                    out[deco.args[0].value] = closure(_class_reads(node))
    return out


def _runner_tier2_reads() -> set:
    """Keys the runner's tier-2 source loader reads from ``params``."""
    tree = ast.parse(inspect.getsource(runner_mod))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_verify_tier2":
            reads = _ParamReads()
            reads.visit(node)
            return reads.required | reads.optional
    return set()


def _runner_template_variables() -> set:
    """The variables the runner hands every template, read from the render
    call in ``tier2._build_message``."""
    tree = ast.parse(inspect.getsource(tier2))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_build_message":
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == "render_prompt" and len(call.args) >= 2
                        and isinstance(call.args[1], ast.Dict)):
                    return {k.value for k in call.args[1].keys if isinstance(k, ast.Constant)}
    return set()


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

def check_t1(catalogue) -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    names = {t.name for t in catalogue.ASSERTION_TYPES}
    for name in sorted(names):
        checked += 1
        if name in VERIFIER_REGISTRY:
            continue
        if name in READ_ONLY_EXEMPT:
            continue
        violations.append(f"T1: catalogue type {name!r} has no structural verifier and no exemption")
    for name in READ_ONLY_EXEMPT:
        checked += 1
        if name in VERIFIER_REGISTRY:
            violations.append(f"T1: {name!r} is exempted as read-only but has a verifier; drop the exemption")
        if name not in names:
            violations.append(f"T1: exemption for {name!r} names no catalogue type")
    return checked, violations


def check_t2(catalogue) -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    reads = _verifier_param_reads()
    runner_reads = _runner_tier2_reads()
    specs = {t.name: t for t in catalogue.ASSERTION_TYPES}
    global_allow = OPTIONAL_READ_ALLOWANCE.get("*", {})

    for name in sorted(VERIFIER_REGISTRY):
        if name not in reads:
            violations.append(f"T2: no source found for the verifier registered as {name!r}")
            continue
        if name not in specs:
            continue  # T1 reports catalogue absence; nothing to compare here
        required, optional = reads[name]
        spec = specs[name]
        declared_required = set(spec.required_params)
        declared_optional = set(spec.optional_params)
        declared = declared_required | declared_optional
        allowance = dict(global_allow)
        allowance.update(OPTIONAL_READ_ALLOWANCE.get(name, {}))

        # (a) a key the verifier REQUIRES must be catalogue-required: a
        # caller who supplies exactly the declared params cannot hit KeyError.
        for key in sorted(required):
            checked += 1
            if key not in declared_required:
                violations.append(
                    f"T2a: {name} requires params[{key!r}] but the catalogue "
                    f"{'declares it optional' if key in declared_optional else 'does not declare it'}")

        # (b) every catalogue-required key is read somewhere the type's
        # verdict is decided: the verifier, or the runner's tier-2 loader
        # for the keys listed as tier-2-only.
        tier2_only = RUNNER_READ_REQUIRED.get(name, set())
        for key in sorted(declared_required):
            checked += 1
            if key in required or key in optional:
                continue
            if key in tier2_only and key in runner_reads:
                continue
            violations.append(
                f"T2b: catalogue requires {key!r} for {name} but nothing reads it"
                + (" (listed as tier-2-only, but the runner does not read it)" if key in tier2_only else ""))
        for key in sorted(tier2_only):
            checked += 1
            if key not in declared_required:
                violations.append(f"T2b: {name} lists {key!r} as tier-2-only but the catalogue does not require it")

        # (c) an optional read is declared, or allowed for a stated reason.
        for key in sorted(optional - required):
            checked += 1
            if key in declared or key in allowance:
                continue
            violations.append(f"T2c: {name} reads params.get({key!r}) which the catalogue does not declare")

    # Allowances are checked against the code: a listed key nobody reads is
    # a stale allowance.
    all_reads: set = set()
    for req, opt in reads.values():
        all_reads |= req | opt
    for scope, keys in OPTIONAL_READ_ALLOWANCE.items():
        for key in keys:
            checked += 1
            if scope == "*":
                if key not in all_reads:
                    violations.append(f"T2: allowance for {key!r} is stale; no verifier reads it")
            elif scope not in reads:
                violations.append(f"T2: allowance scope {scope!r} is not a registered verifier")
            elif key not in reads[scope][0] | reads[scope][1]:
                violations.append(f"T2: allowance {scope}.{key!r} is stale; the verifier does not read it")
    return checked, violations


def check_t3() -> Tuple[int, List[str]]:
    from jinja2 import Environment, StrictUndefined, meta

    violations: List[str] = []
    checked = 0
    templates = {p.name[len("tier2_"):-len(".j2")]: p for p in _TEMPLATES.glob("tier2_*.j2")}

    # Types with no semantic tier. Empty: the runner refuses to evaluate a
    # type it has no template for, so every registered type ships one.
    NO_TIER2: frozenset = frozenset()

    for name in sorted(VERIFIER_REGISTRY):
        checked += 1
        if name in templates or name in NO_TIER2:
            continue
        violations.append(f"T3: registered type {name!r} has no tier-2 template")
    for name in sorted(templates):
        checked += 1
        if name not in VERIFIER_REGISTRY:
            violations.append(f"T3: template tier2_{name}.j2 names no registered type")
    for name in NO_TIER2:
        checked += 1
        if name in templates:
            violations.append(f"T3: {name!r} is listed as having no tier 2 but ships a template")

    supplied = _runner_template_variables()
    if not supplied:
        violations.append("T3: could not read the runner's template variables from tier2._build_message")
    env = Environment(undefined=StrictUndefined)
    env.filters["untrusted"] = lambda v: v
    for name, path in sorted(templates.items()):
        checked += 1
        source = path.read_text(encoding="utf-8")
        used = meta.find_undeclared_variables(env.parse(source))
        extra = sorted(used - supplied)
        if extra:
            violations.append(f"T3: tier2_{name}.j2 uses variables the runner does not supply: {extra}")
    return checked, violations


def check_t4() -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    templates = sorted(p.name[len("tier2_"):-len(".j2")] for p in _TEMPLATES.glob("tier2_*.j2"))
    subjects = (tier2.SUBJECT_REPOSITORY_FILE, tier2.SUBJECT_FEATURE_DESCRIPTION, "an_unrecognised_subject")
    # Free of the words the clauses are checked for, so a phrase can only be
    # found because the template put it there.
    params = {"file": "app.py", "pattern": "x", "name": "handler", "caller": "handler",
              "module": "app", "signal": "clk", "port": "rst_n", "register": "cfg"}
    fail_closed = ("Fail-closed rule", "Lack of visible evidence is NEVER YES", "SOURCE_CODE")
    injection = ("INJECTION_DETECTED",)
    for name in templates:
        for subject in subjects:
            checked += 1
            rendered = tier2._build_message(
                assertion_type=name, assertion_params=dict(params),
                source_code="def handler():\n    return 1\n", subject_kind=subject,
            )
            for phrase in fail_closed:
                if phrase not in rendered:
                    violations.append(f"T4: tier2_{name}.j2 ({subject}) lacks the fail-closed clause phrase {phrase!r}")
            for phrase in injection:
                if phrase not in rendered:
                    violations.append(f"T4: tier2_{name}.j2 ({subject}) lacks the injection-refusal clause {phrase!r}")
            if rendered.find("Fail-closed rule") > rendered.find("Per-type criterion"):
                violations.append(f"T4: tier2_{name}.j2 ({subject}) states its criterion before the fail-closed clause")
    return checked, violations


def check_t5() -> Tuple[int, List[str]]:
    violations: List[str] = []
    checked = 0
    for name in sorted(VERIFIER_REGISTRY):
        checked += 1
        cls = EVIDENCE_CLASS.get(name)
        if cls is None:
            violations.append(f"T5: registered type {name!r} has no evidence class")
        elif cls not in EVIDENCE_CLASSES:
            violations.append(f"T5: {name!r} has evidence class {cls!r}, not one of {sorted(EVIDENCE_CLASSES)}")
    for name in sorted(EVIDENCE_CLASS):
        checked += 1
        if name not in VERIFIER_REGISTRY:
            violations.append(f"T5: evidence class stated for unregistered type {name!r}")
    return checked, violations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def check_t6(catalogue) -> Tuple[int, List[str]]:
    """T6: one mechanism-kind vocabulary.

    The verifier's ``MECHANISM_KINDS`` equals the catalogue's, as a set; the
    catalogue's declared ``mechanism`` pattern accepts ``<file>::<kind>:<name>``
    for every kind and refuses one outside the vocabulary; and every kind
    the verifier accepts explicitly is one the disable adapters and the
    locator also read from the same tuple (there is no second list).
    """
    import re

    from mipiti_verify.languages import definitions as D
    from mipiti_verify.languages.adapters import _common as C
    from mipiti_verify.verifiers.tests import mechanism_kinds

    violations: List[str] = []
    count = 0
    ours, theirs = set(D.MECHANISM_KINDS), set(catalogue.MECHANISM_KINDS)
    count += 1
    if ours != theirs:
        violations.append(f"T6 vocabulary differs: verifier-only={sorted(ours - theirs)} "
                          f"catalogue-only={sorted(theirs - ours)}")
    count += 1
    if C.KINDS is not D.MECHANISM_KINDS:
        violations.append("T6 adapters declare their own kind list")
    spec = next(t for t in catalogue.ASSERTION_TYPES if t.name == "test_attested")
    param = next(p for p in spec.params if p.name == "mechanism")
    pattern = getattr(param, "pattern", "")
    for kind in D.MECHANISM_KINDS:
        count += 2
        if not re.match(pattern, f"src/a.sv::{kind}:name_1"):
            violations.append(f"T6 catalogue pattern refuses kind {kind!r}")
        kinds, name = mechanism_kinds(f"{kind}:name_1")
        if kinds != (kind,) or name != "name_1":
            violations.append(f"T6 verifier does not resolve kind {kind!r} explicitly")
    count += 1
    if re.match(pattern, "src/a.sv::widget:name_1"):
        violations.append("T6 catalogue pattern accepts a kind outside the vocabulary")
    for alias, target in D.TYPE_KIND_ALIASES.items():
        count += 1
        if alias not in D.MECHANISM_KINDS or target not in D.MECHANISM_KINDS:
            violations.append(f"T6 alias {alias!r}->{target!r} names a kind outside the vocabulary")
    return count, violations


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
    print("ASSERTION TYPE DESIGN")
    print("=" * 70)
    _load_all()
    catalogue = _load_catalogue()
    all_pass = True
    established: List[str] = []
    not_established: List[str] = []

    if catalogue is None:
        print("\nT1 catalogue coverage:      NOT ESTABLISHED (mipiti_mcp.assertion_types not available)")
        print("T2 param spec agreement:    NOT ESTABLISHED (mipiti_mcp.assertion_types not available)")
        print("T6 mechanism-kind vocabulary: NOT ESTABLISHED (mipiti_mcp.assertion_types not available)")
        not_established += ["T1", "T2", "T6"]
    else:
        print(f"\nCatalogue: {len(catalogue.ASSERTION_TYPES)} types; registry: {len(VERIFIER_REGISTRY)} verifiers")
        c, v = check_t1(catalogue)
        all_pass &= _report("T1 catalogue coverage", c, v)
        established.append("T1")
        c, v = check_t2(catalogue)
        all_pass &= _report("T2 param spec agreement", c, v)
        established.append("T2")
        if hasattr(catalogue, "MECHANISM_KINDS"):
            c, v = check_t6(catalogue)
            all_pass &= _report("T6 mechanism-kind vocabulary", c, v)
            established.append("T6")
        else:
            print("T6 mechanism-kind vocabulary: NOT ESTABLISHED (catalogue predates MECHANISM_KINDS)")
            not_established.append("T6")

    c, v = check_t3()
    all_pass &= _report("T3 templates", c, v)
    established.append("T3")
    c, v = check_t4()
    all_pass &= _report("T4 fail-closed + injection clauses", c, v)
    established.append("T4")
    c, v = check_t5()
    all_pass &= _report("T5 evidence class", c, v)
    established.append("T5")

    print(f"\n{'=' * 70}")
    if not all_pass:
        print("TYPE PROPERTIES: FAILED")
        return 1
    if not_established:
        print(f"TYPE PROPERTIES {', '.join(established)} VERIFIED; "
              f"{', '.join(not_established)} NOT ESTABLISHED (catalogue not installed, or predates the property)")
        print(f"{'=' * 70}")
        return 0
    print("ALL TYPE PROPERTIES VERIFIED")
    print(f"  Types: {len(VERIFIER_REGISTRY)} registered, {len(catalogue.ASSERTION_TYPES)} catalogued")
    print(f"{'=' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
