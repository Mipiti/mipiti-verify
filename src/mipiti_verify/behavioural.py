"""What each group decision in an audit package rests on, and the re-check of
the certificates and proofs it carries; the same re-check serves a design
proof bundle (``design_bundle``).

An audit package with a behavioural model states, per control objective, how
each mitigation group was decided (``objective_judgements``): by a judge, by
the behavioural analysis alone (``static``) or by a model check
(``model_check``). An analysis decision that credits rests on certificates:
for each obligation, an invariant Apalache checked to be inductive for the
obligation's module at the declared scope, with the module text, the
invariant and the Apalache release. Where its proof closed it also carries
the proof: a TLAPS proof that the invariant is inductive at every scope, with
the module text, the proof text and the prover it was checked with.

Each certificate and proof is checked before anything runs:

- bound to its texts: the module text hashes to the module hash it names; a
  proof is of its certificate's module and invariant;
- about its module and its claim (``certificate_problems``,
  ``proof_problems``): the invariant's module extends only the certificate's
  module and Apalache, ``Prop`` is the module's own claim, the constants are
  bound to values and nothing else, the states the step and property checks
  start from are the invariant's own, and a proof assumes nothing, omits no
  step and proves the claim of every behaviour of the module.

Then the checkers run, where the pinned tools are available (installed here,
or the pinned image, ``tools``):

- a certificate: Apalache's three checks (the invariant holds initially,
  every step keeps it, it implies the property), each on the texts as
  carried, and two witnesses that the checks are not vacuous (a state of the
  module's ``Init``, and a state the step and property checks start from);
- a proof: ``tlapm`` on the proof text, with the platform's command, every
  obligation of which must close.

Nothing here trusts the platform's own verdict: a certificate counts as
re-checked only when its checks hold on this machine, and a proof only when
every step closes here. A certificate the package names but does not carry is
reported as missing, never passed over.

A model check's explored result is reported with what it rests on (the
runner pool and the agreement of two runs): it is not a proof an auditor can
check independently, and nothing here re-runs it.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

#: The Apalache release certificates are checked with, as ``version`` prints
#: it. A certificate naming another release is not re-checked here: a
#: different release may decide the same module differently. It needs a Java
#: 21 runtime.
APALACHE_VERSION = "0.62.4"
#: The jar's entry point, and the thread stack it runs with (a deep module
#: overflows the JVM's default stack on some machines).
APALACHE_MAIN_CLASS = "at.forsyte.apalache.tla.Tool"
APALACHE_THREAD_STACK = "-Xss64m"
#: The ``tlapm`` build proofs are checked with, as ``tlapm --version`` prints
#: it, the Z3 release it calls, and Z3's budget on one step in its resource
#: units: a step closes or not the same way on every machine.
TLAPM_BUILD = "3edc73c"
Z3_VERSION = "5.3.0"
SMT_RLIMIT = 60_000_000
#: The prover a proof names (``tlapm_rev``): a proof checked with another
#: build, Z3 release or budget is not re-checked here.
TLAPM_VERSION = f"{TLAPM_BUILD} z3 {Z3_VERSION} rlimit {SMT_RLIMIT}"
#: How tlapm runs Z3, the back ends tried on each step in order, and the
#: limit of Zenon and LS4 on one step that a proof's own limit stretches.
SMT_SOLVER = (f'z3 -smt2 -v:0 AUTO_CONFIG=false smt.MBQI=true rlimit={SMT_RLIMIT} '
              '"$file"')
TLAPM_METHODS = "smt:600,zenon,ls4"
TLAPM_DEFAULT_STEP_SECONDS = 5.0

CERTIFIED = "holds_certified"
PROVED = "holds_proved"

#: The sources of a decision the analysis made, which carry what they rest on.
ANALYSIS_SOURCES = ("static", "model_check")
#: The readings of a decision that credits on certificates alone. A model
#: check's covered decision may rest on explored runs instead, which carry no
#: certificate.
_CERTIFIED_READINGS = ("covered_by_analysis", "satisfied_by_design")

#: A re-check's outcomes.
RECHECKED = "rechecked"
FAILED = "failed"
NOT_RECHECKED = "not_rechecked"
MISSING = "missing"

#: How each decision reads, for packages that carry no legend of their own.
DEFAULT_READINGS = {
    "judged_covered": "A judge answered that the group covers the objective.",
    "judged_uncovered": "A judge answered that the group does not cover the objective.",
    "undecided": "The answer stored for the objective decides nothing for this group.",
    "awaiting_judgement": "No answer is stored for the objective's current inputs.",
    "covered_by_analysis": "The behavioural analysis decided the group covers the "
                           "objective, certified at the declared scope.",
    "possible_threat": "A possible threat found by analysis, not a judged insufficiency.",
    "covered_by_model_check": "A model check found every obligation holding within its "
                              "declared scope.",
    "violated_by_model_check": "A model check found a replayed trace that violates an "
                               "obligation.",
    "satisfied_by_design": "Every obligation holds with no control, each certified.",
    "design_unverified": "Every obligation holds with no control, on grounds that do not "
                         "credit alone.",
}


@dataclass
class Recheck:
    """One certificate's or proof's re-check."""

    kind: str  # "certificate" or "proof"
    obligation_id: str
    key: str
    status: str
    detail: str = ""


@dataclass
class Decision:
    """One group decision (or one objective's design) as the package states
    it, with the re-checks of what it rests on."""

    co_id: str
    subject: str  # "group 1", "design", or an inherited objective's group
    source: str  # "judge", "static", "model_check", "design", or "" for none
    reading: str
    disposition: str = ""
    #: The certificates and proofs the package states it rests on.
    certificates: list = field(default_factory=list)
    proofs: list = field(default_factory=list)
    rechecks: list = field(default_factory=list)
    #: A model check's statement that its explored result rests on the
    #: runner pool, when the decision carries one.
    runs_limit: str = ""

    @property
    def credits_alone(self) -> bool:
        """Whether no judge stands behind it: an analysis decision that
        covers, or an objective satisfied by design."""
        return self.reading in ("covered_by_analysis", "covered_by_model_check",
                                "satisfied_by_design")


@dataclass
class Report:
    decisions: list = field(default_factory=list)
    #: Why a checker could not run here, by tool, when it could not.
    tools_missing: dict = field(default_factory=dict)

    def rechecks(self) -> list:
        return [r for d in self.decisions for r in d.rechecks]

    def count(self, status: str, kind: Optional[str] = None) -> int:
        return sum(1 for r in self.rechecks()
                   if r.status == status and (kind is None or r.kind == kind))

    @property
    def failed(self) -> bool:
        """A certificate or proof that does not hold up: its texts do not
        hash to what it names, it is not about its module and its claim, or
        the checker refutes it here."""
        return any(r.status == FAILED for r in self.rechecks())

    def unsettled(self) -> list:
        """The re-checks a decision that credits alone rests on and that this
        run did not settle: missing, or not re-checked here."""
        return [r for d in self.decisions if d.credits_alone for r in d.rechecks
                if r.status in (MISSING, NOT_RECHECKED)]


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _str(value) -> str:
    return value if isinstance(value, str) else ""


# --- reading the package ---------------------------------------------------------------


def _list(value) -> list:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _group_decisions(co_id: str, groups, prefix: str = "") -> list:
    """Each group's decision; only an analysis decision carries what it rests
    on (a judge's answer carries no certificate)."""
    out = []
    for g in _list(groups):
        analysis = _str(g.get("source")) in ANALYSIS_SOURCES
        out.append(Decision(
            co_id=co_id, subject=f"{prefix}group {g.get('group_id', '?')}",
            source=_str(g.get("source")), reading=_str(g.get("reading")),
            disposition=_str(g.get("disposition")),
            certificates=_list(g.get("certificate")) if analysis else [],
            proofs=_list(g.get("proof")) if analysis else [],
            runs_limit=_str(g.get("runs_limit"))))
    return out


def decisions(pkg: dict) -> list:
    """Every group decision and design the package's ``objective_judgements``
    states, in the package's order. Empty for a package without one."""
    section = pkg.get("objective_judgements") if isinstance(pkg, dict) else None
    if not isinstance(section, dict):
        return []
    out: list = []
    for obj in _list(section.get("objectives")):
        co_id = _str(obj.get("co_id")) or "?"
        out += _group_decisions(co_id, obj.get("groups"))
        design = obj.get("design")
        if isinstance(design, dict):
            if design.get("unreadable"):
                out.append(Decision(co_id=co_id, subject="design", source="design",
                                    reading="unreadable"))
            else:
                out.append(Decision(
                    co_id=co_id, subject="design", source="design",
                    reading=_str(design.get("reading")) or _str(design.get("standing")),
                    certificates=_list(design.get("certificate")),
                    proofs=_list(design.get("proof"))))
    inherited = section.get("inherited")
    if isinstance(inherited, dict):
        for obj in _list(inherited.get("objectives")):
            co_id = f"{_str(obj.get('owner'))}:{_str(obj.get('co_id'))}"
            out += _group_decisions(co_id, obj.get("groups"), prefix="inherited ")
    return out


def readings(pkg: dict) -> dict:
    """The package's legend of readings, over the defaults."""
    section = pkg.get("objective_judgements") if isinstance(pkg, dict) else None
    own = section.get("readings") if isinstance(section, dict) else None
    return {**DEFAULT_READINGS, **(own if isinstance(own, dict) else {})}


# --- what a certificate and a proof must be about ---------------------------------------

_MODULE_LINE = re.compile(r"\s*-{4,}\s*MODULE\s+(\w+)\s*-{4,}\s*$")
_DEFINITION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))?\s*==", re.M)
#: Lines that end a top-level definition: another definition, a declaration,
#: a theorem or lemma, a comment, or the module's end.
_TOP_LEVEL = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?\s*==|CONSTANTS?\b|VARIABLES?\b|ASSUME\b|"
    r"ASSUMPTION\b|AXIOM\b|THEOREM\b|LEMMA\b|COROLLARY\b|PROPOSITION\b|RECURSIVE\b|"
    r"INSTANCE\b|EXTENDS\b|\\\*|={4,})")
#: Declarations neither an invariant's module nor a proof may make: each could
#: change what is checked (an assumption, an axiom, a constant or variable of
#: its own, another module's operators).
_FORBIDDEN_DECLARATIONS = re.compile(
    r"^(?:CONSTANTS?|VARIABLES?|ASSUME|ASSUMPTION|AXIOM|INSTANCE|RECURSIVE)\b", re.M)
_VALUE = re.compile(r"^(?:-?\d+|\(-\d+\)|\{\s*(?:-?\d+(?:\s*,\s*-?\d+)*)?\s*\})$")
_GEN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Gen\((\d+)\)$")


def _module_name(text: str) -> str:
    """The name a TLA+ module's text declares on its first line
    (``---- MODULE Name ----``)."""
    m = re.match(r"\s*-{4,}\s*MODULE\s+(\w+)", text or "")
    return m.group(1) if m else ""


def _strip_comments(text: str) -> str:
    """The text without block comments ``(* ... *)`` (nested) and line
    comments ``\\* ...``."""
    out, depth, i = [], 0, 0
    while i < len(text):
        if text.startswith("(*", i):
            depth += 1
            i += 2
            continue
        if depth and text.startswith("*)", i):
            depth -= 1
            i += 2
            continue
        if not depth:
            out.append(text[i])
        i += 1
    return re.sub(r"\\\*[^\n]*", "", "".join(out))


def _lines(text: str) -> list:
    return [ln for ln in (text or "").splitlines() if ln.strip()]


def definitions(text: str) -> dict:
    """``name -> body`` of every top-level definition of a module text, the
    body up to the next top-level line, its whitespace collapsed."""
    lines = _strip_comments(text).splitlines()
    out: dict = {}
    current, body = None, []
    for line in lines:
        if line and not line[0].isspace() and _TOP_LEVEL.match(line):
            if current is not None:
                out[current] = " ".join(" ".join(body).split())
            m = _DEFINITION.match(line)
            if m:
                current, body = m.group(1), [line[m.end():]]
            else:
                current, body = None, []
        elif current is not None:
            body.append(line)
    if current is not None:
        out[current] = " ".join(" ".join(body).split())
    return out


def _block(text: str, keyword: str) -> list:
    """The names a top-level ``CONSTANTS`` or ``VARIABLES`` block declares."""
    names: list = []
    inside = False
    for line in _strip_comments(text).splitlines():
        if re.match(rf"^{keyword}S?\b", line):
            inside = True
            line = re.sub(rf"^{keyword}S?\b", "", line)
        elif inside and line and not line[0].isspace():
            break
        if inside:
            names += [n.strip() for n in line.split(",") if n.strip()]
    return names


def _conjuncts(body: str) -> list:
    """The conjuncts of a definition body written as a bulleted ``/\\``
    list, or as one line joined by ``/\\``."""
    parts = [p.strip() for p in re.split(r"(?:^|\s)/\\\s", " " + body) if p.strip()]
    return parts


def _claim_operator(module: str, form: str, kind: str) -> tuple:
    """``(operator, why)``: the operator of the module's own claim the
    invariant's ``Prop`` must name, by the property's form and the
    obligation's kind, or ``("", why)`` when the module states no claim of
    that form."""
    defs = definitions(module)
    claim = defs.get("Claim_0", "")
    if not claim:
        return "", "the module states no claim (Claim_0)"
    if form == "step":
        if kind == "availability":
            return "", "an availability claim is certified as a property of states"
        step = defs.get("ClaimStep_0", "")
        if not step or claim.replace(" ", "") != "[][ClaimStep_0]_vars":
            return "", "a step property's claim is not Claim_0 == [][ClaimStep_0]_vars"
        return "ClaimStep_0", ""
    if kind == "availability" or (not kind and "~>" in claim):
        # Availability: a liveness claim, certified through ``Answerable``,
        # the property of states shown once to imply it.
        if "~>" not in claim:
            return "", "an availability claim is not a liveness claim (~>)"
        return "Answerable", ""
    if "~>" in claim:
        return "", "a liveness claim is certified only as availability"
    return "Claim_0", ""


def certificate_problems(module: str, module_name: str, invariant: str, form: str,
                         kind: str = "") -> list:
    """Why a certificate is not about its module and its claim: the reasons
    the invariant's module could make Apalache's three checks hold without
    checking the module's claim, each named. Empty when there is none."""
    problems: list = []
    inv_name = _module_name(invariant)
    lines = _lines(invariant)
    if not lines or not _MODULE_LINE.match(lines[0]) or not inv_name:
        return ["the invariant's module does not open with its MODULE line"]
    if lines[1:2] != [f"EXTENDS {module_name}, Apalache"]:
        problems.append(f"the invariant's module must extend exactly {module_name} and "
                        "Apalache")
    if not re.fullmatch(r"={4,}", lines[-1].strip()):
        problems.append("the invariant's module does not end with ====")
    body = _strip_comments(invariant)
    if _FORBIDDEN_DECLARATIONS.search(body) or len(re.findall(r"^EXTENDS\b", body, re.M)) != 1:
        problems.append("the invariant's module declares a constant, variable, "
                        "assumption, axiom or another module of its own")
    base = definitions(module)
    own = definitions(invariant)
    shadowed = sorted(set(own) & set(base))
    if shadowed:
        problems.append(f"the invariant's module redefines {', '.join(shadowed)}")
    for name in ("CInit", "IndInv", "Prop", "Assign", "InitInv"):
        if name not in own:
            problems.append(f"the invariant's module does not define {name}")
    if problems:
        return problems
    # Prop is the module's own claim.
    operator, why = _claim_operator(module, form, kind)
    if not operator:
        problems.append(why)
    elif own["Prop"] != operator:
        problems.append(f"Prop is {own['Prop']!r}, not the module's claim {operator}")
    elif operator == "Answerable" and "Answerable" not in own:
        problems.append("an availability certificate defines no Answerable")
    # The constants bound to values, each once, and nothing else.
    constants = _block(module, "CONSTANT")
    bound: dict = {}
    for part in _conjuncts(own["CInit"]):
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", part)
        if not m or not _VALUE.match(m.group(2).strip()) or m.group(1) in bound:
            problems.append(f"CInit's {part!r} does not bind one constant to a value")
            continue
        bound[m.group(1)] = m.group(2).strip()
    if not problems and sorted(bound) != sorted(constants):
        problems.append("CInit does not bind exactly the module's constants")
    # IndInv is the conjunction of the invariant's own conjuncts.
    conjuncts = _conjuncts(own["IndInv"])
    if not conjuncts or any(c not in own for c in conjuncts):
        problems.append("IndInv is not a conjunction of the invariant's own definitions")
    # The states the step and property checks start from are the invariant's.
    if own["InitInv"].replace(" ", "") != "Assign/\\IndInv":
        problems.append("InitInv is not Assign /\\ IndInv")
    variables = set(_block(module, "VARIABLE"))
    typing = {own[c] for c in conjuncts if c in own}
    for part in _conjuncts(own["Assign"]):
        gen = _GEN.match(part)
        if not (gen and gen.group(1) in variables and int(gen.group(2)) >= 1) \
                and part not in typing:
            problems.append(f"Assign's {part!r} is neither a conjunct of IndInv nor a "
                            "variable's generated value")
    return problems


def proof_problems(proof_text: str, module: str, module_name: str, invariant: str,
                   form: str) -> list:
    """Why a proof is not a proof of its certificate's claim at every scope:
    an assumption or axiom of its own, an omitted step, an invariant other
    than the certificate's, or a theorem other than the claim of every
    behaviour of the module. Empty when there is none."""
    problems: list = []
    lines = _lines(proof_text)
    if not lines or not _MODULE_LINE.match(lines[0]):
        return ["the proof does not open with its MODULE line"]
    extends = lines[1] if len(lines) > 1 else ""
    allowed = {f"EXTENDS {module_name}, FiniteSetTheorems, TLAPS",
               f"EXTENDS {module_name}, FiniteSetTheorems, WellFoundedInduction, TLAPS"}
    if extends not in allowed:
        problems.append(f"the proof must extend {module_name} and the proof system's "
                        "libraries only")
    body = _strip_comments(proof_text)
    if _FORBIDDEN_DECLARATIONS.search(body) or len(re.findall(r"^EXTENDS\b", body, re.M)) != 1:
        problems.append("the proof declares an assumption, axiom, constant, variable or "
                        "another module of its own")
    if re.search(r"\bOMITTED\b", body):
        problems.append("the proof omits a step (OMITTED)")
    base = definitions(module)
    own = definitions(proof_text)
    shadowed = sorted(set(own) & set(base))
    if shadowed:
        problems.append(f"the proof redefines {', '.join(shadowed)}")
    # The invariant proved is the certificate's: each of its definitions the
    # same, but the three only Apalache reads.
    for name, text in definitions(invariant).items():
        if name in ("CInit", "Assign", "InitInv"):
            continue
        if own.get(name) != text:
            problems.append(f"the proof's {name} is not the certificate's")
    # The module's specification, and the theorem: its claim of every behaviour.
    if base.get("Spec", "").replace(" ", "") != "Init/\\[][Next]_vars":
        problems.append("the module's Spec is not Init /\\ [][Next]_vars")
    goal = "[]Prop" if form == "state" else "[][Prop]_vars"
    holds = re.findall(r"^THEOREM\s+Holds\s*==\s*(.+)$", body, re.M)
    if len(holds) != 1 or holds[0].replace(" ", "") != f"Spec=>{goal}":
        problems.append(f"the proof's theorem Holds is not Spec => {goal}")
    return problems


# --- the tools ------------------------------------------------------------------------


class Tools:
    """Where the checkers run: commands built here, run in a work directory
    holding copies of the texts checked. ``work_path`` is how a command names
    that directory."""

    jar: str
    tlapm: str

    def work_path(self, work: str) -> str:
        return work

    def run(self, argv: list, work: str, timeout: float) -> tuple:
        """``(exit code or None, output, timed out)``."""
        raise NotImplementedError

    # The commands, as the platform runs them.

    def apalache(self, work: str, args: list, module: str) -> list:
        w = self.work_path(work)
        return ["java", APALACHE_THREAD_STACK, f"-Djava.io.tmpdir={w}", "-cp", self.jar,
                APALACHE_MAIN_CLASS, "check", f"--out-dir={w}/out", "--cinit=CInit",
                "--no-deadlock", *args, f"{module}.tla"]

    def prover(self, work: str, proof_name: str, step_seconds: float) -> list:
        stretch = max(1.0, (step_seconds or TLAPM_DEFAULT_STEP_SECONDS)
                      / TLAPM_DEFAULT_STEP_SECONDS)
        return [self.tlapm, "--strict", "--cache-dir", f"{self.work_path(work)}/cache",
                "--method", TLAPM_METHODS, "--solver", SMT_SOLVER, "--stretch",
                f"{stretch:g}", "--toolbox", "0", "0", f"{proof_name}.tla"]


def _run_process(argv: list, cwd: str, timeout: float, on_timeout=None) -> tuple:
    proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout if timeout > 0 else None)
        return proc.returncode, stdout + stderr, False
    except subprocess.TimeoutExpired:
        if on_timeout is not None:
            on_timeout()
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, AttributeError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
        return None, (stdout or "") + (stderr or ""), True


class LocalTools(Tools):
    """The pinned tools installed on this machine."""

    def __init__(self, jar: Optional[str], tlapm: Optional[str]):
        self.jar = jar or ""
        self.tlapm = tlapm or ""

    def run(self, argv: list, work: str, timeout: float) -> tuple:
        return _run_process(argv, work, timeout)


#: Where the pinned image holds the tools.
IMAGE_JAR = "/tools/apalache/lib/apalache.jar"
IMAGE_TLAPM = "/tools/tlapm/bin/tlapm"


class ImageTools(Tools):
    """The pinned tools image, run with the network off on a copy of the
    texts checked, as an unprivileged user."""

    def __init__(self, image: str, docker: str = "docker"):
        self.image = image
        self.docker = docker
        self.jar = IMAGE_JAR
        self.tlapm = IMAGE_TLAPM

    def work_path(self, work: str) -> str:
        return "/work"

    def container(self, argv: list, work: str, name: str) -> list:
        user = [f"--user={os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
        return [self.docker, "run", "--rm", f"--name={name}", "--network=none", *user,
                "--volume", f"{work}:/work", "--workdir", "/work", "--entrypoint", argv[0],
                self.image, *argv[1:]]

    def run(self, argv: list, work: str, timeout: float) -> tuple:
        name = f"mipiti-design-check-{uuid.uuid4().hex[:12]}"

        def stop():
            subprocess.run([self.docker, "kill", name], capture_output=True, timeout=60)
        return _run_process(self.container(argv, work, name), work, timeout, stop)


def _versions(tools: Tools, names) -> dict:
    """What the tools ``names`` say they are, by name (``apalache``,
    ``tlapm``, ``z3``)."""
    out = {}
    with tempfile.TemporaryDirectory(prefix="mipiti-versions-") as work:
        w = tools.work_path(work)
        for name, argv in (
                ("apalache", ["java", APALACHE_THREAD_STACK, f"-Djava.io.tmpdir={w}", "-cp",
                              tools.jar, APALACHE_MAIN_CLASS, "version"]),
                ("tlapm", [tools.tlapm, "--version"]),
                ("z3", ["z3", "--version"])):
            if name not in names:
                continue
            try:
                _code, text, _t = tools.run(argv, work, 180)
            except OSError as e:
                out[name] = f"did not start: {e}"
                continue
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if name == "z3":
                words = lines[-1].split() if lines else []
                out[name] = words[2] if len(words) > 2 else ""
            else:
                out[name] = lines[-1] if lines else ""
    return out


def check_versions(tools: Tools, names=("apalache", "tlapm", "z3")) -> dict:
    """``{tool: why}`` for each of the pinned tools ``names`` that is not the
    pinned release here (empty when every one is)."""
    want = {t: v for t, v in (("apalache", APALACHE_VERSION), ("tlapm", TLAPM_BUILD),
                              ("z3", Z3_VERSION)) if t in names}
    found = _versions(tools, names)
    return {t: f"{t} is {found.get(t)!r} here; the re-check is pinned to {v}"
            for t, v in want.items() if found.get(t) != v}


def find_apalache() -> tuple:
    """``(jar, "")``: the Apalache jar installed here, from ``APALACHE_JAR``
    or beside the ``apalache-mc`` on PATH; or ``(None, why)``."""
    jar = os.environ.get("APALACHE_JAR")
    if not jar:
        script = os.environ.get("APALACHE") or shutil.which("apalache-mc")
        if script:
            candidate = Path(script).resolve().parent.parent / "lib" / "apalache.jar"
            jar = str(candidate) if candidate.is_file() else None
    if not jar or not Path(jar).is_file():
        return None, ("Apalache is not installed (set APALACHE_JAR, or put apalache-mc "
                      f"{APALACHE_VERSION} on PATH)")
    if shutil.which("java") is None:
        return None, "Apalache needs a Java runtime and none is on PATH"
    return jar, ""


def find_tlapm() -> tuple:
    """``(executable, "")``: the ``tlapm`` installed here, from ``TLAPM`` or
    PATH, with Z3 on PATH; or ``(None, why)``."""
    exe = os.environ.get("TLAPM") or shutil.which("tlapm")
    if not exe:
        return None, f"tlapm is not installed (set TLAPM, or put tlapm {TLAPM_BUILD} on PATH)"
    if shutil.which("z3") is None:
        return None, f"tlapm needs Z3 {Z3_VERSION} on PATH and none is there"
    return exe, ""


def local_tools() -> tuple:
    """``(tools, {tool: why})``: the pinned tools installed here, each
    checked to be the pinned release; a tool that is missing or another
    release is named, and its kind of re-check does not run."""
    jar, jar_why = find_apalache()
    exe, exe_why = find_tlapm()
    missing: dict = {}
    if jar is None:
        missing["apalache"] = jar_why
    if exe is None:
        missing["tlapm"] = exe_why
    tools = LocalTools(jar, exe)
    wrong = check_versions(tools, (("apalache",) if jar else ()) +
                           (("tlapm", "z3") if exe else ()))
    if jar is not None and "apalache" in wrong:
        missing["apalache"] = wrong["apalache"]
        tools.jar = ""
    if exe is not None and ("tlapm" in wrong or "z3" in wrong):
        missing["tlapm"] = wrong.get("tlapm") or wrong["z3"]
        tools.tlapm = ""
    return tools, missing


def image_tools(image: str, docker: str = "docker") -> tuple:
    """``(tools, {tool: why})``: the pinned image, pulled and checked to hold
    the pinned releases; ``(None, {"image": why})`` when it cannot run."""
    if not image:
        return None, {"image": "no tools image is pinned in this release (pass --image)"}
    if shutil.which(docker) is None:
        return None, {"image": f"{docker} is not installed, so the tools image cannot run"}
    present = subprocess.run([docker, "image", "inspect", image], capture_output=True,
                             text=True, timeout=120).returncode == 0
    pulled = present or subprocess.run([docker, "pull", "--quiet", image], capture_output=True,
                                       text=True, timeout=1800)
    if pulled is not True and pulled.returncode != 0:
        return None, {"image": f"could not pull {image}: "
                               f"{(pulled.stderr or pulled.stdout).strip()[:300]}"}
    tools = ImageTools(image, docker)
    wrong = check_versions(tools)
    if wrong:
        return None, {"image": "; ".join(wrong.values())}
    return tools, {}


def _write(work: str, texts: dict) -> None:
    for name, text in texts.items():
        with open(os.path.join(work, f"{name}.tla"), "w", encoding="utf-8") as fh:
            fh.write(text)


# --- running the checkers ------------------------------------------------------------------

#: Apalache's verdict marks.
HOLDS_MARK = "EXITCODE: OK"
FAILS_MARK = "EXITCODE: ERROR (12)"


#: Apalache's arguments for the three checks, by the property's form: the
#: invariant holds initially, every step keeps it, it implies the property
#: (in one step, for a property about steps).
def apalache_checks(form: str) -> list:
    third = ["--init=InitInv", "--inv=Prop", "--length=0" if form == "state" else "--length=1"]
    return [("init", ["--init=Init", "--inv=IndInv", "--length=0"]),
            ("step", ["--init=InitInv", "--inv=IndInv", "--length=1"]),
            ("property", third)]


#: The witnesses that the checks are not vacuous: a state of the module's
#: ``Init`` and a state the step and property checks start from, each found
#: as a violation of an invariant no state satisfies.
WITNESSES = (("init state", ["--init=Init", "--inv=NoState", "--length=0"]),
             ("start state", ["--init=InitInv", "--inv=NoState", "--length=0"]))


def _verdict(text: str) -> str:
    if HOLDS_MARK in text:
        return "holds"
    if FAILS_MARK in text:
        return "fails"
    return "error"


def run_apalache(tools: Tools, module_name: str, module: str, invariant: str, form: str,
                 timeout: float) -> list:
    """The three checks of a certificate, in order, then the two witnesses,
    stopping at the first that does not come out as it must:
    ``[(check, verdict, detail)]``. A check must hold; a witness must find a
    state (``fails``: the invariant no state satisfies is violated)."""
    inv_name = _module_name(invariant)
    witness = f"{inv_name}_witness"
    out = []
    with tempfile.TemporaryDirectory(prefix="mipiti-certificate-") as work:
        _write(work, {module_name: module, inv_name: invariant,
                      witness: (f"---- MODULE {witness} ----\nEXTENDS {inv_name}\n\n"
                                "NoState == FALSE\n====\n")})
        for check, args in apalache_checks(form) + list(WITNESSES):
            target = inv_name if check in ("init", "step", "property") else witness
            code, text, timed_out = tools.run(tools.apalache(work, args, target), work,
                                              max(timeout, 1))
            if timed_out:
                out.append((check, "timeout", ""))
                break
            verdict = _verdict(text)
            if verdict == "error":
                errors = [ln.strip() for ln in text.splitlines() if " E@" in ln]
                out.append((check, "error", " | ".join(errors)[:500] or text[-500:]))
                break
            out.append((check, verdict, ""))
            want = "holds" if check in ("init", "step", "property") else "fails"
            if verdict != want:
                break
    return out


def run_tlapm(tools: Tools, module_name: str, module: str, proof_text: str, *,
              step_seconds: float, timeout: float) -> dict:
    """``tlapm`` on a proof, with the platform's command: ``{exit, timed_out,
    statuses: {id: status}}`` with each obligation's final status."""
    proof_name = _module_name(proof_text)
    with tempfile.TemporaryDirectory(prefix="mipiti-proof-") as work:
        _write(work, {module_name: module, proof_name: proof_text})
        code, out, timed_out = tools.run(tools.prover(work, proof_name, step_seconds), work,
                                         timeout)
    statuses: dict = {}
    for block in out.split("@!!BEGIN")[1:]:
        m = dict(re.findall(r"@!!(\w+):(.*)", block))
        if m.get("type") != "obligation" or m.get("status") not in ("proved", "failed",
                                                                     "trivial"):
            continue
        if statuses.get(m["id"]) in (None, "failed"):
            statuses[m["id"]] = m["status"]
    return {"exit": code, "timed_out": timed_out, "statuses": statuses}


# --- the re-checks --------------------------------------------------------------------


def recheck_certificate(cert: dict, tools: Optional[Tools], timeout: float) -> Recheck:
    """One certificate: bound to its texts, about its module and its claim,
    of the release this verifier pins, and Apalache's three checks holding
    here with both witnesses found. ``tools`` None (or without Apalache)
    checks the certificate before anything runs and reports it not
    re-checked."""
    obligation = _str(cert.get("obligation_id"))
    key = _str(cert.get("key_hash"))

    def result(status: str, detail: str = "") -> Recheck:
        return Recheck("certificate", obligation, key, status, detail)

    if cert.get("stored") is False:
        why = "the store could not be read" if cert.get("unreadable") else \
            "the platform holds no certificate under this key"
        return result(MISSING, why)
    module = _str(cert.get("module_text"))
    invariant = _str(cert.get("invariant"))
    if not module or not invariant:
        return result(FAILED, "the certificate carries no module text or no invariant")
    if _sha256(module) != _str(cert.get("module_hash")):
        return result(FAILED, "the module text does not hash to the module hash it names")
    if _str(cert.get("outcome")) != CERTIFIED:
        return result(FAILED, f"the certificate's outcome is {cert.get('outcome')!r}, "
                              f"not {CERTIFIED}")
    module_name = _str(cert.get("module_name")) or _module_name(module)
    if _module_name(module) != module_name or not _module_name(invariant):
        return result(FAILED, "the module text does not declare the module it names")
    form = _str(cert.get("form")) or "state"
    if form not in ("state", "step"):
        return result(FAILED, f"the certificate's form is {form!r}")
    problems = certificate_problems(module, module_name, invariant, form,
                                    _str(cert.get("kind")))
    if problems:
        return result(FAILED, "; ".join(problems))
    if _str(cert.get("apalache_rev")) != APALACHE_VERSION:
        return result(NOT_RECHECKED, f"it names Apalache {cert.get('apalache_rev')!r}; this "
                                     f"verifier re-checks with {APALACHE_VERSION}")
    if tools is None or not tools.jar:
        return result(NOT_RECHECKED, "Apalache is not available here")
    ran = run_apalache(tools, module_name, module, invariant, form, timeout)
    if len(ran) == 5 and [v for _c, v, _d in ran] == ["holds"] * 3 + ["fails"] * 2:
        return result(RECHECKED)
    check, verdict, detail = ran[-1] if ran else ("init", "error", "nothing ran")
    if check in ("init state", "start state") and verdict == "holds":
        return result(FAILED, f"no {check} exists here, so the checks hold vacuously")
    if verdict == "fails":
        return result(FAILED, f"Apalache refutes the {check} check here")
    return result(NOT_RECHECKED, f"the {check} check gave {verdict} here"
                                 + (f": {detail}" if detail else ""))


def recheck_proof(proof: dict, cert: Optional[dict], tools: Optional[Tools],
                  timeout: float) -> Recheck:
    """One proof: of its certificate's module and invariant, a proof of the
    claim of every behaviour assuming nothing of its own, of the prover this
    verifier pins, and every obligation closing under ``tlapm`` here."""
    obligation = _str(proof.get("obligation_id"))
    key = _str(proof.get("key_hash"))

    def result(status: str, detail: str = "") -> Recheck:
        return Recheck("proof", obligation, key, status, detail)

    module = _str(proof.get("module_text"))
    text = _str(proof.get("proof_text"))
    if not module or not text:
        return result(FAILED, "the proof carries no module text or no proof text")
    if _sha256(module) != _str(proof.get("module_hash")):
        return result(FAILED, "the module text does not hash to the module hash it names")
    if cert is None or cert.get("stored") is False:
        return result(FAILED, "no certificate of this obligation accompanies the proof")
    if _str(proof.get("module_hash")) != _str(cert.get("module_hash")):
        return result(FAILED, "the proof is of another module than its certificate")
    if _str(proof.get("invariant_hash")) != _sha256(_str(cert.get("invariant"))):
        return result(FAILED, "the proof is of another invariant than its certificate")
    if _str(proof.get("outcome")) != PROVED:
        return result(FAILED, f"the proof's outcome is {proof.get('outcome')!r}, not {PROVED}")
    module_name = _str(proof.get("module_name")) or _module_name(module)
    form = _str(cert.get("form")) or "state"
    problems = proof_problems(text, module, module_name, _str(cert.get("invariant")), form)
    if problems:
        return result(FAILED, "; ".join(problems))
    if _str(proof.get("tlapm_rev")) != TLAPM_VERSION:
        return result(NOT_RECHECKED, f"it names the prover {proof.get('tlapm_rev')!r}; this "
                                     f"verifier re-checks with {TLAPM_VERSION}")
    if tools is None or not tools.tlapm:
        return result(NOT_RECHECKED, "tlapm is not available here")
    try:
        step = float(proof.get("step_seconds") or TLAPM_DEFAULT_STEP_SECONDS)
    except (TypeError, ValueError):
        step = TLAPM_DEFAULT_STEP_SECONDS
    ran = run_tlapm(tools, module_name, module, text, step_seconds=step, timeout=timeout)
    failed = [i for i, s in ran["statuses"].items() if s == "failed"]
    if ran["timed_out"]:
        return result(NOT_RECHECKED, "tlapm ran out of time here")
    if failed:
        return result(FAILED, f"{len(failed)} proof obligation(s) do not close here")
    if ran["exit"] != 0 or not ran["statuses"]:
        return result(NOT_RECHECKED, f"tlapm exited {ran['exit']} with "
                                     f"{len(ran['statuses'])} obligation(s) reported")
    return result(RECHECKED)


def resolve_tools(mode: str, image: str = "") -> tuple:
    """``(tools or None, {tool: why})`` for a re-check mode: ``local`` (the
    pinned tools installed here), ``image`` (the pinned tools image) or
    ``auto`` (installed tools where both are, else the image)."""
    if mode == "local":
        return local_tools()
    if mode == "image":
        return image_tools(image)
    tools, missing = local_tools()
    if not missing:
        return tools, {}
    via_image, why = image_tools(image)
    if via_image is not None:
        return via_image, {}
    return tools, {**missing, **why}


def check(pkg: dict, *, run_tools: bool = True, timeout: float = 600.0,
          tools_mode: str = "local", image: str = "") -> Report:
    """Every decision the package states, each analysis decision's
    certificates and proofs checked before anything runs always, and
    re-checked with the pinned tools when ``run_tools`` and they are
    available. Tools are looked for only when some certificate or proof
    needs them."""
    report = Report(decisions=decisions(pkg))
    needed = any(d.certificates or d.proofs for d in report.decisions)
    tools = None
    if run_tools and needed:
        tools, missing = resolve_tools(tools_mode, image)
        report.tools_missing.update(missing)
    if not run_tools and needed:
        report.tools_missing["all"] = "re-checking was turned off (--no-recheck)"
    for d in report.decisions:
        if d.reading in _CERTIFIED_READINGS and not d.certificates:
            # It credits on certificates and the package carries none: what
            # it rests on cannot be produced, which is said, never passed over.
            d.rechecks.append(Recheck("certificate", "", "", MISSING,
                                      "the decision credits with no judge and the package "
                                      "carries no certificate for it"))
        by_obligation = {}
        for c in d.certificates:
            by_obligation.setdefault(_str(c.get("obligation_id")), c)
            d.rechecks.append(recheck_certificate(c, tools, timeout))
        for p in d.proofs:
            d.rechecks.append(recheck_proof(
                p, by_obligation.get(_str(p.get("obligation_id"))), tools, timeout))
    return report


__all__ = ["ANALYSIS_SOURCES", "APALACHE_VERSION", "Decision", "FAILED", "ImageTools",
           "LocalTools", "MISSING", "NOT_RECHECKED", "RECHECKED", "Recheck", "Report",
           "TLAPM_VERSION", "Tools", "apalache_checks", "certificate_problems", "check",
           "check_versions", "decisions", "definitions", "find_apalache", "find_tlapm",
           "image_tools", "local_tools", "proof_problems", "readings", "recheck_certificate",
           "recheck_proof", "resolve_tools", "run_apalache", "run_tlapm"]
