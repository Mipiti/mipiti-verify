"""What each group decision in an audit package rests on, and the re-check of
the certificates and proofs an analysis decision carries.

An audit package with a behavioural model states, per control objective, how
each mitigation group was decided (``objective_judgements``): by a judge, by
the behavioural analysis alone (``static``) or by a model check
(``model_check``). An analysis decision that credits rests on certificates:
for each obligation, an invariant Apalache checked to be inductive for the
obligation's module at the declared scope, with the module text, the
invariant and the Apalache release. Where its proof closed it also carries
the proof: a TLAPS proof that the invariant is inductive at every scope, with
the module text, the proof text and the ``tlapm`` build.

This module reads those decisions, checks that each certificate and proof is
internally bound (the module text hashes to the module hash it names; a proof
is of its certificate's module and invariant), and re-runs the checkers on
them where the pinned tools are installed:

- a certificate: Apalache's three checks of the invariant (it holds
  initially, every step keeps it, it implies the property), each on the
  module text as the package carries it;
- a proof: ``tlapm`` on the proof text, every obligation of which must close.

Nothing here trusts the platform's own verdict: a certificate counts as
re-checked only when the three checks hold on this machine, and a proof only
when every step closes here. A certificate the package names but does not
carry is reported as missing, never passed over.

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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

#: The Apalache release certificates are checked with, as ``version`` prints
#: it. A certificate naming another release is not re-checked here: a
#: different release may decide the same module differently. It needs a Java
#: 21 runtime.
APALACHE_VERSION = "0.62.4"
#: The jar's entry point, and the thread stack the platform runs it with (a
#: deep module overflows the JVM's default stack on some machines).
APALACHE_MAIN_CLASS = "at.forsyte.apalache.tla.Tool"
APALACHE_THREAD_STACK = "-Xss64m"
#: The ``tlapm`` build proofs are checked with, as ``tlapm --version`` prints
#: it, and the back ends tried on each step.
TLAPM_VERSION = "3edc73c"
TLAPM_METHODS = "smt,zenon,ls4"
#: ``tlapm``'s default time limit of its first back end on one step: what a
#: proof's own step limit is stated against (``--stretch``).
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
        hash to what it names, it is not of the decision's obligation, or the
        checker refutes it here."""
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


# --- the tools ------------------------------------------------------------------------


def find_apalache() -> tuple:
    """``(jar, "")``: the pinned Apalache jar, from ``APALACHE_JAR`` or beside
    the ``apalache-mc`` on PATH, checked to be the pinned release; or
    ``(None, why)``."""
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
    with tempfile.TemporaryDirectory(prefix="mipiti-apalache-") as tmp:
        try:
            proc = subprocess.run([*_apalache(jar, tmp), "version"], cwd=tmp,
                                  capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as e:
            return None, f"Apalache did not start: {e}"
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    found = lines[-1] if lines else ""
    if found != APALACHE_VERSION:
        return None, f"{jar} is Apalache {found!r}; certificates are re-checked with {APALACHE_VERSION}"
    return jar, ""


def find_tlapm() -> tuple:
    """``(executable, "")``: the pinned ``tlapm``, from ``TLAPM`` or PATH; or
    ``(None, why)``."""
    exe = os.environ.get("TLAPM") or shutil.which("tlapm")
    if not exe:
        return None, f"tlapm is not installed (set TLAPM, or put tlapm {TLAPM_VERSION} on PATH)"
    try:
        found = subprocess.run([exe, "--version"], capture_output=True, text=True,
                               timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"tlapm did not start: {e}"
    if found != TLAPM_VERSION:
        return None, f"{exe} is tlapm {found!r}; proofs are re-checked with {TLAPM_VERSION}"
    return exe, ""


def _apalache(jar: str, tmpdir: str) -> list:
    return ["java", APALACHE_THREAD_STACK, f"-Djava.io.tmpdir={tmpdir}", "-cp", jar,
            APALACHE_MAIN_CLASS]


def _module_name(text: str) -> str:
    """The name a TLA+ module's text declares on its first line
    (``---- MODULE Name ----``)."""
    m = re.match(r"\s*-{4,}\s*MODULE\s+(\w+)", text or "")
    return m.group(1) if m else ""


#: Apalache's arguments for the three checks, by the property's form: the
#: invariant holds initially, every step keeps it, it implies the property
#: (in one step, for a property about steps).
def apalache_checks(form: str) -> list:
    third = ["--init=InitInv", "--inv=Prop", "--length=0" if form == "state" else "--length=1"]
    return [("init", ["--init=Init", "--inv=IndInv", "--length=0"]),
            ("step", ["--init=InitInv", "--inv=IndInv", "--length=1"]),
            ("property", third)]


def run_apalache(jar: str, module_name: str, module: str, invariant: str, form: str,
                 timeout: float) -> list:
    """The three checks of a certificate, in order, stopping at the first
    that does not hold: ``[(check, verdict, detail)]``, each verdict
    ``holds``, ``fails``, ``error`` or ``timeout``."""
    inv_name = _module_name(invariant)
    out = []
    with tempfile.TemporaryDirectory(prefix="mipiti-certificate-") as work:
        for name, text in ((module_name, module), (inv_name, invariant)):
            with open(os.path.join(work, f"{name}.tla"), "w", encoding="utf-8") as fh:
                fh.write(text)
        for check, args in apalache_checks(form):
            try:
                proc = subprocess.run(
                    [*_apalache(jar, work), "check", f"--out-dir={os.path.join(work, 'out')}",
                     "--cinit=CInit", "--no-deadlock", *args, f"{inv_name}.tla"],
                    cwd=work, capture_output=True, text=True, timeout=max(timeout, 1))
            except subprocess.TimeoutExpired:
                out.append((check, "timeout", ""))
                break
            text = proc.stdout + proc.stderr
            if "EXITCODE: OK" in text:
                out.append((check, "holds", ""))
                continue
            if "EXITCODE: ERROR (12)" in text:
                out.append((check, "fails", ""))
                break
            errors = [ln.strip() for ln in text.splitlines() if " E@" in ln]
            out.append((check, "error", " | ".join(errors)[:500] or text[-500:]))
            break
    return out


def run_tlapm(exe: str, module_name: str, module: str, proof_text: str, *,
              step_seconds: float, timeout: float) -> dict:
    """``tlapm`` on a proof, as the platform runs it: ``{exit, timed_out,
    statuses: {id: status}}`` with each obligation's final status."""
    proof_name = _module_name(proof_text)
    stretch = max(1.0, (step_seconds or TLAPM_DEFAULT_STEP_SECONDS) / TLAPM_DEFAULT_STEP_SECONDS)
    with tempfile.TemporaryDirectory(prefix="mipiti-proof-") as work:
        for name, text in ((module_name, module), (proof_name, proof_text)):
            with open(os.path.join(work, f"{name}.tla"), "w", encoding="utf-8") as fh:
                fh.write(text)
        proc = subprocess.Popen(
            [exe, "--strict", "--cache-dir", os.path.join(work, "cache"),
             "--method", TLAPM_METHODS, "--stretch", f"{stretch:g}", "--toolbox", "0", "0",
             f"{proof_name}.tla"],
            cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout if timeout > 0 else None)
            out, code, timed_out = stdout + stderr, proc.returncode, False
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
            out, code, timed_out = (stdout or "") + (stderr or ""), None, True
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


def recheck_certificate(cert: dict, jar: Optional[str], timeout: float) -> Recheck:
    """One certificate: bound to its texts, of the release this verifier
    pins, and Apalache's three checks holding here. ``jar`` None checks the
    binding alone and reports the certificate not re-checked."""
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
    if _str(cert.get("apalache_rev")) != APALACHE_VERSION:
        return result(NOT_RECHECKED, f"it names Apalache {cert.get('apalache_rev')!r}; this "
                                     f"verifier re-checks with {APALACHE_VERSION}")
    if jar is None:
        return result(NOT_RECHECKED, "Apalache is not available here")
    form = _str(cert.get("form")) or "state"
    ran = run_apalache(jar, module_name, module, invariant, form, timeout)
    if len(ran) == 3 and all(v == "holds" for _c, v, _d in ran):
        return result(RECHECKED)
    check, verdict, detail = ran[-1] if ran else ("init", "error", "nothing ran")
    if verdict == "fails":
        return result(FAILED, f"Apalache refutes the {check} check here")
    return result(NOT_RECHECKED, f"the {check} check gave {verdict} here"
                                 + (f": {detail}" if detail else ""))


def recheck_proof(proof: dict, cert: Optional[dict], exe: Optional[str],
                  timeout: float) -> Recheck:
    """One proof: of its certificate's module and invariant, of the build
    this verifier pins, and every obligation closing under ``tlapm`` here."""
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
    if _str(proof.get("tlapm_rev")) != TLAPM_VERSION:
        return result(NOT_RECHECKED, f"it names tlapm {proof.get('tlapm_rev')!r}; this "
                                     f"verifier re-checks with {TLAPM_VERSION}")
    if exe is None:
        return result(NOT_RECHECKED, "tlapm is not available here")
    module_name = _str(proof.get("module_name")) or _module_name(module)
    try:
        step = float(proof.get("step_seconds") or TLAPM_DEFAULT_STEP_SECONDS)
    except (TypeError, ValueError):
        step = TLAPM_DEFAULT_STEP_SECONDS
    ran = run_tlapm(exe, module_name, module, text, step_seconds=step, timeout=timeout)
    failed = [i for i, s in ran["statuses"].items() if s == "failed"]
    if ran["timed_out"]:
        return result(NOT_RECHECKED, "tlapm ran out of time here")
    if failed:
        return result(FAILED, f"{len(failed)} proof obligation(s) do not close here")
    if ran["exit"] != 0 or not ran["statuses"]:
        return result(NOT_RECHECKED, f"tlapm exited {ran['exit']} with "
                                     f"{len(ran['statuses'])} obligation(s) reported")
    return result(RECHECKED)


def check(pkg: dict, *, run_tools: bool = True, timeout: float = 600.0) -> Report:
    """Every decision the package states, each analysis decision's
    certificates and proofs checked: bound to their texts always, and
    re-checked with the pinned tools when ``run_tools`` and they are
    installed. A tool is looked for only when some certificate or proof
    needs it."""
    report = Report(decisions=decisions(pkg))
    needs_apalache = any(d.certificates for d in report.decisions)
    needs_tlapm = any(d.proofs for d in report.decisions)
    jar = exe = None
    if run_tools and needs_apalache:
        jar, why = find_apalache()
        if jar is None:
            report.tools_missing["apalache"] = why
    if run_tools and needs_tlapm:
        exe, why = find_tlapm()
        if exe is None:
            report.tools_missing["tlapm"] = why
    if not run_tools and (needs_apalache or needs_tlapm):
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
            d.rechecks.append(recheck_certificate(c, jar, timeout))
        for p in d.proofs:
            d.rechecks.append(recheck_proof(
                p, by_obligation.get(_str(p.get("obligation_id"))), exe, timeout))
    return report


__all__ = ["ANALYSIS_SOURCES", "APALACHE_VERSION", "Decision", "FAILED", "MISSING",
           "NOT_RECHECKED", "RECHECKED", "Recheck", "Report", "TLAPM_VERSION",
           "apalache_checks", "check", "decisions", "find_apalache", "find_tlapm",
           "readings", "recheck_certificate", "recheck_proof", "run_apalache", "run_tlapm"]
