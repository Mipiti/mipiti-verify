"""Test-result attestations: the record a CI run leaves behind.

The verifier reads; it never executes. A test result reaches verification as a
statement your CI signed about a run your own workflow performed. Nothing in
this module invokes a test command, and nothing in it should ever grow one.

The predicate is an in-toto statement carried in a DSSE-style envelope, the
shape the Sigstore path already speaks. It is published rather than private:
any CI system can emit a conforming attestation without this CLI.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PREDICATE_TYPE = "https://mipiti.io/attestations/test-result/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Where attest-tests writes and the verifier looks, relative to the project
# root. A convention rather than a parameter so an assertion never has to name
# a path, and so a repository can carry several suites' attestations at once.
ATTESTATION_DIR = ".mipiti/attestations"
ATTESTATION_DIR_ENV = "MIPITI_ATTESTATION_DIR"


def attestation_dir(project_root: Path) -> Path:
    """Where attestations are written and read for ``project_root``.

    ``.mipiti/attestations`` under the project root, unless
    ``MIPITI_ATTESTATION_DIR`` names another directory (absolute, or relative
    to the project root). The action sets it when the checkout is not
    writable by the container's user, which is the common shape of a
    container action: the workspace belongs to the runner's uid.
    """
    override = os.environ.get(ATTESTATION_DIR_ENV, "").strip()
    if override:
        candidate = Path(override)
        return candidate if candidate.is_absolute() else project_root / candidate
    return project_root / ATTESTATION_DIR

# Provenance classes, strongest first. The artifact is identical across CI
# providers; only the signing identity differs, which is the axis the platform
# already classifies for verification runs.
PROVENANCE_CI_OIDC = "ci_oidc"
PROVENANCE_CUSTOMER_KEY = "customer_key"
PROVENANCE_UNSIGNED = "unsigned"


class AttestationError(Exception):
    """Raised when an attestation cannot be produced or read."""


# ---------------------------------------------------------------------------
# Reading a test report -- no execution, only parsing what CI already produced
# ---------------------------------------------------------------------------

def parse_junit(report_path: Path) -> dict:
    """Summarise a JUnit XML report into predicate ``totals`` + test names.

    JUnit XML is the universal interchange format -- pytest, jest, go-junit,
    cargo-nextest, surefire and phpunit all emit it -- so supporting it is what
    makes this CI-agnostic without a per-runner integration.

    Counts are derived from the testcase elements rather than trusting the
    suite-level attributes, which runners populate inconsistently.
    """
    try:
        tree = ET.parse(report_path)
    except (ET.ParseError, OSError) as e:
        raise AttestationError(f"Cannot read JUnit report {report_path}: {e}") from e

    cases = list(tree.getroot().iter("testcase"))
    failed = skipped = errored = 0
    tests: list[dict] = []
    for case in cases:
        name = case.get("name") or ""
        classname = case.get("classname") or ""
        if case.find("failure") is not None:
            status = "failed"
            failed += 1
        elif case.find("error") is not None:
            status = "error"
            errored += 1
        elif case.find("skipped") is not None:
            status = "skipped"
            skipped += 1
        else:
            status = "passed"
        # Each test carries its own outcome. A bare list of names cannot
        # distinguish the test that passed from the one that was skipped in
        # the same run, and a claim about a named test needs that distinction:
        # adding a skip is the cheapest way to stop a test failing.
        entry = {
            "id": f"{classname}::{name}" if classname else name,
            "name": name,
            "classname": classname,
            "status": status,
        }
        # Some runners say where the test lives. Kept as a hint for locating
        # the definition; it is replaced by the resolved path when that
        # succeeds and dropped when the path is not in the checkout.
        junit_file = (case.get("file") or "").strip()
        if junit_file:
            entry["file"] = junit_file
        tests.append(entry)

    total = len(cases)
    return {
        "totals": {
            "total": total,
            "passed": total - failed - skipped - errored,
            "failed": failed,
            "skipped": skipped,
            "errors": errored,
        },
        "tests": tests,
    }


# ---------------------------------------------------------------------------
# Locating each test's definition -- the content the attestation binds
# ---------------------------------------------------------------------------

# pytest appends the parametrize id to the name: ``test_x[case-1]``. Every
# case shares one definition, so the id is stripped before lookup.
_PARAM_SUFFIX = re.compile(r"\[.*$", re.DOTALL)


def base_test_name(name: str) -> str:
    """The function name a recorded test name refers to."""
    return _PARAM_SUFFIX.sub("", str(name or "")).strip()


def normalised_definition(block: str) -> str:
    """Line endings and trailing whitespace are not part of a definition."""
    return "\n".join(
        line.rstrip() for line in block.replace("\r\n", "\n").split("\n")
    )


def definition_sha256(block: str) -> str:
    from .languages.definitions import hash_of

    return hash_of(block)


def _relative_posix(project_root: Path, path: Path) -> str:
    return path.resolve().relative_to(project_root.resolve()).as_posix()


def _resolve_in_root(project_root: Path, rel: str) -> Optional[Path]:
    """``rel`` as a file inside ``project_root``, or ``None``."""
    if not rel or "\0" in rel:
        return None
    try:
        candidate = (project_root / rel).resolve()
        root = project_root.resolve()
    except (OSError, RuntimeError):
        return None
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


def _module_file(project_root: Path, dotted: str) -> Optional[Path]:
    """The file a dotted module path names, as ``a/b/c.py`` or a package."""
    parts = [p for p in dotted.split(".") if p]
    if not parts or len(parts) != len(dotted.split(".")):
        return None
    if any(p in (".", "..") or "/" in p or "\\" in p for p in parts):
        return None
    base = "/".join(parts)
    for rel in (f"{base}.py", f"{base}/__init__.py"):
        found = _resolve_in_root(project_root, rel)
        if found is not None:
            return found
    return None


class DefinitionRecord(tuple):
    """``(sha256, scope, parser)`` of a located definition.

    ``scope`` is ``symbol`` (a parser or an exact keyword-pair block isolated
    the named definition), ``block`` (a block starting at the first line that
    matched the name) or ``file`` (the whole file; ``parser`` is then empty).
    """

    __slots__ = ()

    def __new__(cls, sha256: str, scope: str, parser: str = ""):
        return super().__new__(cls, (sha256, scope, parser))

    @property
    def sha256(self) -> str:
        return self[0]

    @property
    def scope(self) -> str:
        return self[1]

    @property
    def parser(self) -> str:
        return self[2]


def locate_definition_record(
    project_root: Path, rel_file: str, name: str, owner: str = "",
) -> Optional[DefinitionRecord]:
    """Where and how ``name`` is defined in ``rel_file``, or ``None``.

    The language is taken from the file's extension. An empty ``name``
    hashes the file. The hash is taken over the untruncated block: the
    reviewer's copy is bounded, the evidence is not.
    """
    from .definition_extract import locate_definition
    from .languages.definitions import language_of

    path = _resolve_in_root(project_root, rel_file)
    if path is None:
        return None
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if name:
        qualified = f"{owner}.{name}" if owner else name
        kind = "method" if owner else "function"
        found = locate_definition(content, kind, qualified, language=language_of(rel_file))
        if found is not None:
            return DefinitionRecord(definition_sha256(found.text), found.scope, found.parser)
    return DefinitionRecord(definition_sha256(content), "file", "")


def definition_hash_for(
    project_root: Path, rel_file: str, name: str, owner: str = "",
) -> Optional[tuple[str, str]]:
    """``(sha256, scope)`` for ``name`` in ``rel_file``, or ``None``.

    ``scope`` is ``"definition"`` when the block could be isolated -- inside
    ``owner`` when a class is named -- and ``"file"`` when only the file
    could be found, in which case the hash covers the whole file. See
    ``locate_definition_record`` for the finer scope and the parser.
    """
    record = locate_definition_record(project_root, rel_file, name, owner)
    if record is None:
        return None
    return record.sha256, ("file" if record.scope == "file" else "definition")


def _locate_one(project_root: Path, entry: dict) -> None:
    name = base_test_name(entry.get("name"))
    classname = str(entry.get("classname") or "").strip()
    hint = str(entry.get("file") or "").strip()
    entry.pop("file", None)

    candidates: list[tuple[Path, str]] = []  # (file, owning class or "")
    if classname:
        whole = _module_file(project_root, classname)
        if whole is not None:
            candidates.append((whole, ""))
        owner, _, cls = classname.rpartition(".")
        if owner and cls:
            holder = _module_file(project_root, owner)
            if holder is not None:
                candidates.append((holder, cls))
    if hint:
        hinted = _resolve_in_root(project_root, hint.replace("\\", "/"))
        if hinted is not None:
            candidates.append((hinted, ""))

    fallback: Optional[tuple[Path, str]] = None
    for path, owner in candidates:
        rel = _relative_posix(project_root, path)
        if owner:
            # The class must be defined in that file for the method to be
            # the definition; otherwise the file is only a location.
            from .definition_extract import definition_line_span
            from .languages.definitions import language_of

            content = path.read_text(encoding="utf-8", errors="replace")
            if definition_line_span(content, "class", owner, language=language_of(rel)) is None:
                # The dotted name's last segment was read as a class and the
                # file defines none by that name, so this file is not where
                # the test lives; it is not even a fallback location.
                continue
        record = locate_definition_record(project_root, rel, name, owner)
        if record is None:
            continue
        if record.scope != "file":
            entry["file"] = rel
            entry["definition_sha256"] = record.sha256
            entry["definition_scope"] = record.scope
            entry["parser"] = record.parser
            return
        fallback = fallback or (path, "")
    if fallback is not None:
        path, _ = fallback
        record = locate_definition_record(project_root, _relative_posix(project_root, path), "")
        if record is not None:
            entry["file"] = _relative_posix(project_root, path)
            entry["definition_sha256"] = record.sha256
            entry["definition_scope"] = "file"
            entry.pop("parser", None)


def locate_test_definitions(project_root: Path, tests: list) -> None:
    """Record, per test, where it is defined and a hash of that definition.

    Adds ``file`` (repository-relative), ``definition_sha256``,
    ``definition_scope`` (``symbol`` / ``block`` / ``file``) and, unless the
    scope is the file, ``parser`` (what isolated the span) to each entry
    that resolves. An entry that cannot be resolved is left without the
    fields: absence means "not resolved", which a reader treats as unknown,
    never as a match. Nothing here raises.
    """
    for entry in tests or []:
        if not isinstance(entry, dict):
            continue
        try:
            _locate_one(project_root, entry)
        except Exception:  # noqa: BLE001
            entry.pop("file", None)
            entry.pop("definition_sha256", None)
            entry.pop("definition_scope", None)
            entry.pop("parser", None)


# ---------------------------------------------------------------------------
# Coverage contexts -- what each test reached
# ---------------------------------------------------------------------------

def _key_names_entry(key: str, entry: dict) -> bool:
    """Whether a coverage attribution key names the recorded test.

    Keys come in two shapes. A coverage.py context,
    ``tests/test_x.py::TestCase::test_name[case]|run`` (the phase suffix
    is already stripped), names the test by file and leaf; the file must
    be the one the test was located in, unless the test was not located.
    A per-test report's file stem names it by id, with ``::`` spelled
    ``__``, or by bare name.
    """
    name = base_test_name(entry.get("name"))
    if not name:
        return False
    known_file = str(entry.get("file") or "").replace("\\", "/")
    classname = str(entry.get("classname") or "")
    test_id = str(entry.get("id") or "")
    key = str(key or "").replace("\\", "/")
    if "::" in key:
        head, _, rest = key.partition("::")
        if base_test_name(rest.rsplit("::", 1)[-1]) != name:
            return False
        if not head or head == classname or head == test_id.partition("::")[0]:
            return True
        return not known_file or head == known_file
    raw_name = str(entry.get("name") or "")
    accepted = {test_id, raw_name, name}
    for prefix in (classname, known_file):
        if prefix:
            accepted.add(f"{prefix}::{raw_name}")
            accepted.add(f"{prefix}::{name}")
    accepted |= {a.replace("::", "__") for a in accepted}
    return key in accepted


def merge_coverage(summary: dict, coverage: object, project_root: Path) -> None:
    """Record what each test reached, from a coverage report.

    ``coverage`` is a report path (any format ``coverage_readers`` reads, or
    a directory of one report per test), an already-read ``CoverageReport``,
    or a parsed coverage.py JSON export.

    A report that attributes lines to tests gives each recorded test
    ``reached: [{file, lines}]``; a test nothing names gets an explicitly
    empty list, which is a fact (the run had coverage and the test touched
    nothing tracked), unlike the absence of the field. An aggregate report
    gives each test ``suite_reached`` instead and no ``reached``: reach is
    a claim about one test, and a suite-wide report cannot make it.
    """
    from .coverage_readers import CoverageReadError, CoverageReport, read_coverage, read_coveragepy

    try:
        if isinstance(coverage, CoverageReport):
            report = coverage
        elif isinstance(coverage, (str, Path)):
            report = read_coverage(coverage, project_root)
        else:
            report = read_coveragepy(coverage, project_root)
    except CoverageReadError as e:
        raise AttestationError(str(e)) from e

    tests = [t for t in (summary.get("tests") or []) if isinstance(t, dict)]
    if report.attributed:
        for entry in tests:
            entry.pop("suite_reached", None)
            reached: dict[str, set[int]] = {}
            for key, per_file in report.per_test.items():
                if not _key_names_entry(key, entry):
                    continue
                for src, lines in per_file.items():
                    reached.setdefault(src, set()).update(lines)
            entry["reached"] = _reach_list(reached)
        return
    suite = _reach_list(report.suite)
    for entry in tests:
        entry.pop("reached", None)
        entry["suite_reached"] = [
            {"file": item["file"], "lines": list(item["lines"])} for item in suite
        ]


def _reach_list(per_file: dict[str, set[int]]) -> list[dict]:
    return [
        {"file": src, "lines": sorted(lines)}
        for src, lines in sorted(per_file.items()) if src
    ]


# ---------------------------------------------------------------------------
# Building the statement
# ---------------------------------------------------------------------------

def _ci_context() -> dict:
    """The CI identifiers available from the environment, best-effort.

    Recorded for an auditor's benefit. It is NOT the trust anchor -- an
    environment variable proves nothing on its own. The signature does.
    """
    if os.environ.get("GITHUB_ACTIONS"):
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        return {
            "provider": "github",
            "run_id": run_id,
            "run_url": f"https://github.com/{repo}/actions/runs/{run_id}" if repo and run_id else "",
            "workflow": os.environ.get("GITHUB_WORKFLOW_REF", "") or os.environ.get("GITHUB_WORKFLOW", ""),
        }
    if os.environ.get("GITLAB_CI"):
        return {
            "provider": "gitlab",
            "run_id": os.environ.get("CI_PIPELINE_ID", ""),
            "run_url": os.environ.get("CI_PIPELINE_URL", ""),
            "workflow": os.environ.get("CI_JOB_NAME", ""),
        }
    if os.environ.get("CIRCLECI"):
        return {
            "provider": "circleci",
            "run_id": os.environ.get("CIRCLE_WORKFLOW_ID", ""),
            "run_url": os.environ.get("CIRCLE_BUILD_URL", ""),
            "workflow": os.environ.get("CIRCLE_JOB", ""),
        }
    if os.environ.get("BUILDKITE"):
        return {
            "provider": "buildkite",
            "run_id": os.environ.get("BUILDKITE_BUILD_ID", ""),
            "run_url": os.environ.get("BUILDKITE_BUILD_URL", ""),
            "workflow": os.environ.get("BUILDKITE_PIPELINE_SLUG", ""),
        }
    return {"provider": "", "run_id": "", "run_url": "", "workflow": ""}


# Environment keys are nominated by name, never collected wholesale: a signed
# artifact travels to the platform and to auditors, and a CI environment holds
# credentials. These names are refused outright rather than redacted, so an
# operator learns at attestation time instead of discovering a leaked value in
# a signed record that has already been distributed.
SECRET_NAME_PATTERN = re.compile(
    r"SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|APIKEY|API_KEY"
    r"|ACCESS_KEY|SIGNING_KEY|_KEY$|^KEY$",
    re.IGNORECASE,
)

# A nominated key is recorded even when unset, as null. Silence would make
# "the flag was absent" indistinguishable from "nobody asked about the flag",
# and an assertion needs to be able to require that a flag was NOT set.
MAX_ENV_KEYS = 32
MAX_ENV_VALUE_LEN = 512


def collect_environment(keys: list) -> dict:
    """Read the nominated environment keys, for recording in the predicate.

    What a test run proves depends on the configuration it ran under: a suite
    can pass with the control it exercises switched off. Assertions over files
    in the tree constrain the configuration a repository *declares*, not the
    one a run *had*, so the run records its own.
    """
    names = [k.strip() for k in keys if k and k.strip()]
    if len(names) > MAX_ENV_KEYS:
        raise AttestationError(
            f"{len(names)} environment keys nominated; at most {MAX_ENV_KEYS} "
            f"may be recorded."
        )
    out: dict = {}
    for name in names:
        if SECRET_NAME_PATTERN.search(name):
            raise AttestationError(
                f"Refusing to record environment key {name!r}: the name marks "
                f"it as a credential, and an attestation is signed and "
                f"distributed. Nominate a key that describes configuration."
            )
        value = os.environ.get(name)
        if value is not None and len(value) > MAX_ENV_VALUE_LEN:
            raise AttestationError(
                f"Environment key {name!r} holds {len(value)} characters; at "
                f"most {MAX_ENV_VALUE_LEN} may be recorded."
            )
        out[name] = value
    return out


def build_statement(
    *,
    commit: str,
    summary: dict,
    invocation: list[str],
    selected_pattern: str = "",
    coverage: Optional[dict] = None,
    environment: Optional[dict] = None,
    kind: str = "",
    predicate_extra: Optional[dict] = None,
    reach_scope: str = "",
) -> dict:
    """Assemble the in-toto statement for one test run.

    ``kind`` distinguishes a second statement shape carried under the same
    predicate type: absent means a test-result record; ``"dependence"``
    means each test's entry records how it fared with a mechanism disabled;
    ``"reach"`` means each entry records what a coverage run executed.
    ``reach_scope`` says what a reach record's coverage is scoped to:
    ``"test"`` (each test run alone; the entries carry ``reached``) or
    ``"suite"`` (one whole-suite run; the entries carry ``suite_reached``
    and never ``reached``).
    """
    totals = summary["totals"]
    predicate: dict[str, Any] = {
        "invocation": list(invocation),
        "outcome": "passed" if (
            totals["failed"] == 0 and totals["errors"] == 0 and totals["passed"] > 0
        ) else "failed",
        "totals": totals,
        "selected": {
            "pattern": selected_pattern,
            "matched_count": totals["total"],
        },
        "tests": summary.get("tests", []),
        "ci": _ci_context(),
        "attested_at": datetime.now(timezone.utc).isoformat(),
    }
    if kind:
        predicate["kind"] = kind
    if predicate_extra:
        # Record-level facts a kind carries beyond the per-test entries
        # (``strategy`` and ``control_run`` on a hook-built dependence run).
        predicate.update(predicate_extra)
    if reach_scope:
        predicate["reach_scope"] = reach_scope
    if coverage:
        predicate["coverage"] = coverage
    if environment is not None:
        # Present-but-empty is meaningful: it records that nothing was
        # nominated, which is different from a predicate that predates the
        # field. An assertion requiring an environment fact fails on both, but
        # the reader can tell them apart.
        predicate["environment"] = environment
    predicate["commit"] = commit

    # The subject digest is a sha256 over the predicate, not the commit: an
    # in-toto Subject admits sha256 and above, and a git commit is sha1. The
    # commit it covers is carried in the predicate and is what the replay guard
    # reads; the subject digest binds the signature to this exact predicate.
    body = json.dumps(predicate, sort_keys=True, separators=(",", ":")).encode()
    return {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": [{
            "name": f"mipiti:test-result:{commit}",
            "digest": {"sha256": hashlib.sha256(body).hexdigest()},
        }],
        "predicate": predicate,
    }


# ---------------------------------------------------------------------------
# Envelope: sign and verify
# ---------------------------------------------------------------------------

def _canonical(statement: dict) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()


def sign_statement(
    statement: dict,
    *,
    identity_token: str = "",
    key_path: str = "",
    key_passphrase: str = "",
    tuf_url: Optional[str] = None,
    trust_config_path: Optional[str] = None,
) -> tuple[str, str]:
    """Sign a statement. Returns ``(serialised_attestation, provenance_class)``.

    Signing identity is chosen the same way the verification run chooses one, so
    an attestation is no weaker than the run that reads it:

    1. ``ci_oidc`` -- a CI workload identity, signed keylessly through Sigstore.
       Preferred wherever it exists, because the certificate binds the
       repository, ref and workflow, and there is no key to hold or rotate.
    2. ``customer_key`` -- an ECDSA P-256 DSSE bundle, for CI with no workload
       identity. Same envelope shape as the customer-DSSE path already used for
       verification runs.
    3. ``unsigned`` -- neither is available. Recorded as self-declared.
    """
    payload = _canonical(statement)

    if identity_token:
        return _sign_sigstore(
            statement, identity_token, tuf_url, trust_config_path,
        ), PROVENANCE_CI_OIDC

    if key_path:
        return _sign_ecdsa(payload, key_path, key_passphrase), PROVENANCE_CUSTOMER_KEY

    return json.dumps({
        "v": 1,
        "kind": "unsigned",
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
    }), PROVENANCE_UNSIGNED


def _sign_sigstore(statement, identity_token, tuf_url, trust_config_path) -> str:
    from sigstore.dsse import StatementBuilder, Subject
    from sigstore.oidc import IdentityToken
    from sigstore.sign import SigningContext

    from .sigstore_signer import _load_trust_config

    subject = statement["subject"][0]
    built = (
        StatementBuilder()
        .subjects([Subject(name=subject["name"], digest=subject["digest"])])
        .predicate_type(PREDICATE_TYPE)
        .predicate(statement["predicate"])
        .build()
    )
    ctx = SigningContext.from_trust_config(
        _load_trust_config(tuf_url, trust_config_path)
    )
    with ctx.signer(IdentityToken(identity_token)) as signer:
        return signer.sign_dsse(built).to_json()


def _sign_ecdsa(payload: bytes, key_path: str, passphrase: str) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from .customer_dsse_signer import _load_private_key, compute_pae

    key = _load_private_key(key_path, passphrase or None)
    signature = key.sign(compute_pae(payload), ec.ECDSA(hashes.SHA256()))
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return json.dumps({
        "v": 1,
        "kind": "customer-dsse",
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": public_pem,
    })


def verify_attestation(
    raw: str,
    *,
    expected_identity: str = "",
    expected_issuer: str = "",
    expected_key_pem: str = "",
    allow_unsigned: bool = False,
    tuf_url: Optional[str] = None,
    trust_config_path: Optional[str] = None,
) -> tuple[dict, str]:
    """Return ``(statement, provenance_class)`` for a well-formed attestation.

    Raises ``AttestationError`` on anything that does not verify. Each path
    derives trust from something the reader supplied, never from the
    attestation itself:

    - Sigstore: the certificate identity must match ``expected_identity`` and
      ``expected_issuer``. Without a pinned identity any valid Sigstore
      signature from any signer would verify, which would make the check
      decorative, so an unpinned identity is refused.
    - ECDSA: the signature must verify against ``expected_key_pem``, never the
      key embedded in the attestation.
    - Unsigned: accepted only when ``allow_unsigned``, which callers set only
      where no signing identity was available at all.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AttestationError(f"Attestation is not JSON: {e}") from e

    kind = obj.get("kind", "")
    if kind == "customer-dsse":
        statement = _verify_ecdsa(obj, expected_key_pem)
        provenance = PROVENANCE_CUSTOMER_KEY
    elif kind == "unsigned":
        if not allow_unsigned:
            raise AttestationError(
                "Attestation is unsigned, but a signing identity is available "
                "here. Refusing an unsigned attestation where a signed one was "
                "expected."
            )
        statement = _decode_payload(obj.get("payload"))
        provenance = PROVENANCE_UNSIGNED
    else:
        statement = _verify_sigstore(
            raw, expected_identity, expected_issuer, tuf_url, trust_config_path,
        )
        provenance = PROVENANCE_CI_OIDC

    if not isinstance(statement, dict):
        # A payload is attacker-supplied JSON: it need not be an object at all,
        # and every read below assumes one.
        raise AttestationError(
            f"Attestation payload is a {type(statement).__name__}, not a statement."
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise AttestationError(
            f"Unexpected predicateType {statement.get('predicateType')!r}; "
            f"expected {PREDICATE_TYPE}."
        )
    return statement, provenance


def _decode_payload(payload) -> dict:
    if not isinstance(payload, str) or not payload:
        raise AttestationError("Attestation carries no payload.")
    try:
        return json.loads(base64.b64decode(payload))
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation payload is unreadable: {e}") from e


def _verify_ecdsa(obj: dict, expected_key_pem: str) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from .customer_dsse_signer import compute_pae

    if not expected_key_pem:
        raise AttestationError(
            "A signed attestation was found but no public key is configured to "
            "check it against. Trusting the key carried inside the attestation "
            "would let it vouch for itself."
        )
    payload_b64 = obj.get("payload")
    statement = _decode_payload(payload_b64)
    try:
        public_key = serialization.load_pem_public_key(expected_key_pem.encode())
        public_key.verify(
            base64.b64decode(obj.get("signature", "")),
            compute_pae(base64.b64decode(payload_b64)),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as e:
        raise AttestationError(
            "Attestation signature does not verify against the configured key."
        ) from e
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation signature could not be checked: {e}") from e
    return statement


def _verify_sigstore(raw, expected_identity, expected_issuer,
                     tuf_url, trust_config_path) -> dict:
    if not expected_identity or not expected_issuer:
        raise AttestationError(
            "A Sigstore-signed attestation was found but no expected signing "
            "identity is configured. Any valid Sigstore signature would "
            "otherwise verify, whoever produced it."
        )
    from sigstore.models import Bundle
    from sigstore.verify import policy

    from .cli import _build_sigstore_verifier

    try:
        bundle = Bundle.from_json(raw)
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation is not a Sigstore bundle: {e}") from e

    verifier = _build_sigstore_verifier(trust_config_path, tuf_url)
    try:
        _, payload = verifier.verify_dsse(
            bundle,
            policy.Identity(identity=expected_identity, issuer=expected_issuer),
        )
    except Exception as e:  # noqa: BLE001
        raise AttestationError(f"Attestation signature does not verify: {e}") from e
    return json.loads(payload)


# ---------------------------------------------------------------------------
# Locating attestations in a checkout
# ---------------------------------------------------------------------------

def expected_ci_identity() -> tuple[str, str]:
    """The signing identity a Sigstore-signed attestation must carry here.

    Derived from the environment rather than configured, because verification
    runs in the same CI as the attestation it reads: the certificate must name
    this repository's workflow. A pinned identity is what makes the signature
    check mean anything -- without it, any valid Sigstore signature verifies,
    whoever produced it.

    Returns ``("", "")`` where no workload identity exists, which callers take
    as "this CI cannot sign keylessly".
    """
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "").strip()
    if workflow_ref:
        return (
            f"https://github.com/{workflow_ref}",
            "https://token.actions.githubusercontent.com",
        )
    # GitLab: the Fulcio SAN is project URL // config path @ ref, the issuer
    # is the GitLab server. A workload identity exists under the ``id_tokens``
    # keyword (surfaced as SIGSTORE_ID_TOKEN by convention) or the retired
    # CI_JOB_JWT_V2; without either the job cannot sign keylessly.
    gl_url = os.environ.get("CI_PROJECT_URL", "").strip()
    gl_path = os.environ.get("CI_CONFIG_PATH", "").strip()
    gl_ref = os.environ.get("CI_COMMIT_REF_NAME", "").strip()
    has_token = bool(os.environ.get("SIGSTORE_ID_TOKEN") or os.environ.get("CI_JOB_JWT_V2"))
    if gl_url and gl_path and gl_ref and has_token:
        return f"{gl_url}//{gl_path}@{gl_ref}", os.environ.get("CI_SERVER_URL", "").strip()
    return "", ""


def load_attestations(project_root: Path) -> list[str]:
    """Every attestation present in the checkout, unparsed.

    Returned as raw text because the serialised form is what a signature covers:
    parsing and re-serialising before verification would check a signature over
    bytes nobody signed.

    Absence is not an error here -- the caller decides what to make of it. A
    verifier treats it as a failure with a wiring pointer; it never falls back
    to running anything.
    """
    directory = attestation_dir(project_root)
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(path.read_text(encoding="utf-8"))
        except OSError:
            continue
    return out


def statement_of(raw: str) -> Optional[dict]:
    """The statement inside an attestation, without verifying it.

    For presentation only -- rendering what a run reported. Never use this to
    decide whether a claim holds.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    payload = obj.get("payload")
    if not isinstance(payload, str):
        return None
    try:
        return json.loads(base64.b64decode(payload))
    except Exception:  # noqa: BLE001
        return None


def head_commit(project_root: Path) -> str:
    """The commit under verification, from CI or the checkout.

    Read, never executed: the CI variable first, then .git/HEAD resolved by
    hand, so this does not shell out to git.
    """
    for var in ("GITHUB_SHA", "CI_COMMIT_SHA", "CIRCLE_SHA1", "BUILDKITE_COMMIT"):
        val = os.environ.get(var, "").strip()
        if val:
            return val
    head = project_root / ".git" / "HEAD"
    try:
        ref = head.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if ref.startswith("ref:"):
        target = project_root / ".git" / ref.split(" ", 1)[1].strip()
        try:
            return target.read_text(encoding="utf-8").strip()
        except OSError:
            packed = project_root / ".git" / "packed-refs"
            try:
                name = ref.split(" ", 1)[1].strip()
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.endswith(f" {name}"):
                        return line.split(" ", 1)[0].strip()
            except OSError:
                return ""
            return ""
    return ref if re.fullmatch(r"[0-9a-f]{40}", ref) else ""
