"""Test verifiers: test_exists, test_attested.

Neither runs anything. ``test_exists`` globs the filesystem; ``test_attested``
reads an attestation the customer's CI produced and signed.

``test_passes`` was removed. Verification is a read-only operation over
evidence the project already produced, and that is now true of every assertion
type without exception.
"""

from __future__ import annotations

import glob as glob_mod
from pathlib import Path

from . import VerifierResult, register
from ..attestation import (
    ATTESTATION_DIR,
    AttestationError,
    base_test_name,
    definition_hash_for,
    expected_ci_identity,
    head_commit,
    load_attestations,
    verify_attestation,
)

# The second statement shape carried under the test-result predicate type:
# each test entry records how the test fared with a mechanism disabled.
KIND_DEPENDENCE = "dependence"
KIND_REACH = "reach"
# Records that state a fact about a test rather than that it ran and passed.
FACT_KINDS = frozenset({KIND_DEPENDENCE, KIND_REACH})


def load_verified_statements(
    project_root: Path,
) -> tuple[list[tuple[dict, str]], list[str], str]:
    """Every attestation in the checkout that verifies and names this commit.

    Returns ``(statements, problems, commit)`` where each statement is paired
    with its provenance class. The signature is checked here, never merely
    decoded: what a reader is told the mechanical tier accepted must be what
    it accepted. Envelopes that fail are reported as problems, not dropped
    silently, so a sound one later in the directory is still found and an
    unsound one is still visible.
    """
    commit = head_commit(project_root)
    identity, issuer = expected_ci_identity()
    public_key = _expected_public_key()
    # Unsigned is admissible only where nothing could have signed: no CI
    # workload identity and no configured key. Anywhere else, an unsigned
    # attestation is a weaker claim than the environment could produce.
    allow_unsigned = not identity and not public_key
    statements: list[tuple[dict, str]] = []
    problems: list[str] = []
    for raw in load_attestations(project_root):
        try:
            statement, provenance = verify_attestation(
                raw,
                expected_identity=identity,
                expected_issuer=issuer,
                expected_key_pem=public_key,
                allow_unsigned=allow_unsigned,
            )
        except AttestationError as e:
            problems.append(str(e))
            continue
        except Exception as e:  # noqa: BLE001
            # Envelopes are read in filename order, so an unreadable one
            # early in the directory would otherwise hide a sound one
            # later. A bad file is one problem, not the end of the run.
            problems.append(f"{type(e).__name__}: {e}")
            continue
        statements.append((statement, provenance))
    return statements, problems, commit


def statement_kind(statement: dict) -> str:
    predicate = statement.get("predicate") or {}
    return str(predicate.get("kind") or "") if isinstance(predicate, dict) else ""


@register("test_exists")
class TestExistsVerifier:
    """Check that test files matching a pattern exist."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        pattern = params["pattern"]
        matches = glob_mod.glob(str(project_root / pattern), recursive=True)
        if matches:
            return VerifierResult(
                passed=True,
                details=f"Found {len(matches)} test file(s) matching '{pattern}'",
            )
        return VerifierResult(passed=False, details=f"No test files matching '{pattern}'")


@register("test_attested")
class TestAttestedVerifier:
    """Check a signed statement that the customer's CI ran their tests.

    Every check here is a deterministic fact about the attestation. Whether the
    evidence is strong *enough* for the control's clause is a judgment, and
    belongs to the sufficiency verdict, not here.

    Two of these checks exist specifically to reject claims that establish
    nothing: a selection that matched no tests, and a suite in which nothing
    passed. Both otherwise present as a zero failure count, which is the shape
    a deleted test or an added skip produces.
    """

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        test_name = (params.get("test") or params.get("pattern") or "").strip()
        if not test_name:
            return VerifierResult(
                passed=False,
                details="Assertion names no test: expected a 'test' param.",
            )

        if not load_attestations(project_root):
            return VerifierResult(
                passed=False,
                details=(
                    f"No test attestation found in {ATTESTATION_DIR}/. Run "
                    f"'mipiti-verify attest-tests --junit <report>' in the CI job "
                    f"that runs the tests, before verification."
                ),
            )

        try:
            statements, problems, commit = load_verified_statements(project_root)
        except AttestationError as e:
            return VerifierResult(passed=False, details=str(e))

        # A dependence record is a different claim about the same test: it
        # is consulted for a fact once a test-result record has passed, and
        # is never itself the record that a test ran and passed.
        dependence = [
            st for st, _ in statements if statement_kind(st) == KIND_DEPENDENCE
        ]
        # A reach record likewise: per-test coverage produced by running the
        # test alone, consulted for the reach fact, never for the pass.
        reach = [st for st, _ in statements if statement_kind(st) == KIND_REACH]
        for statement, provenance in statements:
            if statement_kind(statement) in FACT_KINDS:
                continue
            result = self._check(
                statement, test_name, commit, provenance, params.get("env"),
                params=params, project_root=project_root, dependence=dependence,
                reach=reach,
            )
            if result.passed:
                return result
            problems.append(result.details)

        return VerifierResult(
            passed=False,
            details=(
                f"No attestation evidences '{test_name}'. "
                + " | ".join(problems[:3])
            ),
        )

    def _check(self, statement: dict, test_name: str, commit: str,
               provenance: str, required_env: object = None, *,
               params: object = None, project_root: Path | None = None,
               dependence: list | None = None,
               reach: list | None = None) -> VerifierResult:
        predicate = statement.get("predicate") or {}
        totals = predicate.get("totals") or {}
        selected = predicate.get("selected") or {}
        tests = predicate.get("tests") or []

        # Bind to the tree under verification. Absence fails: a binding that
        # switches itself off when either side is missing would accept an
        # attestation naming no commit against any tree at all, which is the
        # replay this check exists to stop.
        attested_commit = str(predicate.get("commit") or "")
        if not attested_commit:
            return VerifierResult(
                passed=False,
                details="Attestation names no commit, so it cannot be bound to this tree.",
            )
        if not commit:
            return VerifierResult(
                passed=False,
                details=(
                    "Cannot determine the commit under verification, so an "
                    "attestation cannot be bound to it."
                ),
            )
        if attested_commit != commit:
            return VerifierResult(
                passed=False,
                details=(
                    f"Attestation is for commit {attested_commit[:12]}, "
                    f"not {commit[:12]}."
                ),
            )

        incoherent = _totals_are_coherent(totals)
        if incoherent:
            return VerifierResult(
                passed=False, details=f"Attestation is not self-consistent: {incoherent}.",
            )
        if tests and len(tests) != int(totals.get("total") or 0):
            return VerifierResult(
                passed=False,
                details=(
                    f"Attestation records {len(tests)} test(s) but claims a "
                    f"total of {totals.get('total')}."
                ),
            )

        if predicate.get("outcome") != "passed":
            return VerifierResult(
                passed=False, details="Attested run did not pass.",
            )

        # A selection that matched nothing establishes nothing. It is not weak
        # evidence for a judge to weigh -- it is a claim about a run that did
        # not happen.
        if int(selected.get("matched_count") or 0) <= 0:
            return VerifierResult(
                passed=False,
                details="Attested run selected no tests (matched_count = 0).",
            )
        if int(totals.get("passed") or 0) <= 0:
            return VerifierResult(
                passed=False,
                details="Attested run had no passing tests.",
            )
        if int(totals.get("failed") or 0) or int(totals.get("errors") or 0):
            return VerifierResult(
                passed=False,
                details=(
                    f"Attested run had {totals.get('failed', 0)} failure(s) "
                    f"and {totals.get('errors', 0)} error(s)."
                ),
            )

        # The named test must itself have passed. A substring match over the
        # run's test names would let a neighbouring test satisfy the claim,
        # and presence alone says only that the test was collected -- a
        # skipped test appears in the run exactly like one that ran.
        matched = [t for t in tests if _names_test(t, test_name)]
        if not matched:
            return VerifierResult(
                passed=False,
                details=f"Attested run does not include a test named '{test_name}'.",
            )
        if len(matched) > 1:
            return VerifierResult(
                passed=False,
                details=(
                    f"'{test_name}' names {len(matched)} tests in the attested "
                    f"run; name it unambiguously as 'classname::name'."
                ),
            )
        status = str(matched[0].get("status") or "")
        if status != "passed":
            return VerifierResult(
                passed=False,
                details=f"'{test_name}' did not pass in the attested run: {status or 'no status recorded'}.",
            )

        shortfall = _environment_shortfall(predicate, required_env)
        if shortfall:
            return VerifierResult(
                passed=False,
                details=f"'{test_name}' passed, but {shortfall}.",
                provenance=provenance,
            )

        facts = _evidence_facts(
            matched[0], test_name,
            params if isinstance(params, dict) else {},
            project_root, dependence or [], commit, reach=reach or [],
        )
        return VerifierResult(
            passed=True,
            details=(
                f"Attested by {provenance}: '{test_name}' passed in a run of "
                f"{totals.get('total', 0)} test(s) at commit "
                f"{(attested_commit or commit)[:12]}."
                + _facts_sentence(facts, bool(parse_mechanism(params.get("mechanism"))[0])
                                  if isinstance(params, dict) else False)
            ),
            provenance=provenance,
            **facts,
        )


def parse_mechanism(value: object) -> tuple[str, str]:
    """``(file, symbol)`` from a ``<file>::<symbol>`` mechanism reference."""
    text = str(value or "").strip()
    if "::" not in text:
        return "", ""
    file, _, symbol = text.partition("::")
    file = file.strip().replace("\\", "/")
    symbol = symbol.strip()
    if not file or not symbol:
        return "", ""
    return file, symbol


def mechanism_kinds(symbol: str) -> tuple[tuple[str, ...], str]:
    """``(kinds to try, name)`` for the symbol half of a mechanism reference.

    ``kind:name`` (``module:alu``, ``always:seq_logic``) names the kind
    outright. ``Class.method`` is a method. A bare name is tried as a
    function, then a class, then each HDL kind in a fixed order, so a
    reader can predict which definition a bare name resolves to.
    """
    from ..languages.definitions import HDL_KINDS, MECHANISM_KIND_ORDER

    text = str(symbol or "").strip()
    if ":" in text and "::" not in text:
        kind, _, name = text.partition(":")
        kind, name = kind.strip().lower(), name.strip()
        if kind in ("function", "class", "method") or kind in HDL_KINDS:
            return (kind,), name
    if "." in text:
        return ("method", "class"), text
    return MECHANISM_KIND_ORDER, text


def mechanism_line_span(project_root: Path, file: str, symbol: str) -> tuple[int, int] | None:
    """Where the named mechanism is defined in the checkout, or ``None``.

    Resolved with the language the file's extension names, so the span is
    the parser's where one is installed and the block fallback's otherwise;
    reach is then "any attested line of that file inside the span".
    """
    from . import PathTraversalError, safe_resolve_path
    from ..definition_extract import definition_line_span
    from ..languages.definitions import language_of

    try:
        path = safe_resolve_path(project_root, file)
    except PathTraversalError:
        return None
    if not path.is_file():
        return None
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    kinds, name = mechanism_kinds(symbol)
    if not name:
        return None
    language = language_of(file)
    for kind in kinds:
        span = definition_line_span(content, kind, name, language=language)
        if span is not None:
            return span
    return None


def definition_matches_checkout(project_root: Path, entry: dict) -> bool | None:
    """Whether the attested definition hash equals the checkout's, or unknown.

    Computed the same way the attestation computed it, so the comparison is
    over the same normalised block; a mismatch means the definition the run
    attested is not the definition in this tree.
    """
    attested = str(entry.get("definition_sha256") or "")
    file = str(entry.get("file") or "")
    if not attested or not file:
        return None
    if entry.get("definition_scope") == "file":
        current = definition_hash_for(project_root, file, "")
    else:
        owner = str(entry.get("classname") or "").rpartition(".")[-1]
        name = base_test_name(entry.get("name"))
        current = definition_hash_for(project_root, file, name, owner)
        if current is not None and current[1] != "definition" and owner:
            current = definition_hash_for(project_root, file, name)
        if current is not None and current[1] != "definition":
            return None
    if current is None:
        return None
    return current[0] == attested


def _reached_mechanism(entry: dict, project_root: Path | None,
                       file: str, symbol: str) -> bool | None:
    """Whether the recorded run executed a line of the mechanism, or unknown.

    Unknown when the run recorded no coverage for the test or the mechanism
    cannot be located; ``False`` when it recorded coverage and none of it
    fell inside the mechanism's definition.
    """
    reached = entry.get("reached")
    if not isinstance(reached, list) or project_root is None:
        return None
    span = mechanism_line_span(project_root, file, symbol)
    if span is None:
        return None
    start, end = span
    for item in reached:
        if not isinstance(item, dict):
            continue
        if str(item.get("file") or "").replace("\\", "/") != file:
            continue
        lines = item.get("lines")
        if not isinstance(lines, list):
            continue
        for line in lines:
            try:
                n = int(line)
            except (TypeError, ValueError):
                continue
            if start <= n <= end:
                return True
    return False


def _depends_on_mechanism(dependence: list, test_name: str, commit: str,
                          mechanism: str) -> bool | None:
    """Whether a dependence record says the test fails without the mechanism.

    Only a record for the commit under verification speaks for this tree.
    ``True`` when the test's outcome under the disabled mechanism was
    anything but passed; ``False`` when it still passed; unknown when no
    record names the pair, or when the record says the pair was not run
    (it carries a ``reason``): an outcome that was never produced is not
    evidence in either direction.
    """
    for statement in dependence:
        predicate = statement.get("predicate") or {}
        if not commit or str(predicate.get("commit") or "") != commit:
            continue
        for entry in predicate.get("tests") or []:
            if not _names_test(entry, test_name):
                continue
            for item in entry.get("fails_without") or []:
                if not isinstance(item, dict):
                    continue
                if str(item.get("mechanism") or "").strip() != mechanism:
                    continue
                if item.get("reason"):
                    return None
                return str(item.get("status") or "") != "passed"
    return None


def _reach_entry(reach: list, test_name: str, commit: str, mechanism: str) -> dict | None:
    """The reach record's entry for this test at this commit, when one names
    the same mechanism (or no mechanism, for a record produced per test
    without one) and was actually run (no ``reason``)."""
    for statement in reach or []:
        predicate = statement.get("predicate") or {}
        if not commit or str(predicate.get("commit") or "") != commit:
            continue
        for entry in predicate.get("tests") or []:
            if not _names_test(entry, test_name):
                continue
            if entry.get("reason"):
                continue
            named = str(entry.get("mechanism") or "").strip()
            if named and named != mechanism:
                continue
            if isinstance(entry.get("reached"), list):
                return entry
    return None


def _evidence_facts(entry: dict, test_name: str, params: dict,
                    project_root: Path | None, dependence: list,
                    commit: str, reach: list | None = None) -> dict:
    """The facts a passing test-result record establishes about its evidence."""
    facts: dict = {}
    digest = str(entry.get("definition_sha256") or "")
    if digest:
        facts["evidence_hash"] = f"sha256:{digest}"
    mechanism = str(params.get("mechanism") or "").strip()
    file, symbol = parse_mechanism(mechanism)
    if not file:
        return facts
    reached = _reached_mechanism(entry, project_root, file, symbol)
    if reached is None:
        # The test-result record carried no per-test coverage; a reach record
        # for the same test and commit (``attest-reach``) may.
        reach_entry = _reach_entry(reach or [], test_name, commit, mechanism)
        if reach_entry is not None:
            reached = _reached_mechanism(reach_entry, project_root, file, symbol)
    if reached is not None:
        facts["reached"] = reached
    depends = _depends_on_mechanism(dependence, test_name, commit, mechanism)
    if depends is not None:
        facts["depends"] = depends
    return facts


def _yes_no(value: bool | None) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _facts_sentence(facts: dict, mechanism_named: bool) -> str:
    """One line stating what the evidence establishes, for the details.

    Both mechanism facts are stated whenever the assertion names one, so an
    unknown reads as unknown rather than as an omission.
    """
    parts = []
    digest = facts.get("evidence_hash", "")
    if digest:
        parts.append(f"definition {digest[:19]}…")
    if mechanism_named:
        parts.append(f"reached mechanism: {_yes_no(facts.get('reached'))}")
        parts.append(f"fails without mechanism: {_yes_no(facts.get('depends'))}")
    if not parts:
        return ""
    return " " + "; ".join(parts) + "."


def _names_test(entry: object, test_name: str) -> bool:
    """Whether one recorded test is the one the assertion names.

    Exact, against either the qualified id or the bare name, so a claim about
    ``test_auth`` is not satisfied by ``test_auth_disabled``. An entry that is
    not a structured record carries no outcome, so it can never evidence that a
    named test passed and is refused here rather than matched loosely.
    """
    if not isinstance(entry, dict):
        return False
    return test_name in (
        str(entry.get("id") or ""),
        str(entry.get("name") or ""),
    ) and test_name != ""


def _environment_shortfall(predicate: dict, required: object) -> str:
    """Empty when the attested run's environment satisfies what is required.

    ``required`` maps an environment name to the value the run must have had.
    A required value of ``None`` means the name must have been unset, which is
    how a control is pinned as "not switched off".

    A predicate carrying no ``environment`` cannot satisfy any requirement:
    the run did not record what it ran under, so the fact is unestablished
    rather than assumed benign.
    """
    if not required:
        return ""
    if not isinstance(required, dict):
        return "the assertion's 'env' param is not a mapping of name to value"
    if "environment" not in predicate:
        return (
            "the attested run recorded no environment, so what it ran under "
            "cannot be established; nominate the keys when attesting"
        )
    actual = predicate.get("environment") or {}
    if not isinstance(actual, dict):
        return "the attested run's environment is not a mapping"
    for name, expected in required.items():
        if name not in actual:
            return f"the attested run did not record {name!r}"
        got = actual[name]
        if expected is None:
            if got is not None:
                return f"{name} was set to {got!r} in the attested run; required unset"
        elif got is None:
            return f"{name} was unset in the attested run; required {expected!r}"
        elif str(got) != str(expected):
            return f"{name} was {got!r} in the attested run; required {expected!r}"
    return ""


def _totals_are_coherent(totals: dict) -> str:
    """Empty when the totals describe a run that could have happened.

    A crafted predicate is not obliged to be arithmetically honest, and every
    downstream check reads these numbers, so they are checked against each
    other before they are believed.
    """
    try:
        parts = {k: int(totals.get(k) or 0)
                 for k in ("total", "passed", "failed", "skipped", "errors")}
    except (TypeError, ValueError):
        return "totals are not numbers"
    if any(v < 0 for v in parts.values()):
        return "totals contain a negative count"
    counted = parts["passed"] + parts["failed"] + parts["skipped"] + parts["errors"]
    if counted != parts["total"]:
        return (
            f"totals do not add up: {counted} outcomes against a total of "
            f"{parts['total']}"
        )
    return ""


def _expected_public_key() -> str:
    """Public key an ECDSA-signed attestation must verify against.

    A path or inline PEM, supplied by the reader. The key embedded in an
    attestation is never used: a signature checked against a key the
    attestation carries proves only that it is internally consistent.
    """
    import os
    from pathlib import Path as _Path

    value = os.environ.get("MIPITI_ATTESTATION_PUBLIC_KEY", "").strip()
    if not value:
        return ""
    if "BEGIN PUBLIC KEY" in value:
        return value
    try:
        return _Path(value).read_text(encoding="utf-8")
    except OSError as e:
        # Returning "" here would read as "no key configured", which is what
        # admits an unsigned attestation. A key that was configured and cannot
        # be read is a misconfiguration, not an absence.
        raise AttestationError(
            f"MIPITI_ATTESTATION_PUBLIC_KEY points at {value!r}, which cannot "
            f"be read: {e}"
        ) from e
