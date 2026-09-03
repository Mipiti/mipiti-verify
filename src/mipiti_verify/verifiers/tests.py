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
    expected_ci_identity,
    head_commit,
    load_attestations,
    verify_attestation,
)


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

        envelopes = load_attestations(project_root)
        if not envelopes:
            return VerifierResult(
                passed=False,
                details=(
                    f"No test attestation found in {ATTESTATION_DIR}/. Run "
                    f"'mipiti-verify attest-tests --junit <report>' in the CI job "
                    f"that runs the tests, before verification."
                ),
            )

        commit = head_commit(project_root)
        identity, issuer = expected_ci_identity()
        try:
            public_key = _expected_public_key()
        except AttestationError as e:
            return VerifierResult(passed=False, details=str(e))
        # Unsigned is admissible only where nothing could have signed: no CI
        # workload identity and no configured key. Anywhere else, an unsigned
        # attestation is a weaker claim than the environment could produce.
        allow_unsigned = not identity and not public_key
        problems: list[str] = []

        for raw in envelopes:
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

            result = self._check(
                statement, test_name, commit, provenance, params.get("env"))
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
               provenance: str, required_env: object = None) -> VerifierResult:
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
            )

        return VerifierResult(
            passed=True,
            details=(
                f"Attested by {provenance}: '{test_name}' passed in a run of "
                f"{totals.get('total', 0)} test(s) at commit "
                f"{(attested_commit or commit)[:12]}."
            ),
        )


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
