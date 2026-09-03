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
        public_key = _expected_public_key()
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

            result = self._check(statement, test_name, commit, provenance)
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
               provenance: str) -> VerifierResult:
        predicate = statement.get("predicate") or {}
        totals = predicate.get("totals") or {}
        selected = predicate.get("selected") or {}
        tests = predicate.get("tests") or []

        # Bind to the tree under verification. Without this the attestation is
        # replayable against any later commit. The commit lives in the
        # predicate because an in-toto subject digest cannot be a sha1.
        attested_commit = str(predicate.get("commit") or "")
        if commit and attested_commit and attested_commit != commit:
            return VerifierResult(
                passed=False,
                details=(
                    f"Attestation is for commit {attested_commit[:12]}, "
                    f"not {commit[:12]}."
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

        if not any(test_name in str(t) for t in tests):
            return VerifierResult(
                passed=False,
                details=f"Attested run does not include a test matching '{test_name}'.",
            )

        return VerifierResult(
            passed=True,
            details=(
                f"Attested by {provenance}: '{test_name}' passed in a run of "
                f"{totals.get('total', 0)} test(s) at commit "
                f"{(attested_commit or commit)[:12]}."
            ),
        )


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
    except OSError:
        return ""
