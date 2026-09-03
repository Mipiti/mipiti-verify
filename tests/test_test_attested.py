"""test_attested: the verifier reads a signed statement, and executes nothing.

These tests pin the two properties that define the type: verification performs
no execution, and a claim that establishes nothing is rejected mechanically
rather than handed to a judge as weak evidence.
"""

from __future__ import annotations

import ast
import base64
import copy
import importlib
import json
from pathlib import Path

import pytest

from mipiti_verify.attestation import (
    ATTESTATION_DIR,
    PREDICATE_TYPE,
    PROVENANCE_CUSTOMER_KEY,
    PROVENANCE_UNSIGNED,
    AttestationError,
    build_statement,
    collect_environment,
    expected_ci_identity,
    head_commit,
    parse_junit,
    sign_statement,
    verify_attestation,
)
from mipiti_verify.verifiers import get_verifier

COMMIT = "abc123def456abc123def456abc123def456abcd"
NAMED_TEST = "test_non_loopback_host_is_refused"


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    """An ECDSA P-256 keypair, the signing form for CI with no workload
    identity."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    d = tmp_path_factory.mktemp("keys")
    priv = d / "signing.pem"
    priv.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return str(priv), pub

_JUNIT = """<testsuites>
  <testsuite name="s" tests="4" failures="1" errors="0" skipped="1">
    <testcase classname="tests.test_cors" name="test_cross_origin_gets_no_grant"/>
    <testcase classname="tests.test_host" name="test_non_loopback_host_is_refused"/>
    <testcase classname="tests.test_x" name="test_broken"><failure/></testcase>
    <testcase classname="tests.test_y" name="test_ignored"><skipped/></testcase>
  </testsuite>
</testsuites>
"""

_JUNIT_CLEAN = """<testsuites>
  <testsuite name="s">
    <testcase classname="tests.test_host" name="test_non_loopback_host_is_refused"/>
    <testcase classname="tests.test_cors" name="test_cross_origin_gets_no_grant"/>
  </testsuite>
</testsuites>
"""


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text(COMMIT)
    return tmp_path


def _write_attestation(project: Path, *, key_path: str = "",
                       junit: str = _JUNIT_CLEAN, commit: str = COMMIT,
                       environment: dict = None) -> Path:
    report = project / "report.xml"
    report.write_text(junit)
    statement = build_statement(
        commit=commit, summary=parse_junit(report),
        invocation=["pytest", "-q"], selected_pattern="",
        environment=environment,
    )
    attestation, _ = sign_statement(statement, key_path=key_path)
    out = project / ATTESTATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    path = out / "tests.json"
    path.write_text(attestation)
    return path


def _resign(obj: dict, statement: dict, key_path: str) -> dict:
    """Re-sign a modified statement, so a test exercises a genuinely valid
    signature over altered content rather than a broken one."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from mipiti_verify.customer_dsse_signer import compute_pae

    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    obj["payload"] = base64.b64encode(payload).decode()
    obj["signature"] = base64.b64encode(
        key.sign(compute_pae(payload), ec.ECDSA(hashes.SHA256()))
    ).decode()
    return obj


def _verify(project: Path, params: dict, *, public_key: str = "", monkeypatch=None):
    if monkeypatch is not None:
        # No CI workload identity in the test environment, so the keyless path
        # is not in play; these exercise the explicit-key and unsigned tiers.
        for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL"):
            monkeypatch.delenv(var, raising=False)
        if public_key:
            monkeypatch.setenv("MIPITI_ATTESTATION_PUBLIC_KEY", public_key)
        else:
            monkeypatch.delenv("MIPITI_ATTESTATION_PUBLIC_KEY", raising=False)
    return get_verifier("test_attested").verify(params, project)


# ---------------------------------------------------------------------------
# The property the replacement exists for
# ---------------------------------------------------------------------------

# Modules on the read-only verification path. `git remote get-url origin` for
# repo detection is the package's one subprocess and lives outside them.
READ_ONLY_MODULES = ("mipiti_verify.verifiers.tests", "mipiti_verify.attestation")

# Everything these modules may import. An execution capability arrives as an
# import, so an allowlist refuses one that has no name yet, where a denylist of
# known-bad names only refuses the ones already thought of.
PERMITTED_IMPORTS = {
    "__future__", "base64", "cryptography", "datetime", "glob", "hashlib",
    "json", "os", "pathlib", "re", "sigstore", "typing", "xml",
}

# `os` is permitted for os.environ, and carries the process-spawning surface
# with it, so attribute access is constrained separately.
EXECUTION_SINKS = {
    "system", "popen", "execv", "execve", "execvp", "execl", "execlp", "execle",
    "spawnv", "spawnve", "spawnl", "spawnlp", "posix_spawn", "fork", "forkpty",
    "Popen", "call", "check_call", "check_output", "run",
}
EXECUTION_BUILTINS = {"eval", "exec", "compile", "__import__"}


@pytest.mark.parametrize("module_name", READ_ONLY_MODULES)
def test_nothing_on_the_verification_path_can_execute(module_name):
    """Verification reads; it never executes.

    Asserted over the parsed module rather than its text, so a capability
    reached under another name, or through a module imported for another
    purpose, is refused rather than passing an inspection of the source.
    """
    mod = importlib.import_module(module_name)
    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root in PERMITTED_IMPORTS, (
                    f"{module_name} imports {alias.name}, which is not on the "
                    f"read-only path's allowlist"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative, stays inside the package
                continue
            root = (node.module or "").split(".")[0]
            assert root in PERMITTED_IMPORTS, (
                f"{module_name} imports from {node.module}, which is not on "
                f"the read-only path's allowlist"
            )
        elif isinstance(node, ast.Attribute):
            assert node.attr not in EXECUTION_SINKS, (
                f"{module_name} reaches {node.attr}, which starts a process"
            )
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                assert fn.id not in EXECUTION_BUILTINS, (
                    f"{module_name} calls {fn.id}()"
                )


def test_test_passes_is_gone():
    assert get_verifier("test_passes") is None
    assert get_verifier("test_attested") is not None


# ---------------------------------------------------------------------------
# Reading a report
# ---------------------------------------------------------------------------

def test_totals_come_from_the_testcases_not_the_suite_attributes(tmp_path):
    """Runners populate suite-level attributes inconsistently, so the counts are
    derived from the cases themselves."""
    report = tmp_path / "r.xml"
    report.write_text(_JUNIT)
    summary = parse_junit(report)
    assert summary["totals"] == {
        "total": 4, "passed": 2, "failed": 1, "skipped": 1, "errors": 0,
    }


def test_a_failing_run_is_recorded_as_failed(tmp_path):
    report = tmp_path / "r.xml"
    report.write_text(_JUNIT)
    statement = build_statement(
        commit=COMMIT, summary=parse_junit(report), invocation=["pytest"],
    )
    assert statement["predicate"]["outcome"] == "failed"
    assert statement["predicateType"] == PREDICATE_TYPE


def test_an_unreadable_report_is_an_error_not_an_empty_attestation(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("not xml at all <<<")
    with pytest.raises(AttestationError):
        parse_junit(bad)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------

def test_a_test_that_ran_and_passed_verifies(project, keypair, monkeypatch):
    key_path, public_pem = keypair
    _write_attestation(project, key_path=key_path)
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                public_key=public_pem, monkeypatch=monkeypatch)
    assert r.passed
    assert PROVENANCE_CUSTOMER_KEY in r.details


def test_the_provenance_class_is_reported(project, monkeypatch):
    _write_attestation(project)
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"}, monkeypatch=monkeypatch)
    assert r.passed
    assert PROVENANCE_UNSIGNED in r.details


# ---------------------------------------------------------------------------
# Claims that establish nothing -- rejected here, not deferred to a judge
# ---------------------------------------------------------------------------

def test_a_selection_that_matched_nothing_fails(project, keypair, monkeypatch):
    key_path, public_pem = keypair
    path = _write_attestation(project, key_path=key_path)
    obj = json.loads(path.read_text())
    st = json.loads(base64.b64decode(obj["payload"]))
    st["predicate"]["selected"]["matched_count"] = 0
    path.write_text(json.dumps(_resign(obj, st, key_path)))

    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                public_key=public_pem, monkeypatch=monkeypatch)
    assert not r.passed
    assert "matched_count" in r.details


def test_an_all_skipped_run_fails_despite_zero_failures(project, keypair, monkeypatch):
    """The shape a deleted test or an added skip produces: nothing failed
    because nothing ran."""
    key_path, public_pem = keypair
    path = _write_attestation(project, key_path=key_path)
    obj = json.loads(path.read_text())
    st = json.loads(base64.b64decode(obj["payload"]))
    st["predicate"]["totals"] = {
        "total": 2, "passed": 0, "failed": 0, "skipped": 2, "errors": 0,
    }
    path.write_text(json.dumps(_resign(obj, st, key_path)))

    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                public_key=public_pem, monkeypatch=monkeypatch)
    assert not r.passed
    assert "no passing tests" in r.details


def test_a_run_with_failures_does_not_verify(project, monkeypatch):
    _write_attestation(project, junit=_JUNIT)
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"}, monkeypatch=monkeypatch)
    assert not r.passed


def test_a_test_absent_from_the_run_does_not_verify(project, monkeypatch):
    _write_attestation(project)
    r = _verify(project, {"test": "test_that_never_ran"}, monkeypatch=monkeypatch)
    assert not r.passed


def test_an_assertion_naming_no_test_is_rejected(project, monkeypatch):
    _write_attestation(project)
    r = _verify(project, {}, monkeypatch=monkeypatch)
    assert not r.passed
    assert "names no test" in r.details


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

def test_a_tampered_payload_does_not_verify(project, keypair, monkeypatch):
    key_path, public_pem = keypair
    path = _write_attestation(project, key_path=key_path)
    obj = json.loads(path.read_text())
    st = json.loads(base64.b64decode(obj["payload"]))
    st["predicate"]["tests"].append("test_i_made_this_up")
    obj["payload"] = base64.b64encode(
        json.dumps(st, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    path.write_text(json.dumps(obj))  # original signature retained

    r = _verify(project, {"test": "test_i_made_this_up"},
                public_key=public_pem, monkeypatch=monkeypatch)
    assert not r.passed


def test_the_embedded_key_is_never_trusted(project, keypair, monkeypatch):
    """An attestation carrying its own key proves only internal consistency.
    Verification uses the key the reader configured."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key_path, _ = keypair
    path = _write_attestation(project, key_path=key_path)
    obj = json.loads(path.read_text())
    assert obj["public_key_pem"]  # the attestation does carry one

    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                public_key=other, monkeypatch=monkeypatch)
    assert not r.passed
    assert "does not verify" in r.details


def test_a_signed_attestation_without_a_configured_key_does_not_verify(
        project, keypair, monkeypatch):
    key_path, _ = keypair
    _write_attestation(project, key_path=key_path)
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                monkeypatch=monkeypatch)
    assert not r.passed
    assert "no public key is configured" in r.details


def test_unsigned_is_refused_where_signing_was_possible(project, keypair, monkeypatch):
    """Removing a signature must not lower the bar: an unsigned attestation is
    admissible only where nothing could have signed it."""
    _, public_pem = keypair
    _write_attestation(project)  # unsigned
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                public_key=public_pem, monkeypatch=monkeypatch)
    assert not r.passed
    assert "unsigned" in r.details


def test_unsigned_is_admissible_where_nothing_could_sign(project, monkeypatch):
    _write_attestation(project)
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                monkeypatch=monkeypatch)
    assert r.passed


def test_an_attestation_for_another_commit_does_not_verify(project, monkeypatch):
    """The replay guard: without it an old attestation would satisfy any later
    tree."""
    _write_attestation(project, commit="f" * 40)
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"},
                monkeypatch=monkeypatch)
    assert not r.passed
    assert "commit" in r.details


def test_a_foreign_predicate_type_is_rejected():
    statement = {"predicateType": "https://example.test/other/v1", "predicate": {}}
    raw, _ = sign_statement(statement)
    with pytest.raises(AttestationError):
        verify_attestation(raw, allow_unsigned=True)


# ---------------------------------------------------------------------------
# Signing identity
# ---------------------------------------------------------------------------

def test_a_ci_workload_identity_is_preferred_over_a_key(monkeypatch):
    """Keyless signing binds the repository, ref and workflow and needs no
    secret, so it is chosen wherever it exists."""
    calls = {}

    def fake_sigstore(statement, token, tuf, cfg):
        calls["token"] = token
        return '{"kind": "sigstore-bundle"}'

    monkeypatch.setattr("mipiti_verify.attestation._sign_sigstore", fake_sigstore)
    raw, provenance = sign_statement(
        {"predicateType": PREDICATE_TYPE, "subject": [], "predicate": {}},
        identity_token="an-oidc-token",
        key_path="/should/not/be/used.pem",
    )
    assert provenance == "ci_oidc"
    assert calls["token"] == "an-oidc-token"


def test_the_expected_identity_is_derived_from_the_ci_environment(monkeypatch):
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "acme/widgets/.github/workflows/ci.yml@refs/heads/main")
    identity, issuer = expected_ci_identity()
    assert identity.endswith("acme/widgets/.github/workflows/ci.yml@refs/heads/main")
    assert issuer == "https://token.actions.githubusercontent.com"


def test_no_ci_identity_outside_a_workload(monkeypatch):
    for var in ("GITHUB_WORKFLOW_REF", "CI_JOB_JWT_V2", "CI_PROJECT_URL"):
        monkeypatch.delenv(var, raising=False)
    assert expected_ci_identity() == ("", "")


def test_a_sigstore_attestation_without_a_pinned_identity_is_refused():
    """An unpinned identity would accept any valid Sigstore signature from any
    signer, which makes the check decorative."""
    with pytest.raises(AttestationError) as e:
        verify_attestation('{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"}')
    assert "expected signing identity" in str(e.value)


# ---------------------------------------------------------------------------
# Absence
# ---------------------------------------------------------------------------

def test_no_attestation_fails_with_a_wiring_pointer(project, monkeypatch):
    """It must not fall back to running anything -- that is the capability being
    removed."""
    r = _verify(project, {"test": "test_non_loopback_host_is_refused"}, monkeypatch=monkeypatch)
    assert not r.passed
    assert "attest-tests" in r.details
    assert ATTESTATION_DIR in r.details


def test_head_commit_is_read_not_executed(project):
    assert head_commit(project) == COMMIT


def test_ci_commit_env_wins_over_the_checkout(project, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    assert head_commit(project) == "b" * 40


# ---------------------------------------------------------------------------
# What the run ran under
# ---------------------------------------------------------------------------

def test_a_nominated_key_is_recorded_with_its_value(monkeypatch):
    monkeypatch.setenv("FEATURE_AUTH", "on")
    assert collect_environment(["FEATURE_AUTH"]) == {"FEATURE_AUTH": "on"}


def test_a_nominated_key_that_is_unset_is_recorded_as_unset(monkeypatch):
    monkeypatch.delenv("FEATURE_AUTH", raising=False)
    # Recorded rather than omitted: silence cannot distinguish "the flag was
    # absent" from "nobody asked", and an assertion may require it unset.
    assert collect_environment(["FEATURE_AUTH"]) == {"FEATURE_AUTH": None}


@pytest.mark.parametrize("name", [
    "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DB_PASSWORD",
    "STRIPE_API_KEY", "SIGNING_KEY", "MY_PRIVATE_KEY",
])
def test_a_credential_name_is_refused_rather_than_recorded(name, monkeypatch):
    """An attestation is signed and distributed, so a leak would be durable."""
    monkeypatch.setenv(name, "s3kr3t")
    with pytest.raises(AttestationError) as e:
        collect_environment([name])
    assert "s3kr3t" not in str(e.value)


def test_an_assertion_can_require_the_run_ran_with_a_control_on(project, monkeypatch):
    _write_attestation(project, environment={"FEATURE_AUTH": "on"})
    r = _verify(project, {"test": NAMED_TEST, "env": {"FEATURE_AUTH": "on"}},
                monkeypatch=monkeypatch)
    assert r.passed is True


def test_a_test_that_passed_with_the_control_off_does_not_verify(project, monkeypatch):
    """The whole point: a green suite proves nothing if the control was off."""
    _write_attestation(project, environment={"FEATURE_AUTH": "off"})
    r = _verify(project, {"test": NAMED_TEST, "env": {"FEATURE_AUTH": "on"}},
                monkeypatch=monkeypatch)
    assert r.passed is False
    assert "FEATURE_AUTH" in r.details


def test_an_environment_requirement_fails_on_a_run_that_recorded_none(project, monkeypatch):
    """Unrecorded is unestablished, never assumed benign."""
    _write_attestation(project)
    r = _verify(project, {"test": NAMED_TEST, "env": {"FEATURE_AUTH": "on"}},
                monkeypatch=monkeypatch)
    assert r.passed is False
    assert "recorded no environment" in r.details


def test_an_assertion_can_require_a_flag_was_not_set(project, monkeypatch):
    _write_attestation(project, environment={"DISABLE_AUTH": None})
    assert _verify(project, {"test": NAMED_TEST, "env": {"DISABLE_AUTH": None}},
                   monkeypatch=monkeypatch).passed is True

    _write_attestation(project, environment={"DISABLE_AUTH": "1"})
    assert _verify(project, {"test": NAMED_TEST, "env": {"DISABLE_AUTH": None}},
                   monkeypatch=monkeypatch).passed is False


def test_an_assertion_without_an_env_param_is_unaffected(project, monkeypatch):
    """The field is additive: existing assertions do not start failing."""
    _write_attestation(project)
    assert _verify(project, {"test": NAMED_TEST}, monkeypatch=monkeypatch).passed is True


# ---------------------------------------------------------------------------
# The keyless path is reachable
# ---------------------------------------------------------------------------

def test_the_keyless_verifier_helper_resolves():
    """The strongest provenance class must not fail on a bad import.

    Every other test in this file deletes the workload-identity variables, so
    the keyless branch is never entered and a wiring error inside it stays
    invisible until a real CI run reaches it.
    """
    from mipiti_verify.cli import _build_sigstore_verifier  # noqa: F401


def test_a_malformed_keyless_attestation_fails_as_an_attestation_error(monkeypatch):
    """Typed, so the verifier's loop can move on to the next envelope.

    An untyped exception escaping here does not fail one attestation, it ends
    the whole verification run.
    """
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "o/r/.github/workflows/ci.yml@refs/heads/main")
    identity, issuer = expected_ci_identity()
    assert identity and issuer

    with pytest.raises(AttestationError):
        verify_attestation(
            '{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"}',
            expected_identity=identity,
            expected_issuer=issuer,
        )


def test_a_second_suite_does_not_overwrite_the_first(tmp_path, monkeypatch):
    """Several reports in one run share a commit, so the filename cannot be
    keyed on the commit alone or each suite erases the last."""
    from click.testing import CliRunner

    from mipiti_verify.cli import attest_tests

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text(COMMIT)
    for name, test in (("api", "test_api_thing"), ("web", "test_web_thing")):
        (tmp_path / f"{name}.xml").write_text(
            f'<testsuites><testsuite name="s">'
            f'<testcase classname="t" name="{test}"/></testsuite></testsuites>')
        r = CliRunner().invoke(attest_tests, ["--junit", f"{name}.xml"])
        assert r.exit_code == 0, r.output

    written = sorted((tmp_path / ATTESTATION_DIR).glob("*.json"))
    assert len(written) == 2, [p.name for p in written]

    v = get_verifier("test_attested")
    for test in ("test_api_thing", "test_web_thing"):
        assert v.verify({"test": test}, tmp_path).passed is True, test


def test_one_unreadable_envelope_does_not_hide_a_sound_one(project, monkeypatch):
    """Envelopes are read in filename order, so a bad file sorting first must
    not end the run before a good one later is reached."""
    _write_attestation(project)
    good = (project / ATTESTATION_DIR / "tests.json").read_text()
    # A payload that decodes to a non-object: every field read assumes a
    # mapping, so this once raised an untyped error out of the whole run.
    (project / ATTESTATION_DIR / "aaa-broken.json").write_text(json.dumps({
        "v": 1, "kind": "unsigned", "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(b"[1,2,3]").decode(),
    }))
    (project / ATTESTATION_DIR / "zzz-good.json").write_text(good)
    (project / ATTESTATION_DIR / "tests.json").unlink()

    r = _verify(project, {"test": NAMED_TEST}, monkeypatch=monkeypatch)
    assert r.passed is True
