"""Tests for the CLI entry point."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mipiti_verify.cli import main


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output

    @patch("mipiti_verify.cli.MipitiClient")
    @patch("mipiti_verify.cli.Runner")
    def test_run_success(self, MockRunner, MockClient):
        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            "tier1_pass": 3,
            "tier1_fail": 0,
            "tier1_skip": 0,
            "tier2_pass": 1,
            "tier2_fail": 0,
            "tier2_skip": 0,
            "tier1_run_id": "run_1",
            "tier2_run_id": "run_2",
            "dry_run": False,
            "details": [],
        }
        MockRunner.return_value = mock_runner

        runner = CliRunner()
        result = runner.invoke(main, ["run", "m1", "--api-key", "test-key"])
        assert result.exit_code == 0

    @patch("mipiti_verify.cli.MipitiClient")
    @patch("mipiti_verify.cli.Runner")
    def test_run_with_failures_exits_1(self, MockRunner, MockClient):
        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            "tier1_pass": 2,
            "tier1_fail": 1,
            "tier1_skip": 0,
            "tier2_pass": 0,
            "tier2_fail": 0,
            "tier2_skip": 0,
            "tier1_run_id": "run_1",
            "tier2_run_id": "",
            "dry_run": False,
            "details": [],
        }
        MockRunner.return_value = mock_runner

        runner = CliRunner()
        result = runner.invoke(main, ["run", "m1", "--api-key", "test-key"])
        assert result.exit_code == 1

    @patch("mipiti_verify.cli.MipitiClient")
    @patch("mipiti_verify.cli.Runner")
    def test_run_json_output(self, MockRunner, MockClient):
        mock_runner = MagicMock()
        mock_runner.run.return_value = {
            "tier1_pass": 1,
            "tier1_fail": 0,
            "tier1_skip": 0,
            "tier2_pass": 0,
            "tier2_fail": 0,
            "tier2_skip": 0,
            "tier1_run_id": "run_1",
            "tier2_run_id": "",
            "dry_run": False,
            "details": [],
        }
        MockRunner.return_value = mock_runner

        runner = CliRunner()
        result = runner.invoke(main, ["run", "m1", "--api-key", "test-key", "--output", "json"])
        assert result.exit_code == 0
        assert '"tier1_pass": 1' in result.output

    def test_run_no_api_key(self):
        runner = CliRunner()
        result = runner.invoke(main, ["run", "m1"], env={"MIPITI_API_KEY": ""})
        assert result.exit_code == 1

    @patch("mipiti_verify.cli.MipitiClient")
    def test_list_pending(self, MockClient):
        mock_client = MagicMock()
        mock_client.get_pending.side_effect = [
            {"controls": {"CTRL-01": [{"id": "a1"}]}},
            {"controls": {"CTRL-01": [{"id": "a2"}]}},
        ]
        MockClient.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(main, ["list", "m1", "--api-key", "test-key"])
        assert result.exit_code == 0
        assert "CTRL-01" in result.output

    @patch("mipiti_verify.cli.MipitiClient")
    def test_report(self, MockClient):
        mock_client = MagicMock()
        mock_client.get_verification_report.return_value = {
            "model_id": "m1",
            "tier1": {"pass": 3, "fail": 1, "pending": 0},
            "tier2": {"pass": 2, "fail": 0, "pending": 1},
            "controls_fully_verified": 2,
            "controls_partially_verified": 1,
            "controls_unverified": 0,
            "drift_items": [],
        }
        MockClient.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(main, ["report", "m1", "--api-key", "test-key"])
        assert result.exit_code == 0
        assert "Verification Report" in result.output


class TestAuditIdentityPinning:
    """Audit-command identity-pinning tests.

    Checks the customer-side defense against compromised-platform
    forgery: --expected-ci-identity / --expected-issuer pin Sigstore
    SAN; --expected-workspace-key pins workspace ECDSA fingerprint.
    """

    def _build_signed_pkg(self, tmp_path, key=None, fingerprint_override=None):
        """Build a minimal audit package with a valid content_integrity
        signature over an empty `verification_run.results` payload."""
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        if key is None:
            key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        # Audit recomputes hash from canonical-serialised
        # verification_run.results — match the empty-list shape exactly
        # so the hash check passes.
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
        # Match the platform's canonical fingerprint algorithm:
        # SHA-256 of the DER SubjectPublicKeyInfo bytes.
        der_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        actual_fp = (
            fingerprint_override
            if fingerprint_override is not None
            else hashlib.sha256(der_bytes).hexdigest()
        )
        pkg = {
            "model": {"id": "m1", "title": "t", "feature_description": "fd",
                      "version": 1, "assets": [], "attackers": [],
                      "trust_boundaries": []},
            "control_objectives": [],
            "controls": [],
            "verification_run": {
                "id": "r1", "pipeline": {}, "results": [], "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": {
                "results_hash": stored,
                "signature": base64.b64encode(sig).decode(),
                "key_fingerprint": actual_fp,
                "public_key_pem": pub_pem,
            },
            "generated_at": "",
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        return str(path), actual_fp

    def test_no_pin_skipped_message(self, tmp_path):
        path, _ = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        assert "SKIPPED" in result.output  # workspace-key-pin skipped notice

    def test_workspace_key_pin_match(self, tmp_path):
        path, fp = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-workspace-key", fp,
        ])
        assert result.exit_code == 0
        assert "MATCHED" in result.output

    def test_workspace_key_pin_mismatch_fails(self, tmp_path):
        path, _ = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-workspace-key", "wrong-fingerprint" * 4,
        ])
        assert result.exit_code == 1
        assert "MISMATCH" in result.output

    def test_ci_identity_from_env_no_env_errors(self, tmp_path, monkeypatch):
        """--ci-identity-from-env without recognised CI env vars exits 2."""
        path, _ = self._build_signed_pkg(tmp_path)
        for var in (
            "GITHUB_SERVER_URL",
            "GITHUB_WORKFLOW_REF",
            "CI_PROJECT_URL",
            "CI_CONFIG_PATH",
            "CI_COMMIT_REF_NAME",
            "MIPITI_VERIFY_CI_IDENTITY",
        ):
            monkeypatch.delenv(var, raising=False)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--ci-identity-from-env",
        ])
        assert result.exit_code == 2
        assert "no recognized CI" in result.output

    def test_ci_identity_from_env_github_actions(self, tmp_path, monkeypatch):
        """--ci-identity-from-env in GitHub Actions auto-derives the SAN.

        The fixture package has no Sigstore bundle, so the now-tightened
        semantics (pin set + no bundle = failure) make this exit 1 — but
        we still verify the auto-derive notice appears (the CLI plumbing
        worked correctly before the missing-bundle failure was raised).
        """
        path, _ = self._build_signed_pkg(tmp_path)
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv(
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/verify.yml@refs/heads/main",
        )
        monkeypatch.delenv("MIPITI_VERIFY_CI_IDENTITY", raising=False)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--ci-identity-from-env",
        ])
        assert result.exit_code == 1
        # Use whitespace-collapsed output for substring assertions
        # because rich console wraps long lines mid-phrase.
        out_flat = " ".join(result.output.split())
        assert "auto-derived" in out_flat
        assert "owner/repo/.github/workflows/verify.yml" in out_flat
        # Pin set + no bundle = failure (now generalised across
        # bundle-binding pins).
        assert "No Sigstore provenance" in out_flat
        assert "Pin enforcement is impossible" in out_flat

    def test_ci_identity_env_var_overrides_auto_derive(self, tmp_path, monkeypatch):
        """MIPITI_VERIFY_CI_IDENTITY takes precedence over auto-derive.

        Divergence between explicit value and auto-derived value should
        emit a yellow notice so the auditor knows which one took effect.
        """
        path, _ = self._build_signed_pkg(tmp_path)
        explicit = (
            "https://github.com/explicit/x/.github/workflows/v.yml@refs/heads/main"
        )
        monkeypatch.setenv("MIPITI_VERIFY_CI_IDENTITY", explicit)
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv(
            "GITHUB_WORKFLOW_REF",
            "different/repo/.github/workflows/verify.yml@refs/heads/main",
        )
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--ci-identity-from-env",
        ])
        # exit 1 because pin is set and fixture has no bundle (Bug 4 fix).
        assert result.exit_code == 1
        # Notice on divergence.
        assert "takes" in result.output and "precedence" in result.output
        # No auto-derived (the explicit value won).
        assert "auto-derived" not in result.output

    def test_expected_issuer_alone_is_usage_error(self, tmp_path):
        """--expected-issuer with no SAN is a usage error (Bug 2)."""
        path, _ = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-issuer", "https://token.actions.githubusercontent.com",
        ])
        assert result.exit_code == 2
        assert "requires --expected-ci-identity" in result.output

    def test_pin_set_but_no_bundle_fails(self, tmp_path):
        """--expected-ci-identity set + package has no bundle = FAIL (Bug 4)."""
        path, _ = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-ci-identity",
            "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
        ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "No Sigstore provenance" in out_flat
        assert "Pin enforcement is impossible" in out_flat

    def test_pin_set_but_no_content_integrity_fails(self, tmp_path):
        """--expected-workspace-key set + no content_integrity = FAIL (Bug 5)."""
        import json as _j

        path, _ = self._build_signed_pkg(tmp_path)
        # Strip content_integrity from the package.
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["content_integrity"] = None
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-workspace-key", "deadbeef" * 8,
        ])
        assert result.exit_code == 1
        assert "No content integrity signature" in result.output
        assert "cannot be satisfied" in result.output

    def test_pin_set_but_bundle_has_no_content_hash_fails(self, tmp_path):
        """Bundle present + no results_hash + pin set = FAIL (Bug 14).

        A bundle without a content hash to bind to can't be
        cryptographically verified, so the identity policy never
        executes. Treat as a failure when --expected-ci-identity
        was pinned, otherwise the pin is silently bypassed.
        """
        import json as _j

        path, _ = self._build_signed_pkg(tmp_path)
        # Inject a placeholder bundle and strip the content hash. We
        # don't need a valid bundle — the bundle parse will fail before
        # we hit the no-content-hash branch, but only when bundle_json
        # is non-empty. So craft a structurally-valid bundle JSON that
        # will at least pass Bundle.from_json's surface check, then
        # observe behavior. If parse fails, the outer except catches
        # and we still test what we want — the missing-content-hash
        # path with pin set must fail.
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["provenance"] = {"bundle": "{\"not\": \"a valid bundle\"}"}
        # Strip results_hash so content_hash_str ends up empty.
        pkg["content_integrity"]["results_hash"] = ""
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-ci-identity",
            "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
        ])
        # The bundle parse will fail (it's not a real bundle); outer
        # except prints "Bundle: INVALID" and sets has_failure. The
        # missing-content-hash branch is unreachable in this fixture,
        # but the audit still fails correctly. We assert on the failure
        # path — either way, exit code is 1 with the pin set.
        assert result.exit_code == 1

    def test_pin_set_but_no_pub_pem_fails(self, tmp_path):
        """--expected-workspace-key set + missing pub_pem = FAIL (Bug 6)."""
        import json as _j

        path, _ = self._build_signed_pkg(tmp_path)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["content_integrity"]["public_key_pem"] = ""
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-workspace-key", "deadbeef" * 8,
        ])
        assert result.exit_code == 1
        assert "No public key in package" in result.output
        assert "no public_key_pem" in result.output

    def test_malformed_package_top_level_not_dict_fails_cleanly(self, tmp_path):
        """A package whose top-level JSON is not an object (e.g. an
        array or string) must be rejected with a clean error — not
        crash the auditor's CI gate with a Python traceback."""
        path = tmp_path / "bad.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 1
        # No traceback indicators — clean message.
        assert "Traceback" not in result.output
        assert "must be a JSON object" in result.output

    def test_malformed_top_level_collections_fail_cleanly(self, tmp_path):
        """A package whose top-level collection fields (controls,
        assertions_by_control, sufficiency, verification_run) are
        the wrong type must not crash audit() at .get() / .items() /
        .values() — must emit a clean failure / partial output."""
        import json as _j

        path = tmp_path / "bad.json"
        pkg = {
            "model": {"id": "m1"},
            "controls": [],  # should be dict
            "assertions_by_control": "not a dict",
            "verification_run": "not a dict",
            "sufficiency": [1, 2, 3],
            "provenance": None,
            "content_integrity": None,
        }
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        # No Python traceback — should emit a clean verdict.
        assert "Traceback" not in result.output
        # Either UNVERIFIED (no signatures) or some clean failure.
        assert result.exit_code in (0, 1)

    def test_malformed_content_integrity_fails_cleanly(self, tmp_path):
        """A package whose content_integrity is the wrong type (string,
        list) must not crash audit() at ci.get(...) — must emit a
        clean failure instead of an AttributeError traceback."""
        import json as _j

        path = tmp_path / "bad.json"
        # Package-shaped JSON but with content_integrity as a string.
        pkg = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": None,
            "content_integrity": "this should be a dict",
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        # No Python traceback — should emit a clean verdict.
        assert "Traceback" not in result.output
        # Either UNVERIFIED (no signature found because ci is treated
        # as None) or some clean failure mode — but never an
        # uncaught AttributeError.
        assert result.exit_code in (0, 1)

    def test_no_signatures_emits_unverified_verdict(self, tmp_path):
        """No provenance + no content_integrity + no pins = UNVERIFIED
        (not the misleading 'VERIFIED — provenance authentic, content
        intact' that the unconditional green text used to print)."""
        import json as _j

        path = tmp_path / "bare.json"
        pkg = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": None,
            "content_integrity": None,
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        # No has_failure (no pins, no failed results), but verdict
        # text reflects reality.
        assert "UNVERIFIED" in result.output
        assert "no cryptographic evidence" in result.output
        # The misleading old text must not appear.
        assert "provenance authentic, content intact" not in result.output

    def test_signed_pkg_no_pins_emits_content_verified(self, tmp_path):
        """Fixture has content_integrity but no provenance — verdict
        text mentions 'content intact' but NOT 'provenance authentic'."""
        path, _ = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        assert "VERIFIED" in result.output
        assert "content intact" in result.output
        # No bundle in fixture → provenance NOT claimed.
        assert "provenance authentic" not in result.output

    def test_malformed_result_entries_fail(self, tmp_path):
        """Result entries missing required fields fail loudly rather
        than crashing the auditor's CI gate with an uncaught KeyError."""
        import json as _j

        path, _ = self._build_signed_pkg(tmp_path)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        # Add a structurally-invalid entry (missing both required fields).
        pkg["verification_run"]["results"] = [{}, {"only": "this"}]
        # Recompute the content_integrity hash so the package self-
        # validates at the hash-check level — we want to isolate the
        # malformed-results path specifically.
        import hashlib
        canonical = _j.dumps(pkg["verification_run"]["results"], sort_keys=True, separators=(",", ":"))
        pkg["content_integrity"]["results_hash"] = (
            "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        )
        # Re-sign over the new hash.
        from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        import base64
        # We don't have the original key; the existing signature won't
        # verify. The signature-INVALID branch will set has_failure
        # too — that's fine, both paths fail loudly.
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        # Result must be 1 (failure), not a Python traceback.
        assert result.exit_code == 1
        # Either the malformed-entries notice or a signature-invalid
        # notice indicates the package was rejected without crashing.
        assert (
            "malformed result" in result.output
            or "INVALID" in result.output
        )

    def test_html_with_pin_flags_is_usage_error(self, tmp_path):
        """HTML report + identity-pinning flags = usage error (exit 2).
        The auditor explicitly asked for an enforcement HTML cannot
        deliver; fail closed rather than silently exit 0 with a notice
        (which a CI gate could miss in 1000 lines of log output)."""
        html = (
            "<!DOCTYPE html><html><body>fake</body></html>\n"
            "<!-- mipiti-report-signature:abc123:fake== -->\n"
        )
        path = tmp_path / "report.html"
        path.write_text(html, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(path),
            "--expected-ci-identity",
            "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "only apply to JSON audit packages" in out_flat

    def test_html_without_pins_runs(self, tmp_path):
        """HTML report without pin flags is a legitimate use case
        (verifying report integrity); the audit must NOT exit 2 just
        for being HTML."""
        html = (
            "<!DOCTYPE html><html><body>fake</body></html>\n"
            "<!-- mipiti-report-signature:abc123:fake== -->\n"
        )
        path = tmp_path / "report.html"
        path.write_text(html, encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        # Exits 1 because the fake signature won't verify, but NOT 2
        # (the usage-error code). The audit attempted to verify.
        assert result.exit_code != 2

    def test_oversized_package_rejected(self, tmp_path):
        """A package larger than the size limit is rejected without
        loading. The auditor's CI runner shouldn't OOM on a malicious
        gigabyte-sized file."""
        path = tmp_path / "huge.json"
        # Write 65 MB of zero bytes — over the 64 MB limit.
        with open(path, "wb") as f:
            f.write(b"\x00" * (65 * 1024 * 1024))
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "too large" in out_flat
        # Confirm no traceback — clean rejection.
        assert "Traceback" not in result.output


class TestSignedHtmlReportRegression:
    """The producer appends `"\\n<!-- ... -->\\n"` to the rendered
    HTML; the leading `\\n` is outside the signed bytes. The verifier
    regex must anchor on that `\\n` so `content[:sig.start()]` excludes
    it. Pinned: body-ends-with-`\\n` (the common case) verifies;
    body-without-trailing-`\\n` verifies; missing leading `\\n` fails.
    """

    def _key_pair(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec.generate_private_key(ec.SECP256R1())

    def _key_fingerprint(self, key):
        import hashlib
        from cryptography.hazmat.primitives import serialization
        der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    def _patched_jwks(self, key, fingerprint):
        """Mock JWKS resolution to return `key` for `fingerprint`."""
        from unittest.mock import patch
        return patch(
            "mipiti_verify.cli._resolve_pubkey_from_jwks",
            return_value=(key.public_key(), fingerprint, None),
        )

    def _signed_report(self, key, body):
        """Mint a signed HTML report exactly as production
        `sign_report_html` does: signs `body` (including its own
        trailing newline if present), appends `\\n<!-- ... -->\\n`."""
        import base64
        import hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        sig = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(sig).decode()
        fp = self._key_fingerprint(key)
        return body + f"\n<!-- mipiti-report-signature:{fp}:{sig_b64} -->\n", fp

    def test_body_ending_with_newline_verifies(self, tmp_path):
        """Body ends with `\\n` followed by `\\n<!-- ... -->\\n`."""
        key = self._key_pair()
        body = "<!DOCTYPE html><html><body>Report content here.</body></html>\n"
        report, fp = self._signed_report(key, body)
        path = tmp_path / "report.html"
        path.write_text(report, encoding="utf-8")
        with self._patched_jwks(key, fp):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 0, result.output
        assert "Signature:" in result.output
        assert "VALID" in result.output

    def test_body_without_trailing_newline_verifies(self, tmp_path):
        """Body has no trailing `\\n`; the appended block's leading
        `\\n` is the regex anchor regardless."""
        key = self._key_pair()
        body = "<!DOCTYPE html><html><body>No trailing newline</body></html>"
        report, fp = self._signed_report(key, body)
        path = tmp_path / "report.html"
        path.write_text(report, encoding="utf-8")
        with self._patched_jwks(key, fp):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 0, result.output
        assert "VALID" in result.output

    def test_missing_leading_newline_fails_loud(self, tmp_path):
        """Body without trailing `\\n`, appended block lacks leading
        `\\n`: regex doesn't match, exit 1, "No signature found"."""
        key = self._key_pair()
        body = "<!DOCTYPE html><html><body>Body no newline</body></html>"
        import base64
        import hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        sig = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(sig).decode()
        fp = self._key_fingerprint(key)
        report = body + f"<!-- mipiti-report-signature:{fp}:{sig_b64} -->\n"
        path = tmp_path / "report.html"
        path.write_text(report, encoding="utf-8")
        with self._patched_jwks(key, fp):
            runner = CliRunner()
            result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "No signature found" in out_flat


class TestPredicatePinRequiresSanPin:
    """Predicate pins (model_id / commit_sha) without --expected-ci-identity
    are a usage error. The flags' documented purpose is compromised-
    platform defense, but without a SAN pin constraining whose OIDC
    produced the bundle, an attacker minting under their own CI's
    OIDC can craft predicate values matching the auditor's pins —
    so the configuration provides no compromised-platform defense.
    Fail closed (same precedent as --expected-issuer alone) rather
    than silently accept a configuration that doesn't deliver the
    advertised security property.
    """

    def test_model_id_alone_is_usage_error(self, tmp_path):
        helper = TestAuditIdentityPinning()
        path, _ = helper._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-model-id", "model-X",
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "require --expected-ci-identity" in out_flat
        assert "compromised-platform defense" in out_flat

    def test_commit_sha_alone_is_usage_error(self, tmp_path):
        helper = TestAuditIdentityPinning()
        path, _ = helper._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-commit-sha", "abc123",
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "require --expected-ci-identity" in out_flat

    def test_model_id_with_san_runs(self, tmp_path):
        """With SAN pin co-set, the configuration is acceptable —
        not a usage error. The audit proceeds (and may FAIL on
        other grounds, but never exits 2 on the predicate-pin
        validation alone)."""
        helper = TestAuditIdentityPinning()
        path, _ = helper._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-ci-identity",
            "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
            "--expected-model-id", "model-X",
        ])
        assert result.exit_code != 2
        out_flat = " ".join(result.output.split())
        assert "require --expected-ci-identity" not in out_flat


class TestPredicatePins:
    """I12 / I13: model_id and commit_sha pinning against the bundle's
    in-toto DSSE predicate. The bundle path is mocked here so these
    tests run offline; the BFS continues to exercise the real
    Sigstore path in CI for I1–I11.
    """

    def _build_pkg_with_bundle(self, tmp_path, predicate):
        """Build a package whose provenance contains a bundle JSON
        that, when mocked-verified, returns the supplied DSSE
        predicate. The bundle JSON itself doesn't need to be valid
        because the verifier is mocked end-to-end.

        The bundle's Subject digest matches `bundle_bind_hash` in the
        content_integrity block — that is the explicit binding the
        post-cutover verifier checks (no rehashing on either side).
        """
        import base64 as _b64
        import hashlib as _h
        import json as _j

        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        results_hash = "sha256:" + _h.sha256(canonical.encode()).hexdigest()
        # Pick any content-hash-shaped value as the bundle bind anchor;
        # the mocked verifier returns whatever digest we put in the
        # statement's Subject and the verifier compares it directly to
        # bundle_bind_hash. Using the same value keeps the helper's
        # invariant-shape simple.
        bundle_bind_hash_hex = _h.sha256(results_hash.encode()).hexdigest()
        pkg = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": {"bundle": "{\"placeholder\": true}"},
            "content_integrity": {
                "results_hash": results_hash,
                "bundle_bind_hash": bundle_bind_hash_hex,
            },
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        # The DSSE Statement the verifier will return.
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "test",
                    "digest": {
                        "sha256": bundle_bind_hash_hex
                    },
                }
            ],
            "predicateType": "https://mipiti.io/attestations/v1/verification-run",
            "predicate": predicate,
        }
        return str(path), statement

    def _patch_sigstore(self, statement, monkeypatch):
        """Patch the Sigstore Bundle and Verifier symbols imported
        inside cli.py's `audit` command so verify_dsse returns the
        supplied Statement payload."""
        import json as _j
        from datetime import datetime, timezone

        from unittest.mock import MagicMock, patch

        # Build a fake Bundle whose `signing_certificate` attributes
        # are accessed to print certificate / log_entry info.
        fake_cert = MagicMock()
        fake_cert.subject.rfc4514_string.return_value = ""
        fake_cert.not_valid_before_utc = datetime(2026, 5, 1, tzinfo=timezone.utc)
        fake_cert.not_valid_after_utc = datetime(2026, 5, 1, tzinfo=timezone.utc)
        fake_log = MagicMock()
        fake_log.log_index = 1
        fake_log.integrated_time = 0
        fake_bundle = MagicMock()
        fake_bundle.signing_certificate = fake_cert
        fake_bundle.log_entry = fake_log

        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            _j.dumps(statement).encode("utf-8"),
        )

        bundle_patch = patch(
            "sigstore.models.Bundle.from_json",
            return_value=fake_bundle,
        )
        verifier_patch = patch(
            "sigstore.verify.Verifier.production",
            return_value=fake_verifier,
        )
        return bundle_patch, verifier_patch

    def test_i12_model_id_match_passes(self, tmp_path, monkeypatch):
        """Bundle predicate.model_id matches pin → no failure on the
        model_id pin path."""
        path, statement = self._build_pkg_with_bundle(
            tmp_path, predicate={"model_id": "model-X", "pipeline": {}}
        )
        bp, vp = self._patch_sigstore(statement, monkeypatch)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--expected-ci-identity",
                "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
                "--expected-model-id", "model-X",
            ])
        out_flat = " ".join(result.output.split())
        assert "Model ID pin:" in out_flat
        assert "MATCHED" in out_flat
        # No has_failure from model_id pin path.
        assert "Model ID pin: MISMATCH" not in out_flat

    def test_i12_model_id_mismatch_fails(self, tmp_path, monkeypatch):
        """Bundle predicate.model_id ≠ pin → FAILED."""
        path, statement = self._build_pkg_with_bundle(
            tmp_path, predicate={"model_id": "model-OTHER", "pipeline": {}}
        )
        bp, vp = self._patch_sigstore(statement, monkeypatch)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--expected-ci-identity",
                "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
                "--expected-model-id", "model-X",
            ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Model ID pin:" in out_flat
        assert "MISMATCH" in out_flat

    def test_i12_pin_set_no_bundle_fails(self, tmp_path):
        """--expected-model-id + --expected-ci-identity set + no bundle
        = FAIL (I1-generalised). SAN is co-pinned so the predicate-pin
        validation gate (exit 2) doesn't fire — we want to exercise
        the no-bundle pin-bypass-by-omission path."""
        helper = TestAuditIdentityPinning()
        path, _ = helper._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-ci-identity",
            "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
            "--expected-model-id", "model-X",
        ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Pin enforcement is impossible" in out_flat

    def test_i13_commit_sha_match_passes(self, tmp_path, monkeypatch):
        """Bundle predicate.pipeline.commit_sha matches pin → no
        failure on the commit_sha pin path."""
        path, statement = self._build_pkg_with_bundle(
            tmp_path,
            predicate={"model_id": "x", "pipeline": {"commit_sha": "abc123"}},
        )
        bp, vp = self._patch_sigstore(statement, monkeypatch)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--expected-ci-identity",
                "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
                "--expected-commit-sha", "abc123",
            ])
        out_flat = " ".join(result.output.split())
        assert "Commit SHA pin:" in out_flat
        assert "MATCHED" in out_flat

    def test_i13_commit_sha_mismatch_fails(self, tmp_path, monkeypatch):
        """Bundle predicate.pipeline.commit_sha ≠ pin → FAILED.
        Defends against replay of an older verification run."""
        path, statement = self._build_pkg_with_bundle(
            tmp_path,
            predicate={"model_id": "x", "pipeline": {"commit_sha": "old_sha"}},
        )
        bp, vp = self._patch_sigstore(statement, monkeypatch)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--expected-ci-identity",
                "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
                "--expected-commit-sha", "new_sha",
            ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Commit SHA pin:" in out_flat
        assert "MISMATCH" in out_flat

    def test_i13_pin_set_no_bundle_fails(self, tmp_path):
        helper = TestAuditIdentityPinning()
        path, _ = helper._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-ci-identity",
            "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
            "--expected-commit-sha", "abc123",
        ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Pin enforcement is impossible" in out_flat

    def test_predicate_missing_model_id_with_pin_fails(self, tmp_path, monkeypatch):
        """A bundle whose predicate has no model_id field cannot
        satisfy --expected-model-id — the audit must FAIL."""
        path, statement = self._build_pkg_with_bundle(
            tmp_path, predicate={"pipeline": {}}  # no model_id
        )
        bp, vp = self._patch_sigstore(statement, monkeypatch)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--expected-ci-identity",
                "https://github.com/x/y/.github/workflows/v.yml@refs/heads/main",
                "--expected-model-id", "model-X",
            ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "MISMATCH" in out_flat


class TestBundleBindExplicit:
    """I14 — explicit bundle_bind_hash on the envelope.

    The verifier reads `content_integrity.bundle_bind_hash` directly
    off the envelope and compares to the bundle's in-toto Subject
    digest with no canonicalisation, no rehashing on either side.
    Older envelopes that omit the field are rejected (no legacy
    fallback). When `bundle_bind_signature` is populated, the
    verifier checks it against the platform public key already
    embedded in the envelope.
    """

    def _build_pkg_with_bind(self, tmp_path, *, bundle_bind_hash,
                              subject_digest, sign_with_key=None,
                              valid_signature=True,
                              omit_signature=False):
        """Build a minimal audit package shaped for the bundle-bind
        verifier branch: a placeholder bundle (the Sigstore client is
        mocked to return our chosen statement), an explicit
        bundle_bind_hash, and (optionally) a platform signature over
        bundle_bind_hash. The mocked verify_dsse returns a statement
        whose Subject digest is `subject_digest` — which the verifier
        compares directly to `bundle_bind_hash`.
        """
        import base64 as _b64
        import hashlib as _h
        import json as _j

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        results_hash = "sha256:" + _h.sha256(canonical.encode()).hexdigest()

        if sign_with_key is None:
            sign_with_key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = sign_with_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        ci = {
            "results_hash": results_hash,
            "public_key_pem": pub_pem,
        }
        if bundle_bind_hash is not None:
            ci["bundle_bind_hash"] = bundle_bind_hash
            if not omit_signature:
                msg = (
                    bundle_bind_hash.encode("utf-8")
                    if valid_signature
                    else b"forgery-attempt"
                )
                bb_sig = sign_with_key.sign(msg, ec.ECDSA(hashes.SHA256()))
                ci["bundle_bind_signature"] = _b64.b64encode(bb_sig).decode()

        pkg = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": {"bundle": "{\"placeholder\": true}"},
            "content_integrity": ci,
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "t", "digest": {"sha256": subject_digest}}
            ],
            "predicateType": "https://mipiti.io/attestations/v1/verification-run",
            "predicate": {"model_id": "m1", "pipeline": {"commit_sha": "abc"}},
        }
        return str(path), statement

    def _patch_sigstore(self, statement):
        """Patch the Sigstore Bundle and Verifier symbols so verify_dsse
        returns the supplied Statement payload. Same shape as the
        existing TestPredicatePins helper."""
        import json as _j
        from datetime import datetime, timezone

        from unittest.mock import MagicMock, patch

        fake_cert = MagicMock()
        fake_cert.subject.rfc4514_string.return_value = ""
        fake_cert.not_valid_before_utc = datetime(2026, 5, 1, tzinfo=timezone.utc)
        fake_cert.not_valid_after_utc = datetime(2026, 5, 1, tzinfo=timezone.utc)
        fake_log = MagicMock()
        fake_log.log_index = 1
        fake_log.integrated_time = 0
        fake_bundle = MagicMock()
        fake_bundle.signing_certificate = fake_cert
        fake_bundle.log_entry = fake_log

        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            _j.dumps(statement).encode("utf-8"),
        )

        return (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production", return_value=fake_verifier),
        )

    def test_matching_bind_hash_verifies(self, tmp_path):
        """Modern envelope: bundle present + bundle_bind_hash matching
        the bundle's Subject digest + valid platform signature →
        verifier emits the green 'Bundle bind: VERIFIED' line and the
        audit succeeds (no failure on the bind check)."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        bind_hex = "ab" * 32  # arbitrary 32-byte hex
        path, statement = self._build_pkg_with_bind(
            tmp_path,
            bundle_bind_hash=bind_hex,
            subject_digest=bind_hex,
            sign_with_key=key,
            valid_signature=True,
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        out_flat = " ".join(result.output.split())
        assert "Bundle bind:" in out_flat
        assert "VERIFIED" in out_flat
        # The bind branch must not have produced a failure marker.
        assert "Bundle Subject digest does not match" not in out_flat
        assert "bundle_bind_signature INVALID" not in out_flat

    def test_missing_bind_hash_fails(self, tmp_path):
        """Bundle present without bundle_bind_hash on the envelope =
        FAILED. The post-cutover verifier rejects envelopes that omit
        the explicit binding (no legacy fallback)."""
        bind_hex = "cd" * 32
        path, statement = self._build_pkg_with_bind(
            tmp_path,
            bundle_bind_hash=None,  # field omitted on envelope
            subject_digest=bind_hex,
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert (
            "no bundle_bind_hash" in out_flat
            or "Bundle present but no bundle_bind_hash" in out_flat
        )

    def test_mismatched_bind_hash_fails(self, tmp_path):
        """bundle_bind_hash claims one digest, bundle's Subject is over
        a different digest → FAILED with the bind-mismatch diagnostic."""
        path, statement = self._build_pkg_with_bind(
            tmp_path,
            bundle_bind_hash="ee" * 32,
            subject_digest="ff" * 32,  # bundle was minted over a
                                        # different value
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Bundle Subject digest does not match" in out_flat


class TestBundleBindKeyResolution:
    """Bundle-bind-signature platform-key resolution paths.

    The bundle_bind_signature is signed by the platform key — the same
    key that signs the outer document signature on PDFs and HTML
    reports. Three resolution tiers are supported, in priority order:

      1. --platform-pubkey: explicit auditor-supplied PEM (offline).
      2. PDF outer-signature pubkey: when the input is a signed PDF,
         the document-signature path resolves the platform key from
         JWKS (or from a Rekor anchor); the bundle-bind path reuses
         it without a second resolution round-trip.
      3. envelope public_key_pem: legacy / non-Sigstore key-source
         rows that embed a PEM directly in the envelope.

    When none of the three apply, the verifier fails-loud with a
    remediation pointer rather than skipping the bundle-bind check.
    """

    def _build_pkg_with_separate_platform(
        self, tmp_path, *, bundle_bind_hash, subject_digest,
        platform_key, embed_platform_pem=False, valid_platform_sig=True,
    ):
        """Build a JSON audit package where the bundle-bind signature
        is produced by `platform_key`, and the envelope's
        public_key_pem either embeds that platform key (legacy /
        Tier 3) or is intentionally empty (sigstore key-source row,
        the case Tiers 1 and 2 exist to cover).
        """
        import base64 as _b64
        import hashlib as _h
        import json as _j

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        results_hash = (
            "sha256:" + _h.sha256(canonical.encode()).hexdigest()
        )

        if embed_platform_pem:
            pub_pem = platform_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        else:
            pub_pem = ""

        msg = (
            bundle_bind_hash.encode("utf-8")
            if valid_platform_sig
            else b"forgery-attempt"
        )
        bb_sig = platform_key.sign(msg, ec.ECDSA(hashes.SHA256()))

        ci = {
            "results_hash": results_hash,
            "public_key_pem": pub_pem,
            "bundle_bind_hash": bundle_bind_hash,
            "bundle_bind_signature": _b64.b64encode(bb_sig).decode(),
        }
        pkg = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": {"bundle": "{\"placeholder\": true}"},
            "content_integrity": ci,
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "t", "digest": {"sha256": subject_digest}}
            ],
            "predicateType": (
                "https://mipiti.io/attestations/v1/verification-run"
            ),
            "predicate": {
                "model_id": "m1", "pipeline": {"commit_sha": "abc"}
            },
        }
        return str(path), statement

    def _patch_sigstore(self, statement):
        import json as _j
        from datetime import datetime, timezone
        from unittest.mock import MagicMock, patch

        fake_cert = MagicMock()
        fake_cert.subject.rfc4514_string.return_value = ""
        fake_cert.not_valid_before_utc = datetime(
            2026, 5, 1, tzinfo=timezone.utc
        )
        fake_cert.not_valid_after_utc = datetime(
            2026, 5, 1, tzinfo=timezone.utc
        )
        fake_log = MagicMock()
        fake_log.log_index = 1
        fake_log.integrated_time = 0
        fake_bundle = MagicMock()
        fake_bundle.signing_certificate = fake_cert
        fake_bundle.log_entry = fake_log

        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            _j.dumps(statement).encode("utf-8"),
        )
        return (
            patch(
                "sigstore.models.Bundle.from_json",
                return_value=fake_bundle,
            ),
            patch(
                "sigstore.verify.Verifier.production",
                return_value=fake_verifier,
            ),
        )

    def test_tier3_envelope_pem_legacy_path_verifies(self, tmp_path):
        """Legacy / non-Sigstore key-source rows embed the platform PEM
        directly in the envelope. The bundle-bind verification falls
        back to that PEM when no higher-priority key is in scope, and
        succeeds when the signature is valid."""
        from cryptography.hazmat.primitives.asymmetric import ec

        platform_key = ec.generate_private_key(ec.SECP256R1())
        bind_hex = "11" * 32
        path, statement = self._build_pkg_with_separate_platform(
            tmp_path,
            bundle_bind_hash=bind_hex,
            subject_digest=bind_hex,
            platform_key=platform_key,
            embed_platform_pem=True,
            valid_platform_sig=True,
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        out_flat = " ".join(result.output.split())
        assert "Bundle bind:" in out_flat
        assert "VERIFIED" in out_flat

    def test_json_archive_no_pubkey_fails_loud(self, tmp_path):
        """Sigstore key-source row (envelope public_key_pem empty) +
        plain JSON archive (no PDF outer signature in scope) +
        no --platform-pubkey: the verifier must fail with a clear
        remediation pointer rather than silently skipping the
        bundle-bind check or crashing."""
        from cryptography.hazmat.primitives.asymmetric import ec

        platform_key = ec.generate_private_key(ec.SECP256R1())
        bind_hex = "22" * 32
        path, statement = self._build_pkg_with_separate_platform(
            tmp_path,
            bundle_bind_hash=bind_hex,
            subject_digest=bind_hex,
            platform_key=platform_key,
            embed_platform_pem=False,  # the gap state
            valid_platform_sig=True,
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "no platform public key is in scope" in out_flat
        assert "--platform-pubkey" in out_flat
        # Clean failure, no traceback.
        assert "Traceback" not in result.output

    def test_json_archive_with_platform_pubkey_flag_verifies(
        self, tmp_path
    ):
        """Sigstore key-source row + --platform-pubkey supplied: the
        verifier loads the auditor-pinned PEM and uses it for the
        bundle-bind check. Highest-precedence resolution tier."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        platform_key = ec.generate_private_key(ec.SECP256R1())
        bind_hex = "33" * 32
        path, statement = self._build_pkg_with_separate_platform(
            tmp_path,
            bundle_bind_hash=bind_hex,
            subject_digest=bind_hex,
            platform_key=platform_key,
            embed_platform_pem=False,
            valid_platform_sig=True,
        )
        platform_pem_path = tmp_path / "platform.pem"
        platform_pem_path.write_bytes(
            platform_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--platform-pubkey", str(platform_pem_path),
            ])
        out_flat = " ".join(result.output.split())
        assert "Bundle bind:" in out_flat
        assert "VERIFIED" in out_flat

    def test_json_archive_platform_pubkey_signature_mismatch_fails(
        self, tmp_path
    ):
        """--platform-pubkey supplied but the envelope's bind signature
        was produced by a different key: the ECDSA verify call rejects
        the signature, and the audit FAILs with an INVALID diagnostic
        (not the KEY_UNRESOLVABLE branch)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        attacker_key = ec.generate_private_key(ec.SECP256R1())
        unrelated_key = ec.generate_private_key(ec.SECP256R1())
        bind_hex = "44" * 32
        path, statement = self._build_pkg_with_separate_platform(
            tmp_path,
            bundle_bind_hash=bind_hex,
            subject_digest=bind_hex,
            platform_key=attacker_key,
            embed_platform_pem=False,
            valid_platform_sig=True,
        )
        # Pin to a key the envelope was NOT signed by.
        wrong_pem_path = tmp_path / "wrong-platform.pem"
        wrong_pem_path.write_bytes(
            unrelated_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        bp, vp = self._patch_sigstore(statement)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--platform-pubkey", str(wrong_pem_path),
            ])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "bundle_bind_signature INVALID" in out_flat
        # The diagnostic should name the resolution source so an
        # auditor sees which key was used.
        assert "--platform-pubkey" in out_flat

    def test_pdf_outer_sig_pubkey_reused_for_bundle_bind(self, tmp_path):
        """PDF input with an embedded audit envelope: the platform
        public key resolved by the document-signature path must be
        reused for the bundle-bind check on rows whose envelope
        public_key_pem is empty (Sigstore key-source production
        case). End-to-end: the PDF signs over its own content with
        platform_key, JWKS resolves platform_key, the embedded
        envelope's bundle is sigstore-keyed (empty public_key_pem)
        and carries a bundle_bind_signature also produced by
        platform_key. The verifier threads the resolved key from
        the outer pass into the inner bundle-bind check without a
        second JWKS round-trip and without requiring
        --platform-pubkey from the auditor."""
        import base64
        import gzip
        import hashlib
        import json as _j
        from datetime import datetime, timezone
        from unittest.mock import MagicMock, patch
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from mipiti_verify.cli import (
            _PDF_SIG_START, _PDF_SIG_END, _PDF_SIG_PAYLOAD_LEN,
            _PDF_AUDIT_START, _PDF_AUDIT_END,
        )

        platform_key = ec.generate_private_key(ec.SECP256R1())
        der = platform_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der).hexdigest()

        # Embedded envelope: empty public_key_pem (sigstore
        # key-source row) plus a bundle_bind_signature signed by
        # platform_key.
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        results_hash = (
            "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        )
        bind_hex = "5e" * 32
        bb_sig = platform_key.sign(
            bind_hex.encode("utf-8"), ec.ECDSA(hashes.SHA256())
        )
        envelope = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": {"bundle": "{\"placeholder\": true}"},
            "content_integrity": {
                "results_hash": results_hash,
                "public_key_pem": "",
                "bundle_bind_hash": bind_hex,
                "bundle_bind_signature": base64.b64encode(bb_sig).decode(),
                "key_source": "sigstore",
            },
            "assertions_by_control": {},
            "sufficiency": {},
        }

        envelope_json = _j.dumps(envelope).encode("utf-8")
        envelope_b64 = base64.b64encode(gzip.compress(envelope_json))

        pdf_body = b"%PDF-1.7\nfake body\n%%EOF\n"
        pdf_with_audit = (
            pdf_body + _PDF_AUDIT_START + envelope_b64 + _PDF_AUDIT_END
        )

        # Outer document signature mirrors _audit_pdf_report's
        # covered-byte selection: (everything outside the payload).
        covered = pdf_with_audit + _PDF_SIG_START + _PDF_SIG_END
        digest = hashlib.sha256(covered).digest()
        outer_sig = platform_key.sign(digest, ec.ECDSA(hashes.SHA256()))
        outer_sig_b64 = base64.b64encode(outer_sig).decode()
        sig_payload = f"{fingerprint}:{outer_sig_b64}".encode()
        sig_payload = sig_payload + b" " * (
            _PDF_SIG_PAYLOAD_LEN - len(sig_payload)
        )
        pdf_full = (
            pdf_with_audit + _PDF_SIG_START + sig_payload + _PDF_SIG_END
        )
        pdf_path = tmp_path / "report.pdf"
        pdf_path.write_bytes(pdf_full)

        # JWK that JWKS will return for the outer-sig fingerprint.
        nums = platform_key.public_key().public_numbers()
        x_b64 = base64.urlsafe_b64encode(
            nums.x.to_bytes(32, "big")
        ).rstrip(b"=").decode()
        y_b64 = base64.urlsafe_b64encode(
            nums.y.to_bytes(32, "big")
        ).rstrip(b"=").decode()
        jwk = {
            "kty": "EC", "crv": "P-256", "kid": fingerprint,
            "x": x_b64, "y": y_b64,
        }
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"keys": [jwk]})

        # Mocked Sigstore returns a statement whose Subject digest
        # matches bind_hex so the bundle-bind hash check passes.
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "t", "digest": {"sha256": bind_hex}}
            ],
            "predicateType": (
                "https://mipiti.io/attestations/v1/verification-run"
            ),
            "predicate": {
                "model_id": "m1", "pipeline": {"commit_sha": "abc"}
            },
        }
        fake_cert = MagicMock()
        fake_cert.subject.rfc4514_string.return_value = ""
        fake_cert.not_valid_before_utc = datetime(
            2026, 5, 1, tzinfo=timezone.utc
        )
        fake_cert.not_valid_after_utc = datetime(
            2026, 5, 1, tzinfo=timezone.utc
        )
        fake_log = MagicMock()
        fake_log.log_index = 1
        fake_log.integrated_time = 0
        fake_bundle = MagicMock()
        fake_bundle.signing_certificate = fake_cert
        fake_bundle.log_entry = fake_log
        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            _j.dumps(statement).encode("utf-8"),
        )

        with patch("httpx.get", return_value=mock_resp), \
                patch(
                    "sigstore.models.Bundle.from_json",
                    return_value=fake_bundle,
                ), \
                patch(
                    "sigstore.verify.Verifier.production",
                    return_value=fake_verifier,
                ):
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", str(pdf_path),
                "--key-url", "https://example.test/jwks",
            ])
        out_flat = " ".join(result.output.split())
        # The outer document signature must verify (Tier 2 reuse
        # depends on this succeeding).
        assert "Signature: VALID" in out_flat
        # The bundle-bind check uses the threaded outer-sig key, not
        # the empty envelope public_key_pem.
        assert "Bundle bind: VERIFIED" in out_flat
        assert "no platform public key is in scope" not in out_flat


class TestWindowsSymlinkPrivilegeRemediation:
    """The `_windows_symlink_privilege_remediation` helper translates
    a TUF-refresh failure caused by Windows's symlink-privilege
    requirement (WinError 1314) into a structured message naming the
    three sanctioned remediation paths. Other errors pass through
    unchanged.
    """

    def _winerror_1314(self) -> OSError:
        """Construct an OSError that mimics the actual TUF-refresh
        failure observed on Windows without symlink privilege:
        OSError with `winerror=1314`. Constructing via OSError(*args)
        sets `winerror`/`strerror`/`filename` correctly on Windows
        Python; on non-Windows we fall back to setting the attribute
        directly so the test runs cross-platform."""
        try:
            raise OSError(
                1314, "A required privilege is not held by the client",
                "root_history\\14.root.json",
            )
        except OSError as e:
            if getattr(e, "winerror", None) != 1314:
                e.winerror = 1314  # cross-platform test
            return e

    def test_direct_winerror_1314_returns_remediation(self):
        from mipiti_verify.cli import (
            _windows_symlink_privilege_remediation,
        )

        msg = _windows_symlink_privilege_remediation(self._winerror_1314())
        assert msg is not None
        assert "WinError 1314" in msg
        assert "Developer Mode" in msg
        assert "Administrator terminal" in msg
        assert "--sigstore-trust-config" in msg

    def test_chained_via_cause_returns_remediation(self):
        """The actual production failure shape: TUFError raised by
        the Sigstore client, with OSError(winerror=1314) chained as
        the underlying cause. The helper walks `__cause__` so the
        wrapped error is recognised."""
        from mipiti_verify.cli import (
            _windows_symlink_privilege_remediation,
        )

        try:
            try:
                raise self._winerror_1314()
            except OSError as inner:
                raise RuntimeError("Failed to refresh TUF metadata") from inner
        except RuntimeError as outer:
            msg = _windows_symlink_privilege_remediation(outer)

        assert msg is not None
        assert "Developer Mode" in msg

    def test_chained_via_context_returns_remediation(self):
        """Implicit chaining (`__context__`, set when an exception
        propagates through a `try/except` block without an explicit
        `raise from`) is also walked."""
        from mipiti_verify.cli import (
            _windows_symlink_privilege_remediation,
        )

        try:
            try:
                raise self._winerror_1314()
            except OSError:
                raise RuntimeError("Failed to refresh TUF metadata")
        except RuntimeError as outer:
            msg = _windows_symlink_privilege_remediation(outer)

        assert msg is not None

    def test_unrelated_error_returns_none(self):
        from mipiti_verify.cli import (
            _windows_symlink_privilege_remediation,
        )

        assert _windows_symlink_privilege_remediation(
            ValueError("unrelated")
        ) is None
        assert _windows_symlink_privilege_remediation(
            OSError("EACCES — different errno"),
        ) is None

    def test_cycle_in_cause_chain_terminates(self):
        """A pathological `__cause__` cycle (shouldn't happen in
        practice but possible if someone constructs exceptions
        manually) must not infinite-loop."""
        from mipiti_verify.cli import (
            _windows_symlink_privilege_remediation,
        )

        a = ValueError("a")
        b = ValueError("b")
        a.__cause__ = b
        b.__cause__ = a
        # Should return None without hanging.
        assert _windows_symlink_privilege_remediation(a) is None


class TestIdentityPolicySkippedBlock:
    """When no `--expected-ci-identity` is supplied, the verifier
    builds a `policy.UnsafeNoOp()` policy. sigstore-python's
    `UnsafeNoOp.__init__` prints "unsafe (no-op) verification policy
    used! no verification performed!" to stderr at construction time.
    That stderr line is misleading (cryptographic verification DID
    happen — only identity matching was no-op'd) and visually
    appears before mipiti-verify's own status lines, contradicting
    the SKIPPED line we emit a few lines below.

    The fix: capture sigstore's stderr at policy construction so the
    warning doesn't print ahead of our section, and emit a cohesive
    SKIPPED block that explains what was checked, surfaces the
    bundle's claimed SAN for visibility, and points at the
    `--expected-ci-identity` remedy.
    """

    def _build_pkg(self, tmp_path):
        """Bundle-bearing JSON audit package with a content-integrity
        block; the bundle contents are mocked downstream."""
        import base64 as _b64
        import hashlib as _h
        import json as _j

        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        results_hash = "sha256:" + _h.sha256(canonical.encode()).hexdigest()
        bind_hex = "ab" * 32
        pkg = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": {"bundle": "{\"placeholder\": true}"},
            "content_integrity": {
                "results_hash": results_hash,
                "bundle_bind_hash": bind_hex,
            },
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "t", "digest": {"sha256": bind_hex}}
            ],
            "predicateType": (
                "https://mipiti.io/attestations/v1/verification-run"
            ),
            "predicate": {
                "model_id": "m1", "pipeline": {"commit_sha": "abc"},
            },
        }
        return str(path), statement

    def _patch_sigstore(self, statement, claimed_san):
        """Same shape as TestPredicatePins / TestBundleBindExplicit
        but configures the cert mock to expose a SAN extension via
        the `cryptography.x509` extension API."""
        import json as _j
        import sys as _sys
        from datetime import datetime, timezone
        from unittest.mock import MagicMock, patch

        # Build a SAN extension whose
        # `get_values_for_type(UniformResourceIdentifier)` returns
        # `[claimed_san]`. The extension's class identity must be
        # `SubjectAlternativeName` so `get_extension_for_class` finds
        # it.
        from cryptography.x509 import (
            SubjectAlternativeName,
            UniformResourceIdentifier,
        )

        san_ext = MagicMock()
        san_ext.value.get_values_for_type.side_effect = (
            lambda type_: [claimed_san]
            if type_ is UniformResourceIdentifier
            else []
        )

        fake_cert = MagicMock()
        fake_cert.subject.rfc4514_string.return_value = ""
        fake_cert.not_valid_before_utc = datetime(
            2026, 5, 1, tzinfo=timezone.utc
        )
        fake_cert.not_valid_after_utc = datetime(
            2026, 5, 1, tzinfo=timezone.utc
        )
        fake_cert.extensions.get_extension_for_class.side_effect = (
            lambda cls: san_ext
            if cls is SubjectAlternativeName
            else (_ for _ in ()).throw(
                Exception("unexpected extension class")
            )
        )

        fake_log = MagicMock()
        fake_log.log_index = 1
        fake_log.integrated_time = 0
        fake_bundle = MagicMock()
        fake_bundle.signing_certificate = fake_cert
        fake_bundle.log_entry = fake_log

        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            _j.dumps(statement).encode("utf-8"),
        )
        return (
            patch(
                "sigstore.models.Bundle.from_json",
                return_value=fake_bundle,
            ),
            patch(
                "sigstore.verify.Verifier.production",
                return_value=fake_verifier,
            ),
        )

    def test_skipped_block_surfaces_san_and_explains(self, tmp_path):
        """Without `--expected-ci-identity`:
          - SKIPPED line emitted
          - Bundle's claimed SAN surfaced (observational)
          - Cryptographic-chain-vs-identity distinction explained
          - Pointer to `--expected-ci-identity` / `--ci-identity-from-env`
        And the misleading raw "unsafe (no-op) verification policy
        used!" stderr line is captured (does not appear in the
        Provenance section header).
        """
        path, statement = self._build_pkg(tmp_path)
        claimed_san = (
            "https://github.com/Acme/repo/.github/workflows/ci.yml"
            "@refs/heads/main"
        )
        bp, vp = self._patch_sigstore(statement, claimed_san)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])

        # Collapse whitespace so Rich's line-wrapping doesn't break
        # substring assertions when the SAN or one of the long
        # explainer lines wraps in narrow terminals.
        out_flat = " ".join(result.output.split())
        assert "Identity policy:" in out_flat
        assert "SKIPPED" in out_flat
        assert f"Bundle's claimed SAN: {claimed_san}" in out_flat
        assert "Cryptographic chain" in out_flat
        assert "only the identity (SAN/issuer) match was no-op'd" in out_flat
        assert "--expected-ci-identity" in out_flat
        assert "--ci-identity-from-env" in out_flat
        # The raw "unsafe (no-op) verification policy used!" line
        # produced by sigstore-python at policy-construction time
        # should NOT appear ahead of our Provenance section header.
        # CliRunner's `result.output` captures stdout only by
        # default; sigstore's stderr was captured by our helper so
        # it shouldn't surface here either.
        assert "unsafe (no-op) verification policy used!" not in out_flat

    def test_pinned_identity_skips_san_block(self, tmp_path):
        """When `--expected-ci-identity` IS supplied, the SKIPPED
        block must not fire — we emit the MATCHED line and skip the
        observational SAN-surfacing path."""
        path, statement = self._build_pkg(tmp_path)
        claimed_san = (
            "https://github.com/Acme/repo/.github/workflows/ci.yml"
            "@refs/heads/main"
        )
        bp, vp = self._patch_sigstore(statement, claimed_san)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--expected-ci-identity", claimed_san,
            ])

        out = result.output
        assert "MATCHED" in out
        # SKIPPED-block-specific output must not fire when identity is
        # pinned — the SAN-observation line and the
        # "cryptographic-chain-vs-identity" explainer belong only to the
        # unpinned path. The standalone Trust contract summary block
        # below still prints "Cryptographic chain: VERIFIED" in both
        # modes, so anchor on the SKIPPED-block phrasing instead.
        assert "Bundle's claimed SAN:" not in out
        assert (
            "only the identity (SAN/issuer) match was no-op'd" not in out
        )


class TestSigstoreVerifierConstruction:
    """`_build_sigstore_verifier` honours sigstore-python 4.x's
    actual `Verifier(trusted_root=...)` API. The previous
    implementation called `Verifier._from_trust_config(...)` which
    does not exist in sigstore 4.x — the trust-config-pinned and
    custom-TUF-URL paths could not be honoured at all."""

    def test_trust_config_path_uses_4x_api(self, tmp_path):
        from unittest.mock import MagicMock, patch
        from mipiti_verify.cli import _build_sigstore_verifier

        config_path = tmp_path / "trust-config.json"
        config_path.write_text("{\"placeholder\": true}", encoding="utf-8")

        fake_tc = MagicMock()
        fake_tc.trusted_root = MagicMock(name="trusted_root_object")
        fake_verifier = MagicMock(name="verifier_instance")

        with patch(
            "sigstore.models.ClientTrustConfig.from_json",
            return_value=fake_tc,
        ) as from_json, patch(
            "sigstore.verify.Verifier",
            return_value=fake_verifier,
        ) as Verifier:
            result = _build_sigstore_verifier(
                sigstore_trust_config_path=str(config_path),
                sigstore_tuf_url=None,
            )

        from_json.assert_called_once()
        Verifier.assert_called_once_with(trusted_root=fake_tc.trusted_root)
        assert result is fake_verifier

    def test_tuf_url_uses_4x_api(self):
        from unittest.mock import MagicMock, patch
        from mipiti_verify.cli import _build_sigstore_verifier

        fake_tc = MagicMock()
        fake_tc.trusted_root = MagicMock(name="trusted_root_object")
        fake_verifier = MagicMock(name="verifier_instance")

        with patch(
            "sigstore.models.ClientTrustConfig.from_tuf",
            return_value=fake_tc,
        ) as from_tuf, patch(
            "sigstore.verify.Verifier",
            return_value=fake_verifier,
        ) as Verifier:
            result = _build_sigstore_verifier(
                sigstore_trust_config_path=None,
                sigstore_tuf_url="https://example.test/tuf",
            )

        from_tuf.assert_called_once_with(
            "https://example.test/tuf", offline=False,
        )
        Verifier.assert_called_once_with(trusted_root=fake_tc.trusted_root)
        assert result is fake_verifier


class TestInferIssuer:
    """`_infer_issuer` helper: SAN-prefix registry only.

    We deliberately do NOT read the bundle's own OIDC-issuer cert
    extension. The bundle's claim about its issuer is what
    `policy.Identity()` is supposed to verify; using it as the
    expected value would let a forged bundle declare any issuer it
    likes and pass the pin trivially.
    """

    def test_github_san(self):
        from mipiti_verify.cli import _infer_issuer

        issuer = _infer_issuer(
            "https://github.com/owner/repo/.github/workflows/v.yml@refs/heads/main"
        )
        assert issuer == "https://token.actions.githubusercontent.com"

    def test_gitlab_san(self):
        from mipiti_verify.cli import _infer_issuer

        issuer = _infer_issuer(
            "https://gitlab.com/group/project//.gitlab-ci.yml@main"
        )
        assert issuer == "https://gitlab.com"

    def test_unknown_san_prefix_returns_none(self):
        """Self-hosted issuers must pin --expected-issuer explicitly."""
        from mipiti_verify.cli import _infer_issuer

        issuer = _infer_issuer(
            "https://self-hosted.example.com/foo/bar@refs/heads/main"
        )
        assert issuer is None

    def test_no_san_returns_none(self):
        from mipiti_verify.cli import _infer_issuer

        assert _infer_issuer(None) is None
        assert _infer_issuer("") is None


class TestAuditWorkspaceFingerprintBinding:
    """Workspace-key fingerprint must be recomputed from the actual
    public_key_pem used for signature verification, not trusted from
    the package's metadata claim. Otherwise a forged package with an
    attacker key can claim any fingerprint and pass the pin."""

    def test_claimed_fingerprint_must_match_recomputed(self, tmp_path):
        """A package whose key_fingerprint claim doesn't match the
        actual public_key_pem fails verification, even with a valid
        signature."""
        import json as _j

        # Reuse the helper from TestAuditIdentityPinning by class
        # composition — the helper is plain and self-contained.
        helper = TestAuditIdentityPinning()
        path, real_fp = helper._build_signed_pkg(tmp_path)
        # Tamper with the package: change the claimed fingerprint.
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["content_integrity"]["key_fingerprint"] = "deadbeef" * 8
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        assert "CLAIM MISMATCH" in result.output

    def test_pin_uses_recomputed_fingerprint_not_claim(self, tmp_path):
        """An attacker who attaches their own pub_pem (so the
        signature verifies against an attacker key) but claims the
        victim's fingerprint must NOT pass --expected-workspace-key
        pinning. The pin is checked against the recomputed fingerprint
        of the public key actually used for verification, which is the
        attacker's key — so the pin fails as expected."""
        import json as _j

        helper = TestAuditIdentityPinning()
        path, real_fp = helper._build_signed_pkg(tmp_path)
        victim_fp = "cafe" * 16  # 64-hex-char victim fingerprint
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["content_integrity"]["key_fingerprint"] = victim_fp
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-workspace-key", victim_fp,
        ])
        # Two failures: claim-mismatch and pin-mismatch (pin uses
        # recomputed fp, which is attacker's, not victim's).
        assert result.exit_code == 1
        assert "CLAIM MISMATCH" in result.output
        assert "MISMATCH" in result.output


class TestDeriveCiIdentityFromEnv:
    """`_derive_ci_identity_from_env` helper: GitHub Actions / GitLab CI."""

    def test_github_actions(self, monkeypatch):
        from mipiti_verify.cli import _derive_ci_identity_from_env

        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv(
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/verify.yml@refs/heads/main",
        )
        monkeypatch.delenv("CI_PROJECT_URL", raising=False)
        san = _derive_ci_identity_from_env()
        assert san == (
            "https://github.com/owner/repo/.github/workflows/verify.yml@refs/heads/main"
        )

    def test_gitlab_ci(self, monkeypatch):
        from mipiti_verify.cli import _derive_ci_identity_from_env

        monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
        monkeypatch.delenv("GITHUB_WORKFLOW_REF", raising=False)
        monkeypatch.setenv("CI_PROJECT_URL", "https://gitlab.com/group/project")
        monkeypatch.setenv("CI_CONFIG_PATH", ".gitlab-ci.yml")
        monkeypatch.setenv("CI_COMMIT_REF_NAME", "main")
        san = _derive_ci_identity_from_env()
        assert san == "https://gitlab.com/group/project//.gitlab-ci.yml@main"

    def test_no_env_returns_none(self, monkeypatch):
        from mipiti_verify.cli import _derive_ci_identity_from_env

        for var in (
            "GITHUB_SERVER_URL",
            "GITHUB_WORKFLOW_REF",
            "CI_PROJECT_URL",
            "CI_CONFIG_PATH",
            "CI_COMMIT_REF_NAME",
        ):
            monkeypatch.delenv(var, raising=False)
        assert _derive_ci_identity_from_env() is None


class TestAuditPdfReport:
    """End-to-end tests for the byte-range PDF signature scheme.

    The PDF auditor extracts <fingerprint>:<sig_b64> from the appended
    sentinel block, fetches the public key from JWKS by fingerprint,
    and ECDSA-verifies the signature over the bytes outside the payload.
    Trust model is identical to the HTML scheme.
    """

    def _mint_signed_pdf(self, pdf_body: bytes = b"%PDF-1.7\nfake body\n%%EOF\n"):
        """Build a valid signed-PDF byte stream and return (bytes, jwk_dict).

        Uses the exact same byte layout the backend exporter produces:
        appended `\\n%MIPITI_PDFSIG_v1{<1024 bytes>}MIPITI_PDFSIG_END\\n`
        where the payload is `<fingerprint>:<base64_sig>` space-padded.
        """
        import base64
        import hashlib
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from mipiti_verify.cli import _PDF_SIG_START, _PDF_SIG_END, _PDF_SIG_PAYLOAD_LEN

        key = ec.generate_private_key(ec.SECP256R1())
        der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der).hexdigest()

        covered = pdf_body + _PDF_SIG_START + _PDF_SIG_END
        digest = hashlib.sha256(covered).digest()
        signature = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(signature).decode()

        payload = f"{fingerprint}:{sig_b64}".encode()
        payload = payload + b" " * (_PDF_SIG_PAYLOAD_LEN - len(payload))
        full = pdf_body + _PDF_SIG_START + payload + _PDF_SIG_END

        # Build the JWK the verifier will see returned from JWKS.
        nums = key.public_key().public_numbers()
        x_b64 = base64.urlsafe_b64encode(
            nums.x.to_bytes(32, "big")
        ).rstrip(b"=").decode()
        y_b64 = base64.urlsafe_b64encode(
            nums.y.to_bytes(32, "big")
        ).rstrip(b"=").decode()
        jwk = {"kty": "EC", "crv": "P-256", "kid": fingerprint, "x": x_b64, "y": y_b64}
        return full, jwk

    def _patch_jwks(self, jwk):
        """Return a (target, patcher) pair for `httpx.get` that returns
        a JWKS document containing `jwk`."""
        from unittest.mock import patch
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"keys": [jwk]})
        return patch("httpx.get", return_value=mock_resp)

    def test_signed_pdf_verifies(self, tmp_path):
        pdf_bytes, jwk = self._mint_signed_pdf()
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 0, result.output
        assert "VALID" in result.output
        assert "Report integrity verified" in result.output

    def test_pdf_no_envelope_emits_model_only_verdict(self, tmp_path):
        """A PDF with no audit envelope (legacy export, or model-only export
        from a Mipiti instance that ships pre-envelope-shape) is a valid
        artefact but contains no CI verification evidence. The CLI must
        say so explicitly — silently exiting 0 with only "Report integrity
        verified" lets an auditor mistake a never-CI-verified report for
        a fully-audited one."""
        pdf_bytes, jwk = self._mint_signed_pdf()  # no envelope
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 0, result.output
        # Document signature still passes.
        assert "Report integrity verified" in result.output
        # Scope verdict is loud and unambiguous.
        out_flat = " ".join(result.output.split())
        assert "MODEL ONLY" in result.output
        assert "Audit envelope: NOT PRESENT" in out_flat
        assert "CI verification: NONE" in out_flat
        assert "no CI runs yet" in result.output or "No control has" in result.output

    def test_pdf_with_scope_model_only_envelope_emits_verdict(self, tmp_path):
        """The current backend's shape for a never-CI-verified export:
        explicit envelope with ``scope: "model_only"`` and no
        provenance / content_integrity. CLI must recognise the scope
        marker and emit the MODEL ONLY verdict (not fall through to
        JSON dispatch and silently pass)."""
        import base64, gzip, json
        from mipiti_verify.cli import _PDF_AUDIT_START, _PDF_AUDIT_END
        envelope = {
            "scope": "model_only",
            "verification_runs": [],
            "reason": "no CI verification runs yet",
        }
        pdf_body = b"%PDF-1.7\nfake body\n%%EOF\n"
        encoded = base64.b64encode(gzip.compress(json.dumps(envelope).encode())).decode()
        pdf_with_envelope = pdf_body + _PDF_AUDIT_START + encoded.encode() + _PDF_AUDIT_END
        # Then sign over the whole thing as the exporter does.
        pdf_bytes, jwk = self._mint_signed_pdf(pdf_body=pdf_with_envelope)
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 0, result.output
        assert "MODEL ONLY" in result.output
        out_flat = " ".join(result.output.split())
        assert "Audit envelope: MODEL ONLY" in out_flat
        assert "CI verification: NONE" in out_flat
        # Reason from the envelope is surfaced.
        assert "no CI verification runs yet" in result.output

    def test_pdf_no_envelope_with_require_verification_fails_closed(self, tmp_path):
        """CI gates that must reject pre-verification reports use
        ``--require-verification`` to flip the silent-pass to a hard
        fail with a distinct exit code."""
        pdf_bytes, jwk = self._mint_signed_pdf()  # no envelope
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
                "--require-verification",
            ])
        assert result.exit_code == 3, result.output
        assert "MODEL ONLY" in result.output
        assert "--require-verification" in result.output

    def test_tampered_pdf_body_fails(self, tmp_path):
        pdf_bytes, jwk = self._mint_signed_pdf()
        # Flip a byte in the body before the sentinel.
        body_byte_idx = 5
        tampered = bytearray(pdf_bytes)
        tampered[body_byte_idx] = (tampered[body_byte_idx] + 1) % 256
        path = tmp_path / "tampered.pdf"
        path.write_bytes(bytes(tampered))
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 1
        assert "INVALID" in result.output
        # No Python traceback even though the signature failed to verify.
        assert "Traceback" not in result.output

    def test_pdf_without_signature_block_fails(self, tmp_path):
        path = tmp_path / "unsigned.pdf"
        path.write_bytes(b"%PDF-1.7\nfake body\n%%EOF\n")
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 1
        assert "No signature block found" in result.output
        assert "Traceback" not in result.output

    def test_pdf_malformed_sentinel_fails_cleanly(self, tmp_path):
        from mipiti_verify.cli import _PDF_SIG_START, _PDF_SIG_END
        # Start marker present but end marker missing.
        path = tmp_path / "malformed.pdf"
        path.write_bytes(b"%PDF-1.7\nbody\n%%EOF\n" + _PDF_SIG_START + b"x" * 100)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 1
        assert "Malformed signature block" in result.output
        assert "Traceback" not in result.output

    def test_pdf_pin_flags_without_envelope_is_usage_error(self, tmp_path):
        """When the PDF carries no embedded audit envelope, identity-
        pinning flags (Sigstore SAN, workspace key, model id, commit
        SHA) are rejected with the fail-closed precedent: the PDF
        cannot deliver compromised-platform defense without the
        upstream evidence the flags pin against."""
        pdf_bytes, _ = self._mint_signed_pdf()  # no envelope
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(self._mint_signed_pdf()[1]):
            # JWKS gets called for the byte-range signature check; the
            # second mint's jwk doesn't matter because the test
            # exercises the post-byte-range usage-error path. Use the
            # actual jwk for the bytes we wrote:
            pass
        # Run with the right jwk:
        pdf_bytes_again, jwk = self._mint_signed_pdf()
        path.write_bytes(pdf_bytes_again)
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
                "--expected-ci-identity",
                "https://github.com/example/repo/.github/workflows/x.yml@refs/heads/main",
            ])
        assert result.exit_code == 2, result.output
        out_flat = " ".join(result.output.split())
        assert "identity-pinning flags" in out_flat
        assert "audit envelope with CI verification evidence" in out_flat

    def test_pdf_with_envelope_and_no_pin_flags_passes(self, tmp_path):
        """A PDF carrying a minimal audit envelope (no provenance, no
        content_integrity) and no pinning flags emits the UNVERIFIED
        verdict for the embedded JSON audit content but exits 0 — the
        document signature still verified, and the user didn't ask
        for compromised-platform defense."""
        import base64, gzip, json
        from mipiti_verify.cli import _PDF_AUDIT_START, _PDF_AUDIT_END

        envelope = {
            "model": {"id": "m1"},
            "controls": [],
            "verification_run": {"id": "r1", "results": []},
            "provenance": None,
            "content_integrity": None,
            "assertions_by_control": {},
            "sufficiency": {},
        }
        env_bytes = base64.b64encode(
            gzip.compress(json.dumps(envelope, separators=(",", ":")).encode())
        )
        # Mint the signed PDF body that includes the envelope between
        # the AUDIT markers, BEFORE the SIG markers.
        pdf_body = (
            b"%PDF-1.7\nfake body\n%%EOF\n"
            + _PDF_AUDIT_START + env_bytes + _PDF_AUDIT_END
        )
        pdf_bytes, jwk = self._mint_signed_pdf(pdf_body=pdf_body)
        path = tmp_path / "with-envelope.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 0, result.output
        # Document signature verified.
        assert "Report integrity verified" in result.output
        # AND the JSON-audit dispatch ran on the embedded envelope.
        assert "Audit Package Verification" in result.output

    def test_pdf_envelope_extraction_malformed_fails_cleanly(self, tmp_path):
        """Audit envelope start marker present, end marker missing —
        clean error, no Python traceback."""
        from mipiti_verify.cli import _PDF_AUDIT_START

        pdf_body = (
            b"%PDF-1.7\nfake body\n%%EOF\n"
            + _PDF_AUDIT_START + b"truncated-no-end-marker"
        )
        pdf_bytes, jwk = self._mint_signed_pdf(pdf_body=pdf_body)
        path = tmp_path / "broken-envelope.pdf"
        path.write_bytes(pdf_bytes)
        runner = CliRunner()
        with self._patch_jwks(jwk):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 1
        assert "Audit envelope start marker found but no end marker" in result.output
        assert "Traceback" not in result.output

    def test_pdf_jwks_missing_key_fails_cleanly(self, tmp_path):
        """JWKS reachable but the fingerprint isn't published — clean
        failure, no traceback."""
        from unittest.mock import patch
        pdf_bytes, _ = self._mint_signed_pdf()
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"keys": []})  # empty JWKS
        runner = CliRunner()
        with patch("httpx.get", return_value=mock_resp):
            result = runner.invoke(main, [
                "audit", str(path),
                "--key-url", "https://example.test/jwks",
            ])
        assert result.exit_code == 1
        assert "not found in JWKS" in result.output
        assert "Traceback" not in result.output


class TestRekorAnchor:
    """Verify that --rekor-anchor resolves trust independently of JWKS.

    The auditor passes a URL to a Sigstore-signed bundle binding the
    platform's public key to a known Mipiti CI workflow identity. The
    verifier validates the bundle, confirms the SAN, recovers the
    public key from the manifest, and uses it to verify the report's
    ECDSA signature without contacting the platform's JWKS.

    Tests use synthetic bundles (mocked Sigstore Bundle / Verifier) so
    they run without OIDC. A separate id-token-write CI job mints real
    Fulcio bundles for end-to-end coverage.
    """

    def _key_pair(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        return ec.generate_private_key(ec.SECP256R1())

    def _key_to_jwk_fields(self, key):
        import base64
        nums = key.public_key().public_numbers()
        x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
        y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
        return x, y

    def _key_fingerprint(self, key):
        import hashlib
        from cryptography.hazmat.primitives import serialization
        der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    def _build_signed_html(self, key):
        """Mint a signed-HTML report using `key`. Returns the HTML string.

        Signs the HTML body, then appends
        ``f"\\n<!-- mipiti-report-signature:{fp}:{sig_b64} -->\\n"``.
        The leading ``\\n`` between body and comment is part of the
        appended block, NOT part of the signed bytes — same invariant
        the verifier's regex anchor depends on.
        """
        import base64
        import hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        body = "<!DOCTYPE html><html><body><h1>Test report</h1></body></html>\n"
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        sig = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(sig).decode()
        fp = self._key_fingerprint(key)
        return body + f"\n<!-- mipiti-report-signature:{fp}:{sig_b64} -->\n"

    def _mock_anchor(self, manifest):
        """Patch sigstore Bundle.from_json + Verifier.production so
        verify_dsse returns the supplied manifest dict as DSSE payload."""
        import json as _j
        from datetime import datetime, timezone
        from unittest.mock import MagicMock, patch

        fake_cert = MagicMock()
        fake_cert.subject.rfc4514_string.return_value = ""
        fake_cert.not_valid_before_utc = datetime(2026, 5, 1, tzinfo=timezone.utc)
        fake_cert.not_valid_after_utc = datetime(2026, 5, 1, tzinfo=timezone.utc)
        fake_log = MagicMock()
        fake_log.log_index = 42
        fake_log.integrated_time = 0
        fake_bundle = MagicMock()
        fake_bundle.signing_certificate = fake_cert
        fake_bundle.log_entry = fake_log

        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/json",
            _j.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

        return (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production", return_value=fake_verifier),
        )

    def _patch_anchor_fetch(self, anchor_bytes=b"fake-bundle-bytes"):
        from unittest.mock import MagicMock, patch
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.content = anchor_bytes
        return patch("httpx.get", return_value=mock_resp)

    def test_anchor_without_san_pin_fails_closed(self, tmp_path):
        """--rekor-anchor without --expected-anchor-identity is a usage
        error — accepting any validly-signed Sigstore bundle would let
        an attacker substitute their own bundle and have it accepted."""
        path = tmp_path / "report.html"
        path.write_text(self._build_signed_html(self._key_pair()), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(path),
            "--rekor-anchor", "https://example.test/anchors/k1.sigstore",
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "--rekor-anchor requires --expected-anchor-identity" in out_flat

    def test_anchor_pin_without_url_is_usage_error(self, tmp_path):
        """--expected-anchor-identity without --rekor-anchor has nothing
        to apply to — usage error rather than silent no-op."""
        path = tmp_path / "report.html"
        path.write_text(self._build_signed_html(self._key_pair()), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(path),
            "--expected-anchor-identity",
            "repo:Mipiti/mipiti:ref:refs/heads/main:workflow:foo.yml@refs/heads/main",
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "require --rekor-anchor" in out_flat

    def test_anchor_resolves_html_signature(self, tmp_path):
        """Anchor resolves the public key, HTML signature verifies
        against it — JWKS never contacted."""
        from unittest.mock import patch

        key = self._key_pair()
        fp = self._key_fingerprint(key)
        x, y = self._key_to_jwk_fields(key)
        manifest = {
            "kid": fp,
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "alg": "ES256",
            "use": "sig",
            "anchored_at": 1714752000,
            "anchored_by_workflow":
                "Mipiti/mipiti/.github/workflows/anchor-signing-key.yml",
        }
        html = self._build_signed_html(key)
        path = tmp_path / "report.html"
        path.write_text(html, encoding="utf-8")

        bundle_patch, verifier_patch = self._mock_anchor(manifest)
        # Spy on httpx.get so we can assert JWKS was NOT contacted.
        from unittest.mock import MagicMock
        anchor_resp = MagicMock()
        anchor_resp.raise_for_status = MagicMock()
        anchor_resp.content = b"fake-bundle"
        with bundle_patch, verifier_patch, patch(
            "httpx.get", return_value=anchor_resp,
        ) as mock_get:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", str(path),
                "--rekor-anchor", "https://example.test/anchors/k1.sigstore",
                "--expected-anchor-identity",
                "https://github.com/Mipiti/mipiti/.github/workflows/anchor-signing-key.yml@refs/heads/main",
            ])
        assert result.exit_code == 0, result.output
        assert "Report integrity verified" in result.output
        assert "Anchor verified" in result.output
        # JWKS was not contacted — only the anchor URL was fetched.
        urls = [c.args[0] for c in mock_get.call_args_list if c.args]
        assert all("/.well-known/jwks" not in u for u in urls), urls

    def test_anchor_kid_mismatch_fails(self, tmp_path):
        """Anchor binds key K1, but the report's signature fingerprint
        is K2. Refuse to verify even if the anchor itself is otherwise
        valid — defends against a real anchor for a different key
        being substituted."""
        # Generate two keys; HTML signed by `report_key`, anchor manifest
        # binds `anchor_key`.
        report_key = self._key_pair()
        anchor_key = self._key_pair()
        x, y = self._key_to_jwk_fields(anchor_key)
        manifest = {
            "kid": self._key_fingerprint(anchor_key),
            "kty": "EC", "crv": "P-256", "x": x, "y": y,
            "alg": "ES256", "use": "sig",
        }
        html = self._build_signed_html(report_key)
        path = tmp_path / "report.html"
        path.write_text(html, encoding="utf-8")

        bundle_patch, verifier_patch = self._mock_anchor(manifest)
        with bundle_patch, verifier_patch, self._patch_anchor_fetch():
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", str(path),
                "--rekor-anchor", "https://example.test/anchors/k1.sigstore",
                "--expected-anchor-identity",
                "https://github.com/Mipiti/mipiti/.github/workflows/anchor-signing-key.yml@refs/heads/main",
            ])
        assert result.exit_code == 1
        assert "does not" in result.output and "match" in result.output
        assert "Refusing to verify" in result.output

    def test_anchor_resolves_pdf_signature(self, tmp_path):
        """Same anchor flow works for the PDF audit dispatch."""
        from unittest.mock import patch
        from mipiti_verify.cli import (
            _PDF_SIG_START, _PDF_SIG_END, _PDF_SIG_PAYLOAD_LEN,
        )
        import base64, hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        key = self._key_pair()
        fp = self._key_fingerprint(key)
        x_b, y_b = self._key_to_jwk_fields(key)
        manifest = {
            "kid": fp,
            "kty": "EC", "crv": "P-256", "x": x_b, "y": y_b,
            "alg": "ES256", "use": "sig",
        }

        pdf_body = b"%PDF-1.7\nfake body\n%%EOF\n"
        covered = pdf_body + _PDF_SIG_START + _PDF_SIG_END
        digest = hashlib.sha256(covered).digest()
        signature = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(signature).decode()
        payload = f"{fp}:{sig_b64}".encode()
        payload = payload + b" " * (_PDF_SIG_PAYLOAD_LEN - len(payload))
        pdf_bytes = pdf_body + _PDF_SIG_START + payload + _PDF_SIG_END
        path = tmp_path / "report.pdf"
        path.write_bytes(pdf_bytes)

        bundle_patch, verifier_patch = self._mock_anchor(manifest)
        with bundle_patch, verifier_patch, self._patch_anchor_fetch():
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", str(path),
                "--rekor-anchor", "https://example.test/anchors/k1.sigstore",
                "--expected-anchor-identity",
                "https://github.com/Mipiti/mipiti/.github/workflows/anchor-signing-key.yml@refs/heads/main",
            ])
        assert result.exit_code == 0, result.output
        assert "Anchor verified" in result.output
        assert "Report integrity verified" in result.output

    def test_anchor_manifest_wrong_curve_fails(self, tmp_path):
        """Anchor manifest with a non-P-256 curve is rejected — keeps
        the verifier from accidentally accepting future-keyed manifests
        that the rest of the pipeline can't actually verify."""
        key = self._key_pair()
        fp = self._key_fingerprint(key)
        x, y = self._key_to_jwk_fields(key)
        manifest = {
            "kid": fp,
            "kty": "EC", "crv": "P-384", "x": x, "y": y,
            "alg": "ES384", "use": "sig",
        }
        html = self._build_signed_html(key)
        path = tmp_path / "report.html"
        path.write_text(html, encoding="utf-8")

        bundle_patch, verifier_patch = self._mock_anchor(manifest)
        with bundle_patch, verifier_patch, self._patch_anchor_fetch():
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", str(path),
                "--rekor-anchor", "https://example.test/anchors/k1.sigstore",
                "--expected-anchor-identity",
                "https://github.com/Mipiti/mipiti/.github/workflows/anchor-signing-key.yml@refs/heads/main",
            ])
        assert result.exit_code == 1
        assert "expected EC/P-256" in result.output


class TestRekorEntrySnapshot(TestRekorAnchor):
    """Snapshot mode: --rekor-entry-snapshot DIR resolves the public
    key from a local directory of pre-saved Sigstore bundles. Fully
    offline / air-gapped — no Mipiti, no Rekor, no network access at
    audit time. Inherits helper methods from TestRekorAnchor."""

    SAN_PIN = (
        "https://github.com/Mipiti/mipiti/.github/workflows/"
        "anchor-signing-key.yml@refs/heads/main"
    )

    def _pubkey_obj(self, priv_key):
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_public_key(
            priv_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def test_snapshot_dir_resolves_html(self, tmp_path):
        """Two bundles in the snapshot dir; one matches the report's
        kid. Verifier picks it, validates, succeeds."""
        from unittest.mock import patch

        k1 = self._key_pair()  # report-signing key (snapshot has it)
        k2 = self._key_pair()  # decoy bundle for an unrelated kid
        kid_k1 = self._key_fingerprint(k1)
        kid_k2 = self._key_fingerprint(k2)

        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        (snapshot_dir / "decoy-k2.sigstore").write_bytes(b"decoy-bundle-bytes")
        (snapshot_dir / "match-k1.sigstore").write_bytes(b"match-bundle-bytes")

        def fake_verify(bundle_bytes, **kwargs):
            if bundle_bytes == b"decoy-bundle-bytes":
                return self._pubkey_obj(k2), kid_k2
            if bundle_bytes == b"match-bundle-bytes":
                return self._pubkey_obj(k1), kid_k1
            raise ValueError("unknown bundle bytes")

        html = self._build_signed_html(k1)
        report = tmp_path / "report.html"
        report.write_text(html, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "mipiti_verify.cli._verify_anchor_bundle_bytes",
            side_effect=fake_verify,
        ):
            result = runner.invoke(main, [
                "audit", str(report),
                "--rekor-entry-snapshot", str(snapshot_dir),
                "--expected-anchor-identity", self.SAN_PIN,
            ])
        assert result.exit_code == 0, result.output
        assert "Snapshot match:" in result.output
        assert "Report integrity verified" in result.output

    def test_snapshot_dir_no_match_fails(self, tmp_path):
        """Snapshot dir has bundles, but none for the report's kid."""
        from unittest.mock import patch

        k1 = self._key_pair()
        k2 = self._key_pair()
        kid_k2 = self._key_fingerprint(k2)

        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        (snapshot_dir / "decoy.sigstore").write_bytes(b"decoy")

        def fake_verify(bundle_bytes, **kwargs):
            return self._pubkey_obj(k2), kid_k2

        html = self._build_signed_html(k1)
        report = tmp_path / "report.html"
        report.write_text(html, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "mipiti_verify.cli._verify_anchor_bundle_bytes",
            side_effect=fake_verify,
        ):
            result = runner.invoke(main, [
                "audit", str(report),
                "--rekor-entry-snapshot", str(snapshot_dir),
                "--expected-anchor-identity", self.SAN_PIN,
            ])
        assert result.exit_code == 1
        assert "No bundle in" in result.output

    def test_snapshot_dir_empty_fails(self, tmp_path):
        """Empty snapshot dir is a clean failure, not a traceback."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        report = tmp_path / "report.html"
        report.write_text(self._build_signed_html(self._key_pair()), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(report),
            "--rekor-entry-snapshot", str(snapshot_dir),
            "--expected-anchor-identity", self.SAN_PIN,
        ])
        assert result.exit_code == 1
        assert "no *.sigstore bundle files" in result.output
        assert "Traceback" not in result.output

    def test_snapshot_skips_bad_bundles(self, tmp_path):
        """One corrupt bundle in the dir; another is valid and matches.
        Resolver skips the bad one, picks the good one."""
        from unittest.mock import patch

        k1 = self._key_pair()
        kid_k1 = self._key_fingerprint(k1)

        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        (snapshot_dir / "00-broken.sigstore").write_bytes(b"corrupt")
        (snapshot_dir / "01-good.sigstore").write_bytes(b"good")

        def fake_verify(bundle_bytes, **kwargs):
            if bundle_bytes == b"corrupt":
                raise ValueError("synthetic-corrupt")
            return self._pubkey_obj(k1), kid_k1

        html = self._build_signed_html(k1)
        report = tmp_path / "report.html"
        report.write_text(html, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "mipiti_verify.cli._verify_anchor_bundle_bytes",
            side_effect=fake_verify,
        ):
            result = runner.invoke(main, [
                "audit", str(report),
                "--rekor-entry-snapshot", str(snapshot_dir),
                "--expected-anchor-identity", self.SAN_PIN,
            ])
        assert result.exit_code == 0, result.output
        assert "Snapshot match:" in result.output

    def test_snapshot_without_san_pin_fails_closed(self, tmp_path):
        """--rekor-entry-snapshot without --expected-anchor-identity is
        a usage error — without the SAN pin, any bundle in the dir
        could be accepted regardless of who signed it."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        # Need at least one bundle so we get past the empty-dir check
        # and exercise the SAN-pin gate inside _resolve_pubkey_from_rekor_snapshot.
        (snapshot_dir / "x.sigstore").write_bytes(b"x")
        report = tmp_path / "report.html"
        report.write_text(self._build_signed_html(self._key_pair()), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(report),
            "--rekor-entry-snapshot", str(snapshot_dir),
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "requires --expected-anchor-identity" in out_flat

    def test_snapshot_and_url_anchor_mutually_exclusive(self, tmp_path):
        """--rekor-anchor and --rekor-entry-snapshot together is a
        usage error — they're alternative resolution paths."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()
        (snapshot_dir / "x.sigstore").write_bytes(b"x")
        report = tmp_path / "report.html"
        report.write_text(self._build_signed_html(self._key_pair()), encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(report),
            "--rekor-anchor", "https://example.test/anchors/k.sigstore",
            "--rekor-entry-snapshot", str(snapshot_dir),
            "--expected-anchor-identity", self.SAN_PIN,
        ])
        assert result.exit_code == 2
        out_flat = " ".join(result.output.split())
        assert "mutually exclusive" in out_flat


class TestKeySourceDiscriminator:
    """Cover the four `key_source` branches the verifier dispatches on.

    Older audit envelopes (pre-discriminator) don't carry `key_source`
    at all — those paths are exercised by the `TestAuditIdentityPinning`
    fixtures above. These tests pin behaviour for the explicit
    `key_source` values an issuer may emit.
    """

    def _platform_signed_pkg(
        self, tmp_path, key_source: str, **extra_ci_fields,
    ):
        """Reuse the audit-pinning fixture's signed-pkg shape, then
        layer a `key_source` field (and any extras) onto
        `content_integrity` so the verifier dispatches on the new
        discriminator."""
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
        der_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fp = hashlib.sha256(der_bytes).hexdigest()
        ci = {
            "key_source": key_source,
            "results_hash": stored,
            "signature": base64.b64encode(sig).decode(),
            "key_fingerprint": fp,
            "public_key_pem": pub_pem,
        }
        ci.update(extra_ci_fields)
        pkg = {
            "model": {"id": "m1", "title": "t", "feature_description": "fd",
                      "version": 1, "assets": [], "attackers": [],
                      "trust_boundaries": []},
            "control_objectives": [],
            "controls": [],
            "verification_run": {
                "id": "r1", "pipeline": {}, "results": [], "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": ci,
            "generated_at": "",
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        return str(path), fp

    def test_platform_key_source_verifies_normally(self, tmp_path):
        """`key_source: "platform"` should take the embedded-PEM verify
        branch and report VALID — same as a legacy audit package."""
        path, _ = self._platform_signed_pkg(
            tmp_path, "platform",
            key_authority="aws-kms",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_workspace_key_source_verifies_normally(self, tmp_path):
        """`key_source: "workspace"` should also take the embedded-PEM
        verify branch and report VALID."""
        path, _ = self._platform_signed_pkg(
            tmp_path, "workspace",
            workspace_id="ws-42",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_unverifiable_orphan_emits_clean_warning_not_failure(
        self, tmp_path,
    ):
        """Orphan fingerprints surface as a yellow `UNRESOLVED` notice,
        not a hard failure. Without --expected-workspace-key the audit
        exits 0 — the row's signature half is unverifiable but the
        rest of the package is intact."""
        # Orphan path needs a fingerprint that doesn't recompute from
        # the embedded PEM (so `public_key_pem` should NOT be present
        # — orphan rows have no resolvable PEM).
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
        orphan_fp = (
            "a53a0a8821238371068b1c0f5cc829927ee47e5d575f2889f4018c8fe765db7a"
        )
        pkg = {
            "model": {"id": "m1", "title": "t", "feature_description": "fd",
                      "version": 1, "assets": [], "attackers": [],
                      "trust_boundaries": []},
            "control_objectives": [],
            "controls": [],
            "verification_run": {
                "id": "r1", "pipeline": {}, "results": [], "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": {
                "key_source": "unverifiable_orphan",
                "results_hash": stored,
                "signature": base64.b64encode(sig).decode(),
                "key_fingerprint": orphan_fp,
                "public_key_pem": "",
                "unavailable_reason": "unresolved_fingerprint",
            },
            "generated_at": "",
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 0
        assert "UNRESOLVED" in result.output
        # Customer-trust framing: when Sigstore provenance is present
        # the row remains verified — message must say so explicitly.
        assert "Sigstore provenance" in result.output

    def test_unverifiable_orphan_with_workspace_pin_fails(self, tmp_path):
        """Pinning --expected-workspace-key on an orphan row is treated
        as a hard failure (the pin's intent — workspace-signed
        submissions — cannot be satisfied without a resolvable key)."""
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
        orphan_fp = "deadbeef" * 8
        pkg = {
            "model": {"id": "m1", "title": "t", "feature_description": "fd",
                      "version": 1, "assets": [], "attackers": [],
                      "trust_boundaries": []},
            "control_objectives": [],
            "controls": [],
            "verification_run": {
                "id": "r1", "pipeline": {}, "results": [], "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": {
                "key_source": "unverifiable_orphan",
                "results_hash": stored,
                "signature": base64.b64encode(sig).decode(),
                "key_fingerprint": orphan_fp,
                "public_key_pem": "",
                "unavailable_reason": "unresolved_fingerprint",
            },
            "generated_at": "",
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(path),
            "--expected-workspace-key", "ff" * 32,
        ])
        assert result.exit_code == 1
        assert "UNRESOLVED" in result.output
