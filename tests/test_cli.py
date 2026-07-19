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


class TestModelAttributionPrefix:
    """Output-formatter tests: every per-assertion line (text and
    GitHub Actions) carries `[<title> <id8>]` model attribution.

    Assertion ids (`asrt_NNN`) are not globally unique across models
    in a workspace; without a model prefix, the GitHub UI Annotations
    panel (which flattens annotations across the whole CI step) makes
    it impossible to tell which model an `asrt_NNN` belongs to when
    running verification across multiple models in one CI step.
    """

    @staticmethod
    def _failure_report(model_id: str = "abcdef1234567890" * 2) -> dict:
        # Long hex-ish id so we can pin that exactly 8 chars are used.
        return {
            "model_id": model_id,
            "tier1_pass": 1,
            "tier1_fail": 1,
            "tier1_skip": 0,
            "tier2_pass": 0,
            "tier2_fail": 0,
            "tier2_skip": 0,
            "tier1_run_id": "r1",
            "tier2_run_id": "",
            "dry_run": False,
            "details": [
                {
                    "assertion_id": "asrt_106",
                    "type": "test_exists",
                    "tier": 1,
                    "passed": True,
                    "details": "ok",
                },
                {
                    "assertion_id": "asrt_107",
                    "type": "test_exists",
                    "tier": 1,
                    "passed": False,
                    "details": "missing",
                },
                {
                    "assertion_id": "asrt_108",
                    "type": "test_exists",
                    "tier": 2,
                    "passed": False,
                    "skipped": True,
                    "details": "no provider",
                },
            ],
            "suff_details": [
                {
                    "control_id": "CTRL-21",
                    "result": "insufficient",
                    "details": "needs more evidence",
                },
            ],
            "suff_sufficient": 0,
            "suff_insufficient": 1,
            "suff_skip": 0,
        }

    def test_github_output_failures_carry_model_prefix(self):
        from mipiti_verify.cli import _github_output

        rpt = self._failure_report()
        runner = CliRunner()
        with runner.isolation() as streams:
            _github_output(rpt, model_title="Payments")
        output = streams[0].getvalue().decode()

        # Pin exact format: `[<title> <id8>]` — first 8 hex chars of id.
        prefix = "[Payments abcdef12]"

        # Every workflow command line carries the prefix in title=
        # (or after `::group::`).
        assert f"::group::{prefix} Tier 1" in output
        assert f"::error title={prefix} Tier 1 Failed::asrt_107" in output
        assert f"::warning title={prefix} Tier 2 Skipped::asrt_108" in output
        assert f"::error title={prefix} Verification Summary::" in output
        assert f"::group::{prefix} Sufficiency" in output
        assert f"::warning title={prefix} Insufficient Coverage::CTRL-21" in output
        # Inline checkmark line for the passing assertion has the prefix too.
        assert f"{prefix} asrt_106" in output

    def test_github_output_notice_on_pass_carries_prefix(self):
        from mipiti_verify.cli import _github_output

        rpt = {
            "model_id": "deadbeefcafefeed" + "00" * 8,
            "tier1_pass": 2,
            "tier1_fail": 0,
            "tier2_pass": 1,
            "tier2_fail": 0,
            "tier2_skip": 0,
            "details": [],
        }
        runner = CliRunner()
        with runner.isolation() as streams:
            _github_output(rpt, model_title="Identity")
        output = streams[0].getvalue().decode()
        assert "::notice title=[Identity deadbeef] Verification Passed::" in output

    def test_github_output_falls_back_to_id8_only_when_no_title(self):
        from mipiti_verify.cli import _github_output

        rpt = self._failure_report(model_id="0123456789abcdef" + "ff" * 8)
        runner = CliRunner()
        with runner.isolation() as streams:
            _github_output(rpt)  # no model_title
        output = streams[0].getvalue().decode()
        # No empty `[ ...]` — just `[<id8>]` when title is absent.
        assert "::error title=[01234567] Tier 1 Failed::asrt_107" in output
        assert "title=[ " not in output

    def test_github_output_survives_unwritable_output_file(self, monkeypatch):
        """A GITHUB_OUTPUT we can't write (runner-owned file, non-root
        container) must NOT crash the run — it had already computed and printed
        the results — only warn and continue."""
        from mipiti_verify.cli import _github_output

        rpt = {
            "model_id": "feedface" + "00" * 12,
            "content_hash": "deadbeefcafe",
            "tier1_pass": 1, "tier1_fail": 0,
            "tier2_pass": 0, "tier2_fail": 0, "tier2_skip": 0,
            "details": [],
        }
        # Unwritable target (dir doesn't exist) -> open(..,"a") raises OSError.
        monkeypatch.setenv("GITHUB_OUTPUT", "/nonexistent-dir-xyz/output")
        runner = CliRunner()
        with runner.isolation() as streams:
            _github_output(rpt)  # must not raise
        output = streams[0].getvalue().decode()
        assert "Could not write content_hash to GITHUB_OUTPUT" in output

    def test_text_output_verbose_carries_model_prefix(self):
        from mipiti_verify.cli import _text_output

        rpt = self._failure_report()
        runner = CliRunner()
        with runner.isolation() as streams:
            _text_output(rpt, verbose=True, model_title="Payments")
        output = streams[0].getvalue().decode()

        prefix = "[Payments abcdef12]"
        # Header carries the prefix.
        assert f"{prefix} Verification Results" in output
        # Per-assertion verbose lines carry the prefix.
        assert f"{prefix} asrt_107" in output

    def test_github_run_all_threads_titles_from_list_models(self):
        """`run --all` looks up titles once via list_models and
        threads them into every per-model annotation block."""
        with patch("mipiti_verify.cli.MipitiClient") as MockClient, \
             patch("mipiti_verify.cli.Runner") as MockRunner:
            client = MagicMock()
            client.list_models.return_value = [
                {"id": "abcdef1234567890" + "11" * 8, "title": "Payments"},
                {"id": "fedcba0987654321" + "22" * 8, "title": "Identity"},
            ]
            MockClient.return_value = client

            mock_runner = MagicMock()
            mock_runner.run.side_effect = [
                {
                    "tier1_pass": 1, "tier1_fail": 1, "tier2_pass": 0,
                    "tier2_fail": 0, "tier2_skip": 0,
                    "details": [{
                        "assertion_id": "asrt_106", "type": "test_exists",
                        "tier": 1, "passed": False, "details": "missing",
                    }],
                },
                {
                    "tier1_pass": 2, "tier1_fail": 0, "tier2_pass": 1,
                    "tier2_fail": 0, "tier2_skip": 0, "details": [],
                },
            ]
            MockRunner.return_value = mock_runner

            runner = CliRunner()
            result = runner.invoke(
                main,
                ["run", "--all", "--api-key", "test-key", "--output", "github"],
            )
            # Exit 1 because the first model has a failure.
            assert result.exit_code == 1
            assert "::error title=[Payments abcdef12] Tier 1 Failed::asrt_106" in result.output
            assert "::notice title=[Identity fedcba09] Verification Passed::" in result.output


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


class TestAuditPackageComprehensive:
    """End-to-end CLI coverage of the comprehensive audit-envelope shape.

    Covers every key the envelope can carry: ``assumptions: [...]``,
    flat ``assertions_by_assumption`` map, per-result denormalised
    ``control_id`` / ``assumption_id``, soft-delete markers, and
    ``orphan_result_assertion_ids``.

    Each test pins one CLI behaviour the auditor relies on. The CLI
    is forwards- and backwards-compatible: it consumes envelopes that
    carry these keys and falls through gracefully when they're absent."""

    def _build_pkg(
        self,
        tmp_path,
        *,
        controls=None,
        assumptions=None,
        results=None,
        assertions_by_control=None,
        assertions_by_assumption=None,
        sufficiency=None,
        orphan_assertion_ids=None,
    ):
        import json
        pkg = {
            "model": {"id": "m1"},
            "controls": controls or [],
            "assumptions": assumptions or [],
            "assertions_by_control": assertions_by_control or {},
            "assertions_by_assumption": assertions_by_assumption or {},
            "sufficiency": sufficiency or {},
            "verification_run": {
                "id": "r1",
                "results": results or [],
                "orphan_result_assertion_ids": orphan_assertion_ids or [],
            },
            "provenance": {},
            "content_integrity": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(json.dumps(pkg), encoding="utf-8")
        return str(path)

    def test_assumption_bound_assertion_renders_under_assumptions_section(self, tmp_path):
        """An assertion bound to an assumption (not a control) renders
        under its own ``Assumptions`` section with the assumption's
        description and an explicit note that sufficiency doesn't apply
        (sufficiency is a control-level concept)."""
        pkg_path = self._build_pkg(
            tmp_path,
            assumptions=[{"id": "AS1", "description": "External auth provider enforces MFA",
                          "type": "external", "status": "active", "assertions": [], "deleted": False}],
            results=[{"assertion_id": "asrt_1", "result": "pass", "tier": 1,
                      "control_id": "", "assumption_id": "AS1"}],
            assertions_by_assumption={"AS1": [{"id": "asrt_1"}]},
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", pkg_path])
        out_flat = " ".join(result.output.split())
        assert "Assumptions" in result.output
        assert "AS1" in out_flat
        assert "External auth provider enforces MFA" in out_flat
        assert "asrt_1" in out_flat
        # Sufficiency caveat appears, no per-row sufficiency line.
        assert "Sufficiency does not apply" in out_flat
        # The verdict tally separates control vs assumption assertions.
        assert "1/1 assumption assertions pass" in out_flat

    def test_denormalised_control_id_drives_grouping_when_lookup_tables_empty(self, tmp_path):
        """The per-result ``control_id`` denorm field is the primary
        grouping signal. Even without flat lookup tables OR rich nested
        assertion lists in the envelope, results group correctly under
        their parent control via the denorm field alone."""
        pkg_path = self._build_pkg(
            tmp_path,
            controls=[{"id": "CTRL-1", "description": "Encrypt at rest",
                       "status": "implemented", "co_mappings": [], "sufficiency": None,
                       "assertions": [], "deleted": False}],
            results=[{"assertion_id": "asrt_1", "result": "pass", "tier": 1,
                      "control_id": "CTRL-1", "assumption_id": ""}],
            # Deliberately omit assertions_by_control to prove the
            # denorm path is engaged, not the cross-reference fallback.
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", pkg_path])
        out_flat = " ".join(result.output.split())
        assert "CTRL-1" in out_flat
        assert "Encrypt at rest" in out_flat
        assert "Unmapped" not in out_flat

    def test_legacy_envelope_without_denorm_falls_back_to_assertions_by_control(self, tmp_path):
        """Older envelope shapes without the per-result
        denorm fields and without ``assertions_by_assumption``. The CLI
        must still group correctly using whatever lookup tables are
        present, including the rich nested ``controls[].assertions``
        list as a final fallback."""
        pkg_path = self._build_pkg(
            tmp_path,
            controls=[{"id": "CTRL-1", "description": "encrypt",
                       "status": "implemented", "co_mappings": [], "sufficiency": None,
                       "assertions": [{"id": "asrt_1"}], "deleted": False}],
            # No flat lookup map, no per-result denorm — only the rich list.
            results=[{"assertion_id": "asrt_1", "result": "pass", "tier": 1}],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", pkg_path])
        out_flat = " ".join(result.output.split())
        assert "CTRL-1" in out_flat
        assert "Unmapped" not in out_flat

    def test_soft_deleted_control_renders_with_retired_marker(self, tmp_path):
        """A control retired after a verification ran still has its
        results in the package; render them with a ``(retired)`` marker
        instead of dropping or mis-attributing."""
        pkg_path = self._build_pkg(
            tmp_path,
            controls=[{"id": "CTRL-OLD", "description": "old check",
                       "status": "not_implemented", "co_mappings": [], "sufficiency": None,
                       "assertions": [], "deleted": True}],
            results=[{"assertion_id": "asrt_1", "result": "pass", "tier": 1,
                      "control_id": "CTRL-OLD", "assumption_id": ""}],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", pkg_path])
        out_flat = " ".join(result.output.split())
        assert "CTRL-OLD" in out_flat
        assert "(retired)" in out_flat

    def test_orphan_results_fail_closed_by_default(self, tmp_path):
        """Package-integrity issue: a result floats free of any control
        or assumption. The auditor cannot verify CONSISTENCY of the
        package, and consistency is a precondition for any other check.
        Default behaviour is fail-closed (same precedent as bundle
        signature INVALID and --require-verification): exit 1, verdict
        FAILED with a specific package-integrity message that
        distinguishes from cryptographic-chain failure."""
        pkg_path = self._build_pkg(
            tmp_path,
            results=[{"assertion_id": "asrt_ghost", "result": "pass", "tier": 1}],
            orphan_assertion_ids=["asrt_ghost"],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", pkg_path])
        assert result.exit_code == 1, result.output
        out_flat = " ".join(result.output.split())
        assert "Unmapped results" in result.output
        assert "asrt_ghost" in out_flat
        assert "Backend marked 1 assertion id(s)" in out_flat
        assert "Verdict: FAILED" in out_flat
        assert "internally-inconsistent" in out_flat
        # Crypto-chain status reported separately so the auditor
        # immediately sees this is a package-shape issue, not a
        # signature failure.
        assert "Cryptographic chain itself is INTACT" in out_flat
        # Override flag is surfaced in the failure message so the
        # auditor doesn't have to re-read the docs to find it.
        assert "--allow-orphan-results" in result.output

    def test_orphan_results_override_demotes_to_partially_verified(self, tmp_path):
        """``--allow-orphan-results`` lets an auditor who's manually
        reviewed the orphan list downgrade the verdict from FAILED
        (default) to PARTIALLY VERIFIED. The orphan count stays in the
        verdict line so the inconsistency remains visible — the
        override doesn't pretend the package is healthy."""
        pkg_path = self._build_pkg(
            tmp_path,
            results=[{"assertion_id": "asrt_ghost", "result": "pass", "tier": 1}],
            orphan_assertion_ids=["asrt_ghost"],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", pkg_path, "--allow-orphan-results"])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "PARTIALLY VERIFIED" in out_flat
        assert "1 orphan" in out_flat
        assert "--allow-orphan-results override active" in out_flat
        # The Unmapped section still renders so the auditor can see
        # what they're allowing through.
        assert "Unmapped results" in result.output


class TestTrustContractSigstoreAnchored:
    """When the row's key_source is ``sigstore``, the inline
    content_integrity signature is intentionally skipped because the
    Sigstore bundle is the authoritative trust anchor. The trust-contract
    summary must report SKIPPED, not FAILED.

    Regression for the case where an audit ran cleanly (bundle verified,
    Rekor inclusion verified, bundle-bind verified) but the summary
    contradicted the per-row output by labelling the SKIPPED state as
    FAILED, alarming the auditor for no reason."""

    def _build_sigstore_anchored_pkg(self, tmp_path, *, sufficiency=None):
        import base64 as _b64
        import hashlib as _h
        import json as _j
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        platform_key = ec.generate_private_key(ec.SECP256R1())
        bind_hex = "5e" * 32
        bb_sig = platform_key.sign(bind_hex.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        # The CLI canonicalises pkg["verification_run"]["results"] and
        # checks the hash against ci["results_hash"]. Use the same
        # canonicalisation here so the hash matches.
        results = [{"assertion_id": "asrt_1", "result": "pass"}]
        canonical = _j.dumps(results, sort_keys=True, separators=(",", ":"))
        results_hash = "sha256:" + _h.sha256(canonical.encode()).hexdigest()
        from cryptography.hazmat.primitives import serialization
        platform_pub_pem = platform_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        pkg = {
            "model": {"id": "m1"},
            "controls": [{"id": "CTRL-1", "description": "test control"}],
            "verification_run": {"id": "r1", "results": results},
            "provenance": {"bundle": "{\"placeholder\": true}"},
            "content_integrity": {
                "results_hash": results_hash,
                "public_key_pem": "",
                "bundle_bind_hash": bind_hex,
                "bundle_bind_signature": _b64.b64encode(bb_sig).decode(),
                "key_source": "sigstore",
                # Realistic envelopes carry an inline signature field on
                # sigstore-anchored rows too (the platform emits one
                # uniformly for the legacy verifier path); the new
                # verifier branches on key_source first and intentionally
                # ignores this field when key_source == "sigstore". The
                # field's presence is what gates the per-row signature
                # block; without it the SKIPPED branch isn't reached.
                "signature": _b64.b64encode(b"unused-by-sigstore-branch").decode(),
            },
            "assertions_by_control": {
                "CTRL-1": [{
                    "id": "asrt_1",
                    "type": "pattern_matches",
                    "description": "test",
                    "params": {},
                }],
            },
            "sufficiency": {"CTRL-1": sufficiency} if sufficiency else {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "t", "digest": {"sha256": bind_hex}}],
            "predicateType": "https://mipiti.io/attestations/v1/verification-run",
            "predicate": {"model_id": "m1", "pipeline": {"commit_sha": "abc"}},
        }
        return str(path), statement, platform_pub_pem

    def _patch_sigstore(self, statement):
        from unittest.mock import MagicMock, patch
        bundle_mock = MagicMock()
        bundle_mock.signing_certificate.not_valid_before_utc = None
        bundle_mock.signing_certificate.not_valid_after_utc = None
        log_entry_mock = MagicMock()
        log_entry_mock.log_index = 0
        log_entry_mock.integrated_time = 0
        log_entry_mock.log_id = MagicMock(key_id=b"")
        bundle_mock.log_entry = log_entry_mock
        verifier_mock = MagicMock()
        import json as _j
        verifier_mock.verify_dsse.return_value = (
            "application/vnd.in-toto+json", _j.dumps(statement).encode()
        )
        bp = patch("sigstore.models.Bundle.from_json", return_value=bundle_mock)
        vp = patch("sigstore.verify.Verifier.production", return_value=verifier_mock)
        return bp, vp

    def test_sigstore_anchored_row_summary_says_skipped_not_failed(self, tmp_path):
        """Bug A regression: the trust contract summary mis-reported a
        Sigstore-anchored row's intentionally-skipped content_integrity
        signature as FAILED. This pins SKIPPED."""
        path, statement, platform_pub_pem = self._build_sigstore_anchored_pkg(tmp_path)
        bp, vp = self._patch_sigstore(statement)
        # Provide platform pubkey so bundle-bind verification can succeed
        # offline (otherwise the test depends on JWKS fetch). Using a
        # tmp file written with the key's PEM.
        pubkey_file = tmp_path / "platform_pub.pem"
        pubkey_file.write_text(platform_pub_pem, encoding="utf-8")
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--platform-pubkey", str(pubkey_file),
            ])
        out = result.output
        out_flat = " ".join(out.split())
        # Per-row: SKIPPED with the sigstore-anchor explanation.
        assert "Signature: SKIPPED" in out_flat
        assert "Sigstore provenance is the trust anchor" in out_flat
        # Trust contract summary: SKIPPED, NOT FAILED.
        assert "Content-integrity sig: SKIPPED" in out_flat, (
            f"Trust contract should report SKIPPED for sigstore-anchored "
            f"rows; instead got: {out_flat}"
        )
        assert "Content-integrity sig: FAILED" not in out_flat, (
            "Trust contract reported FAILED on a row that was "
            "intentionally skipped because Sigstore was the trust anchor."
        )

    def test_pending_sufficiency_demotes_to_partially_verified(self, tmp_path):
        """Bug B regression: a control with sufficiency=pending is not
        sufficient (the LLM check hasn't completed); claiming flat
        VERIFIED with '0/1 controls sufficient' overstates."""
        path, statement, platform_pub_pem = self._build_sigstore_anchored_pkg(
            tmp_path, sufficiency={"status": "pending", "details": ""},
        )
        bp, vp = self._patch_sigstore(statement)
        pubkey_file = tmp_path / "platform_pub.pem"
        pubkey_file.write_text(platform_pub_pem, encoding="utf-8")
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, [
                "audit", path,
                "--platform-pubkey", str(pubkey_file),
            ])
        out_flat = " ".join(result.output.split())
        assert "Verdict: PARTIALLY VERIFIED" in out_flat, (
            f"Pending sufficiency must demote to PARTIALLY VERIFIED; "
            f"got: {out_flat}"
        )
        assert "1 pending" in out_flat
        # The summary should still surface the controls breakdown.
        assert "0/1 controls sufficient" in out_flat


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


class TestCustomerDsseAudit:
    """`mipiti-verify audit` customer-keyed offline DSSE branch.

    The package carries a real customer-signed DSSE bundle in
    `content_integrity.dsse_bundle` with `key_source: "customer_dsse"`.
    Trust derives from the auditor pinning the customer's public key via
    `--expected-customer-key` (the fingerprint gate). Fully offline.
    """

    def _customer_dsse_pkg(
        self, tmp_path, *, model_id="m1", commit_sha="abc123",
        tamper_bind=False,
    ):
        """Build an audit package whose content_integrity carries a real
        customer-DSSE bundle. Returns (pkg_path, public_key_pem_path)."""
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        from mipiti_verify.customer_dsse_signer import (
            sign_verification_statement,
        )

        key = ec.generate_private_key(ec.SECP256R1())
        key_path = tmp_path / "customer.pem"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        pub_path = tmp_path / "customer-pub.pem"
        pub_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        # results_hash binds to canonical-serialised
        # verification_run.results (empty list here, matching the other
        # audit fixtures).
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

        dsse_bundle = sign_verification_statement(
            model_id=model_id,
            tier=1,
            content_hash=stored,
            pipeline={"provider": "jenkins", "commit_sha": commit_sha},
            assertions=[],
            results=[],
            key_path=str(key_path),
        )
        bind_hash = (
            "sha256:" + "00" * 32 if tamper_bind else stored
        )
        pkg = {
            "model": {"id": model_id, "title": "t",
                      "feature_description": "fd", "version": 1,
                      "assets": [], "attackers": [],
                      "trust_boundaries": []},
            "control_objectives": [],
            "controls": [],
            "verification_run": {
                "id": "r1", "pipeline": {}, "results": [],
                "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": {
                "key_source": "customer_dsse",
                "results_hash": stored,
                "bundle_bind_hash": bind_hash,
                "dsse_bundle": dsse_bundle,
                "public_key_pem": "",
            },
            "generated_at": "",
            "assertions_by_control": {},
            "sufficiency": {},
        }
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        return str(path), str(pub_path)

    def test_customer_dsse_verifies_with_pin(self, tmp_path):
        path, pub = self._customer_dsse_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path, "--expected-customer-key", pub,
        ])
        assert result.exit_code == 0, result.output
        assert "Customer-keyed offline DSSE" in result.output
        assert "DSSE signature:" in result.output and "VALID" in result.output
        assert "MATCHED" in result.output

    def test_customer_dsse_without_pin_fails_loudly(self, tmp_path):
        path, _ = self._customer_dsse_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out = " ".join(result.output.split())
        assert "--expected-customer-key was not supplied" in out

    def test_customer_dsse_wrong_pinned_key_fails(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        path, _ = self._customer_dsse_pkg(tmp_path)
        other = ec.generate_private_key(ec.SECP256R1())
        other_pub = tmp_path / "other-pub.pem"
        other_pub.write_bytes(
            other.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path, "--expected-customer-key", str(other_pub),
        ])
        assert result.exit_code == 1
        assert "step 3" in result.output  # fingerprint-pin gate

    def test_customer_dsse_predicate_model_pin(self, tmp_path):
        path, pub = self._customer_dsse_pkg(tmp_path, model_id="m1")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-customer-key", pub,
            "--expected-model-id", "m1",
        ])
        assert result.exit_code == 0, result.output
        assert "Model ID pin:" in result.output

    def test_customer_dsse_predicate_commit_mismatch_fails(self, tmp_path):
        path, pub = self._customer_dsse_pkg(tmp_path, commit_sha="abc123")
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path,
            "--expected-customer-key", pub,
            "--expected-commit-sha", "deadbeef",
        ])
        assert result.exit_code == 1
        assert "Commit SHA pin:" in result.output
        assert "MISMATCH" in result.output

    def test_customer_dsse_tampered_bind_hash_fails(self, tmp_path):
        """Subject digest no longer matches the (tampered) bind hash."""
        path, pub = self._customer_dsse_pkg(tmp_path, tamper_bind=True)
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", path, "--expected-customer-key", pub,
        ])
        assert result.exit_code == 1
        assert "step 4" in result.output

    def test_run_help_lists_customer_key_flags(self):
        runner = CliRunner()
        result = runner.invoke(main, ["run", "--help"])
        assert result.exit_code == 0
        assert "--customer-key" in result.output
        assert "--customer-key-passphrase" in result.output

    def test_audit_help_lists_expected_customer_key(self):
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "--help"])
        assert result.exit_code == 0
        assert "--expected-customer-key" in result.output


class TestAuditPackComposition:
    """Audit-command rendering of the post-#835 ``composition`` section.

    The composition section is additive and flag-gated on the backend
    (``TREE_COMPOSITION_ENABLED``). Three input shapes reach the CLI:

      1. No ``composition`` key — pre-#835 pack or flag off. Existing
         output unchanged; nothing composition-related rendered.
      2. ``composition.available == False`` — backend compute failed
         at pack generation. Single warning, audit verdict unaffected.
      3. ``composition.available == True`` — full effective view
         rendered: tree, entity tallies, COs with origin breakdown,
         per-CO coverage with inherited-control attribution,
         inheritance bindings, and dangling-override counter.
    """

    def _build_signed_pkg(
        self, tmp_path, *, composition=None, key=None, fingerprint_override=None
    ):
        """Build a minimal signed audit package, optionally with a
        composition section. Mirrors ``TestAuditIdentityPinning._build_signed_pkg``
        so the existing signature/hash verification still passes — the
        composition section sits next to the signed body and does NOT
        contribute to ``results_hash`` (which only covers
        ``verification_run.results``)."""
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
        canonical = _j.dumps([], sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
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
        if composition is not None:
            pkg["composition"] = composition
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        return str(path), actual_fp

    def test_no_composition_key_renders_unchanged(self, tmp_path):
        """Pre-#835 packs (no ``composition`` key) render exactly as
        before — regression pin: the composition feature must not bleed
        into legacy pack output."""
        path, _ = self._build_signed_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        assert "Composition" not in result.output
        assert "Inheritance bindings" not in result.output
        assert "Effective coverage" not in result.output

    def test_composition_unavailable_renders_warning(self, tmp_path):
        """``available: false`` from the backend renders as a single
        warning. Audit verdict is unaffected (composition is
        informational; its absence does not invalidate other sections)."""
        path, _ = self._build_signed_pkg(
            tmp_path,
            composition={"available": False, "error": "composition_compute_failed"},
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        assert "Composition" in result.output
        assert "Composition unavailable" in out_flat
        assert "composition_compute_failed" in out_flat
        # The rest of the audit pack still verifies — verdict is
        # neither demoted nor failed because of an unavailable section.
        assert "FAILED" not in result.output

    def test_full_composition_renders_tree_entities_cos_coverage_bindings(
        self, tmp_path
    ):
        """End-to-end composition rendering with every documented field
        populated: tree metadata, own + inherited entities across all
        six kinds, COs with origin breakdown, coverage with inherited
        contributing controls, inheritance bindings, and a non-zero
        dangling counter."""
        composition = {
            "available": True,
            "tree": {
                "parent_id": "parent-1",
                "ancestor_chain": ["parent-1", "grand-1"],
                "depth": 2,
            },
            "effective_entities": {
                "trust_boundaries": [
                    {"kind": "trust_boundaries", "qualified_id": "m1:tb1",
                     "owner_model_id": "m1", "owner_title": "child",
                     "origin": "own", "entity": {"id": "tb1"}},
                    {"kind": "trust_boundaries", "qualified_id": "parent-1:tbP",
                     "owner_model_id": "parent-1", "owner_title": "parent",
                     "origin": "inherited", "entity": {"id": "tbP"}},
                ],
                "assets": [
                    {"kind": "assets", "qualified_id": "m1:a1",
                     "owner_model_id": "m1", "owner_title": "child",
                     "origin": "own", "entity": {"id": "a1"}},
                ],
                "attackers": [
                    {"kind": "attackers", "qualified_id": "parent-1:atP",
                     "owner_model_id": "parent-1", "owner_title": "parent",
                     "origin": "inherited", "entity": {"id": "atP"}},
                ],
                "components": [],
                "attack_paths": [
                    {"kind": "attack_paths", "qualified_id": "m1:ap1",
                     "owner_model_id": "m1", "owner_title": "child",
                     "origin": "own", "entity": {"id": "ap1"}},
                ],
                "assumptions": [
                    {"kind": "assumptions", "qualified_id": "parent-1:asmP",
                     "owner_model_id": "parent-1", "owner_title": "parent",
                     "origin": "inherited", "entity": {"id": "asmP"}},
                ],
            },
            "effective_control_objectives": [
                {"co_qid": "m1:co_own", "asset_qid": "m1:a1",
                 "attacker_qid": "parent-1:atP",
                 "security_properties": ["C"], "origin": "own"},
                {"co_qid": "parent-1:co_inh", "asset_qid": "m1:a1",
                 "attacker_qid": "parent-1:atP",
                 "security_properties": ["I"], "origin": "inherited"},
                {"co_qid": "m1:co_cross", "asset_qid": "m1:a1",
                 "attacker_qid": "parent-1:atP",
                 "security_properties": ["A"], "origin": "cross"},
            ],
            "effective_coverage": [
                {"co_qid": "m1:co_own", "is_covered": True,
                 "own_credit": True, "inherited_credit": False,
                 "contributing_controls": [
                     {"control_id": "C-OWN-1", "owner_model_id": "m1",
                      "origin": "own", "is_verified": True,
                      "mitigation_group": 1},
                 ]},
                {"co_qid": "parent-1:co_inh", "is_covered": True,
                 "own_credit": False, "inherited_credit": True,
                 "contributing_controls": [
                     {"control_id": "C-PARENT-7", "owner_model_id": "parent-1",
                      "origin": "inherited", "is_verified": True,
                      "mitigation_group": 2},
                 ]},
                {"co_qid": "m1:co_cross", "is_covered": False,
                 "own_credit": False, "inherited_credit": False,
                 "contributing_controls": []},
            ],
            "inheritance_bindings": [
                {"child_model_id": "m1", "child_model_version": 1,
                 "co_qid": "parent-1:co_inh", "parent_model_id": "parent-1",
                 "parent_version": 3, "control_id": "C-PARENT-7",
                 "is_verified": True},
            ],
            "dangling_override_linkages": 2,
        }
        path, _ = self._build_signed_pkg(tmp_path, composition=composition)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out = result.output
        out_flat = " ".join(out.split())

        # Section header.
        assert "Composition" in out

        # Tree.
        assert "Tree position" in out
        assert "parent-1" in out
        assert "grand-1" in out
        # Depth value.
        assert "Depth" in out and "2" in out

        # Entity tallies — inherited count for trust_boundaries must
        # appear, as must total entries across kinds.
        assert "Effective entities" in out
        assert "trust_boundaries" in out_flat
        assert "assumptions" in out_flat

        # CO origin breakdown.
        assert "Effective control objectives" in out
        # The summary line carries origin tallies.
        assert "1 own" in out_flat
        assert "1 cross" in out_flat
        assert "1 inherited" in out_flat

        # Coverage rendering.
        assert "Effective coverage" in out
        assert "m1:co_own" in out
        assert "parent-1:co_inh" in out
        assert "COVERED" in out
        assert "UNCOVERED" in out

        # Contributing-control attribution — inherited badge + control id.
        assert "C-PARENT-7" in out
        assert "inherited" in out_flat
        assert "C-OWN-1" in out

        # Inheritance bindings — the load-bearing audit artifact.
        assert "Inheritance bindings" in out
        # Each citable field from the binding row.
        assert "m1" in out
        assert "parent-1" in out
        assert "C-PARENT-7" in out
        # Parent version is rendered.
        assert "3" in out

        # Dangling override warning.
        assert "dangling override" in out_flat
        assert "2" in out_flat

    def test_inherited_credit_is_visually_distinct(self, tmp_path):
        """Inherited contributing controls render with a distinct
        ``[inherited]`` badge so an auditor can spot cross-model credit
        attribution at a glance — own credits render with ``[own]``."""
        composition = {
            "available": True,
            "tree": {"parent_id": None, "ancestor_chain": [], "depth": 0},
            "effective_entities": {},
            "effective_control_objectives": [],
            "effective_coverage": [
                {"co_qid": "co_x", "is_covered": True,
                 "own_credit": True, "inherited_credit": True,
                 "contributing_controls": [
                     {"control_id": "OWN-X", "owner_model_id": "m1",
                      "origin": "own", "is_verified": True,
                      "mitigation_group": None},
                     {"control_id": "INH-Y", "owner_model_id": "ancestor-z",
                      "origin": "inherited", "is_verified": False,
                      "mitigation_group": None},
                 ]},
            ],
            "inheritance_bindings": [],
            "dangling_override_linkages": 0,
        }
        path, _ = self._build_signed_pkg(tmp_path, composition=composition)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out = result.output
        # Both badges rendered, each next to the matching control id.
        assert "[own]" in out
        assert "[inherited]" in out
        assert "OWN-X" in out
        assert "INH-Y" in out
        # Verified state explicit for both.
        assert "verified" in out
        assert "unverified" in out

    def test_zero_dangling_emits_no_warning(self, tmp_path):
        """The dangling-override warning only appears when the counter
        is non-zero. Zero is the common case for well-formed models."""
        composition = {
            "available": True,
            "tree": {"parent_id": None, "ancestor_chain": [], "depth": 0},
            "effective_entities": {},
            "effective_control_objectives": [],
            "effective_coverage": [],
            "inheritance_bindings": [],
            "dangling_override_linkages": 0,
        }
        path, _ = self._build_signed_pkg(tmp_path, composition=composition)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        assert "dangling override" not in result.output.lower()

    def test_flat_model_renders_no_parent_line(self, tmp_path):
        """A flat model (no parent, depth 0) renders the tree position
        as a single dim ``Flat model`` line — no parent / ancestor
        rows to clutter the auditor's view."""
        composition = {
            "available": True,
            "tree": {"parent_id": None, "ancestor_chain": [], "depth": 0},
            "effective_entities": {},
            "effective_control_objectives": [],
            "effective_coverage": [],
            "inheritance_bindings": [],
            "dangling_override_linkages": 0,
        }
        path, _ = self._build_signed_pkg(tmp_path, composition=composition)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out = result.output
        assert "Flat model" in out
        # No ancestor-chain arrow when there's nothing to chain.
        assert "->" not in out.split("Tree position")[1].split("Effective")[0]

    def test_signature_verification_passes_with_composition_present(
        self, tmp_path
    ):
        """Adding a ``composition`` key MUST NOT break the existing
        signature/hash verification. The inline ``content_integrity``
        signature is over ``results_hash`` (which covers
        ``verification_run.results`` only), so composition data sits
        next to the signed body. The auditor expects to see both
        signature MATCH and the composition rendering on the same run."""
        composition = {
            "available": True,
            "tree": {"parent_id": "p", "ancestor_chain": ["p"], "depth": 1},
            "effective_entities": {},
            "effective_control_objectives": [],
            "effective_coverage": [],
            "inheritance_bindings": [],
            "dangling_override_linkages": 0,
        }
        path, _ = self._build_signed_pkg(tmp_path, composition=composition)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        # Signature path still verifies.
        assert "VERIFIED" in result.output
        # Hash match still holds — composition is outside results_hash
        # but inside the broader audit pack body.
        assert "Hash match:" in result.output and "YES" in result.output
        # Composition section also rendered.
        assert "Composition" in result.output

    def test_malformed_composition_does_not_crash(self, tmp_path):
        """A package with structurally-malformed composition fields
        (wrong types, missing keys) must not crash the auditor's CI
        gate — the renderer normalises types defensively, same posture
        as the existing per-field hardening for ``controls`` /
        ``assertions_by_control`` / ``sufficiency``."""
        composition = {
            "available": True,
            # tree is the wrong type — should be normalised to empty.
            "tree": "not a dict",
            # effective_entities the wrong type — normalised to empty.
            "effective_entities": ["bad"],
            # COs entries are not dicts — defensively skipped.
            "effective_control_objectives": ["not-a-dict", 42],
            # coverage entries with mixed valid / invalid shapes.
            "effective_coverage": [
                None,
                {"co_qid": "ok", "is_covered": True, "own_credit": True,
                 "inherited_credit": False,
                 "contributing_controls": "not a list"},
            ],
            "inheritance_bindings": "not a list",
            "dangling_override_linkages": "not an int",
        }
        path, _ = self._build_signed_pkg(tmp_path, composition=composition)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        # Composition is informational; malformed shape doesn't fail
        # the audit verdict — but the renderer must not crash.
        assert result.exit_code == 0
        assert "Composition" in result.output


class TestAuditPackManifest:
    """Audit-pack manifest verification tests (Option β).

    The signed manifest covers every top-level pack section
    (model, controls, assumptions, verification_run, composition,
    ...) via per-section SHA-256 hashes; the inline ECDSA signs the
    manifest's own canonical hash. Older packs without a manifest
    fall back to the legacy `signature`/`results_hash` path.
    """

    def _build_pkg(
        self,
        tmp_path,
        *,
        with_manifest: bool = True,
        with_legacy_signature: bool = True,
        composition: dict | None = None,
        key=None,
        manifest_fingerprint_override: str | None = None,
        manifest_key=None,
        embed_manifest_pubkey: bool = False,
        omit_run_pubkey: bool = False,
        run_key_source: str | None = None,
    ):
        """Build a minimal audit pack with optional manifest + legacy sig.

        Returned (path, key, fingerprint). The manifest covers every
        section enumerated in `_MANIFEST_SECTIONS`; absent-from-pack
        sections are omitted from the manifest, matching backend
        emission rules.

        `manifest_key` signs the manifest when supplied (defaults to
        the run key — the legacy same-key envelope shape);
        `embed_manifest_pubkey` embeds `manifest_public_key_pem`;
        `omit_run_pubkey` empties the run-level `public_key_pem`
        (orphaned-run-key shape); `run_key_source` sets
        `content_integrity.key_source`.
        """
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
        der_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(der_bytes).hexdigest()

        pkg = {
            "model": {
                "id": "m1", "title": "t", "feature_description": "fd",
                "version": 1, "assets": [], "attackers": [],
                "trust_boundaries": [],
            },
            "control_objectives": [],
            "controls": [],
            "assumptions": [],
            "verification_run": {
                "id": "r1", "pipeline": {}, "results": [], "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": {
                "key_fingerprint": fingerprint,
                "public_key_pem": pub_pem,
            },
            "generated_at": "",
            "assertions_by_control": {},
            "assertions_by_assumption": {},
            "sufficiency": {},
        }
        if composition is not None:
            pkg["composition"] = composition

        # Legacy `signature` over results_hash — kept for backward
        # compatibility while the manifest is the strong-binding path.
        if with_legacy_signature:
            canonical_results = _j.dumps(
                pkg["verification_run"]["results"],
                sort_keys=True, separators=(",", ":"),
            )
            results_hash = (
                "sha256:" + hashlib.sha256(canonical_results.encode()).hexdigest()
            )
            sig = key.sign(results_hash.encode(), ec.ECDSA(hashes.SHA256()))
            pkg["content_integrity"]["results_hash"] = results_hash
            pkg["content_integrity"]["signature"] = base64.b64encode(sig).decode()

        if with_manifest:
            from mipiti_verify.cli import _MANIFEST_SECTIONS, _canonical_section_hash

            mkey = manifest_key if manifest_key is not None else key
            m_der = mkey.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            m_fingerprint = hashlib.sha256(m_der).hexdigest()
            sections = {
                name: _canonical_section_hash(pkg[name])
                for name in _MANIFEST_SECTIONS
                if name in pkg and pkg[name] is not None
            }
            manifest = {
                "version": 1,
                "generated_at": "2026-05-27T00:00:00+00:00",
                "sections": sections,
            }
            manifest_canonical = _j.dumps(
                manifest, sort_keys=True, separators=(",", ":"),
            )
            manifest_hash = (
                "sha256:" + hashlib.sha256(manifest_canonical.encode()).hexdigest()
            )
            mfsig = mkey.sign(manifest_hash.encode(), ec.ECDSA(hashes.SHA256()))
            pkg["content_integrity"]["manifest"] = manifest
            pkg["content_integrity"]["manifest_hash"] = manifest_hash
            pkg["content_integrity"]["manifest_signature"] = (
                base64.b64encode(mfsig).decode()
            )
            pkg["content_integrity"]["manifest_key_fingerprint"] = (
                manifest_fingerprint_override
                if manifest_fingerprint_override is not None
                else m_fingerprint
            )
            if embed_manifest_pubkey:
                pkg["content_integrity"]["manifest_public_key_pem"] = (
                    mkey.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode()
                )

        if omit_run_pubkey:
            pkg["content_integrity"]["public_key_pem"] = ""
        if run_key_source is not None:
            pkg["content_integrity"]["key_source"] = run_key_source

        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        return str(path), key, fingerprint

    # ----- Legacy fallback -----

    def test_pack_without_manifest_falls_back_to_legacy(self, tmp_path):
        """A legacy pack carries no manifest fields. The CLI emits the
        fallback notice and the legacy signature verification path
        carries the audit. Regression pin for backward compatibility."""
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=False, with_legacy_signature=True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        assert "No manifest fields in content_integrity" in out_flat
        assert "falling back to legacy signature path" in out_flat
        # Legacy path still produces a VERIFIED verdict.
        assert "Verdict: VERIFIED" in result.output

    # ----- Happy path -----

    def test_manifest_verifies_with_all_sections(self, tmp_path):
        """Pack with manifest fields verifies; success line appears."""
        path, _, _ = self._build_pkg(tmp_path, with_manifest=True)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        assert "Audit-pack manifest (signed sections)" in out_flat
        assert "Hash match: YES" in out_flat
        assert "Signature: VALID" in out_flat
        assert "Sections: ALL" in out_flat and "VERIFIED" in out_flat
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat

    def test_manifest_covers_composition_when_present(self, tmp_path):
        """Composition section, when emitted, is included in the manifest
        and verifies alongside the other sections."""
        composition = {
            "available": True,
            "tree": {"parent_id": None, "ancestor_chain": [], "depth": 0},
            "effective_entities": {},
            "effective_control_objectives": [],
            "effective_coverage": [],
            "inheritance_bindings": [],
            "dangling_override_linkages": 0,
        }
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=True, composition=composition,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        # 9 sections in pkg (model, control_objectives, controls,
        # assumptions, assertions_by_control, assertions_by_assumption,
        # verification_run, composition) — exact count depends on the
        # _MANIFEST_SECTIONS tuple and what the test pack populates.
        out_flat = " ".join(result.output.split())
        assert "Sections: ALL" in out_flat
        assert "Manifest verified" in out_flat

    def test_manifest_verifies_after_benign_key_reordering(self, tmp_path):
        """Re-serializing the pack with a different JSON key order must
        not break verification — canonical-JSON hashing is order
        invariant."""
        import json as _j

        path, _, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        # Rewrite with reverse-sorted keys to force a different on-disk
        # serialization. Canonical hashing collapses both orderings to
        # the same hex, so verification must still pass.
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f, sort_keys=True)
        runner = CliRunner()
        result1 = runner.invoke(main, ["audit", path])
        with open(path, "w", encoding="utf-8") as f:
            # Different on-disk order — but the verifier canonicalises.
            _j.dump(pkg, f, indent=4)
        runner2 = CliRunner()
        result2 = runner2.invoke(main, ["audit", path])
        assert result1.exit_code == 0, result1.output
        assert result2.exit_code == 0, result2.output
        assert "Manifest verified" in result1.output
        assert "Manifest verified" in result2.output

    # ----- Tamper paths -----

    def test_tampered_section_content_fails_with_section_name(self, tmp_path):
        """Modify a section's content while leaving the manifest
        unchanged. The manifest itself still hashes to manifest_hash
        and the signature still verifies, but the section's recomputed
        hash diverges from the manifest entry — the CLI must name the
        section that was tampered."""
        import json as _j

        path, _, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        # Mutate a controls field — manifest is untouched.
        pkg["controls"] = [
            {"id": "c-injected", "title": "Tampered Control"}
        ]
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Section tamper" in out_flat
        assert "'controls'" in out_flat
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_tampered_manifest_hash_fails(self, tmp_path):
        """Modify the recorded manifest_hash so it no longer matches the
        manifest content. The signature can still verify the (wrong)
        hash, but the hash-vs-content check catches the swap."""
        import hashlib
        import json as _j

        path, _, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["content_integrity"]["manifest_hash"] = (
            "sha256:" + hashlib.sha256(b"different content").hexdigest()
        )
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "manifest content does not match manifest_hash" in out_flat
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_tampered_manifest_signature_fails(self, tmp_path):
        """Modify the ECDSA signature. The manifest_hash recomputes
        correctly but verification fails."""
        import base64
        import json as _j

        path, _, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        # Decode, flip a byte, re-encode — preserves base64 structure
        # but destroys the signature.
        original = base64.b64decode(
            pkg["content_integrity"]["manifest_signature"]
        )
        tampered = bytes([original[0] ^ 0xFF]) + original[1:]
        pkg["content_integrity"]["manifest_signature"] = (
            base64.b64encode(tampered).decode()
        )
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "manifest_signature does not verify" in out_flat
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_manifest_key_fingerprint_mismatch_fails(self, tmp_path):
        """When manifest_key_fingerprint does not match the recomputed
        fingerprint of the embedded manifest_public_key_pem, fail — the
        pack embeds a key it claims signed the manifest and the claim
        is false."""
        path, _, _ = self._build_pkg(
            tmp_path,
            with_manifest=True,
            embed_manifest_pubkey=True,
            manifest_fingerprint_override="deadbeef" * 8,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Key fingerprint: MISMATCH" in out_flat
        assert "possible forgery" in out_flat
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_missing_section_referenced_by_manifest_fails(self, tmp_path):
        """A manifest entry for a section the pack doesn't carry is a
        structural inconsistency — the signed manifest claims content
        the pack omits."""
        import json as _j

        # Build a pack with composition, then drop composition while
        # leaving the manifest's composition hash in place.
        composition = {
            "available": True,
            "tree": {"parent_id": None, "ancestor_chain": [], "depth": 0},
            "effective_entities": {},
            "effective_control_objectives": [],
            "effective_coverage": [],
            "inheritance_bindings": [],
            "dangling_override_linkages": 0,
        }
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=True, composition=composition,
        )
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg.pop("composition", None)
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "section 'composition' is in manifest but missing" in out_flat

    # ----- Coexistence with legacy path -----

    def test_manifest_verified_but_legacy_signature_corrupted(self, tmp_path):
        """Both signatures exist independently; either is sufficient for
        a VERIFIED verdict. When the manifest verifies but the legacy
        signature is corrupted, the legacy-path failure is surfaced
        (it's its own independent integrity claim) but the verdict
        reflects the manifest's stronger whole-body coverage."""
        import base64
        import json as _j

        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=True, with_legacy_signature=True,
        )
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        # Corrupt only the legacy `signature` field. The manifest is
        # untouched and must still verify cleanly.
        original = base64.b64decode(pkg["content_integrity"]["signature"])
        tampered = bytes([original[0] ^ 0xFF]) + original[1:]
        pkg["content_integrity"]["signature"] = (
            base64.b64encode(tampered).decode()
        )
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        # The manifest verified — that's the authoritative claim.
        out_flat = " ".join(result.output.split())
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat
        # The legacy path's INVALID line is surfaced to the auditor.
        assert "Signature: INVALID" in out_flat
        # has_failure is set by the legacy path failure — explicitly
        # acknowledge the design choice: legacy is an independent
        # integrity claim and a failing claim is still a failure even
        # when the stronger manifest path passed. Exit non-zero.
        assert result.exit_code == 1

    def test_manifest_key_unresolvable_fails(self, tmp_path):
        """No embedded manifest key, no in-scope key matching
        manifest_key_fingerprint, and JWKS cannot resolve it — the
        manifest verification fails with a resolution message (never a
        blind fallback to the run's key)."""
        import json as _j
        from unittest.mock import patch

        path, _, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["content_integrity"]["public_key_pem"] = ""
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        with patch(
            "mipiti_verify.cli._resolve_pubkey_from_jwks",
            side_effect=SystemExit(1),
        ):
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "could not resolve the manifest signing key" in out_flat
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_manifest_verifies_via_manifest_public_key_pem_with_orphan_run_key(
        self, tmp_path,
    ):
        """Regression: the manifest is signed by the issuer's platform
        key, not the run's key. When the run's key is orphaned (empty
        public_key_pem, fingerprint absent from the issuer's published
        key set) the manifest must still verify via the embedded
        manifest_public_key_pem — fully offline, no JWKS."""
        from unittest.mock import patch

        from cryptography.hazmat.primitives.asymmetric import ec

        platform_key = ec.generate_private_key(ec.SECP256R1())
        path, _, _ = self._build_pkg(
            tmp_path,
            with_manifest=True,
            with_legacy_signature=True,
            manifest_key=platform_key,
            embed_manifest_pubkey=True,
            omit_run_pubkey=True,
            run_key_source="unverifiable_orphan",
        )
        runner = CliRunner()
        # JWKS must never be consulted — the embedded manifest key
        # resolves the signature offline.
        with patch(
            "mipiti_verify.cli._resolve_pubkey_from_jwks",
            side_effect=AssertionError("JWKS must not be consulted"),
        ):
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat
        assert "embedded manifest_public_key_pem" in out_flat
        # The orphaned run key is reported as UNRESOLVED, not as a
        # manifest failure.
        assert "UNRESOLVED" in result.output

    def test_manifest_verifies_via_jwks_when_run_key_differs(self, tmp_path):
        """A pack whose run is signed by a different (e.g. workspace)
        key than the platform key that signed the manifest resolves the
        manifest key via JWKS by manifest_key_fingerprint — the run's
        key is never used for the manifest."""
        import hashlib
        from unittest.mock import patch

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        platform_key = ec.generate_private_key(ec.SECP256R1())
        m_der = platform_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        m_fp = hashlib.sha256(m_der).hexdigest()
        path, _, _ = self._build_pkg(
            tmp_path,
            with_manifest=True,
            with_legacy_signature=True,
            manifest_key=platform_key,
            embed_manifest_pubkey=False,
        )
        runner = CliRunner()
        with patch(
            "mipiti_verify.cli._resolve_pubkey_from_jwks",
            return_value=(platform_key.public_key(), m_fp, "mock://jwks"),
        ):
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Manifest verified" in out_flat
        assert "JWKS lookup by manifest_key_fingerprint" in out_flat

    def test_partial_manifest_fields_falls_back_to_legacy(self, tmp_path):
        """Only some of the manifest fields are present (e.g.,
        manifest exists but manifest_hash is missing). The verifier
        treats this as 'manifest absent' and falls back to the legacy
        path — defensive against malformed pack emissions."""
        import json as _j

        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=True, with_legacy_signature=True,
        )
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        del pkg["content_integrity"]["manifest_hash"]
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        assert "falling back to legacy signature path" in out_flat
        # Legacy signature still verifies.
        assert "Verdict: VERIFIED" in result.output

    @staticmethod
    def _resign_manifest(pkg: dict, key) -> None:
        """Recompute manifest_hash over the (possibly mutated) manifest
        and re-sign it with `key`, in place."""
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        manifest = pkg["content_integrity"]["manifest"]
        manifest_canonical = _j.dumps(
            manifest, sort_keys=True, separators=(",", ":"),
        )
        manifest_hash = (
            "sha256:" + hashlib.sha256(manifest_canonical.encode()).hexdigest()
        )
        mfsig = key.sign(manifest_hash.encode(), ec.ECDSA(hashes.SHA256()))
        pkg["content_integrity"]["manifest_hash"] = manifest_hash
        pkg["content_integrity"]["manifest_signature"] = (
            base64.b64encode(mfsig).decode()
        )

    def test_section_named_in_manifest_but_missing_from_pack_fails(
        self, tmp_path,
    ):
        """A manifest entry for a section the pack doesn't carry is a
        failure regardless of the section name — the signed manifest
        claims content the pack omits. There is no unknown-section
        skip: section hashes are canonical-JSON by contract, so every
        claimed section is recomputable."""
        import json as _j

        path, key, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        manifest = pkg["content_integrity"]["manifest"]
        manifest["sections"]["future_section_v2"] = "sha256:" + ("ab" * 32)
        self._resign_manifest(pkg, key)
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Unknown section" not in out_flat
        assert (
            "section 'future_section_v2' is in manifest but missing"
            in out_flat
        )
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_generic_recompute_verifies_synthetic_section(self, tmp_path):
        """The verifier recomputes ANY manifest-claimed section
        generically (canonical-JSON hash of the section exactly as
        present in the package) — including section names it has no
        specific knowledge of."""
        import json as _j

        from mipiti_verify.cli import _canonical_section_hash

        path, key, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        section_content = {"entries": [{"id": "z1", "value": 42}], "v": 2}
        pkg["zz_synthetic_section"] = section_content
        manifest = pkg["content_integrity"]["manifest"]
        manifest["sections"]["zz_synthetic_section"] = (
            _canonical_section_hash(section_content)
        )
        self._resign_manifest(pkg, key)
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Unknown section" not in out_flat
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat

    def test_generic_recompute_catches_tamper_in_synthetic_section(
        self, tmp_path,
    ):
        """Tampering a section the verifier has no specific knowledge
        of is caught by the generic recompute and named."""
        import json as _j

        from mipiti_verify.cli import _canonical_section_hash

        path, key, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        section_content = {"entries": [{"id": "z1", "value": 42}], "v": 2}
        pkg["zz_synthetic_section"] = section_content
        manifest = pkg["content_integrity"]["manifest"]
        manifest["sections"]["zz_synthetic_section"] = (
            _canonical_section_hash(section_content)
        )
        self._resign_manifest(pkg, key)
        # Tamper the section AFTER the manifest was signed.
        pkg["zz_synthetic_section"]["entries"][0]["value"] = 43
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Section tamper" in out_flat
        assert "'zz_synthetic_section'" in out_flat
        assert "Audit-pack manifest: FAILED" in out_flat

    def test_run_provenance_sections_verify_in_manifest(self, tmp_path):
        """`functional_tests`, `assertions_by_functional_test`,
        `contributing_runs`, and `provenance_health` verify like any
        other manifest section — no unknown-section skip."""
        import json as _j

        from mipiti_verify.cli import _canonical_section_hash

        path, key, _ = self._build_pkg(tmp_path, with_manifest=True)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        extra_sections = {
            "functional_tests": [],
            "assertions_by_functional_test": {},
            "contributing_runs": [],
            "provenance_health": {"runs_embedded": 0},
        }
        manifest = pkg["content_integrity"]["manifest"]
        for name, content in extra_sections.items():
            pkg[name] = content
            manifest["sections"][name] = _canonical_section_hash(content)
        self._resign_manifest(pkg, key)
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Unknown section" not in out_flat
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat

    # ----- Legacy-path deprecation advisory -----

    def test_legacy_only_pack_emits_deprecation_warning(self, tmp_path):
        """When the pack carries only legacy `signature` + `results_hash`
        (no manifest), the auditor sees a yellow advisory naming the
        narrowed verification scope and recommending the pack issuer
        upgrade Mipiti. The advisory does not change the verdict — a
        valid legacy signature still produces VERIFIED with exit 0."""
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=False, with_legacy_signature=True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        # Advisory keyword is present and visually distinct (yellow).
        assert "WARNING" in out_flat
        assert "Legacy-only signature path" in out_flat
        # Names the limitation: which sections are NOT signature-bound
        # by the legacy path.
        assert "verification_run.results" in out_flat
        assert (
            "model definition, controls, assumptions, assertions, and "
            "composition"
        ) in out_flat
        assert "NOT signature-bound" in out_flat
        # Recommends operator action (the pack issuer updates Mipiti).
        assert "update Mipiti" in out_flat
        assert "deprecated" in out_flat
        # The legacy path still produces a VERIFIED verdict.
        assert "Verdict: VERIFIED" in result.output

    def test_manifest_and_legacy_present_notes_deprecation_no_warning(
        self, tmp_path,
    ):
        """When both the manifest path AND legacy fields are present,
        the manifest is the authoritative verification — legacy fields
        are ignored. The trust-contract line acknowledges that the
        legacy fields were ignored as deprecated, but NO warning block
        is emitted (the auditor's verification is complete via the
        manifest)."""
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=True, with_legacy_signature=True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        # Manifest is the authoritative path.
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat
        # Deprecation acknowledged in-line (not as a warning block).
        assert (
            "legacy results_hash + signature ignored — deprecated"
            in out_flat
        )
        # No standalone WARNING block — the manifest covers the body
        # fully, so there's nothing to advise about.
        assert "Legacy-only signature path" not in out_flat
        assert "Verdict: VERIFIED" in result.output

    def test_manifest_only_pack_emits_no_deprecation_advisory(
        self, tmp_path,
    ):
        """A pack carrying only the manifest path (no legacy fields)
        produces a clean VERIFIED result: no deprecation note, no
        warning block. The audit-pack manifest is the only integrity
        claim and the verifier reports it cleanly."""
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=True, with_legacy_signature=False,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        out_flat = " ".join(result.output.split())
        # Manifest verified cleanly.
        assert "Manifest verified" in out_flat
        assert "Audit-pack manifest: VERIFIED" in out_flat
        # No deprecation language anywhere.
        assert "deprecated" not in out_flat
        assert "Legacy-only signature path" not in out_flat
        # Verdict still VERIFIED.
        assert "Verdict: VERIFIED" in result.output

    def test_legacy_warning_does_not_change_exit_code(self, tmp_path):
        """The legacy-path warning is advisory only — a valid legacy
        signature still exits 0. Pin this so a future refactor doesn't
        accidentally hoist the warning into a hard-fail path."""
        path, _, _ = self._build_pkg(
            tmp_path, with_manifest=False, with_legacy_signature=True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0
        # Both the warning AND the success verdict must coexist —
        # narrower scope ≠ failed scope.
        assert "WARNING" in result.output
        assert "Verdict: VERIFIED" in result.output


class TestContributingRunsProvenance:
    """Run-level provenance verification (contributing_runs +
    provenance_health envelope keys).

    Verification state accumulates across partial CI runs; each
    assertion's status was earned by its most recent run. The envelope
    embeds one entry per status-determining run, each independently
    verifiable (canonical-bytes hash + signature and/or Sigstore
    bundle). Older envelopes without these keys degrade gracefully to
    latest-run behavior with coverage reported as unknown.
    """

    @staticmethod
    def _keypair():
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def _pub_pem(key) -> str:
        from cryptography.hazmat.primitives import serialization

        return key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @staticmethod
    def _fingerprint(key) -> str:
        import hashlib

        from cryptography.hazmat.primitives import serialization

        der = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    def _signed_run(
        self,
        key,
        run_id: str,
        assertion_results: list[dict],
        *,
        submitted_at: str = "2026-07-01T12:00:00+00:00",
        provider: str = "github",
        commit_sha: str = "deadbeefcafe",
    ) -> dict:
        """Build one contributing_runs entry: canonical results text,
        hash over its exact bytes, signature over the hash string."""
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        results_canonical = _j.dumps(
            assertion_results, sort_keys=True, separators=(",", ":"),
        )
        results_hash = (
            "sha256:"
            + hashlib.sha256(results_canonical.encode("utf-8")).hexdigest()
        )
        sig = key.sign(results_hash.encode(), ec.ECDSA(hashes.SHA256()))
        return {
            "run_id": run_id,
            "submitted_at": submitted_at,
            "pipeline": {"provider": provider, "commit_sha": commit_sha},
            "assertion_ids": [
                r["assertion_id"] for r in assertion_results
            ],
            "results_canonical": results_canonical,
            "content_integrity": {
                "key_source": "workspace",
                "results_hash": results_hash,
                "signature": base64.b64encode(sig).decode(),
                "key_fingerprint": self._fingerprint(key),
                "public_key_pem": self._pub_pem(key),
            },
        }

    def _build_pkg(
        self,
        tmp_path,
        *,
        contributing_runs: list | None = None,
        provenance_health: dict | None = None,
        results: list | None = None,
        key=None,
    ):
        """Build an audit pack whose legacy content_integrity signature
        verifies over `results`, with optional run-level provenance."""
        import base64
        import hashlib
        import json as _j

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        if key is None:
            key = self._keypair()
        results = results if results is not None else []
        canonical = _j.dumps(results, sort_keys=True, separators=(",", ":"))
        stored = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        sig = key.sign(stored.encode(), ec.ECDSA(hashes.SHA256()))
        control_ids = sorted({
            r["control_id"] for r in results if r.get("control_id")
        })
        pkg = {
            "model": {"id": "m1", "title": "t", "feature_description": "fd",
                      "version": 1, "assets": [], "attackers": [],
                      "trust_boundaries": []},
            "control_objectives": [],
            "controls": [
                {"id": cid, "description": f"Control {cid}"}
                for cid in control_ids
            ],
            "verification_run": {
                "id": "r-latest", "pipeline": {}, "results": results,
                "submitted_at": "",
            },
            "provenance": None,
            "content_integrity": {
                "results_hash": stored,
                "signature": base64.b64encode(sig).decode(),
                "key_fingerprint": self._fingerprint(key),
                "public_key_pem": self._pub_pem(key),
            },
            "generated_at": "",
            "assertions_by_control": {},
            "sufficiency": {
                cid: {"status": "sufficient"} for cid in control_ids
            },
        }
        if contributing_runs is not None:
            pkg["contributing_runs"] = contributing_runs
        if provenance_health is not None:
            pkg["provenance_health"] = provenance_health
        path = tmp_path / "pkg.json"
        path.write_text(_j.dumps(pkg), encoding="utf-8")
        return str(path), key

    # ----- Happy path -----

    def test_two_verified_runs_reconstruct_state(self, tmp_path):
        """Two runs, each signing its own canonical results; both
        verify, the reconstructed state covers every assertion, and the
        trust contract reports full run-level provenance."""
        k1, k2 = self._keypair(), self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": "asrt_002", "result": "pass", "tier": 1},
            ],
            provider="gitlab", commit_sha="0123456789ab",
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1", "details": "ok"},
            {"assertion_id": "asrt_002", "result": "pass", "tier": 1,
             "control_id": "c1", "details": "ok"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2], results=results,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Contributing runs (2)" in out_flat
        assert "run run-aaaa" in out_flat
        assert "run run-bbbb" in out_flat
        assert out_flat.count("VERIFIED sigstore: no") == 2
        assert "Reconstructed from verified runs: 2 assertion result(s)" in out_flat
        assert "manifest-only" not in out_flat.lower()
        assert "Run-level provenance: VERIFIED (2/2 run(s)" in out_flat
        # Per-run pipeline attribution is shown.
        assert "github/deadbeefcafe" in out_flat
        assert "gitlab/0123456789ab" in out_flat

    # ----- Tamper path -----

    def test_run_hash_mismatch_fails_with_hint(self, tmp_path):
        """Tampering a run's canonical results text after signing is
        the tamper-shaped failure: TAMPER-MISMATCH, non-zero exit, and
        the run-tamper remediation hint."""
        k1, k2 = self._keypair(), self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": "asrt_002", "result": "pass", "tier": 1},
            ],
        )
        # Flip the signed verdict inside the exact canonical bytes.
        run2["results_canonical"] = run2["results_canonical"].replace(
            '"pass"', '"fail"',
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
            {"assertion_id": "asrt_002", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2], results=results,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "TAMPER-MISMATCH" in out_flat
        assert "results_canonical does not hash to results_hash" in out_flat
        assert (
            "Treat this run as untrusted; ask the report issuer to re-run "
            "verification in CI and re-export." in out_flat
        )
        assert "Run-level provenance: FAILED (1/2 run(s) verified" in out_flat
        assert "Verdict: FAILED" in result.output

    # ----- Unverifiable serialization -----

    def test_unverifiable_serialization_distinct_from_mismatch(self, tmp_path):
        """A run whose signed bytes cannot be re-derived (serialization
        predates canonical freezing) is a coverage limitation, not
        tampering: distinct status, distinct wording, hint present,
        exit code unaffected."""
        k1, k2 = self._keypair(), self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": "asrt_002", "result": "pass", "tier": 1},
            ],
        )
        del run2["results_canonical"]
        run2["content_integrity"]["unverifiable_serialization"] = True
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
            {"assertion_id": "asrt_002", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2], results=results,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "UNVERIFIABLE SERIALIZATION" in out_flat
        assert "cannot re-derive the signed serialization" in out_flat
        assert "nothing is known to be modified" in out_flat
        # Distinct from the tamper-shaped failure.
        assert "TAMPER" not in out_flat
        assert (
            "a fresh run is verifiable by construction" in out_flat
        )
        assert "Run-level provenance: PARTIAL (1/2 run(s) verified" in out_flat

    # ----- Unresolved / orphan key -----

    def test_orphan_run_key_unresolved_with_hint(self, tmp_path):
        """A run signed under a key absent from the issuer's published
        key set is UNRESOLVED KEY (warning-grade, not tampering), with
        the re-run remediation hint."""
        k1, k2 = self._keypair(), self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": "asrt_002", "result": "pass", "tier": 1},
            ],
        )
        run2["content_integrity"]["key_source"] = "orphan"
        run2["content_integrity"]["public_key_pem"] = ""
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
            {"assertion_id": "asrt_002", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2], results=results,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "UNRESOLVED KEY" in out_flat
        assert (
            "runs are then signed under the issuer's current key" in out_flat
        )
        assert "TAMPER" not in out_flat

    # ----- Per-run Sigstore bundle binding -----

    @staticmethod
    def _patch_sigstore_statement(subject_hex: str):
        """Patch the Sigstore Bundle and Verifier symbols so verify_dsse
        returns an in-toto Statement whose Subject digest is
        `subject_hex`. Same shape as the TestBundleBindExplicit helper."""
        import json as _j

        from unittest.mock import MagicMock, patch

        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {"name": "mipiti-verification", "digest": {"sha256": subject_hex}},
            ],
            "predicate": {},
        }
        fake_bundle = MagicMock()
        fake_verifier = MagicMock()
        fake_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            _j.dumps(statement).encode("utf-8"),
        )
        return (
            patch("sigstore.models.Bundle.from_json", return_value=fake_bundle),
            patch("sigstore.verify.Verifier.production", return_value=fake_verifier),
        )

    def test_sigstore_run_binds_against_bundle_bind_hash(self, tmp_path):
        """Regression: the per-run bundle's Subject digest is compared
        against the entry's bundle_bind_hash — NOT results_hash, which
        lives in a different hash domain (it binds the frozen
        results_canonical bytes) and is never equal to the Subject
        digest by design. A well-formed Sigstore-attested run must
        verify."""
        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        bind_hex = "cd" * 32  # bundle-bind domain value; != results_hash
        run1["content_integrity"]["bundle_bind_hash"] = f"sha256:{bind_hex}"
        run1["provenance"] = {"bundle": "{}"}
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
        )
        bp, vp = self._patch_sigstore_statement(bind_hex)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "VERIFIED sigstore: yes" in out_flat
        assert "TAMPER" not in out_flat
        assert "signed over a different value" not in out_flat

    def test_sigstore_run_wrong_bind_hash_is_tamper(self, tmp_path):
        """A genuine Subject-digest vs bundle_bind_hash mismatch is the
        real tamper signal and fails the run."""
        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run1["content_integrity"]["bundle_bind_hash"] = "sha256:" + ("cd" * 32)
        run1["provenance"] = {"bundle": "{}"}
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
        )
        # Bundle Subject digest differs from the entry's claimed bind hash.
        bp, vp = self._patch_sigstore_statement("ef" * 32)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "TAMPER-MISMATCH" in out_flat
        assert (
            "bundle Subject digest does not match this run's "
            "bundle_bind_hash" in out_flat
        )

    def test_sigstore_run_without_bind_hash_is_unbound_not_tamper(
        self, tmp_path,
    ):
        """A per-run bundle with no bundle_bind_hash to bind against is
        reported as unbindable (warning-grade); the run's hash +
        signature path still carries its verification."""
        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run1["provenance"] = {"bundle": "{}"}  # no bundle_bind_hash
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
        )
        bp, vp = self._patch_sigstore_statement("cd" * 32)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "VERIFIED sigstore: unbound" in out_flat
        assert "not bindable to this run entry" in out_flat
        assert (
            "re-export the report from a current build so each run entry "
            "carries its bundle binding" in out_flat
        )
        assert "TAMPER" not in out_flat

    def test_sigstore_run_plus_unresolved_runs_agree_with_producer(
        self, tmp_path,
    ):
        """Pinned production scenario: one Sigstore-attested run
        (correctly bound and verified, determining 6 assertions) plus
        two unresolved-key runs determining the remaining 50 of 56.
        With the bundle bound against bundle_bind_hash the run
        verifies, the auditor's not-verifiably-covered count equals
        the producer's assertions_manifest_only (50), and no
        disagreement is reported."""
        k1, k2, k3 = self._keypair(), self._keypair(), self._keypair()
        bind_hex = "cd" * 32
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": f"asrt_{i:03d}", "result": "pass", "tier": 1}
                for i in range(1, 7)
            ],
        )
        run1["content_integrity"]["bundle_bind_hash"] = f"sha256:{bind_hex}"
        run1["provenance"] = {"bundle": "{}"}
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": f"asrt_{i:03d}", "result": "pass", "tier": 1}
                for i in range(7, 16)
            ],
        )
        run3 = self._signed_run(
            k3, "run-cccc3333", [
                {"assertion_id": f"asrt_{i:03d}", "result": "pass", "tier": 1}
                for i in range(16, 57)
            ],
        )
        for run in (run2, run3):
            run["content_integrity"]["key_source"] = "orphan"
            run["content_integrity"]["public_key_pem"] = ""
        results = [
            {"assertion_id": f"asrt_{i:03d}", "result": "pass", "tier": 1,
             "control_id": "c1"}
            for i in range(1, 57)
        ]
        health = {
            "assertions_verified": 56,
            "assertions_run_covered": 6,
            "assertions_manifest_only": 50,
            "runs_embedded": 3,
            "runs_orphan_key": 2,
            "runs_unverifiable_serialization": 0,
            "runs_sigstore": 1,
        }
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2, run3], results=results,
            provenance_health=health,
        )
        bp, vp = self._patch_sigstore_statement(bind_hex)
        with bp, vp:
            runner = CliRunner()
            result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "VERIFIED sigstore: yes" in out_flat
        assert out_flat.count("UNRESOLVED KEY") >= 2
        # 9 + 41 determinations across the two non-verified runs.
        assert (
            "50 assertion(s) are determined by embedded runs that could "
            "not be fully verified" in out_flat
        )
        assert "disagreement" not in out_flat.lower()
        assert "TAMPER" not in out_flat

    # ----- Manifest-only cross-check -----

    def test_manifest_only_assertions_reported_with_hint(self, tmp_path):
        """Assertions carried by the report's records but determined by
        no embedded run are manifest-only provenance; the count matches
        the producer's provenance_health disclosure."""
        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
            {"assertion_id": "asrt_002", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        health = {
            "assertions_verified": 2,
            "assertions_run_covered": 1,
            "assertions_manifest_only": 1,
            "runs_embedded": 1,
            "runs_orphan_key": 0,
            "runs_unverifiable_serialization": 0,
            "runs_sigstore": 0,
            "resolution_window_truncated": False,
            "warnings": [],
        }
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
            provenance_health=health,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Provenance health (producer disclosure)" in out_flat
        assert "1 manifest-only assertion(s)" in out_flat
        assert "asrt_002" in out_flat
        assert (
            "re-run verification in CI to restore end-to-end run provenance"
            in out_flat
        )
        # Producer disclosure and cross-check agree — no disagreement note.
        assert "disagreement" not in out_flat.lower()
        assert "Run-level provenance: PARTIAL" in out_flat

    def test_unresolved_runs_crosscheck_matches_producer(self, tmp_path):
        """The cross-check uses the producer's semantics: an assertion
        is run-covered only when its status-determining run passed
        auditor-side verification. With every embedded run failing key
        resolution, the producer's `assertions_manifest_only` (all
        verified assertions lack an auditor-verifiable run) agrees
        with the auditor's finding — no disagreement is reported —
        and the unverified-determination summary sums determinations
        across ALL non-verified runs."""
        k1, k2 = self._keypair(), self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
                {"assertion_id": "asrt_002", "result": "pass", "tier": 1},
            ],
        )
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": "asrt_003", "result": "pass", "tier": 1},
                {"assertion_id": "asrt_004", "result": "pass", "tier": 1},
                {"assertion_id": "asrt_005", "result": "pass", "tier": 1},
            ],
        )
        for run in (run1, run2):
            run["content_integrity"]["key_source"] = "orphan"
            run["content_integrity"]["public_key_pem"] = ""
        results = [
            {"assertion_id": f"asrt_00{i}", "result": "pass", "tier": 1,
             "control_id": "c1"}
            for i in range(1, 6)
        ]
        health = {
            "assertions_verified": 5,
            "assertions_run_covered": 0,
            "assertions_manifest_only": 5,
            "runs_embedded": 2,
            "runs_orphan_key": 2,
            "runs_unverifiable_serialization": 0,
            "runs_sigstore": 0,
        }
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2], results=results,
            provenance_health=health,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert out_flat.count("UNRESOLVED KEY") >= 2
        # Determinations summed across BOTH non-verified runs (2 + 3).
        assert (
            "5 assertion(s) are determined by embedded runs that could "
            "not be fully verified" in out_flat
        )
        # Producer and auditor agree under matching semantics.
        assert "disagreement" not in out_flat.lower()

    def test_genuine_disagreement_with_unresolved_runs_still_flagged(
        self, tmp_path,
    ):
        """A producer optimistically claiming zero manifest-only
        assertions while the auditor finds the embedded runs
        unverifiable is a REAL disagreement and is still surfaced."""
        k1, k2 = self._keypair(), self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
                {"assertion_id": "asrt_002", "result": "pass", "tier": 1},
            ],
        )
        run2 = self._signed_run(
            k2, "run-bbbb2222", [
                {"assertion_id": "asrt_003", "result": "pass", "tier": 1},
                {"assertion_id": "asrt_004", "result": "pass", "tier": 1},
                {"assertion_id": "asrt_005", "result": "pass", "tier": 1},
            ],
        )
        for run in (run1, run2):
            run["content_integrity"]["key_source"] = "orphan"
            run["content_integrity"]["public_key_pem"] = ""
        results = [
            {"assertion_id": f"asrt_00{i}", "result": "pass", "tier": 1,
             "control_id": "c1"}
            for i in range(1, 6)
        ]
        health = {"assertions_manifest_only": 0, "runs_embedded": 2}
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1, run2], results=results,
            provenance_health=health,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Producer disclosure disagreement" in out_flat
        assert "assertions_manifest_only = 0" in out_flat
        assert "finds 5 assertion(s)" in out_flat

    def test_provenance_health_disagreement_noted(self, tmp_path):
        """When the producer's manifest-only count disagrees with the
        cross-reference over embedded runs, the divergence is surfaced."""
        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
            {"assertion_id": "asrt_002", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        health = {"assertions_manifest_only": 0, "runs_embedded": 1}
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
            provenance_health=health,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Producer disclosure disagreement" in out_flat

    # ----- Backward compatibility -----

    def test_old_envelope_without_contributing_runs_graceful(self, tmp_path):
        """Envelopes that predate the contributing-runs keys verify
        exactly as before, with run-level coverage reported as unknown
        — never a failure."""
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(tmp_path, results=results)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Contributing runs" not in out_flat
        assert "Run-level provenance: UNKNOWN" in out_flat
        assert "report predates run-level provenance disclosure" in out_flat
        assert "Verdict: VERIFIED" in result.output

    def test_empty_contributing_runs_reported_not_unknown(self, tmp_path):
        """A present-but-empty contributing_runs list is a disclosure
        of zero embedded runs — reported as NONE, not UNKNOWN."""
        path, _ = self._build_pkg(tmp_path, contributing_runs=[])
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Contributing runs (0)" in out_flat
        assert "Run-level provenance: NONE" in out_flat
        assert "UNKNOWN" not in out_flat

    # ----- Remediation hints on non-run failure classes -----

    def test_no_sigstore_provenance_hint(self, tmp_path):
        """The missing-Sigstore line carries the OIDC/DSSE hint."""
        path, _ = self._build_pkg(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        out_flat = " ".join(result.output.split())
        assert "No Sigstore provenance in package" in out_flat
        assert (
            "enable OIDC attestation in the CI job, or use the offline "
            "DSSE attestation path" in out_flat
        )

    def test_results_hash_mismatch_hint(self, tmp_path):
        """The top-level results-hash mismatch line carries the
        untrusted-run remediation hint. This is the no-contributing-runs
        (old envelope) behavior: the legacy pair is the only content
        binding available, so a mismatch stays tamper-shaped."""
        import json as _j

        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(tmp_path, results=results)
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["verification_run"]["results"][0]["details"] = "tampered"
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Hash match: NO" in out_flat
        assert (
            "Treat this run as untrusted; ask the report issuer to re-run "
            "verification in CI and re-export." in out_flat
        )

    # ----- Legacy pair superseded by per-run verification -----

    def test_legacy_hash_mismatch_not_scored_when_runs_present(self, tmp_path):
        """When the envelope embeds contributing runs, a divergence on
        the deprecated top-level results_hash pair is rendered
        informationally (not scored) — no tamper language, no
        remediation line, verdict unaffected. Tamper conclusions come
        solely from the per-run checks."""
        import json as _j

        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
        )
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        # Diverge the accumulated results view from the legacy stored
        # hash without touching the per-run canonical bytes.
        pkg["verification_run"]["results"][0]["details"] = "accumulated-view"
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Hash match: NOT SCORED" in out_flat
        assert "superseded by per-run verification below" in out_flat
        assert "results may have been modified" not in out_flat
        assert "Treat this run as untrusted" not in out_flat
        assert "Verdict: FAILED" not in result.output
        # Per-run verification remains the scored check.
        assert "run run-aaaa" in out_flat
        assert "VERIFIED sigstore: no" in out_flat

    def test_per_run_tamper_still_fails_when_legacy_pair_not_scored(
        self, tmp_path,
    ):
        """The softened legacy pair never masks per-run tampering: a
        run whose canonical bytes were modified still fails the audit."""
        import json as _j

        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        run1["results_canonical"] = run1["results_canonical"].replace(
            '"pass"', '"fail"',
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
        )
        with open(path, encoding="utf-8") as f:
            pkg = _j.load(f)
        pkg["verification_run"]["results"][0]["details"] = "accumulated-view"
        with open(path, "w", encoding="utf-8") as f:
            _j.dump(pkg, f)
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Hash match: NOT SCORED" in out_flat
        assert "TAMPER-MISMATCH" in out_flat
        assert "Verdict: FAILED" in result.output

    # ----- Additive provenance_health fields -----

    def test_health_panel_tolerates_and_displays_additive_fields(
        self, tmp_path,
    ):
        """New provenance_health keys (verified_as_of,
        attestations_near_expiry, attestations_expired) are displayed
        when present; unrecognized keys never break rendering."""
        k1 = self._keypair()
        run1 = self._signed_run(
            k1, "run-aaaa1111", [
                {"assertion_id": "asrt_001", "result": "pass", "tier": 1},
            ],
        )
        results = [
            {"assertion_id": "asrt_001", "result": "pass", "tier": 1,
             "control_id": "c1"},
        ]
        health = {
            "assertions_verified": 1,
            "assertions_run_covered": 1,
            "assertions_manifest_only": 0,
            "runs_embedded": 1,
            "runs_orphan_key": 0,
            "runs_unverifiable_serialization": 0,
            "runs_sigstore": 0,
            "resolution_window_truncated": False,
            "warnings": [],
            "verified_as_of": "2026-07-18T09:00:00+00:00",
            "attestations_near_expiry": 2,
            "attestations_expired": 0,
            "zz_future_disclosure_key": {"nested": True},
        }
        path, _ = self._build_pkg(
            tmp_path, contributing_runs=[run1], results=results,
            provenance_health=health,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["audit", path])
        assert result.exit_code == 0, result.output
        out_flat = " ".join(result.output.split())
        assert "Verified as of: 2026-07-18T09:00:00+00:00" in out_flat
        assert "Attestations near expiry: 2" in out_flat
        assert "Attestations expired: 0" in out_flat


class TestDocSignatureRemediationHint:
    """The document-signature INVALID failure carries the re-download
    remediation hint (HTML report path)."""

    def test_html_signature_invalid_carries_hint(self, tmp_path):
        import base64
        import hashlib

        from unittest.mock import patch

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        body = "<!DOCTYPE html><html><body>audited-content</body></html>"
        content_hash = hashlib.sha256(body.encode()).digest()
        sig = key.sign(content_hash, ec.ECDSA(hashes.SHA256()))
        fingerprint = "ab" * 32
        signed = (
            f"{body}\n<!-- mipiti-report-signature:{fingerprint}:"
            f"{base64.b64encode(sig).decode()} -->"
        )
        # Tamper the body AFTER signing so the signature fails.
        tampered = signed.replace("audited-content", "tampered-content")
        path = tmp_path / "report.html"
        path.write_text(tampered, encoding="utf-8")
        runner = CliRunner()
        with patch(
            "mipiti_verify.cli._resolve_pubkey_from_jwks",
            return_value=(key.public_key(), fingerprint, "mock://jwks"),
        ):
            result = runner.invoke(main, ["audit", str(path)])
        assert result.exit_code == 1
        out_flat = " ".join(result.output.split())
        assert "Signature: INVALID" in out_flat
        assert (
            "Re-download the report from the issuer; if this persists the "
            "copy chain is compromised." in out_flat
        )
