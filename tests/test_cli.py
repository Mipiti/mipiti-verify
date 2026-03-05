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
        assert "mipiti-verify" in result.output or "0.1.0" in result.output

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
