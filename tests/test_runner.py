"""Tests for the verification runner."""

from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.runner import Runner, _pipeline_metadata


class TestRunner:
    def _make_runner(self, **kwargs) -> Runner:
        client = kwargs.pop("client", MagicMock())
        return Runner(client=client, project_root=".", **kwargs)

    def test_run_no_pending(self):
        client = MagicMock()
        client.get_pending.return_value = {"model_id": "m1", "controls": {}}
        runner = self._make_runner(client=client)

        report = runner.run("m1")
        assert report["tier1_pass"] == 0
        assert report["tier1_fail"] == 0
        assert report["tier2_pass"] == 0
        assert report["tier2_fail"] == 0

    def test_run_tier1_pass(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {  # tier 1
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},  # tier 2
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path))
        report = runner.run("m1")

        assert report["tier1_pass"] == 1
        assert report["tier1_fail"] == 0

    def test_run_tier1_fail(self, tmp_path):
        (tmp_path / "auth.py").write_text("def other_func():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path))
        report = runner.run("m1")

        assert report["tier1_fail"] == 1
        assert report["tier1_pass"] == 0

    def test_run_tier2_skipped_without_provider(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {"model_id": "m1", "controls": {}},
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {
                            "id": "asrt_001",
                            "type": "parameter_validated",
                            "params": {"file": "auth.py", "function": "verify_token", "parameter": "token"},
                            "tier2_prompt": "Verify that...",
                        },
                    ],
                },
            },
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), tier2_provider=None)
        report = runner.run("m1")

        assert report["tier2_skip"] == 1

    def test_run_dry_run_no_submit(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]

        runner = Runner(client=client, project_root=str(tmp_path), dry_run=True)
        report = runner.run("m1")

        assert report["dry_run"] is True
        client.submit_results.assert_not_called()

    def test_run_unknown_verifier_skipped(self):
        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "unknown_type_xyz", "params": {}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=".")
        report = runner.run("m1")

        assert report["tier1_skip"] == 1

    def test_details_included_in_report(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), verbose=True)
        report = runner.run("m1")

        assert len(report["details"]) == 1
        assert report["details"][0]["passed"] is True
        assert report["details"][0]["type"] == "function_exists"

    def test_multiple_assertions_multiple_controls(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")
        (tmp_path / "config.json").write_text('{"key": "value"}')

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                    ],
                    "CTRL-02": [
                        {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}},
                        {"id": "asrt_003", "type": "file_exists", "params": {"file": "missing.txt"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path))
        report = runner.run("m1")

        assert report["tier1_pass"] == 2  # verify_token + config.json
        assert report["tier1_fail"] == 1  # missing.txt


class TestChangedFilesFilter:
    def test_filters_to_changed_files(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")
        (tmp_path / "config.json").write_text('{"key": "value"}')

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                        {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), changed_files={"auth.py"})
        report = runner.run("m1")

        assert report["tier1_pass"] == 1  # only auth.py verified
        assert report["tier1_fail"] == 0

    def test_none_verifies_all(self, tmp_path):
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")
        (tmp_path / "config.json").write_text('{"key": "value"}')

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                        {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), changed_files=None)
        report = runner.run("m1")

        assert report["tier1_pass"] == 2  # both verified

    def test_includes_assertions_without_file_param(self, tmp_path):
        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "other.py", "name": "foo"}},
                        {"id": "asrt_002", "type": "config_key_exists", "params": {"manifest": "config.json", "key": "db"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), changed_files={"unrelated.py"})
        report = runner.run("m1")

        # asrt_001 filtered out (file=other.py not in changed), asrt_002 included (no file param)
        assert report["tier1_pass"] + report["tier1_fail"] + report["tier1_skip"] == 1


class TestConcurrency:
    def test_tier2_concurrent(self, tmp_path):
        """Tier 2 runs concurrently when concurrency > 1."""
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {"model_id": "m1", "controls": {}},  # tier 1
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}, "tier2_prompt": "Check it"},
                        {"id": "asrt_002", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}, "tier2_prompt": "Check it"},
                    ],
                },
            },
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), concurrency=4, tier2_provider=None)
        report = runner.run("m1")

        # Both skipped (no provider), but verifies concurrent path doesn't crash
        assert report["tier2_skip"] == 2

    def test_concurrency_default_sequential(self, tmp_path):
        """Default concurrency=1 runs sequentially (existing behavior)."""
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path))
        assert runner.concurrency == 1
        report = runner.run("m1")
        assert report["tier1_pass"] == 1


class TestPipelineMetadata:
    def test_local_default(self, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("GITLAB_CI", raising=False)
        meta = _pipeline_metadata()
        assert meta["provider"] == "local"

    def test_github_actions(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_RUN_ID", "12345")
        monkeypatch.setenv("GITHUB_SHA", "abc123")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv("GITHUB_REPOSITORY", "user/repo")

        meta = _pipeline_metadata()
        assert meta["provider"] == "github_actions"
        assert meta["run_id"] == "12345"
        assert meta["commit_sha"] == "abc123"

    def test_gitlab_ci(self, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("CI_PIPELINE_ID", "67890")
        monkeypatch.setenv("CI_COMMIT_SHA", "def456")
        monkeypatch.setenv("CI_COMMIT_REF_NAME", "main")

        meta = _pipeline_metadata()
        assert meta["provider"] == "gitlab_ci"
        assert meta["run_id"] == "67890"
