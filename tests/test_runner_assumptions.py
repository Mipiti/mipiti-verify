"""Tests for runner assumption merge (Flow O)."""

from unittest.mock import MagicMock

from mipiti_verify.runner import Runner, compute_content_hash


class TestRunnerMergesAssumptions:
    def test_runner_merges_assumptions_into_controls(self, tmp_path):
        """Mock client returns controls + assumptions; runner processes both."""
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
                },
                "assumptions": {
                    "AS1": [
                        {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},  # tier 2
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), reverify=False)
        report = runner.run("m1")

        # Both the control assertion and the assumption assertion should be verified
        assert report["tier1_pass"] == 2
        assert report["tier1_fail"] == 0

    def test_runner_assumption_failure_counted(self, tmp_path):
        """Assumption assertion that fails is counted as tier1_fail."""
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
                "assumptions": {
                    "AS1": [
                        {"id": "asrt_002", "type": "file_exists", "params": {"file": "missing_file.py"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), reverify=False)
        report = runner.run("m1")

        assert report["tier1_pass"] == 1
        assert report["tier1_fail"] == 1

    def test_runner_only_assumptions_no_controls(self, tmp_path):
        """Runner works when there are only assumptions and no controls."""
        (tmp_path / "data.txt").write_text("some content")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {},
                "assumptions": {
                    "AS1": [
                        {"id": "asrt_001", "type": "file_exists", "params": {"file": "data.txt"}},
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = Runner(client=client, project_root=str(tmp_path), reverify=False)
        report = runner.run("m1")

        assert report["tier1_pass"] == 1
        assert report["tier1_fail"] == 0


class TestContentHashIncludesAssumptions:
    def test_content_hash_includes_both_control_and_assumption_assertions(self):
        """Content hash computation covers both control and assumption assertions."""
        all_assertions = [
            {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}, "description": ""},
            {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}, "description": ""},
        ]
        results = [
            {"assertion_id": "asrt_001", "result": "pass"},
            {"assertion_id": "asrt_002", "result": "pass"},
        ]

        content_hash = compute_content_hash(all_assertions, results)

        assert content_hash.startswith("sha256:")
        assert len(content_hash) == len("sha256:") + 64  # SHA-256 hex digest

    def test_content_hash_changes_with_different_verdicts(self):
        """Content hash differs when verdict changes for an assertion."""
        all_assertions = [
            {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}, "description": ""},
            {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}, "description": ""},
        ]

        results_pass = [
            {"assertion_id": "asrt_001", "result": "pass"},
            {"assertion_id": "asrt_002", "result": "pass"},
        ]
        results_fail = [
            {"assertion_id": "asrt_001", "result": "pass"},
            {"assertion_id": "asrt_002", "result": "fail"},
        ]

        hash_pass = compute_content_hash(all_assertions, results_pass)
        hash_fail = compute_content_hash(all_assertions, results_fail)

        assert hash_pass != hash_fail

    def test_content_hash_deterministic(self):
        """Content hash is deterministic for the same inputs."""
        all_assertions = [
            {"id": "asrt_002", "type": "file_exists", "params": {"file": "config.json"}, "description": ""},
            {"id": "asrt_001", "type": "function_exists", "params": {"file": "auth.py", "name": "verify_token"}, "description": ""},
        ]
        results = [
            {"assertion_id": "asrt_002", "result": "pass"},
            {"assertion_id": "asrt_001", "result": "pass"},
        ]

        hash1 = compute_content_hash(all_assertions, results)
        hash2 = compute_content_hash(all_assertions, results)

        assert hash1 == hash2
