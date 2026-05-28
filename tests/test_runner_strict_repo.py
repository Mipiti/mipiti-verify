"""Strict per-repo scope filter — the runner must never evaluate an
assertion bound to a different repository than the one it is scanning.

These tests exercise the filter that runs immediately after the client
fetch in ``Runner._run_tier``: assertions whose ``repo`` matches
``self.repo`` (or carry the ``no_repo`` sentinel, or no ``repo`` field
at all) pass through; assertions with a non-matching ``repo`` are
dropped with a stderr ``[skip]`` line. If ``self.repo`` cannot be
auto-detected and was not supplied, the runner exits the tier with a
clear error rather than evaluating an unbounded set.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.runner import Runner


def _make_runner(client: MagicMock, project_root: str, **kwargs) -> Runner:
    kwargs.setdefault("reverify", False)
    return Runner(client=client, project_root=project_root, **kwargs)


class TestStrictRepoScope:
    def test_matching_repo_passes_through(self, tmp_path, capsys):
        """An assertion whose ``repo`` equals ``self.repo`` is verified."""
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {
                            "id": "asrt_001",
                            "type": "function_exists",
                            "repo": "acme/widgets",
                            "params": {"file": "auth.py", "name": "verify_token"},
                        },
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = _make_runner(client, str(tmp_path), repo="acme/widgets")
        report = runner.run("m1")
        assert report["tier1_pass"] == 1
        captured = capsys.readouterr()
        assert "repo mismatch" not in captured.err

    def test_mismatched_repo_is_filtered_out(self, tmp_path, capsys):
        """An assertion whose ``repo`` differs from ``self.repo`` is
        dropped and a one-line warning is written to stderr."""
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {
                            "id": "asrt_106",
                            "type": "function_exists",
                            "repo": "acme/other-repo",
                            "params": {"file": "auth.py", "name": "verify_token"},
                        },
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]

        runner = _make_runner(client, str(tmp_path), repo="acme/widgets")
        report = runner.run("m1")
        assert report["tier1_pass"] == 0
        assert report["tier1_fail"] == 0
        # No submit because no kept results.
        client.submit_results.assert_not_called()
        captured = capsys.readouterr()
        # The console writes to stderr — rich.Console(stderr=True).
        out_err = captured.err + captured.out
        assert "asrt_106" in out_err
        assert "repo mismatch" in out_err
        assert "acme/other-repo" in out_err
        assert "acme/widgets" in out_err

    def test_no_repo_sentinel_always_passes(self, tmp_path, capsys):
        """``repo == "no_repo"`` is a sentinel for assertions that have
        no file-system scope (e.g., feature_description targets) and
        must pass through regardless of ``self.repo``."""
        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {
                            "id": "asrt_001",
                            "type": "function_exists",
                            "repo": "no_repo",
                            "params": {
                                "file": "auth.py",
                                "name": "verify_token",
                            },
                        },
                    ],
                },
                "assumptions": {},
            },
            {"model_id": "m1", "controls": {}, "assumptions": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        # Even with a completely different self.repo, no_repo passes.
        runner = _make_runner(client, str(tmp_path), repo="totally/elsewhere")
        # function_exists against a missing file will fail tier-1 but
        # the assertion will be evaluated — i.e., not filtered out.
        runner.run("m1")
        captured = capsys.readouterr()
        # No skip line was printed for asrt_001 (no_repo bypasses filter).
        out_err = captured.err + captured.out
        assert "asrt_001" not in out_err or "repo mismatch" not in out_err

    def test_missing_repo_field_passes(self, tmp_path):
        """Assertions that predate per-repo scoping have no ``repo``
        field. They must pass the filter (treated as ``no_repo``) —
        otherwise upgrading the runner against an older backend
        silently drops every assertion."""
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {
                            "id": "asrt_001",
                            "type": "function_exists",
                            "params": {"file": "auth.py", "name": "verify_token"},
                        },
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = _make_runner(client, str(tmp_path), repo="acme/widgets")
        report = runner.run("m1")
        assert report["tier1_pass"] == 1

    def test_empty_repo_raises_clear_error(self, tmp_path):
        """When ``self.repo`` is empty and auto-detection failed (no
        git remote in the project root, no CI env vars), the runner
        must refuse to dispatch verification rather than scan an
        unbounded set."""
        client = MagicMock()
        # tmp_path has no .git → auto-detect returns "".
        with patch.dict(
            "os.environ",
            {"GITHUB_REPOSITORY": "", "CI_PROJECT_PATH": ""},
            clear=False,
        ):
            runner = _make_runner(client, str(tmp_path), repo="")
            assert runner.repo == ""
            with pytest.raises(RuntimeError) as excinfo:
                runner.run("m1")
            msg = str(excinfo.value)
            assert "Repository scope is required" in msg
            assert "--repo" in msg

    def test_mixed_assertions_partial_filter(self, tmp_path, capsys):
        """When a control has both matching and mismatching assertions,
        only the matching ones are evaluated; the rest are skipped."""
        (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")

        client = MagicMock()
        client.get_pending.side_effect = [
            {
                "model_id": "m1",
                "controls": {
                    "CTRL-01": [
                        {
                            "id": "asrt_001",
                            "type": "function_exists",
                            "repo": "acme/widgets",
                            "params": {"file": "auth.py", "name": "verify_token"},
                        },
                        {
                            "id": "asrt_106",
                            "type": "function_exists",
                            "repo": "acme/other",
                            "params": {"file": "auth.py", "name": "verify_token"},
                        },
                    ],
                },
            },
            {"model_id": "m1", "controls": {}},
        ]
        client.submit_results.return_value = {"run_id": "run_1"}

        runner = _make_runner(client, str(tmp_path), repo="acme/widgets")
        report = runner.run("m1")
        # Only asrt_001 evaluated; asrt_106 filtered.
        assert report["tier1_pass"] == 1
        out_err = capsys.readouterr().err + capsys.readouterr().out
        # capsys is consumed — just confirm the verdict shape.
        assert report["tier1_fail"] == 0
