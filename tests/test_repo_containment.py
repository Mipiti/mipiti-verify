"""Every path the runner reads or counts for an assertion stays under the
project root (formal/RepoContainment.tla): a glob's matches, a mechanism's
file and a component's root, as a file parameter's already did."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from mipiti_verify import hook
from mipiti_verify.runner import Runner, _load_pattern_source
from mipiti_verify.verifiers import PathTraversalError, get_verifier, safe_glob


@pytest.fixture()
def tree(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    (repo / "tests").mkdir(parents=True)
    outside.mkdir()
    (outside / "secret.py").write_text("def f():\n    return 'SECRET'\n")
    (repo / "tests" / "test_a.py").write_text("def f():\n    return 'inside'\n")
    os.symlink(outside, repo / "link_dir")
    return repo, outside


@pytest.mark.parametrize("pattern", ["/etc/*", "../outside/*.py", "tests/../../outside/*",
                                     "{outside}/*.py"])
def test_a_pattern_that_leaves_the_root_is_refused(tree, pattern):
    """Refused by the guard, which the tier-1 runner reports as a failure,
    and read by tier two as nothing."""
    repo, outside = tree
    pattern = pattern.format(outside=outside)
    with pytest.raises(PathTraversalError):
        safe_glob(repo, pattern)
    with pytest.raises(PathTraversalError):
        get_verifier("test_exists").verify({"pattern": pattern}, repo)
    assert _load_pattern_source(repo, {"pattern": pattern}) == ""


def test_a_match_through_a_link_out_is_left_out(tree):
    repo, _outside = tree
    assert safe_glob(repo, "link_dir/*.py") == []
    assert not get_verifier("test_exists").verify({"pattern": "link_dir/*.py"}, repo).passed
    assert "SECRET" not in _load_pattern_source(repo, {"pattern": "**/*.py"})
    assert [p.name for p in safe_glob(repo, "tests/*.py")] == ["test_a.py"]


@pytest.mark.parametrize("file", ["../outside/secret.py", "link_dir/secret.py"])
def test_a_mechanism_file_outside_the_root_is_not_read(tree, file):
    repo, _outside = tree
    spans, why = hook.mechanism_spans(repo, f"{file}::f")
    assert spans == [] and "escapes" in why


def test_a_component_path_outside_the_root_stops_the_run(tree):
    repo, _outside = tree
    client = MagicMock()
    client.key_scope = "verifier"
    client.get_model.return_value = {"components": [{"id": "C", "path": "../outside"}]}
    runner = Runner(client=client, project_root=str(repo), repo="acme/w",
                    reverify=False, component_id="C")
    with pytest.raises(RuntimeError, match="outside the repository"):
        runner._resolve_component_path("m1")
    assert runner.project_root == repo.resolve()


def test_a_component_path_inside_moves_the_root(tree):
    repo, _outside = tree
    client = MagicMock()
    client.key_scope = "verifier"
    client.get_model.return_value = {"components": [{"id": "C", "path": "tests"}]}
    runner = Runner(client=client, project_root=str(repo), repo="acme/w",
                    reverify=False, component_id="C")
    runner._resolve_component_path("m1")
    assert runner.project_root == (repo / "tests").resolve()
