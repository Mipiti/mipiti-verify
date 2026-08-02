"""VCS-neutral source provenance: any source-control system can supply run
provenance. CI providers use their own env vars; a generic provider reads
SOURCE_REVISION / SOURCE_REPO / SOURCE_BRANCH so non-git runners work.
"""

from mipiti_verify.provenance import SourceProvenance, resolve_provenance


def test_github_provider():
    p = resolve_provenance({
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": "abc123",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "org/repo",
        "GITHUB_RUN_ID": "42",
        "GITHUB_SERVER_URL": "https://github.com",
    })
    assert p.provider == "github_actions"
    assert p.revision_id == "abc123"
    assert p.repo_ref == "org/repo"
    assert p.run_url == "https://github.com/org/repo/actions/runs/42"


def test_gitlab_provider():
    p = resolve_provenance({
        "GITLAB_CI": "true",
        "CI_COMMIT_SHA": "def456",
        "CI_COMMIT_REF_NAME": "trunk",
        "CI_PROJECT_PATH": "grp/proj",
    })
    assert p.provider == "gitlab_ci"
    assert p.revision_id == "def456"
    assert p.branch == "trunk"


def test_generic_provider_unlocks_non_git():
    # The whole point: an SVN / Perforce / custom runner supplies provenance via
    # env vars, no git required. The revision id is opaque (here an svn revision).
    p = resolve_provenance({
        "SOURCE_REVISION": "r12345",
        "SOURCE_REPO": "svn://host/repo",
        "SOURCE_BRANCH": "trunk",
        "SOURCE_PROVIDER": "svn",
    })
    assert p.provider == "svn"
    assert p.revision_id == "r12345"
    assert p.repo_ref == "svn://host/repo"


def test_generic_provider_defaults_provider_name():
    p = resolve_provenance({"SOURCE_REVISION": "changelist-9"})
    assert p.provider == "generic"
    assert p.revision_id == "changelist-9"


def test_local_fallback_when_nothing_set():
    p = resolve_provenance({})
    assert p.provider == "local"
    assert p.revision_id == ""


def test_ci_provider_takes_precedence_over_generic():
    p = resolve_provenance({
        "GITHUB_ACTIONS": "true", "GITHUB_SHA": "gh",
        "SOURCE_REVISION": "generic",  # ignored — CI provider wins
    })
    assert p.provider == "github_actions"
    assert p.revision_id == "gh"


def test_to_pipeline_dict_maps_revision_to_commit_sha():
    # Backward-compatible shape: the opaque revision rides in commit_sha.
    d = SourceProvenance(provider="svn", revision_id="r99", branch="trunk").to_pipeline_dict()
    assert d == {
        "provider": "svn", "run_id": "", "run_url": "",
        "commit_sha": "r99", "branch": "trunk",
    }


def test_pipeline_metadata_delegates(monkeypatch):
    monkeypatch.setenv("SOURCE_REVISION", "rev-1")
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITLAB_CI", raising=False)
    from mipiti_verify.runner import _pipeline_metadata
    d = _pipeline_metadata()
    assert d["provider"] == "generic"
    assert d["commit_sha"] == "rev-1"
