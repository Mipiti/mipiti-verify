"""VCS-neutral source provenance for verification runs.

The verifier's provenance (revision id, branch, repo) was sourced git/CI-first
(``GITHUB_SHA`` / ``CI_COMMIT_SHA`` / ``git remote``). This resolves it through
pluggable providers so any source-control system works: CI providers
(GitHub/GitLab) supply their own env vars; a **generic** provider reads
``SOURCE_REVISION`` / ``SOURCE_REPO`` / ``SOURCE_BRANCH`` so SVN, Perforce,
Mercurial, or any runner can supply provenance without git.

The ``revision_id`` is an OPAQUE label — compared for equality, never parsed.
The precise, fully VCS-neutral "same code" key is ``source_digest`` (a content
hash of the verified files, computed elsewhere and independent of any provider);
this module only sources the human/traceability labels.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceProvenance:
    """Source-control-neutral provenance for a verification run."""

    provider: str          # "github_actions" | "gitlab_ci" | "generic" | "local"
    revision_id: str = ""  # opaque: git SHA / svn revision / p4 changelist / …
    branch: str = ""
    repo_ref: str = ""     # opaque repo identity (remote URL / depot path / …)
    run_id: str = ""
    run_url: str = ""

    def to_pipeline_dict(self) -> dict[str, str]:
        """Serialize to the pipeline-metadata shape the API expects.

        ``commit_sha`` carries the opaque ``revision_id`` — the field name is
        git-legacy but the value may come from any VCS. Shape is unchanged from
        the pre-provider dict, so the signed predicate is byte-compatible."""
        return {
            "provider": self.provider,
            "run_id": self.run_id,
            "run_url": self.run_url,
            "commit_sha": self.revision_id,
            "branch": self.branch,
        }


def resolve_provenance(env: dict[str, str] | None = None) -> SourceProvenance:
    """Select a provider from the environment: CI providers first, then a generic
    env-var provider (any VCS), then a local fallback."""
    env = os.environ if env is None else env

    if env.get("GITHUB_ACTIONS"):
        repo = env.get("GITHUB_REPOSITORY", "")
        run_id = env.get("GITHUB_RUN_ID", "")
        server = env.get("GITHUB_SERVER_URL", "")
        return SourceProvenance(
            provider="github_actions",
            revision_id=env.get("GITHUB_SHA", ""),
            branch=env.get("GITHUB_REF", ""),
            repo_ref=repo,
            run_id=run_id,
            run_url=f"{server}/{repo}/actions/runs/{run_id}" if server else "",
        )

    if env.get("GITLAB_CI"):
        return SourceProvenance(
            provider="gitlab_ci",
            revision_id=env.get("CI_COMMIT_SHA", ""),
            branch=env.get("CI_COMMIT_REF_NAME", ""),
            repo_ref=env.get("CI_PROJECT_PATH", ""),
            run_id=env.get("CI_PIPELINE_ID", ""),
            run_url=env.get("CI_PIPELINE_URL", ""),
        )

    # Generic / any-VCS provider: explicit env vars so a non-git runner (SVN,
    # Perforce, Mercurial, a custom pipeline) can supply provenance. The revision
    # is whatever that system reports (an svn revision, a p4 changelist, …).
    rev = env.get("SOURCE_REVISION", "")
    repo = env.get("SOURCE_REPO", "")
    branch = env.get("SOURCE_BRANCH", "")
    if rev or repo or branch:
        return SourceProvenance(
            provider=env.get("SOURCE_PROVIDER", "") or "generic",
            revision_id=rev,
            branch=branch,
            repo_ref=repo,
        )

    return SourceProvenance(provider="local")
