"""The gate that decides what reaches main says what it means.

Two properties, both learned from the same failure: a set maintained in one
place and consumed in another drifts, and CI going green is not evidence that
it asked anything.

The assertions run the workflow's own shell with its outward calls stubbed,
rather than matching its text, so a rewording does not fail them and a dropped
guard does not pass them.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"


def _spec(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_no_two_workflows_define_the_same_job_name():
    """A check context names a job. Two workflows defining one name post that
    context twice on a commit, and GitHub does not define which one a required
    check reads -- its own guidance is to keep job names unique across
    workflows. The docs-only twin published every required name a second time
    on any PR touching both prose and code."""
    seen: dict[str, str] = {}
    clashes = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        spec = _spec(wf) or {}
        for job_id, job in (spec.get("jobs") or {}).items():
            name = (job or {}).get("name") or job_id
            if name in seen and seen[name] != wf.name:
                clashes.append(f"{name!r} in both {seen[name]} and {wf.name}")
            seen[name] = wf.name
    assert not clashes, "; ".join(clashes)


def _guard_verdicts(files: list[str]) -> dict[str, str]:
    """Run detect-changes' own script over a changed-file list."""
    step = next(s for s in _spec(CI)["jobs"]["detect-changes"]["steps"]
                if s.get("name") == "Inert-path guard")
    listing = "\n".join(files)
    preamble = "\n".join([
        f'gh() {{ printf "%s\\n" {listing!r}; }}',
        "PR=1", "REPO=o/r", "",
    ])
    out = Path(subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c",
         'echo "$GITHUB_OUTPUT"'], capture_output=True, text=True).stdout)
    import tempfile
    with tempfile.NamedTemporaryFile("w+", delete=False) as fh:
        gh_out = fh.name
    result = subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c", preamble + step["run"]],
        capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "GITHUB_OUTPUT": gh_out},
    )
    assert result.returncode == 0, result.stderr[-400:]
    return dict(
        line.split("=", 1) for line in Path(gh_out).read_text().splitlines() if "=" in line
    )


@pytest.mark.parametrize("files,docs_only", [
    (["README.md"], "true"),
    (["README.md", "CHANGELOG.md"], "true"),
    (["docs/guide.md"], "true"),
    # The shape that ran both workflows: prose beside code.
    (["README.md", "src/mipiti_verify/runner.py"], "false"),
    (["src/mipiti_verify/runner.py"], "false"),
    # A workflow edit is inert for the formal work but must still run the
    # suite, which is why docs_only is narrower than inert.
    ([".github/workflows/ci.yml"], "false"),
    # No answer is not a licence to skip.
    ([], "false"),
])
def test_docs_only_admits_prose_and_nothing_else(files, docs_only):
    assert _guard_verdicts(files).get("docs_only") == docs_only


def _aggregate(result: str, guard: str = "success", docs_only: str = "false") -> int:
    step = next(s for s in _spec(CI)["jobs"]["audit-tlc-all"]["steps"]
                if s.get("name") == "Every audit-tlc config succeeded")
    return subprocess.run(
        [shutil.which("bash") or "/bin/bash", "-c", step["run"]],
        capture_output=True, text=True, timeout=60,
        env={"RESULT": result, "GUARD": guard, "DOCS_ONLY": docs_only,
             "PATH": "/usr/bin:/bin"},
    ).returncode


@pytest.mark.parametrize("result,ok", [
    ("success", True), ("failure", False), ("cancelled", False), ("skipped", False),
])
def test_the_aggregate_gate_passes_only_on_success(result, ok):
    """A matrix that failed, was cancelled, or never ran must not satisfy the
    gate by having produced no failure."""
    assert (_aggregate(result) == 0) is ok


@pytest.mark.parametrize("result,guard,docs_only,ok", [
    # The one skip that is an argument: the guard answered, and said prose.
    ("skipped", "success", "true", True),
    # Every other skip is the absence of an argument.
    ("skipped", "success", "false", False),
    ("skipped", "failure", "true", False),
    ("cancelled", "success", "true", False),
    # A real failure is never excused by the diff being prose.
    ("failure", "success", "true", False),
])
def test_a_skipped_matrix_counts_only_on_the_guard_s_own_verdict(result, guard, docs_only, ok):
    assert (_aggregate(result, guard, docs_only) == 0) is ok


def test_the_aggregate_covers_the_whole_matrix():
    """The point of the aggregate is that nobody has to restate the matrix
    anywhere. It must therefore depend on the matrix job itself, not on a
    list of configs that would drift the same way the ruleset did."""
    spec = _spec(CI)
    needs = spec["jobs"]["audit-tlc-all"]["needs"]
    needs = [needs] if isinstance(needs, str) else needs
    assert "audit-tlc" in needs, needs
    assert "audit-tlc" in spec["jobs"], "the matrix job it stands for is gone"
    # It must depend on the matrix JOB, whose result covers every instance --
    # never on an enumeration of configs, which is the drift being removed.
    cfgs = spec["jobs"]["audit-tlc"]["strategy"]["matrix"]["cfg"]
    assert len(cfgs) > 1, cfgs
    assert not [n for n in needs if n in cfgs], (
        f"audit-tlc-all names individual configs in `needs`: {needs}"
    )
