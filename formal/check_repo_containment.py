"""Every file the runner reads or counts lies under its project root:
RepoContainment.tla, on a real file system.

``RepoContainment.tla`` states containment over every resolution function;
``RepoContainmentProofs.tla`` proves it. This checker builds a real tree (a
repository beside an outside directory holding a secret, with links out of
the repository and within it) and, for every raw path and pattern of a set
covering ``..``, absolute paths, links to files and to directories, in and
out, drives the shipped entry points:

- **file**: the ``function_exists`` verifier's ``file`` parameter;
- **mechanism**: ``hook.mechanism_spans`` of ``<file>::f``;
- **glob**: the ``test_exists`` verifier (tier one) and tier two's
  ``runner._load_pattern_source``;
- **component**: ``Runner._resolve_component_path`` with a component path.

The module's verdict for each is computed from the real resolution
(``Path.resolve``): read where the resolved path is under the root, refused
otherwise; a glob reads exactly its matches that resolve under the root, its
pattern refused when absolute or climbing. The code must agree in every case,
and never put the secret's text in anything it returns. Three code
regressions (an unguarded glob, an unguarded resolution, an unguarded
component root) must each be caught.

Run from the repository root: ``python formal/check_repo_containment.py``.
"""

from __future__ import annotations

import contextlib
import glob
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mipiti_verify import hook  # noqa: E402
from mipiti_verify import runner as R  # noqa: E402
from mipiti_verify import verifiers as V  # noqa: E402
from mipiti_verify.verifiers import get_verifier  # noqa: E402

SECRET = "SECRET-OUTSIDE-THE-REPOSITORY"


def build(top: Path) -> tuple[Path, Path]:
    """``(repo, outside)``: the tree every case runs on."""
    repo, outside = top / "repo", top / "outside"
    (repo / "sub").mkdir(parents=True)
    outside.mkdir()
    (outside / "secret.py").write_text(f"def f():\n    return '{SECRET}'\n")
    (repo / "in.py").write_text("def f():\n    return 'inside-in'\n")
    (repo / "sub" / "mod.py").write_text("def f():\n    return 'inside-mod'\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_a.py").write_text("def f():\n    return 'inside-test'\n")
    os.symlink(outside / "secret.py", repo / "link_file.py")
    os.symlink(outside, repo / "link_dir")
    os.symlink(repo / "sub", repo / "link_in")
    return repo, outside


def raws(outside: Path) -> list:
    return ["in.py", "sub/mod.py", "sub/../in.py", "../outside/secret.py",
            str(outside / "secret.py"), "link_file.py", "link_dir/secret.py",
            "link_in/mod.py", "sub/../../outside/secret.py", "missing.py"]


def patterns(outside: Path) -> list:
    return ["**/*.py", "*.py", "tests/*.py", "link_dir/*.py", "link_*",
            "../outside/*.py", str(outside) + "/*.py", "sub/../../outside/*.py", "nothing/*"]


def inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def climbs(pattern: str) -> bool:
    return pattern.startswith("/") or ".." in pattern.split("/")


# --- the cases ------------------------------------------------------------------------

def case_file(repo: Path, raw: str) -> list:
    target = repo / raw
    allowed = inside(repo, target) and target.is_file()
    try:
        result = get_verifier("function_exists").verify({"file": raw, "name": "f"}, repo)
        passed, details = result.passed, result.details
    except Exception as e:  # noqa: BLE001: a refusal raised is a refusal
        passed, details = False, str(e)
    problems = []
    if passed and not allowed:
        problems.append(f"file {raw!r}: read outside the root")
    if allowed and not passed:
        problems.append(f"file {raw!r}: inside the root, not read ({details})")
    if SECRET in details:
        problems.append(f"file {raw!r}: the secret in what it returned")
    return problems


def case_mechanism(repo: Path, raw: str) -> list:
    target = repo / raw
    allowed = inside(repo, target) and target.is_file()
    spans, why = hook.mechanism_spans(repo, f"{raw}::f")
    problems = []
    if spans and not allowed:
        problems.append(f"mechanism {raw!r}: read outside the root")
    if allowed and not spans:
        problems.append(f"mechanism {raw!r}: inside the root, not read ({why})")
    if SECRET in why:
        problems.append(f"mechanism {raw!r}: the secret in what it returned")
    return problems


def expected_matches(repo: Path, pattern: str) -> list:
    if climbs(pattern):
        return []
    return sorted(m for m in glob.glob(str(repo / pattern), recursive=True)
                  if inside(repo, Path(m)))


def case_glob(repo: Path, pattern: str) -> list:
    want = expected_matches(repo, pattern)
    problems = []
    try:
        passed = get_verifier("test_exists").verify({"pattern": pattern}, repo).passed
    except Exception:  # noqa: BLE001: a refusal raised is a refusal
        passed = False
    if passed != bool(want):
        problems.append(f"test_exists {pattern!r}: passed={passed}, the module {bool(want)}")
    text = R._load_pattern_source(repo, {"pattern": pattern})
    if SECRET in text:
        problems.append(f"tier-2 source {pattern!r}: the secret read")
    for m in want:
        if Path(m).is_file() and Path(m).read_text() not in text and len(text) < 16000:
            problems.append(f"tier-2 source {pattern!r}: {m} inside, not read")
    return problems


def case_component(repo: Path, raw: str) -> list:
    target = (repo / raw.strip("/"))
    allowed = inside(repo, target)
    client = MagicMock()
    client.key_scope = "verifier"
    client.get_model.return_value = {"components": [{"id": "C", "path": raw}]}
    runner = R.Runner(client=client, project_root=str(repo), repo="acme/w",
                      reverify=False, component_id="C")
    try:
        runner._resolve_component_path("m1")
        stopped = False
    except RuntimeError:
        stopped = True
    problems = []
    if not inside(repo, runner.project_root):
        problems.append(f"component {raw!r}: the root moved outside ({runner.project_root})")
    if allowed and stopped:
        problems.append(f"component {raw!r}: inside the root, refused")
    if not allowed and not stopped:
        problems.append(f"component {raw!r}: outside the root, not refused")
    return problems


def check(top: Path) -> list:
    repo, outside = build(top)
    problems = []
    for raw in raws(outside):
        problems += case_file(repo, raw) + case_mechanism(repo, raw) + case_component(repo, raw)
    for pattern in patterns(outside):
        problems += case_glob(repo, pattern)
    return problems


# --- regressions ----------------------------------------------------------------------

@contextlib.contextmanager
def _mutant(name: str):
    if name == "unguarded_glob":
        real = V.safe_glob
        V.safe_glob = lambda root, pattern: sorted(
            Path(m) for m in glob.glob(str(root / pattern), recursive=True))
        try:
            yield
        finally:
            V.safe_glob = real
    elif name == "unguarded_resolve":
        real = V.safe_resolve_path
        V.safe_resolve_path = lambda root, p: (root / p).resolve()
        try:
            yield
        finally:
            V.safe_resolve_path = real
    else:  # unguarded_component: the root joined and resolved, unchecked
        real = R.Runner._resolve_component_path

        def joined(self, model_id):
            model = self.client.get_model(model_id)
            comp = next(c for c in model["components"] if c["id"] == self.component_id)
            self.project_root = (self.project_root / comp["path"].strip().strip("/")).resolve()
        R.Runner._resolve_component_path = joined
        try:
            yield
        finally:
            R.Runner._resolve_component_path = real


MUTANTS = ("unguarded_glob", "unguarded_resolve", "unguarded_component")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="repo-containment-") as top:
        problems = check(Path(top))
    caught = 0
    for name in MUTANTS:
        with _mutant(name), tempfile.TemporaryDirectory(prefix="repo-containment-") as top:
            found = check(Path(top))
        if found:
            caught += 1
        else:
            problems.append(f"regression {name} was not caught")
    n = len(raws(Path("/x"))) * 3 + len(patterns(Path("/x")))
    print(f"repository containment: {n} cases on a real tree, {caught}/{len(MUTANTS)} "
          f"regressions caught, {len(problems)} problems")
    for p in problems[:40]:
        print("  " + p)
    if not problems:
        print("EVERY READ STAYS IN THE REPOSITORY")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
