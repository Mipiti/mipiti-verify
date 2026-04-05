#!/usr/bin/env python3
"""Regenerate dependency lockfiles with SHA-256 hashes.

Run after changing dependencies in pyproject.toml:
    python lock-deps.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def run(args: list[str]) -> None:
    subprocess.check_call([sys.executable, "-m", "uv", "pip", "compile", *args], cwd=ROOT)


def strip_self_reference(path: Path) -> None:
    """Remove the mipiti-verify self-referencing file:// line from lockfile."""
    lines = path.read_text().splitlines(keepends=True)
    filtered = []
    skip_next_via = False
    for line in lines:
        if line.startswith("# WARNING") and "hashed" in line:
            skip_next_via = True
            continue
        if line.startswith("# Consider using"):
            continue
        if line.startswith("mipiti-verify"):
            skip_next_via = True
            continue
        if skip_next_via and line.strip().startswith("# via"):
            skip_next_via = False
            continue
        skip_next_via = False
        filtered.append(line)
    path.write_text("".join(filtered))


def main() -> None:
    # Target 3.12 (our minimum CI/Docker version) so transitive deps
    # like typing_extensions are included even when running on 3.13+.
    common = ["--generate-hashes", "--strip-extras", "--python-version=3.12"]

    print("Compiling requirements.lock ...")
    run([*common, "-o", "requirements.lock", "pyproject.toml"])

    print("Compiling requirements-all.lock ...")
    run([*common, "--extra=all", "-o", "requirements-all.lock", "pyproject.toml"])
    strip_self_reference(ROOT / "requirements-all.lock")

    print("Done. Review and commit requirements.lock and requirements-all.lock.")


if __name__ == "__main__":
    main()
