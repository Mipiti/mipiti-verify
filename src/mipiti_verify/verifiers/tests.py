"""Test verifiers: test_exists, test_passes."""

from __future__ import annotations

import glob as glob_mod
import subprocess
from pathlib import Path

from . import VerifierResult, register


@register("test_exists")
class TestExistsVerifier:
    """Check that test files matching a pattern exist."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        pattern = params["pattern"]
        matches = glob_mod.glob(str(project_root / pattern), recursive=True)
        if matches:
            return VerifierResult(
                passed=True,
                details=f"Found {len(matches)} test file(s) matching '{pattern}'",
            )
        return VerifierResult(passed=False, details=f"No test files matching '{pattern}'")


@register("test_passes")
class TestPassesVerifier:
    """Run tests matching a pattern and check they pass."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        pattern = params["pattern"]
        runner = _detect_runner(project_root)

        if runner == "pytest":
            cmd = ["python", "-m", "pytest", "-x", "-k", pattern, "--tb=short", "-q"]
        elif runner == "npm":
            cmd = ["npm", "test", "--", "--testPathPattern", pattern]
        elif runner == "cargo":
            cmd = ["cargo", "test", pattern, "--", "--test-threads=1"]
        else:
            return VerifierResult(passed=False, details=f"Could not detect test runner in {project_root}")

        try:
            result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                return VerifierResult(passed=True, details=f"Tests passed ({runner}: {pattern})")
            output = (result.stdout + result.stderr)[-500:]
            return VerifierResult(passed=False, details=f"Tests failed ({runner}: {pattern}): {output}")
        except subprocess.TimeoutExpired:
            return VerifierResult(passed=False, details=f"Tests timed out ({runner}: {pattern})")
        except FileNotFoundError:
            return VerifierResult(passed=False, details=f"Test runner '{runner}' not found")
        except Exception as e:
            return VerifierResult(passed=False, details=f"Test runner error: {e}")


def _detect_runner(project_root: Path) -> str:
    """Detect the test runner from project structure."""
    if (project_root / "pytest.ini").exists() or (project_root / "pyproject.toml").exists():
        return "pytest"
    if (project_root / "setup.py").exists() or (project_root / "setup.cfg").exists():
        return "pytest"
    if (project_root / "package.json").exists():
        return "npm"
    if (project_root / "Cargo.toml").exists():
        return "cargo"
    # Default to pytest
    return "pytest"
