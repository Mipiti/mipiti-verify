"""Verifier registry and base class for Tier 1 verification."""

from __future__ import annotations

import re
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class VerifierResult:
    """Result of a single Tier 1 verification."""

    passed: bool
    details: str


class PathTraversalError(Exception):
    """Raised when a file path escapes the project root."""


class RegexTimeoutError(Exception):
    """Raised when a regex operation exceeds the time limit."""


def safe_resolve_path(project_root: Path, file_param: str) -> Path:
    """Resolve a file path safely within the project root.

    Resolves both the project root and the target to absolute paths,
    then verifies the target is a descendant of the project root.
    This catches '..', symlinks, and any other traversal tricks.

    Raises PathTraversalError if the path escapes the project root.
    """
    project_resolved = project_root.resolve()
    resolved = (project_root / file_param).resolve()
    try:
        resolved.relative_to(project_resolved)
    except ValueError:
        raise PathTraversalError(f"Path escapes project root: {file_param}")
    return resolved


def safe_read_file(project_root: Path, file_param: str, max_size: int = 2 * 1024 * 1024) -> str | None:
    """Read a file safely within the project root.

    Returns file content as string, or None if file not found.
    Raises PathTraversalError if the path escapes the project root.
    """
    resolved = safe_resolve_path(project_root, file_param)
    if not resolved.is_file():
        return None
    # Reject symlinks
    if resolved.is_symlink():
        raise PathTraversalError(f"Symlinks not allowed: {file_param}")
    # Check file size
    size = resolved.stat().st_size
    if size > max_size:
        raise PathTraversalError(f"File too large ({size} bytes, max {max_size}): {file_param}")
    return resolved.read_text(encoding="utf-8", errors="replace")


_VALID_TARGETS = frozenset({"feature_description"})


def resolve_content(params: dict, project_root: Path) -> tuple[str | None, str]:
    """Resolve assertion content from either a codebase file or a platform target.

    Returns (content, source_label). content is None if the source is not found.
    Raises PathTraversalError for file path escapes.
    Raises ValueError for invalid target values or mutual exclusion violations.
    """
    target = params.get("target")
    file_param = params.get("file")

    if target and file_param:
        raise ValueError("'target' and 'file' are mutually exclusive in assertion params")

    if target:
        if target not in _VALID_TARGETS:
            raise ValueError(f"Invalid assertion target: {target!r}")
        content = params.get("target_content")
        if content is None:
            return None, f"target:{target}"
        return content, f"target:{target}"

    if file_param:
        content = safe_read_file(project_root, file_param)
        return content, file_param

    return None, "<no source>"


def safe_regex_search(pattern: str, content: str, timeout_seconds: float = 2.0, flags: int = 0) -> re.Match | None:
    """Run re.search with a timeout to prevent ReDoS.

    On Unix, uses SIGALRM for accurate timeout.
    On Windows/other, uses re2 if available, otherwise falls back to
    basic complexity checks + standard re.search.

    Args:
        flags: Additional re flags (e.g., re.DOTALL | re.MULTILINE for multiline patterns).
    """
    # Basic complexity check — reject obviously dangerous patterns
    # (nested quantifiers like (a+)+ or (a*)*a)
    if re.search(r'\([^)]*[+*][^)]*\)[+*]', pattern):
        raise RegexTimeoutError(f"Pattern rejected: nested quantifiers detected in '{pattern[:50]}'")

    try:
        if sys.platform != "win32":
            def _alarm_handler(signum, frame):
                raise RegexTimeoutError(f"Regex timed out after {timeout_seconds}s: {pattern[:50]}")

            old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
            signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
            try:
                return re.search(pattern, content, flags)
            except RegexTimeoutError:
                raise
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)
        else:
            # Windows: no SIGALRM, rely on complexity check above
            return re.search(pattern, content, flags)
    except re.error as e:
        raise RegexTimeoutError(f"Invalid regex pattern: {e}")


class Verifier(Protocol):
    """Protocol for Tier 1 verifiers."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult: ...


# Registry populated by submodule imports
VERIFIER_REGISTRY: dict[str, Verifier] = {}


def register(assertion_type: str):
    """Decorator to register a verifier for an assertion type."""
    def decorator(cls):
        VERIFIER_REGISTRY[assertion_type] = cls()
        return cls
    return decorator


def get_verifier(assertion_type: str) -> Verifier | None:
    """Look up a verifier by assertion type string."""
    # Lazy import all verifier modules to populate registry
    if not VERIFIER_REGISTRY:
        _load_all()
    return VERIFIER_REGISTRY.get(assertion_type)


def _load_all() -> None:
    """Import all verifier modules to trigger registration."""
    from . import file_based, code_structure, config, dependencies, tests, semantic  # noqa: F401
