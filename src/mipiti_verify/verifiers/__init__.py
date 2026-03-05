"""Verifier registry and base class for Tier 1 verification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class VerifierResult:
    """Result of a single Tier 1 verification."""

    passed: bool
    details: str


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
