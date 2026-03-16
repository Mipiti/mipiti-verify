"""File-based verifiers: file_exists, file_hash, pattern_matches, pattern_absent, no_plaintext_secret."""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import (
    PathTraversalError,
    RegexTimeoutError,
    VerifierResult,
    register,
    safe_read_file,
    safe_regex_search,
    safe_resolve_path,
)


@register("file_exists")
class FileExistsVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            resolved = safe_resolve_path(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if resolved.is_file():
            return VerifierResult(passed=True, details=f"File exists: {params['file']}")
        return VerifierResult(passed=False, details=f"File not found: {params['file']}")


@register("file_hash")
class FileHashVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            resolved = safe_resolve_path(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if not resolved.is_file():
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        algorithm = params.get("algorithm", "sha256")
        expected = params["expected_hash"]

        try:
            h = hashlib.new(algorithm)
            h.update(resolved.read_bytes())
            actual = h.hexdigest()
        except ValueError:
            return VerifierResult(passed=False, details=f"Unsupported hash algorithm: {algorithm}")

        if actual == expected:
            return VerifierResult(passed=True, details=f"Hash matches ({algorithm})")
        return VerifierResult(passed=False, details=f"Hash mismatch: expected {expected[:16]}... got {actual[:16]}...")


@register("pattern_matches")
class PatternMatchesVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        pattern = params["pattern"]
        try:
            match = safe_regex_search(pattern, content)
        except RegexTimeoutError as e:
            return VerifierResult(passed=False, details=str(e))

        if match:
            return VerifierResult(passed=True, details=f"Pattern found: {pattern}")
        return VerifierResult(passed=False, details=f"Pattern not found: {pattern}")


@register("pattern_absent")
class PatternAbsentVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        pattern = params["pattern"]
        try:
            match = safe_regex_search(pattern, content)
        except RegexTimeoutError as e:
            return VerifierResult(passed=False, details=str(e))

        if match:
            return VerifierResult(passed=False, details=f"Pattern found (should be absent): {pattern}")
        return VerifierResult(passed=True, details=f"Pattern correctly absent: {pattern}")


@register("no_plaintext_secret")
class NoPlaintextSecretVerifier:
    def verify(self, params: dict, project_root: Path) -> VerifierResult:
        try:
            content = safe_read_file(project_root, params["file"])
        except PathTraversalError as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"File not found: {params['file']}")

        patterns = params.get("patterns", [])
        found = []
        for pattern in patterns:
            try:
                if safe_regex_search(pattern, content):
                    found.append(pattern)
            except RegexTimeoutError:
                found.append(f"{pattern} (timed out)")

        if found:
            return VerifierResult(passed=False, details=f"Plaintext secrets found: {', '.join(found)}")
        return VerifierResult(passed=True, details=f"No plaintext secrets found ({len(patterns)} patterns checked)")
