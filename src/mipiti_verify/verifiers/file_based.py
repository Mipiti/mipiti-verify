"""File-based verifiers: file_exists, file_hash, pattern_matches, pattern_absent, no_plaintext_secret."""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import (
    PathTraversalError,
    RegexTimeoutError,
    VerifierResult,
    register,
    resolve_content,
    safe_regex_search,
    safe_resolve_path,
)


def _extract_scope(content: str, params: dict) -> str:
    """Extract the section of content between scope_start and scope_end patterns.

    Returns the full content if no scope params are provided.

    Both ``scope_start`` and ``scope_end`` come from user-supplied assertion
    JSON, so they go through the same ReDoS-protected helper as the main
    pattern (RE2 linear-time guarantee + threading timeout). The
    ``(?m)`` inline modifier is prepended so anchors like ``^`` and ``$``
    match line boundaries inside the content, matching the behaviour the
    helper had when it used ``re.MULTILINE``.

    Raises ``RegexTimeoutError`` if either scope regex exceeds the time
    limit. Callers should catch this and return a fail-closed
    ``VerifierResult`` — a scope that can't be evaluated must not silently
    extend to the wrong region (which would let an attacker craft a
    ReDoS-inducing scope_end to evade pattern_present or pattern_absent
    checks by widening / narrowing the search region).
    """
    scope_start = params.get("scope_start")
    if not scope_start:
        return content

    start_match = safe_regex_search(f"(?m){scope_start}", content)
    if not start_match:
        return ""  # scope_start not found — nothing to search

    start_pos = start_match.start()
    scope_end = params.get("scope_end")
    if scope_end:
        end_match = safe_regex_search(f"(?m){scope_end}", content[start_match.end():])
        end_pos = start_match.end() + end_match.start() if end_match else len(content)
    else:
        end_pos = len(content)

    return content[start_pos:end_pos]


def _apply_inline_regex_flags(pattern: str, params: dict) -> str:
    """Prepend RE2 inline flag modifiers to ``pattern`` based on assertion params.

    google-re2 does not accept Python ``re`` flag integers; flags must be
    embedded in the pattern itself using the ``(?ims)`` syntax. We accept
    boolean-ish strings ("true"/"1") for ``multiline`` and ``dotall`` from
    assertion JSON and translate them to ``(?m)``/``(?s)`` modifiers.
    """
    inline = ""
    if str(params.get("multiline", "")).lower() in ("true", "1"):
        inline += "m"
    if str(params.get("dotall", "")).lower() in ("true", "1"):
        inline += "s"
    if inline:
        return f"(?{inline}){pattern}"
    return pattern


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
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        try:
            content = _extract_scope(content, params)
            if not content and params.get("scope_start"):
                return VerifierResult(passed=False, details=f"Scope pattern not found: {params['scope_start']}")
            pattern = _apply_inline_regex_flags(params["pattern"], params)
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
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

        try:
            content = _extract_scope(content, params)
            if not content and params.get("scope_start"):
                return VerifierResult(passed=False, details=f"Scope pattern not found: {params['scope_start']}")
            pattern = _apply_inline_regex_flags(params["pattern"], params)
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
            content, source = resolve_content(params, project_root)
        except (PathTraversalError, ValueError) as e:
            return VerifierResult(passed=False, details=str(e))
        if content is None:
            return VerifierResult(passed=False, details=f"Source not found: {source}")

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
