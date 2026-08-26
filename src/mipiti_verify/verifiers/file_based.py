"""File-based verifiers: file_exists, file_hash, pattern_matches, pattern_absent, no_plaintext_secret."""

from __future__ import annotations

import hashlib
from pathlib import Path

import re2

from . import (
    _RE2_OPTS,
    PathTraversalError,
    RegexTimeoutError,
    VerifierResult,
    register,
    resolve_content,
    resolve_file_content,
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


# Short non-empty subjects used to rule out a purely positional regex
# during the vacuity check. ``possiblematchrange`` collapses to an
# empty range both for a regex nothing can satisfy and for one that
# only asserts a position (``\b``, for instance), so the collapse on
# its own does not separate the two. The probes cover a leading word
# boundary, non-word characters around a digit and an underscore, and
# an interior non-boundary; a regex that matches none of them and not
# the empty subject either is one no content can satisfy.
_VACUITY_PROBES: tuple[str, ...] = ("a", "0 _", "ab _ 12")

# Upper bound handed to ``possiblematchrange`` — long enough that a
# real pattern yields a non-empty range, short enough to stay cheap.
_VACUITY_RANGE_MAXLEN = 10


def _reject_degenerate_pattern(pattern: str, *, absent: bool) -> str | None:
    """Reject a regex that no subject is able to refute.

    A pattern assertion is evidence only if the subject can falsify
    it. Two regex shapes remove that possibility, one per direction:

    - ``pattern_matches`` with a regex that the empty subject already
      satisfies. Tier 1 then reports a match against any content
      whatsoever, so a pass states nothing about the subject.
    - ``pattern_absent`` with a regex that no subject can satisfy. Its
      absence is a property of the regex rather than of the content.

    Either shape mints a claim for free, which weighs most when the
    subject is the feature description: what it mints reads as a
    verified statement about the design.

    ``pattern`` must already carry the assertion's inline flag
    modifiers, so that the regex judged here is exactly the one tier 1
    evaluates.

    Returns the rejection details, or ``None`` to let the assertion
    proceed. Every inconclusive signal returns ``None``: rejecting a
    genuine assertion is the worse error, so only an unambiguous
    reading is a rejection. A pattern RE2 cannot compile returns
    ``None`` as well — that case stays with the caller's existing
    invalid-pattern path, which reports it in its own terms.
    """
    try:
        matches_empty = re2.search(pattern, "", options=_RE2_OPTS) is not None
    except Exception:
        return None

    if not absent:
        if matches_empty:
            return (
                "Unfalsifiable pattern - matches any content, "
                f"including empty: {pattern}"
            )
        return None

    # The dual, for ``pattern_absent``. A regex the empty subject
    # satisfies is plainly not impossible, so it is ruled out first;
    # what remains is separated by the collapsed possible-match range
    # plus the probes above.
    if matches_empty:
        return None
    try:
        low, high = re2.compile(pattern, options=_RE2_OPTS).possiblematchrange(
            _VACUITY_RANGE_MAXLEN
        )
    except Exception:
        return None
    if low or high:
        return None
    try:
        for probe in _VACUITY_PROBES:
            if re2.search(pattern, probe, options=_RE2_OPTS) is not None:
                return None
    except Exception:
        return None
    return f"Vacuous pattern - cannot match any content: {pattern}"


def _reject_unwitnessed_match(match: object, pattern: str) -> str | None:
    r"""Reject a tier-1 match that consumed no byte of the subject.

    Kept apart from ``_reject_degenerate_pattern`` because it reads the
    match rather than the regex, and applied in one direction only:
    where a match is what mints a pass. A zero-width match (``\b``
    against prose, say) shows that a position exists, not that any text
    the assertion names is there, so nothing in the subject took part
    in its own proof. ``pattern_absent`` needs no equivalent — a
    zero-width match there yields a failure, and a failure mints
    nothing.

    What this catches is the regex whose every match is zero-width yet
    which the empty subject still refuses; anything the empty subject
    accepts is already handled by ``_reject_degenerate_pattern``.

    Returns the rejection details, or ``None``. A match object that
    reports no span is inconclusive and proceeds.
    """
    try:
        zero_width = match.end() == match.start()
    except Exception:
        return None
    if zero_width:
        return (
            "Unwitnessed pattern - matched zero characters of the "
            f"content: {pattern}"
        )
    return None


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
            degenerate = _reject_degenerate_pattern(pattern, absent=False)
            if degenerate:
                return VerifierResult(passed=False, details=degenerate)
            match = safe_regex_search(pattern, content)
        except RegexTimeoutError as e:
            return VerifierResult(passed=False, details=str(e))

        if match:
            unwitnessed = _reject_unwitnessed_match(match, pattern)
            if unwitnessed:
                return VerifierResult(passed=False, details=unwitnessed)
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
            degenerate = _reject_degenerate_pattern(pattern, absent=True)
            if degenerate:
                return VerifierResult(passed=False, details=degenerate)
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
            content, source = resolve_file_content(params, project_root)
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
