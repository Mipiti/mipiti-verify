"""Verifier registry and base class for Tier 1 verification."""

from __future__ import annotations

import importlib.util
import os
import re2
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Protocol


@dataclass
class VerifierResult:
    """Result of a single Tier 1 verification.

    ``provenance`` names the class of signing identity the evidence carried,
    for the verifiers whose evidence is a signed statement rather than a file
    in the tree (``ci_oidc`` / ``customer_key`` / ``unsigned``). Empty for
    every other verifier. It travels on the result record as data so the
    platform and an auditor can weigh it without parsing prose.
    """

    passed: bool
    details: str
    provenance: str = ""
    # Facts a signed-evidence verifier can establish about the evidence
    # beyond pass/fail, each unknown unless the evidence carries it: the
    # hash of the definition the evidence binds (``sha256:<hex>``), whether
    # the recorded run reached the assertion's named mechanism, and whether
    # the test fails once that mechanism is disabled. ``None`` is "unknown"
    # and is never reported as either outcome.
    evidence_hash: str = ""
    reached: bool | None = None
    depends: bool | None = None
    # What qualifies an unknown ``reached``: ``"suite"`` when the only
    # coverage on record for the test is a whole-suite run (a reach record
    # with ``reach_scope = "suite"``), which says what the suite executed,
    # not what the test did. Empty otherwise. Not a fact: never reported
    # as an outcome.
    reach_scope: str = ""
    # Whether the mechanism an assertion names resolves to a definition in
    # the checkout. ``None`` when the assertion names no mechanism (the
    # question does not arise); ``False`` when it names one the checkout
    # does not define, so a reader can demote a claim about a mechanism
    # that cannot be located rather than carry it as unknown indefinitely.
    mechanism_found: bool | None = None
    # Counted facts a verifier established beside the verdict (the sink
    # engine's per-form, per-file and per-assumption counts). What the
    # details state in prose, as data a reader can index.
    #
    # Two of them travel further than the rest. How many sites of the
    # declared sinks a run examined, and how many of those stand on a
    # reviewed exception, are what separate a claim about every site in a
    # scope from a claim about a scope nothing was found in, so they are
    # forwarded as fields of the submitted result row rather than being
    # left for a reader to parse out of ``details``. Only a run that
    # enumerated a scope states them; every other verifier leaves them
    # absent, and absent is not zero -- it is a question this run did not
    # answer.
    facts: dict = field(default_factory=dict)


class PathTraversalError(Exception):
    """Raised when a file path escapes the project root."""


class RegexTimeoutError(Exception):
    """Raised when a regex operation exceeds the time limit."""


# Shared RE2 compile options — silence google-re2's C++ ABSL logger so that
# patterns containing RE2-rejected constructs (lookahead, lookbehind,
# backreferences) do not emit a red ``E0000 ... re2.cc:... Error parsing ...
# invalid perl operator: (?!`` line to stderr before our Python exception
# handler sees the re2.error. The parse error still propagates normally and
# is surfaced via RegexTimeoutError with a clean details string; log_errors
# only controls the noisy ABSL pre-exception log.
_RE2_OPTS = re2.Options()
_RE2_OPTS.log_errors = False


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


# Bounds on a scope enumeration. A check that must read EVERY file a scope
# names to certify anything about the scope cannot silently drop one, so a
# file over the size bound and a scope over the count bound are refusals,
# never omissions.
SCOPE_MAX_FILES = 5000
SCOPE_MAX_FILE_SIZE = 2 * 1024 * 1024
# The file count and each file's size bound one dimension each; their
# product is what a run actually holds, since every file in scope is read
# and parsed and every parse tree is live at once while the sink set is
# closed over the whole scope. Without a bound on the total, a scope well
# inside both other caps exhausts the machine and the job dies with no
# verdict at all -- the one outcome a check that must refuse rather than
# sample cannot produce.
SCOPE_MAX_TOTAL_SIZE = 16 * 1024 * 1024

_GLOB_CHARS = ("*", "?", "[")


def _scope_entry_is_safe(entry: str) -> bool:
    """A scope entry is repository-relative and never climbs: no absolute
    path, no drive letter, no ``..`` segment."""
    text = str(entry or "").replace("\\", "/")
    if not text or text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        return False
    return all(segment != ".." for segment in text.split("/"))


def _glob_search_root(entry: str) -> str:
    """The leading segments of a pattern that carry no glob character.

    This is the directory the pattern search starts from, and so the region
    whose contents decide what the entry enumerates.
    """
    kept: list[str] = []
    for segment in entry.split("/"):
        if any(ch in segment for ch in _GLOB_CHARS):
            break
        kept.append(segment)
    return "/".join(kept) or "."


def _refuse_link_on_the_entry(root: Path, entry: str, raw) -> None:
    """Refuse when the entry's OWN path is, or passes through, a link.

    ``_refuse_links_under`` walks the region an entry searches and refuses a
    link found inside it. It cannot see a link at the TOP of the entry, because
    the base it is handed has already been resolved — and a resolved link is
    indistinguishable from a real directory by then. So an entry naming a link
    enumerates the target's tree while the scope still reads as the name that
    was declared, which is the one thing a declared scope has to mean.

    Checked segment by segment from the project root down, so a link anywhere
    along the entry is refused and not only one at its end.
    """
    here = root
    for segment in entry.split("/"):
        if not segment or segment == ".":
            continue
        here = here / segment
        if here.is_symlink():
            try:
                where = here.relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - built from root downward
                where = segment
            raise ValueError(
                f"Scope entry {raw!r} names a link ({where}); a link is not read "
                f"as content, so name the target's own path"
            )
        if not here.exists():
            return


def _refuse_links_under(base: Path, root: Path, raw) -> None:
    """Refuse when the region a scope entry searches holds any link.

    A pattern walk does not descend through a linked directory, and a
    linked file is content the tree does not own under that name, so a link
    in the region means the enumeration is not the set the entry names.
    The refusal is unconditional: whether the link would have matched is
    not knowable from the pattern alone, and a guess in that direction is
    an omission with nothing to report it.

    This covers links INSIDE the region. A link at the top of the entry is
    ``_refuse_link_on_the_entry``'s job, and has to be asked first: the base
    handed here is already resolved.
    """
    if not base.exists() or not base.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        here = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            path = here / name
            if not path.is_symlink():
                continue
            try:
                path.resolve().relative_to(root)
            except (ValueError, OSError):
                raise PathTraversalError(
                    f"Scope entry follows a link out of the project root: {raw!r}")
            try:
                where = path.relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - base is inside root
                where = name
            raise ValueError(
                f"Scope entry {raw!r} searches a region holding a link ({where}); "
                f"a link is not read as content, so name the target's own path"
            )


def resolve_scope_files(
    project_root: Path,
    entries: list,
    *,
    max_files: int = SCOPE_MAX_FILES,
    max_size: int = SCOPE_MAX_FILE_SIZE,
    max_total_size: int = SCOPE_MAX_TOTAL_SIZE,
) -> list[Path]:
    """Every regular file inside ``project_root`` that a list of scope
    entries names, sorted and de-duplicated, each safe to read.

    An entry is a repository-relative glob (``**`` recurses), a directory
    (walked recursively) or a single file. An entry that is absolute or
    carries a ``..`` segment, and a match that resolves outside the root,
    raise :class:`PathTraversalError`. A file above ``max_size``, a scope
    above ``max_files``, and a scope whose files come to more than
    ``max_total_size`` together all raise :class:`ValueError`: the scope is
    too broad to read soundly and must be narrowed, never sampled.

    A link anywhere in the region an entry searches is a refusal, whether
    it is matched or not. Enumeration through links is not reliable -- a
    pattern walk does not descend through a linked directory at all, and a
    linked file names content under a path the tree does not own -- so a
    link found in the region would otherwise leave the enumeration short
    of what the entry names, with nothing to say so. The refusal names the
    link; the scope names the target's own path instead.
    """
    root = project_root.resolve()
    out: dict[Path, None] = {}
    total = 0
    for raw in entries:
        entry = str(raw or "").replace("\\", "/").strip()
        if not _scope_entry_is_safe(entry):
            raise PathTraversalError(f"Scope entry escapes or leaves the project root: {raw!r}")
        entry = entry.rstrip("/") or "."
        if any(ch in entry for ch in _GLOB_CHARS):
            # The entry's own leading path first: resolving it would turn a
            # link into a directory nothing downstream can tell apart.
            _refuse_link_on_the_entry(project_root, _glob_search_root(entry), raw)
            _refuse_links_under(project_root.joinpath(_glob_search_root(entry)), root, raw)
            candidates = project_root.glob(entry)
        else:
            _refuse_link_on_the_entry(project_root, entry, raw)
            base = safe_resolve_path(project_root, entry)
            if base.is_dir():
                _refuse_links_under(base, root, raw)
                candidates = base.rglob("*")
            else:
                candidates = iter((base,))
        for p in candidates:
            if not p.is_file():
                continue
            resolved = p.resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                raise PathTraversalError(f"Scope entry escapes project root: {raw!r}")
            size = resolved.stat().st_size
            if size > max_size:
                raise ValueError(
                    f"File in scope too large to read: {resolved.relative_to(root).as_posix()} "
                    f"(> {max_size} bytes); narrow the scope"
                )
            if resolved not in out:
                total += size
            out[resolved] = None
            if len(out) > max_files:
                raise ValueError(
                    f"Scope names more than {max_files} files; narrow it"
                )
            if total > max_total_size:
                raise ValueError(
                    f"Scope names more than {max_total_size} bytes of source "
                    f"({len(out)} file(s) so far); narrow it"
                )
    return sorted(out)


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


def resolve_file_content(params: dict, project_root: Path) -> tuple[str | None, str]:
    """Resolve assertion content from a repository file, refusing a target.

    For verifiers whose subject is a repository artifact by definition
    (RTL sources, for example): platform-held content is not a subject
    they can be evaluated against, so a ``target`` param is refused
    rather than honoured.

    A type may accept a target only where both of these hold:

    1. Its tier-1 predicate is a caller-supplied regex evaluated over
       arbitrary text, drawing on no structure of a source language.
    2. Its tier-2 criterion and its schema description are stated over
       the matched text itself, not over the role the scanned artifact
       plays in the running system.

    ``pattern_matches`` and ``pattern_absent`` are the two types that
    meet both, and they read through ``resolve_content``. A type that
    fails either half means something different of a design
    specification than it does of a file — a symbol found in prose
    describes the prose, not anything the running system does — so it
    resolves through here and its subject stays the file.

    Returns (content, source_label). content is None if the file is not found.
    Raises PathTraversalError for file path escapes.
    Raises ValueError when a target is supplied.
    """
    if params.get("target"):
        raise ValueError(
            "This assertion type verifies a repository file and does not accept a 'target'"
        )
    file_param = params.get("file")
    if file_param:
        content = safe_read_file(project_root, file_param)
        return content, file_param
    return None, "<no source>"


def safe_regex_search(pattern: str, content: str, timeout_seconds: float = 2.0) -> object | None:
    """Run regex search using RE2 with a cross-platform threading timeout.

    Two layers of protection:
    - RE2 prevents ReDoS by construction (linear-time, no backtracking)
    - Threading timeout prevents slow linear scans on large inputs

    Patterns using backreferences, lookahead, or lookbehind are rejected
    at parse time (these are the constructs that enable ReDoS).

    Returns the google-re2 match object on success (truthy), or None.
    Callers may use truthiness or call ``.group(N)`` for capture groups.

    To pass flags, embed them as inline modifiers in the pattern itself
    using google-re2's ``(?ims)`` syntax (e.g. ``(?m)^foo`` for multiline).
    google-re2 does not accept Python ``re`` flag integers.

    Args:
        timeout_seconds: Maximum wall-clock time for the search (default 2s).
    """
    import threading

    result_box: list = []
    error_box: list = []

    def _run():
        try:
            result_box.append(re2.search(pattern, content, options=_RE2_OPTS))
        except re2.error as e:
            error_box.append(e)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        raise RegexTimeoutError(f"Regex timed out after {timeout_seconds}s: {pattern[:50]}")

    if error_box:
        raise RegexTimeoutError(f"Invalid regex pattern: {error_box[0]}")

    return result_box[0] if result_box else None


class Verifier(Protocol):
    """Protocol for Tier 1 verifiers."""

    def verify(self, params: dict, project_root: Path) -> VerifierResult: ...


# Registry populated by submodule imports
VERIFIER_REGISTRY: dict[str, Verifier] = {}

# Whether every verifier module has been imported. The registry being
# non-empty does NOT answer that question: importing any single verifier
# module -- directly, or as a side effect of a module-level import
# elsewhere in the package -- registers its own types and leaves the rest
# absent. A lookup that used emptiness as the signal would then report
# "no verifier" for every type whose module had not happened to load, and
# a run would submit a skipped result for evidence that verifies fine.
# The completion of the import pass is its own fact, recorded here.
_ALL_LOADED = False

# What a type's evidence IS, stated once per registered type as the FACT the
# verdict reports, never inferred from the type's name, a param or a path.
#
# ``presence``                  a named construct, configuration value,
#                               dependency, file or pattern occurrence exists
#                               in the tree. Existence, not behaviour: a test
#                               FILE existing is presence.
# ``under_approximating_scan``  a syntactic scan over a subject with no
#                               false-positive guarantee. A clean scan proves
#                               the absence of the syntactic form only.
# ``existential_witness``       a signed statement that a named execution ran
#                               and passed at this commit. It proves the path
#                               it drove, nothing about any other path.
# ``sound_over_approximation``  every site in a declared scope that could
#                               violate the property was enumerated and each
#                               is a declared safe form or a reviewed
#                               exception; sound modulo the declared sink
#                               list.
# ``by_construction``           the sink accepts only a declared boundary
#                               type whose every construction site is
#                               default-denied.
#
# The vocabulary is the assertion catalogue's; the tuple below is the copy
# this package carries for when the catalogue is not installed, and the
# formal check ``formal/check_types.py`` (T7) holds the two equal. Every
# registered type declares exactly one class at registration; T5 refuses a
# registration that does not.
SOUNDNESS_PRESENCE = "presence"
SOUNDNESS_SCAN = "under_approximating_scan"
SOUNDNESS_WITNESS = "existential_witness"
SOUNDNESS_OVER_APPROXIMATION = "sound_over_approximation"
SOUNDNESS_BY_CONSTRUCTION = "by_construction"

_FALLBACK_EVIDENCE_CLASSES: tuple[str, ...] = (
    SOUNDNESS_PRESENCE,
    SOUNDNESS_SCAN,
    SOUNDNESS_WITNESS,
    SOUNDNESS_OVER_APPROXIMATION,
    SOUNDNESS_BY_CONSTRUCTION,
)

# Rank, weakest first. A class's rank is data other readers fold over; the
# registry itself only checks membership.
SOUNDNESS_RANK: dict[str, int] = {
    name: rank for rank, name in enumerate(_FALLBACK_EVIDENCE_CLASSES)
}

# The classes whose verdict is a statement over EVERY site of a scope.
SOUND_CLASSES = frozenset({SOUNDNESS_OVER_APPROXIMATION, SOUNDNESS_BY_CONSTRUCTION})

# Older names, kept for readers of the registry: ``presence`` is the same
# class; ``behavioral`` was the class of a signed execution witness.
EVIDENCE_PRESENCE = SOUNDNESS_PRESENCE
EVIDENCE_BEHAVIORAL = SOUNDNESS_WITNESS


@lru_cache(maxsize=None)
def catalogue_soundness_classes() -> tuple[str, ...] | None:
    """The assertion catalogue's soundness vocabulary, or ``None``.

    Read from the ``assertion_types`` module the installed catalogue
    package ships, loaded by file path so that reading a tuple of names
    does not import the package's entry point (a running server). ``None``
    when the catalogue is not installed or predates the vocabulary.
    """
    try:
        spec = importlib.util.find_spec("mipiti_mcp")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.submodule_search_locations:
        return None
    for location in spec.submodule_search_locations:
        path = Path(location) / "assertion_types.py"
        if not path.is_file():
            continue
        try:
            module_spec = importlib.util.spec_from_file_location("_mipiti_assertion_catalogue", path)
            module = importlib.util.module_from_spec(module_spec)
            sys.modules[module_spec.name] = module
            module_spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001 - a catalogue that cannot load is one that is not installed
            return None
        classes = getattr(module, "SOUNDNESS_CLASSES", None)
        if isinstance(classes, (tuple, list)) and all(isinstance(c, str) for c in classes):
            return tuple(classes)
        return None
    return None


def _vocabulary() -> frozenset:
    """The classes a registration may declare.

    The catalogue is the source of the vocabulary, and the fallback tuple is
    this package's copy of it for when the catalogue is not installed. A
    catalogue that ADDS a class is honoured; one that is missing a class this
    package already registers is not allowed to make the package unimportable,
    so the two are unioned here and held equal by the type checker (T7), which
    is where a divergence is a finding rather than a crash.
    """
    theirs = catalogue_soundness_classes() or ()
    return frozenset(_FALLBACK_EVIDENCE_CLASSES) | frozenset(theirs)


EVIDENCE_CLASSES = _vocabulary()

EVIDENCE_CLASS: dict[str, str] = {}


def evidence_class(assertion_type: str) -> str:
    """The evidence class of a registered type, or ``""`` when unregistered."""
    _load_all()
    return EVIDENCE_CLASS.get(assertion_type, "")


def register(assertion_type: str, *, soundness: str):
    """Decorator to register a verifier for an assertion type.

    ``soundness`` is the class of the fact the verifier's verdict reports,
    one of :data:`EVIDENCE_CLASSES`. It is declared here, at the one place
    the type is defined, so no reader downstream infers it from the type's
    name or its params. A registration outside the vocabulary is refused
    at import time.
    """
    if soundness not in EVIDENCE_CLASSES:
        raise ValueError(
            f"{assertion_type!r} declares evidence class {soundness!r}, not one of "
            f"{sorted(EVIDENCE_CLASSES)}"
        )

    def decorator(cls):
        VERIFIER_REGISTRY[assertion_type] = cls()
        EVIDENCE_CLASS[assertion_type] = soundness
        return cls
    return decorator


def get_verifier(assertion_type: str) -> Verifier | None:
    """Look up a verifier by assertion type string."""
    _load_all()
    return VERIFIER_REGISTRY.get(assertion_type)


def _load_all() -> None:
    """Import every verifier module, so the registry holds every type.

    Idempotent and unconditional: it runs once per process and is a no-op
    after that. It is called on every lookup rather than only when the
    registry looks empty, so a partially populated registry cannot be
    mistaken for a complete one.
    """
    global _ALL_LOADED
    if _ALL_LOADED:
        return
    from . import file_based, code_structure, config, dependencies, tests, semantic, rtl, sound  # noqa: F401
    _ALL_LOADED = True
