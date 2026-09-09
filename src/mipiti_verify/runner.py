"""Orchestrator: pull pending assertions, verify, submit results."""

from __future__ import annotations

import hashlib
import json
import os
import re
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .client import MipitiClient
from .customer_dsse_signer import (
    sign_verification_statement as sign_customer_dsse_statement,
)
from .sigstore_signer import sign_verification_statement
from .tier2 import ABSENCE_TYPES, SUBJECT_FEATURE_DESCRIPTION, SUBJECT_REPOSITORY_FILE
from .verifiers import get_verifier
from .verifiers.sound import SCOPE_TYPES
from .workspace_key_signer import WorkspaceKeySigner

console = Console(stderr=True)


# Tier-2 source-loading: types whose params carry ``pattern`` (a glob
# expression resolved against ``project_root``) rather than ``file``.
# Tier-1 globs the pattern; tier-2 mirrors the glob here so it sees
# the same matched files. Keeping this list explicit (rather than
# falling back to "if params has pattern, use it") preserves the
# defense that types map to a single, expected source-resolution
# strategy.
_PATTERN_GLOB_TYPES: frozenset[str] = frozenset({"test_exists"})

# Tier-2 source-loading: types whose subject is a SCOPE of files rather than
# one file, and whose tier-2 question is asked over the inventory the
# mechanical tier built (every site of a declared sink with each argument's
# static form) rather than over the files themselves. Tier 2 never re-scans:
# it judges whether the declared sinks are the sinks through which the
# stated property could be violated in the code the inventory shows.
_SCOPE_TYPES: frozenset[str] = SCOPE_TYPES

# What a tier-1 result forwards beside its verdict, declared once and read
# by both the verifier call and the row that is submitted, so a name on the
# wire cannot be carried by one and dropped by the other.
#
# ``_RESULT_FACTS`` are the per-evidence facts a verifier establishes about
# a run it was shown. ``_RESULT_COUNTS`` are the two numbers only a run that
# ENUMERATED a scope holds: how many sites of the declared sinks it examined,
# and how many of those stand on a reviewed exception rather than on a form
# it admitted. A reader deciding whether a claim about every site rests on an
# enumeration that actually happened needs those two as data; left inside the
# prose of ``details`` they are not a fact anyone can act on. Neither is ever
# read from an assertion's params: a count of what a run examined is a fact
# only that run holds, so a number a submitter supplied would be a claim
# about a run, dressed as its result.
_RESULT_FACTS: tuple[str, ...] = ("reached", "depends", "mechanism_found")
_RESULT_COUNTS: tuple[str, ...] = ("sites", "allowlisted")

# Tier-2 source-loading: types whose tier-2 criterion may legitimately
# be evaluated with empty SOURCE_CODE. The conservative default is the
# empty set — every type requires source-code evidence and the pre-LLM
# guard fails-closed otherwise. Add a type here only after confirming
# its tier-2 template can produce a sound YES/NO verdict from params
# alone.
_EMPTY_SOURCE_OK_TYPES: frozenset[str] = frozenset()

# Tier-2 subject resolution: which platform ``target`` values name a
# subject the tier-2 templates can frame in their own terms. An
# assertion whose content came from a target the runner has no framing
# for keeps the repository-file framing it had before subjects were
# modelled — the conservative default, not a silent re-interpretation.
_TARGET_SUBJECT_KINDS: dict[str, str] = {
    "feature_description": SUBJECT_FEATURE_DESCRIPTION,
}


def _load_attestation_source(project_root: Path) -> str:
    """Load attestation statements as tier-2 source content.

    An attested test has no file in the tree that constitutes its evidence --
    the evidence is what the CI run reported. Hand tier 2 the statements
    themselves so it judges the claim against the recorded outcome, rather than
    hitting the fail-closed empty-source guard.

    Returns "" when nothing is present; the caller's guard turns that into a
    refusal to ask the LLM about empty evidence.
    """
    import json

    blocks = []
    for statement in _verified_statements_for_commit(project_root):
        blocks.append(json.dumps(statement, indent=2, sort_keys=True))
    if not blocks:
        return ""
    return "\n\n".join(blocks)[:16000]


def _verified_statements_for_commit(project_root: Path) -> list[dict]:
    """Attestation statements that verify and name the commit under review.

    Verified here, not merely decoded. The semantic tier is told the
    mechanical tier already checked these, so handing it an envelope that
    failed -- or one for a different commit -- makes that framing false, and
    test names are free-form text that reaches the model.
    """
    from .attestation import AttestationError
    from .verifiers.tests import load_verified_statements

    try:
        statements, _, commit = load_verified_statements(project_root)
    except AttestationError:
        return []
    out = []
    for statement, _ in statements:
        attested_commit = str((statement.get("predicate") or {}).get("commit") or "")
        if commit and attested_commit == commit:
            out.append(statement)
    return out


def _yes_no_unknown(value: object) -> str:
    return "unknown" if value is None else ("yes" if value else "no")


def _load_test_attested_source(project_root: Path, params: dict[str, Any]) -> str:
    """SOURCE_CODE for a ``test_attested`` review: the closure of the claim.

    The test's definition, read from the checkout at the path the attestation
    names; the named mechanism's definition when the assertion names one;
    then a facts block stating what the mechanical tier established -- the
    definition hash match, whether the run reached the mechanism, and whether
    the test fails without it. The judge decides only what the facts leave
    open. When the attestation names no definition, the statement itself is
    handed over as before.
    """
    from .attestation import base_test_name
    from .definition_extract import MAX_DEFINITION_CHARS, extract_definition
    from .verifiers import PathTraversalError, safe_resolve_path
    from .verifiers.tests import (
        FACT_KINDS, TestAttestedVerifier, _names_test,
        definition_matches_checkout, mechanism_line_span, parse_mechanism, reach_wording,
        statement_kind,
    )

    test_name = str(params.get("test") or params.get("pattern") or "").strip()
    entry: dict | None = None
    for statement in _verified_statements_for_commit(project_root):
        if statement_kind(statement) in FACT_KINDS:
            continue
        for candidate in (statement.get("predicate") or {}).get("tests") or []:
            if _names_test(candidate, test_name):
                entry = candidate
                break
        if entry is not None:
            break

    def _read(rel: str) -> str:
        try:
            path = safe_resolve_path(project_root, rel)
        except PathTraversalError:
            return ""
        if not path.is_file():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    test_block = ""
    test_file = str((entry or {}).get("file") or "")
    if entry is not None and test_file:
        content = _read(test_file)
        if content:
            name = base_test_name(entry.get("name"))
            owner = str(entry.get("classname") or "").rpartition(".")[-1]
            block = extract_definition(content, "function", f"{owner}.{name}") if owner else None
            if block is None:
                block = extract_definition(content, "function", name)
            if block is None and entry.get("definition_scope") == "file":
                block = content[:16000]
            if block:
                test_block = f"--- Test {test_file}::{name} ---\n{block}"
    if not test_block:
        fallback = _load_attestation_source(project_root)
        if not fallback:
            return ""
        test_block = fallback

    sections = [test_block]
    mechanism = str(params.get("mechanism") or "").strip()
    mech_file, symbol = parse_mechanism(mechanism)
    if mech_file:
        # Resolved the way the reach fact is: the symbol's kind (a bare
        # name, ``Class.method``, or ``kind:name`` such as ``module:alu``)
        # in the language the file's extension names, so an HDL mechanism
        # shows the judge its definition too.
        sections.append(_mechanism_section(project_root, mech_file, symbol, _read(mech_file)))

    # The facts the mechanical tier established, restated for the judge.
    matches = definition_matches_checkout(project_root, entry) if entry else None
    reached: object = None
    depends: object = None
    reach_scope = ""
    if mech_file:
        try:
            verdict = TestAttestedVerifier().verify(params, project_root)
        except Exception:  # noqa: BLE001
            verdict = None
        if verdict is not None and verdict.passed:
            reached = verdict.reached
            depends = verdict.depends
            reach_scope = getattr(verdict, "reach_scope", "") or ""
    facts = [
        f"definition_sha256 matches attestation: {_yes_no_unknown(matches)}",
    ]
    if mech_file:
        # Whether the named mechanism resolves to a definition here at all.
        # Stated before the two facts about it, because both are unknowable
        # when it does not.
        found = mechanism_line_span(project_root, mech_file, symbol) is not None
        facts.append(f"mechanism defined in the checkout: {_yes_no_unknown(found)}")
        facts.append(f"reached mechanism: {reach_wording(reached, reach_scope)}")
        facts.append(f"fails without mechanism: {_yes_no_unknown(depends)}")
    sections.append("--- Facts ---\n" + "\n".join(facts))
    return "\n\n".join(sections)[:16000]


def _reference_sites(content: str, name: str, *, context: int = 3, limit: int = 6) -> str:
    """The lines of ``content`` that name ``name``, each with ``context``
    lines either side and a line number, at most ``limit`` sites. Empty when
    nothing names it."""
    import re as _re
    lines = content.splitlines()
    hits = [i for i, line in enumerate(lines) if _re.search(rf"\b{_re.escape(name)}\b", line)]
    if not hits:
        return ""
    out: list[str] = []
    last_end = -1
    for i in hits[:limit]:
        start, end = max(0, i - context), min(len(lines), i + context + 1)
        if start > last_end + 1 and out:
            out.append("...")
        for j in range(max(start, last_end + 1), end):
            out.append(f"{j + 1:5d}  {lines[j]}")
        last_end = end - 1
    if len(hits) > limit:
        out.append(f"... ({len(hits) - limit} more site(s) not shown)")
    return "\n".join(out)[:MAX_DEFINITION_CHARS_FOR_SITES]


MAX_DEFINITION_CHARS_FOR_SITES = 6000


def _mechanism_section(project_root: Path, mech_file: str, symbol: str, content: str) -> str:
    """The ``--- Mechanism ---`` section of a ``test_attested`` review.

    The mechanism's definition when the checkout defines it. When it does
    not (the symbol is imported, or provided by a library such as a
    framework middleware class), the sites in the file that reference it,
    since that is where the mechanism is configured and the only surface the
    judge can hold the test against. The judge is told which of the two it is
    looking at; a bare "not found" would read as the mechanism being absent,
    which the mechanical tier never established.
    """
    from .definition_extract import MAX_DEFINITION_CHARS
    from .verifiers.tests import mechanism_kinds, mechanism_line_span

    header = f"--- Mechanism {mech_file}::{symbol} ---\n"
    if content:
        span = mechanism_line_span(project_root, mech_file, symbol)
        if span is not None:
            start, end = span
            return header + "\n".join(content.splitlines()[start - 1:end])[:MAX_DEFINITION_CHARS]
        _kinds, name = mechanism_kinds(symbol)
        sites = _reference_sites(content, name) if name else ""
        if sites:
            return (
                header
                + "(no definition in this file: the symbol is imported or provided by a "
                "library. These are the sites in the file that reference it; the "
                "mechanism is configured here, and this is the surface to hold the "
                "test against.)\n" + sites
            )
    return header + "(definition not found in the checkout)"


# Path shapes that mark a file as a test. A test-backed assertion's subject is
# the code its test exercises, not the test file, so a change filter keyed on
# the assertion's own file does not apply to it.
_TEST_PATH_MARKERS = ("/tests/", "/test/", "/__tests__/")
_TEST_BASENAME_MARKERS = ("_test.", "_spec.", ".test.", ".spec.")


def _is_test_file(path: str, pattern: re.Pattern[str] | None = None) -> bool:
    """Whether a repository-relative path is a test file.

    The layout heuristic always applies; ``pattern`` (from
    ``--test-file-pattern``) marks additional paths for repositories whose
    tests live outside the conventional layouts.
    """
    rel = str(path or "").replace("\\", "/")
    if pattern is not None and pattern.search(rel):
        return True
    text = "/" + rel.lstrip("/")
    if any(marker in text for marker in _TEST_PATH_MARKERS):
        return True
    base = text.rsplit("/", 1)[-1]
    if base.startswith("test_") or base.startswith("conftest"):
        return True
    return any(marker in base for marker in _TEST_BASENAME_MARKERS)


def _is_test_backed(assertion: dict[str, Any],
                    pattern: re.Pattern[str] | None = None) -> bool:
    """Whether an assertion's verdict can change while its own file does not.

    Two rules, each with its own reason. An assertion whose evidence class is
    a signed execution witness speaks about a RUN, not about a file, so no
    file scoping applies to it and it is always re-verified. An assertion
    whose subject is a test file is re-verified because the operator marked
    that file as a test: what a test evidences is the code it exercises, so
    its own file being unchanged says nothing about the claim. The class is
    read from the registry rather than from a list of type names here, so a
    type's evidence class is stated once, where the type is registered.
    """
    from .verifiers import EVIDENCE_BEHAVIORAL, evidence_class

    a_type = str(assertion.get("type") or "")
    if evidence_class(a_type) == EVIDENCE_BEHAVIORAL:
        return True
    if a_type in ("function_exists", "class_exists"):
        return _is_test_file(
            str((assertion.get("params") or {}).get("file") or ""), pattern)
    return False


def _load_scope_inventory_source(project_root: Path, a_type: str,
                                 params: dict[str, Any]):
    """``(SOURCE_CODE, verdict)`` for a sound-witness review.

    The mechanical tier enumerated every site of a declared sink over the
    scope and classified each guarded argument's static form. That inventory
    -- plus every undeclared call into the sinks' receivers, every
    construction site of a boundary type, every allowlisted site with its
    reviewed reason, and a facts block carrying the counts and the parser
    used per file -- is what the semantic tier reviews. It is not asked to
    re-scan: the question left for it is whether the declared sinks are the
    sinks through which the stated property could be violated in this code.

    The engine's verdict comes back with the inventory so the caller's
    structural precheck reads the run that produced what the reviewer is
    shown, rather than running the scope a second time and judging one
    against the other.
    """
    from .verifiers.sound import render_facts, render_inventory, run_engine, to_result

    report = run_engine(params, project_root, a_type)
    return f"{render_inventory(report)}\n\n{render_facts(report)}", to_result(report)


def _load_pattern_source(project_root: Path, params: dict[str, Any]) -> str:
    """Load source content for pattern-based tier-2 types.

    Globs ``params["pattern"]`` against ``project_root`` (recursive,
    same glob semantics as tier-1's pattern verifiers), reads each
    matched file, concatenates with a ``# === <relative_path> ===``
    separator so the LLM can distinguish files in multi-match results,
    and truncates the combined content to 16K chars to match the
    truncation budget the rest of the tier-2 source-loading path uses.

    Returns ``""`` when no files match, the pattern is empty, or every
    read fails — the caller's pre-LLM fail-closed guard catches that
    case before invoking the LLM.
    """
    import glob

    pattern = (params.get("pattern") or "").strip()
    if not pattern:
        return ""
    try:
        matches = glob.glob(str(project_root / pattern), recursive=True)
    except Exception:
        return ""
    if not matches:
        return ""
    parts: list[str] = []
    for match in sorted(matches):
        try:
            mpath = Path(match)
            if not mpath.is_file():
                continue
            content = mpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        try:
            rel = str(mpath.relative_to(project_root))
        except ValueError:
            rel = match
        parts.append(f"# === {rel} ===\n{content}")
    combined = "\n".join(parts)
    if len(combined) > 16000:
        combined = combined[:16000] + "\n... (truncated)"
    return combined


class AttestationRequiredError(RuntimeError):
    """Raised when ``--require-attestation`` is set and no signer
    produced a usable attestation for the run.

    The runner's default behaviour on missing/failed signing is to
    log a warning and submit unsigned; that's appropriate for
    operator-friendly defaults but is not what a security-sensitive
    CI gate wants. ``--require-attestation`` flips the failure mode
    to fail-closed: the run exits non-zero rather than submitting
    a result the audit-tool side cannot pin to a signing identity.
    """


def compute_content_hash(
    all_assertions: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> str:
    """Compute SHA-256 hash of assertion content + verdicts.

    Binds what CI verified (assertion definitions) to what it concluded
    (pass/fail). The backend validates this hash at submission time to
    detect modifications between CI pull and result submission.
    """
    verdict_map = {r["assertion_id"]: r["result"] for r in results}
    records = []
    for a in all_assertions:
        aid = a.get("id", "")
        verdict = verdict_map.get(aid, "skipped")
        records.append({
            "assertion_id": aid,
            "type": a.get("type", ""),
            "params": a.get("params", {}),
            "description": a.get("description", ""),
            "verdict": verdict,
        })
    records.sort(key=lambda x: x["assertion_id"])
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


# Fields of a pulled assertion record that describe the assertion itself:
# the verified content (bound by ``compute_content_hash``) and its identity /
# binding / provenance. Everything else on the record is the platform's
# stored verdict state from earlier runs and is deliberately excluded.
ATTESTED_ASSERTION_FIELDS: tuple[str, ...] = (
    # content bound by the content hash
    "id",
    "type",
    "params",
    "description",
    # binding: what the assertion evidences, and where
    "control_id",
    "assumption_id",
    "functional_test_id",
    "node_id",
    "repo",
    # provenance
    "origin",
    "inherited_from_model_id",
    "created_by",
    "created_at",
)


def attestation_assertion_records(
    all_assertions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Reduce pulled assertion records to what the attestation should carry.

    A pulled record also holds the platform's stored verdict state from
    earlier runs (tier statuses, reviewer prose, verification timestamps,
    coherence results, supersession / deletion flags). CI did not verify
    any of that, and this run's own verdicts travel in ``results``, so it
    is left out. The signed payload is then a function of the assertion
    specs, their bindings, and this run's verdicts — not of how much
    history the platform holds on them. The content hash is unaffected:
    every field it binds is kept.
    """
    return [
        {k: a[k] for k in ATTESTED_ASSERTION_FIELDS if k in a}
        for a in all_assertions
    ]


class Runner:
    """Orchestrates the pull → verify → submit flow."""

    def __init__(
        self,
        client: MipitiClient,
        project_root: str = ".",
        tier2_provider: str | None = None,
        tier2_model: str | None = None,
        tier2_api_key: str | None = None,
        ollama_url: str = "http://localhost:11434",
        oidc_token: str | None = None,
        sigstore_tuf_url: str | None = None,
        sigstore_trust_config_path: str | None = None,
        workspace_signing_key_path: str | None = None,
        customer_key_path: str | None = None,
        customer_key_passphrase: str | None = None,
        signing_prefer: str = "sigstore",
        require_attestation: bool = False,
        dry_run: bool = False,
        reverify: bool = True,
        verbose: bool = False,
        repo: str = "",
        changed_files: set[str] | None = None,
        concurrency: int = 1,
        component_id: str | None = None,
        auto_component_path: bool = True,
        test_file_pattern: str | None = None,
        tier2_consistency_n: int | None = None,
    ) -> None:
        self.client = client
        # Extra test-file identification, on top of the layout heuristic.
        # Compiled here so a bad expression stops the run before any
        # assertion is judged, rather than silently matching nothing.
        self.test_file_pattern: re.Pattern[str] | None = None
        if test_file_pattern:
            try:
                self.test_file_pattern = re.compile(test_file_pattern)
            except re.error as e:
                raise ValueError(
                    f"--test-file-pattern {test_file_pattern!r} is not a valid "
                    f"regular expression: {e}"
                ) from e
        self.project_root = Path(project_root).resolve()
        self.repo = repo or _auto_detect_repo(self.project_root)
        self.component_id = component_id
        self.auto_component_path = auto_component_path
        self._component_path_resolved = False
        self.tier2_provider_name = tier2_provider
        self.tier2_model = tier2_model
        self.tier2_api_key = tier2_api_key
        self.ollama_url = ollama_url
        # Self-consistency sample count for tier-2 (N judgments per fresh
        # evidence; a PASS requires all N to agree). Default 3; override via the
        # constructor or MIPITI_TIER2_CONSISTENCY_N. Clamped to >= 1.
        _n_env = os.environ.get("MIPITI_TIER2_CONSISTENCY_N", "").strip()
        if tier2_consistency_n is not None:
            self.tier2_consistency_n = max(1, int(tier2_consistency_n))
        elif _n_env.isdigit():
            self.tier2_consistency_n = max(1, int(_n_env))
        else:
            self.tier2_consistency_n = 3
        # The raw OIDC token is used only locally to mint a Sigstore bundle
        # (see _sign_with_sigstore); it is never transmitted to Mipiti. For
        # Sigstore signing, the token MUST have `aud=sigstore` — Fulcio
        # and sigstore-python's IdentityToken validator both require it.
        # An explicitly supplied token is used exactly as given: its lifetime
        # is the caller's to manage. A detected one is re-minted at the point
        # of use (see _fresh_oidc_token); what is kept here is the fact that
        # OIDC is AVAILABLE, which is what the checks below ask.
        self._oidc_explicit = oidc_token or ""
        self.oidc_token = self._oidc_explicit or _auto_detect_oidc("sigstore")
        self.sigstore_tuf_url = sigstore_tuf_url or os.environ.get(
            "MIPITI_SIGSTORE_TUF_URL", ""
        ) or None
        self.sigstore_trust_config_path = sigstore_trust_config_path or os.environ.get(
            "MIPITI_SIGSTORE_TRUST_CONFIG", ""
        ) or None

        # Workspace-ECDSA fallback signer. Used when:
        #   (a) no OIDC token is available (Jenkins / Buildkite / self-managed
        #       GitLab without ID tokens), OR
        #   (b) the operator explicitly picks workspace-key over sigstore via
        #       ``signing_prefer="workspace"`` (e.g. policy / testing).
        # Auto-detected from MIPITI_WORKSPACE_SIGNING_KEY env var when the
        # CLI flag is omitted, mirroring the `oidc_token` auto-detect pattern.
        key_path = workspace_signing_key_path or os.environ.get(
            "MIPITI_WORKSPACE_SIGNING_KEY", ""
        ) or None
        self.workspace_signer: WorkspaceKeySigner | None = None
        if key_path:
            try:
                self.workspace_signer = WorkspaceKeySigner(key_path)
            except ValueError as e:
                # Bad key file is a hard error — surfacing it as silent fall-
                # through to "submit unsigned" would defeat the operator's
                # explicit signing intent.
                raise ValueError(f"--workspace-signing-key load failed: {e}") from e

        # Customer-keyed offline DSSE signer. Used for air-gapped and
        # non-Sigstore CI (Jenkins, self-managed/older GitLab,
        # Buildkite/CircleCI without OIDC, regulated networks) that cannot
        # reach Sigstore at sign time. When a customer key is supplied it
        # is the *preferred* path (before Sigstore) — the operator has
        # explicitly opted into the customer-controlled, offline-verifiable
        # attestation. Auto-detected from MIPITI_CUSTOMER_SIGNING_KEY /
        # MIPITI_CUSTOMER_SIGNING_KEY_PASSPHRASE when the CLI flags are
        # omitted, mirroring the other signer auto-detect patterns. The
        # PEM is read lazily at sign time so a bad passphrase surfaces a
        # clear error rather than silently submitting unsigned.
        self.customer_key_path = customer_key_path or os.environ.get(
            "MIPITI_CUSTOMER_SIGNING_KEY", ""
        ) or None
        self.customer_key_passphrase = customer_key_passphrase or os.environ.get(
            "MIPITI_CUSTOMER_SIGNING_KEY_PASSPHRASE", ""
        ) or None

        prefer = (signing_prefer or "sigstore").lower()
        if prefer not in ("sigstore", "workspace"):
            raise ValueError(
                f"--signing-prefer must be 'sigstore' or 'workspace' "
                f"(got {signing_prefer!r})"
            )
        self.signing_prefer = prefer
        self.require_attestation = bool(require_attestation)

        self.dry_run = dry_run
        self._developer_key = client.key_scope == "developer"
        self.reverify = reverify
        self.verbose = verbose
        self.changed_files = changed_files
        self.concurrency = max(1, concurrency)

    def _sign_with_workspace_key(self, content_hash: str) -> tuple[str, str]:
        """Sign ``content_hash`` with the workspace ECDSA key.

        Returns ``(signature_b64, signed_hex)`` accepted by the backend's
        ``signature`` + ``signed_hash`` body fields, or ``("", "")`` if no
        workspace key is configured. Failures are logged and also return
        empty strings — the run still submits unsigned, mirroring the
        Sigstore fallback path.
        """
        if self.workspace_signer is None:
            return "", ""
        try:
            return self.workspace_signer.sign(content_hash)
        except Exception as e:
            console.print(
                f"  [yellow]Workspace-key signing failed: {e} — submitting without attestation[/yellow]"
            )
            return "", ""

    def _sign_with_customer_key(
        self,
        *,
        model_id: str,
        tier: int,
        content_hash: str,
        pipeline: dict[str, Any],
        assertions: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> str:
        """Build a customer-keyed offline DSSE bundle for this tier's run.

        Returns the bundle JSON, or ``""`` when no customer key is
        configured. A bad key / passphrase is a hard error — surfacing it
        as a silent fall-through to "submit unsigned" would defeat the
        operator's explicit signing intent (same contract as the
        workspace-key load error).
        """
        if not self.customer_key_path:
            return ""
        try:
            return sign_customer_dsse_statement(
                model_id=model_id,
                tier=tier,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=assertions,
                results=results,
                key_path=self.customer_key_path,
                passphrase=self.customer_key_passphrase,
            )
        except ValueError as e:
            raise ValueError(f"--customer-key signing failed: {e}") from e

    def _choose_attestation(
        self,
        *,
        model_id: str,
        tier: int,
        content_hash: str,
        pipeline: dict[str, Any],
        assertions: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> tuple[str, str, str, str]:
        """Pick the attestation path per precedence.

        Returns ``(bundle, signature, signed_hash, dsse_bundle)`` — exactly
        one of ``dsse_bundle``, ``bundle``, or (``signature`` +
        ``signed_hash``) is populated when signing succeeds; all empty when
        no signer is available or every signer fails.

        Precedence: when a customer key is supplied, the customer-keyed
        offline DSSE path wins (the operator explicitly opted into the
        customer-controlled, offline-verifiable attestation). Otherwise
        Sigstore wins by default; ``signing_prefer="workspace"`` forces the
        workspace-ECDSA path even when an OIDC token is present.
        """
        bundle, signature, signed_hash, dsse_bundle = "", "", "", ""

        if self.customer_key_path:
            dsse_bundle = self._sign_with_customer_key(
                model_id=model_id,
                tier=tier,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=assertions,
                results=results,
            )
            if dsse_bundle:
                if self.verbose:
                    console.print(
                        f"  [dim]Tier {tier} attestation: customer-dsse (offline)[/dim]"
                    )
                return "", "", "", dsse_bundle

        if self.oidc_token and self.signing_prefer != "workspace":
            bundle = self._sign_with_sigstore(
                model_id=model_id,
                tier=tier,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=assertions,
                results=results,
            )
            if bundle:
                if self.verbose:
                    console.print(f"  [dim]Tier {tier} attestation: sigstore[/dim]")
                return bundle, "", "", ""
            # Sigstore failed — fall through to workspace key if available.

        if self.workspace_signer is not None:
            signature, signed_hash = self._sign_with_workspace_key(content_hash)
            if signature:
                if self.verbose:
                    console.print(f"  [dim]Tier {tier} attestation: workspace-ecdsa[/dim]")
                return "", signature, signed_hash, ""

        if self.require_attestation:
            raise AttestationRequiredError(
                "No attestation available for this run "
                f"(tier {tier}) and --require-attestation is set. "
                "Configure one of: a customer-keyed offline DSSE key "
                "(--customer-key, env: MIPITI_CUSTOMER_SIGNING_KEY) for "
                "air-gapped / non-Sigstore CI; an OIDC token (CI "
                "environment with id-token: write) for Sigstore signing; "
                "or --workspace-signing-key (env: "
                "MIPITI_WORKSPACE_SIGNING_KEY) for workspace-ECDSA "
                "signing. All available signers attempted; none "
                "produced an attestation."
            )

        if self.verbose:
            console.print(f"  [dim]Tier {tier} attestation: none (submitting unsigned)[/dim]")
        return "", "", "", ""

    def _fresh_oidc_token(self) -> str:
        """A token minted now, rather than the one detected at construction.

        A workload identity token is short-lived by design, and a run spends
        as long as its evidence takes between constructing this object and
        signing its first statement -- long enough, on a repository of any
        size, for the token detected at startup to have expired before it is
        ever used. The credential that MINTS tokens stays valid for the whole
        job, so asking for one at the point of use is the only form that
        cannot have aged out in between.

        The failure this prevents is quiet and easy to misread: an expired
        token and a token that was never valid are reported identically, as
        malformed or missing claims, because the underlying validator wraps
        every rejection in one message. So a run that had a perfectly good
        identity would report that its identity was malformed, drop the
        attestation, and -- where one is required -- fail for a reason that
        names nothing a reader could act on.

        An explicitly supplied token is returned unchanged; re-minting would
        substitute an identity the caller did not choose.
        """
        if self._oidc_explicit:
            return self._oidc_explicit
        # Fall back to the startup token only if a fresh mint is unavailable:
        # a stale token that may still be in date beats no attempt at all.
        return _auto_detect_oidc("sigstore") or self.oidc_token

    def _sign_with_sigstore(
        self,
        *,
        model_id: str,
        tier: int,
        content_hash: str,
        pipeline: dict[str, Any],
        assertions: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> str:
        """Build a DSSE attestation for this tier's run and wrap it in a
        Sigstore bundle.

        Returns the bundle as a JSON string, or "" when no OIDC token is
        available (self-hosted / non-OIDC CI). Failures are logged and also
        return "" — the run still submits; it just lacks attestation. The
        bundle's DSSE envelope carries the assertion + verdict payload
        directly, making it self-contained for offline auditor verification.
        """
        if not self.oidc_token:
            return ""
        token = self._fresh_oidc_token()
        try:
            return sign_verification_statement(
                token,
                model_id=model_id,
                tier=tier,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=assertions,
                results=results,
                tuf_url=self.sigstore_tuf_url,
                trust_config_path=self.sigstore_trust_config_path,
            )
        except Exception as e:
            console.print(
                f"  [yellow]Sigstore signing failed: {e}{_expiry_hint(token)} — "
                "submitting without attestation[/yellow]"
            )
            return ""

    def _resolve_component_path(self, model_id: str) -> None:
        """When ``--component CMP`` is set and the component declares a
        ``path`` (e.g., ``services/auth`` for a monorepo sub-component),
        join that path onto ``project_root`` so assertion paths resolve
        relative to the component's directory.

        Idempotent — safe to call multiple times. No-ops when:
          - ``--component`` is not set (CLI verifies the whole repo).
          - ``--no-component-path`` was passed (operator opted out, e.g.
            because they're already invoking the CLI from the component
            sub-directory).
          - the component has no declared ``path`` (component lives at
            repo root).
          - the model fetch fails (network error, auth error, etc.) —
            we log a warning and fall back to the unmodified
            ``project_root`` rather than abort.
        """
        if self._component_path_resolved:
            return
        self._component_path_resolved = True
        if not self.component_id or not self.auto_component_path:
            return
        try:
            model = self.client.get_model(model_id)
        except Exception as e:
            if self.verbose:
                console.print(
                    f"  [yellow]Could not fetch model to resolve component path: {e}[/yellow]"
                )
            return
        components = model.get("components") or []
        target = next(
            (c for c in components if c.get("id") == self.component_id),
            None,
        )
        if target is None:
            if self.verbose:
                console.print(
                    f"  [yellow]Component {self.component_id!r} not found on model;"
                    " using --project-root as-is[/yellow]"
                )
            return
        comp_path = (target.get("path") or "").strip().strip("/")
        if not comp_path:
            return
        new_root = (self.project_root / comp_path).resolve()
        if self.verbose:
            console.print(
                f"  [dim]Component {self.component_id!r} declares path "
                f"{comp_path!r} → resolving assertion paths under {new_root}[/dim]"
            )
        self.project_root = new_root

    def run(self, model_id: str) -> dict[str, Any]:
        """Execute full verification pipeline. Returns summary report."""
        self._resolve_component_path(model_id)
        self._repo_bound_assertions = 0
        details: list[dict[str, Any]] = []

        # --- Tier 1 ---
        t1_results, t1_details, t1_assertions = self._run_tier(model_id, tier=1)
        details.extend(t1_details)

        pipeline = _pipeline_metadata()
        # VCS-neutral "same code" identity — a content digest of the verified
        # files. Shared by both tier submissions below. Independent of git/SVN/P4.
        pipeline["source_digest"] = _source_digest(self.project_root, t1_assertions)

        t1_run_id = ""
        if t1_results and not self.dry_run and not self._developer_key:
            content_hash = compute_content_hash(t1_assertions, t1_results)
            bundle, signature, signed_hash, dsse_bundle = self._choose_attestation(
                model_id=model_id,
                tier=1,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=attestation_assertion_records(t1_assertions),
                results=t1_results,
            )
            resp = self.client.submit_results(
                model_id,
                pipeline=pipeline,
                results=t1_results,
                bundle=bundle,
                signature=signature,
                signed_hash=signed_hash,
                content_hash=content_hash,
                dsse_bundle=dsse_bundle,
            )
            t1_run_id = resp.get("run_id", "")

        # --- Tier 2 ---
        t2_results, t2_details, t2_assertions = self._run_tier(model_id, tier=2)
        details.extend(t2_details)

        t2_run_id = ""
        if t2_results and not self.dry_run and not self._developer_key:
            content_hash = compute_content_hash(t2_assertions, t2_results)
            bundle, signature, signed_hash, dsse_bundle = self._choose_attestation(
                model_id=model_id,
                tier=2,
                content_hash=content_hash,
                pipeline=pipeline,
                assertions=attestation_assertion_records(t2_assertions),
                results=t2_results,
            )
            resp = self.client.submit_results(
                model_id,
                pipeline=pipeline,
                results=t2_results,
                bundle=bundle,
                signature=signature,
                signed_hash=signed_hash,
                content_hash=content_hash,
                dsse_bundle=dsse_bundle,
            )
            t2_run_id = resp.get("run_id", "")

        # --- Sufficiency ---
        # Evaluated server-side at assertion submission. Fetch for display.
        suff_all: list[dict[str, Any]] = []
        try:
            vr = self.client.get_verification_report(model_id)
            for ctrl in vr.get("control_details", []):
                suff = ctrl.get("sufficiency")
                if suff and suff.get("status") in ("sufficient", "insufficient"):
                    suff_all.append({
                        "control_id": ctrl.get("control_id", ""),
                        "result": suff["status"],
                        "details": suff.get("details", ""),
                    })
        except Exception:
            pass

        # Compute combined content hash across both tiers for attestation
        all_verified = t1_assertions + t2_assertions
        all_results = t1_results + t2_results
        combined_content_hash = compute_content_hash(all_verified, all_results) if all_verified else ""

        return {
            "tier1_pass": sum(1 for r in t1_results if r["result"] == "pass"),
            "tier1_fail": sum(1 for r in t1_results if r["result"] == "fail"),
            "tier1_skip": sum(1 for r in t1_results if r["result"] == "skipped"),
            "tier2_pass": sum(1 for r in t2_results if r["result"] == "pass"),
            "tier2_fail": sum(1 for r in t2_results if r["result"] == "fail"),
            "tier2_skip": sum(1 for r in t2_results if r["result"] == "skipped"),
            "suff_sufficient": sum(1 for r in suff_all if r["result"] == "sufficient"),
            "suff_insufficient": sum(1 for r in suff_all if r["result"] == "insufficient"),
            "suff_skip": 0,
            "tier1_run_id": t1_run_id,
            "tier2_run_id": t2_run_id,
            "content_hash": combined_content_hash,
            "dry_run": self.dry_run,
            "developer_key": self._developer_key,
            "details": details,
            "suff_details": suff_all,
            "repo_bound_assertions": getattr(self, "_repo_bound_assertions", 0),
        }

    def _run_tier(
        self, model_id: str, tier: int
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Run verification for a single tier. Returns (api_results, detail_records, all_assertions)."""
        if not self.repo:
            raise RuntimeError(
                "Repository scope is required but could not be auto-detected. "
                "Pass --repo <owner/name> or run in an environment that exports "
                "GITHUB_REPOSITORY (GitHub Actions) or CI_PROJECT_PATH (GitLab CI)."
            )
        if self.reverify:
            pending = self.client.get_all_assertions(model_id, repo=self.repo)
        else:
            pending = self.client.get_pending(model_id, tier=tier, repo=self.repo)
        controls = pending.get("controls", {})
        # Merge assumption assertions into the same verification pass
        for as_id, as_assertions in pending.get("assumptions", {}).items():
            controls[as_id] = as_assertions
        if not controls:
            if self.verbose:
                console.print(f"  No tier {tier} assertions pending")
            return [], [], []

        # Strict per-repo scope filter. The server already scopes by
        # ``repo`` at fetch time, but a misconfigured or impersonated
        # response could include cross-repo assertions; the runner must
        # never evaluate (and submit verdicts for) an assertion bound to
        # a different repository. Sentinel ``no_repo`` is the contract
        # for assertions that have no file-system scope (e.g.,
        # feature_description targets) and passes through unconditionally.
        # Assertions with no ``repo`` field at all are treated as
        # ``no_repo`` — they predate per-repo scoping and have no
        # filesystem boundary to enforce.
        for ctrl_id, assertions in list(controls.items()):
            kept_scope: list[dict[str, Any]] = []
            for a in assertions:
                a_repo = (a.get("repo") or "").strip()
                if not a_repo or a_repo == "no_repo" or a_repo == self.repo:
                    kept_scope.append(a)
                    continue
                console.print(
                    f"[skip] {a.get('id', '<no-id>')}: "
                    f"repo mismatch (assertion={a_repo}, "
                    f"runner={self.repo})"
                )
            if kept_scope:
                controls[ctrl_id] = kept_scope
            else:
                del controls[ctrl_id]
        # Everything that survived the repo-scope filter is evidence bound
        # to this repository, before any changed-files or component
        # narrowing; the report carries the count so a caller can tell a
        # model with no evidence here from one whose evidence was scoped out.
        self._repo_bound_assertions = max(
            getattr(self, "_repo_bound_assertions", 0),
            sum(len(v) for v in controls.values()),
        )
        if not controls:
            if self.verbose:
                console.print(
                    f"  No tier {tier} assertions remained after repo-scope filter"
                )
            return [], [], []

        # Filter by component — only verify assertions for controls in this component
        if self.component_id:
            # Fetch controls to determine which belong to this component
            try:
                ctrl_data = self.client.get_controls(model_id, component_id=self.component_id)
                component_ctrl_ids = {c["id"] for c in ctrl_data.get("controls", [])}
                filtered_by_cmp: dict[str, list] = {}
                for ctrl_id, assertions in controls.items():
                    if ctrl_id in component_ctrl_ids:
                        filtered_by_cmp[ctrl_id] = assertions
                if self.verbose:
                    skipped_cmp = len(controls) - len(filtered_by_cmp)
                    if skipped_cmp:
                        console.print(f"  Tier {tier}: skipped {skipped_cmp} control(s) (different component)")
                controls = filtered_by_cmp
                if not controls:
                    return [], [], []
            except Exception as e:
                console.print(f"  [yellow]Warning: component filter failed ({e}), verifying all[/yellow]")

        # Filter to assertions referencing changed files when --changed-files is set.
        # Assertions without a file param are always included (can't be scoped).
        # Test-backed assertions are always kept: what a test evidences is
        # the code it exercises, so an unchanged test file says nothing
        # about whether its claim still holds.
        if self.changed_files is not None:
            filtered: dict[str, list] = {}
            skipped = 0
            kept_test_backed = 0
            for ctrl_id, assertions in controls.items():
                kept = []
                for a in assertions:
                    a_file = a.get("params", {}).get("file", "")
                    if _is_test_backed(a, self.test_file_pattern):
                        kept.append(a)
                        if a_file and a_file not in self.changed_files:
                            kept_test_backed += 1
                    elif not a_file or a_file in self.changed_files:
                        kept.append(a)
                    else:
                        skipped += 1
                if kept:
                    filtered[ctrl_id] = kept
            if self.verbose and skipped:
                console.print(f"  Tier {tier}: skipped {skipped} assertions (files unchanged)")
            if self.verbose and kept_test_backed:
                console.print(
                    f"  Tier {tier}: kept {kept_test_backed} test-backed "
                    f"assertion(s) despite unchanged files (a test's subject "
                    f"is the code it exercises)"
                )
            controls = filtered
            if not controls:
                return [], [], []

        total = sum(len(assertions) for assertions in controls.values())
        results: list[dict[str, Any]] = []
        details: list[dict[str, Any]] = []

        # Flatten assertions for processing
        all_assertions = [
            a for _ctrl_id, assertions in controls.items() for a in assertions
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Tier {tier}: verifying {total} assertions", total=total)

            if tier == 2 and self.concurrency > 1:
                # Parallel tier2 verification
                futures = {}
                with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                    for assertion in all_assertions:
                        future = pool.submit(self._verify_tier2, assertion)
                        futures[future] = assertion
                    for future in as_completed(futures):
                        assertion = futures[future]
                        a_id = assertion["id"]
                        a_type = assertion["type"]
                        result = future.result()
                        results.append(_result_row(a_id, a_type, tier, result))
                        details.append({
                            "assertion_id": a_id,
                            "type": a_type,
                            "tier": tier,
                            "passed": result["status"] == "pass",
                            "skipped": result["status"] == "skipped",
                            "details": result["details"],
                        })
                        progress.advance(task)
            else:
                # Sequential (tier1 or concurrency=1)
                for assertion in all_assertions:
                    a_id = assertion["id"]
                    a_type = assertion["type"]

                    if tier == 1:
                        result = self._verify_tier1(assertion)
                    else:
                        result = self._verify_tier2(assertion)

                    results.append(_result_row(a_id, a_type, tier, result))
                    details.append({
                        "assertion_id": a_id,
                        "type": a_type,
                        "tier": tier,
                        "passed": result["status"] == "pass",
                        "skipped": result["status"] == "skipped",
                        "details": result["details"],
                    })
                    progress.advance(task)

        return results, details, all_assertions

    def _verify_tier1(self, assertion: dict) -> dict[str, Any]:
        """Run Tier 1 mechanical verification."""
        a_type = assertion["type"]
        params = assertion.get("params", {})

        verifier = get_verifier(a_type)
        if verifier is None:
            return {"status": "skipped", "details": f"No verifier for type '{a_type}'"}

        try:
            result = verifier.verify(params, self.project_root)
            out = {
                "status": "pass" if result.passed else "fail",
                "details": result.details,
            }
            if getattr(result, "provenance", ""):
                out["provenance"] = result.provenance
            if getattr(result, "evidence_hash", ""):
                out["evidence_hash"] = result.evidence_hash
            for fact in _RESULT_FACTS:
                value = getattr(result, fact, None)
                if value is not None:
                    out[fact] = bool(value)
            # The counts come from the engine's own report of the run and
            # from nowhere else: a verifier that enumerated nothing states
            # none, and no other verifier states them at all.
            established = getattr(result, "facts", None) or {}
            for count in _RESULT_COUNTS:
                value = established.get(count)
                if isinstance(value, int) and not isinstance(value, bool):
                    out[count] = value
            return out
        except Exception as e:
            return {"status": "fail", "details": f"Verifier error: {e}"}

    def _verify_tier2(self, assertion: dict) -> dict[str, Any]:
        """Run Tier 2 semantic verification using AI provider.

        The backend payload MUST carry the structured ``type`` +
        ``params`` fields. The runner renders its own per-type
        template locally with a fresh per-call boundary token —
        there is no legacy path that consumes a backend-rendered
        prompt. A payload missing these fields surfaces a clear
        version-mismatch error so operators running mismatched
        CLI/backend versions can upgrade.
        """
        if self.tier2_provider_name is None:
            return {"status": "skipped", "details": "No --tier2-provider specified"}

        a_type = assertion.get("type", "") or ""
        a_params = assertion.get("params", {})
        if not a_type or not isinstance(a_params, dict) or not a_params:
            return {
                "status": "fail",
                "details": (
                    "Backend payload missing required `type` / `params` "
                    "fields. This mipiti-verify release requires a backend "
                    "that ships the structured tier-2 payload. Upgrade the "
                    "platform, or pin mipiti-verify to a release matching "
                    "your backend."
                ),
            }

        # Read source content for context
        params = a_params
        # For file_hash, tier 2 reviews the code that pins the hash (scope_file),
        # not the hashed file itself.
        if a_type == "file_hash":
            source_file = params.get("scope_file", "")
        else:
            source_file = params.get("file", "")
        source_code = ""
        # What the loaded content IS. The tier-2 template states its
        # criterion in terms of the subject, so whichever branch below
        # loads the content is also what settles the subject: a regex
        # match in a repository file is code, the same match in the
        # model's feature description is a design statement, and the
        # two are not judged by the same rule. The runner is the only
        # place that knows which one it loaded.
        subject_kind = SUBJECT_REPOSITORY_FILE
        # The mechanical verdict a scope type's loader already produced, so
        # the precheck below does not run the scope a second time.
        scope_verdict = None
        # For target-based assertions (e.g., feature_description), use
        # platform-injected content instead of reading from disk.
        # No truncation — content must match what Tier 1 verified via
        # resolve_content(). If it exceeds the provider's context window,
        # the provider will fail naturally with an informative error.
        if not source_file and params.get("target_content"):
            # The mechanical tier evaluates its predicate over the
            # SCOPED region of the target content — the same
            # ``scope_start`` / ``scope_end`` slice it applies to a
            # repository file — so that is the region its verdict
            # speaks about. The tier-2 instruction text states, as
            # trusted framing outside the boundary, that a mechanical
            # step has already settled the regex over the payload
            # below; handing over the whole target while the
            # mechanical step read one section would make that framing
            # false. Slice with the mechanical tier's own helper so
            # both tiers read byte-identical text.
            #
            # Only the two pattern types may carry a target today, and
            # they are exactly the types that scope through this
            # helper. Applying it unconditionally keeps the invariant
            # (tier 2 never reviews more than the mechanical tier
            # judged) intact for any target-bearing type added later.
            from .verifiers import RegexTimeoutError
            from .verifiers.file_based import _extract_scope

            try:
                source_code = _extract_scope(params["target_content"], params)
            except RegexTimeoutError as e:
                # Fail closed, as the mechanical tier does on the same
                # helper: a scope that cannot be evaluated leaves the
                # reviewed region undetermined, and the unsliced
                # content would ship that false framing. A scope that
                # matches nothing yields empty content, which the
                # pre-LLM guard below turns into its own refusal.
                return {
                    "status": "fail",
                    "details": (
                        f"Tier-2 could not resolve the assertion's scope over "
                        f"the {params.get('target', 'target')!r} content: {e}. "
                        f"Refusing to review a region wider than the one the "
                        f"mechanical tier evaluated."
                    ),
                }
            subject_kind = _TARGET_SUBJECT_KINDS.get(
                params.get("target", ""), SUBJECT_REPOSITORY_FILE
            )
        elif a_type == "test_attested":
            # The evidence for an attested test is the test the attestation
            # names, read from the checkout, with the mechanism it is meant
            # to exercise and the facts the mechanical tier established. The
            # statement itself is the fallback when the attestation names no
            # definition.
            source_code = _load_test_attested_source(self.project_root, params)
        elif a_type in _SCOPE_TYPES:
            # A sound witness has no single file: its subject is the scope,
            # and its evidence is the inventory the mechanical tier built
            # over it. The property the witness proves is what sink adequacy
            # is judged against, so a witness that states none leaves the
            # semantic tier nothing to judge and is refused here rather than
            # asked as an open question.
            if not str(params.get("property") or "").strip():
                return {
                    "status": "fail",
                    "details": (
                        f"Tier-2 cannot review a {a_type!r} witness that states no "
                        f"`property`: sink adequacy is judged against the property "
                        f"the sinks realise, and there is none to judge against."
                    ),
                }
            source_code, scope_verdict = _load_scope_inventory_source(
                self.project_root, a_type, params)
        elif not source_file and a_type in _PATTERN_GLOB_TYPES:
            # Pattern-based types (test_exists) use
            # ``params["pattern"]`` and tier-1 globs it. Mirror that
            # resolution here so tier-2 has the matched file contents as
            # SOURCE_CODE — previously the runner looked up
            # ``params["file"]`` and received empty source content while
            # tier-1's glob succeeded, leaving tier-2 to evaluate an
            # assertion with no evidence.
            source_code = _load_pattern_source(self.project_root, params)
        elif source_file:
            from .verifiers import safe_resolve_path, PathTraversalError
            try:
                fpath = safe_resolve_path(self.project_root, source_file)
            except PathTraversalError:
                fpath = None
            if fpath and fpath.is_file():
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    # If scope_start/scope_end provided, extract scoped section
                    # for tier 2 review — more focused and token-efficient.
                    # scope_start only: from match to EOF
                    # scope_end only: from BOF to match
                    # both: from scope_start to scope_end
                    scope_start = params.get("scope_start", "")
                    scope_end = params.get("scope_end", "")
                    if (scope_start or scope_end) and a_type in ("pattern_matches", "pattern_absent", "file_hash"):
                        import re
                        s_pos = 0
                        e_pos = len(content)
                        if scope_start:
                            s_match = re.search(scope_start, content, re.MULTILINE)
                            if s_match:
                                s_pos = s_match.start()
                        if scope_end:
                            search_from = s_pos if scope_start else 0
                            e_match = re.search(scope_end, content[search_from:], re.MULTILINE)
                            if e_match:
                                e_pos = search_from + e_match.start()
                        content = content[s_pos:e_pos]
                    # For pattern_matches/pattern_absent, center context around
                    # the match rather than taking the file head — ensures the
                    # reviewer sees the relevant code even in large files.
                    # For function_exists/class_exists, hand the reviewer the
                    # isolated definition block rather than the enclosing
                    # file. Existence is settled by the structural tier; the
                    # semantic tier judges only the body, so it must never be
                    # asked to locate the symbol first. When the block can't
                    # be isolated, fall through to the file-level handling.
                    isolated = None
                    if a_type in ("function_exists", "class_exists"):
                        from .definition_extract import extract_definition
                        isolated = extract_definition(
                            content,
                            "function" if a_type == "function_exists" else "class",
                            params.get("name", ""),
                        )
                        if isolated is not None:
                            content = isolated
                    pattern = params.get("pattern", "")
                    if isolated is not None:
                        pass
                    elif len(content) > 16000 and pattern and a_type in ("pattern_matches", "pattern_absent"):
                        import re
                        match = re.search(pattern, content)
                        if match:
                            center = match.start()
                            # Take ~8K chars before and after the match
                            start = max(0, center - 8000)
                            end = min(len(content), center + 8000)
                            prefix = "... (truncated)\n" if start > 0 else ""
                            suffix = "\n... (truncated)" if end < len(content) else ""
                            content = prefix + content[start:end] + suffix
                        else:
                            content = content[:16000] + "\n... (truncated)"
                    # For function_exists/class_exists, locate the definition
                    # and center context around it so the tier 2 reviewer can
                    # see the implementation body, not just the file head.
                    elif len(content) > 16000 and a_type in ("function_exists", "class_exists"):
                        import re
                        name = params.get("name", "")
                        if name:
                            if a_type == "function_exists":
                                def_pat = rf'^[ \t]*(async\s+)?def\s+{re.escape(name)}\s*\('
                            else:
                                def_pat = rf'^[ \t]*class\s+{re.escape(name)}[\s(:]'
                            match = re.search(def_pat, content, re.MULTILINE)
                            if match:
                                center = match.start()
                                # Bias toward showing the body (4K before, 12K after)
                                start = max(0, center - 4000)
                                end = min(len(content), center + 12000)
                                prefix = "... (truncated)\n" if start > 0 else ""
                                suffix = "\n... (truncated)" if end < len(content) else ""
                                content = prefix + content[start:end] + suffix
                            else:
                                content = content[:16000] + "\n... (truncated)"
                        else:
                            content = content[:16000] + "\n... (truncated)"
                    # For function_calls, center context on the caller's
                    # definition so a large file doesn't hide the caller past
                    # the 16K head window (leaving the reviewer with no way to
                    # see the call).
                    elif len(content) > 16000 and a_type == "function_calls":
                        import re
                        caller = params.get("caller", "")
                        if caller:
                            def_pat = rf'^[ \t]*(async\s+)?def\s+{re.escape(caller)}\s*\('
                            match = re.search(def_pat, content, re.MULTILINE)
                            if match:
                                center = match.start()
                                # Bias toward showing the body (4K before, 12K after)
                                start = max(0, center - 4000)
                                end = min(len(content), center + 12000)
                                prefix = "... (truncated)\n" if start > 0 else ""
                                suffix = "\n... (truncated)" if end < len(content) else ""
                                content = prefix + content[start:end] + suffix
                            else:
                                content = content[:16000] + "\n... (truncated)"
                        else:
                            content = content[:16000] + "\n... (truncated)"
                    elif len(content) > 16000:
                        content = content[:16000] + "\n... (truncated)"
                    source_code = content
                except Exception:
                    pass

        # Pre-LLM fail-closed guard. If a type requires source-code
        # evidence and loading produced nothing, refuse to call the LLM:
        # an empty SOURCE_CODE block leaves nothing for the model to
        # ground its verdict on, and an LLM that returns YES from the
        # assertion's description alone is a false-pass — the assertion's
        # ``description`` is a CLAIM, not evidence. Types listed in
        # ``_EMPTY_SOURCE_OK_TYPES`` are exempted because their tier-2
        # criterion can legitimately be evaluated on params alone.
        if not source_code and a_type not in _EMPTY_SOURCE_OK_TYPES:
            return {
                "status": "fail",
                "details": (
                    f"Tier-2 has no source content to evaluate for "
                    f"{a_type!r} assertion. Loading from params "
                    f"(file / pattern / target_content) produced empty "
                    f"content, and this type requires source-code "
                    f"evidence — refusing to ask the LLM to evaluate "
                    f"empty evidence."
                ),
            }

        # Deterministic structural-presence precheck for existence types.
        # Whether a symbol EXISTS is a structural fact; the deterministic
        # structural verifier (the mechanical tier) is its sole authority. The
        # semantic tier assesses the QUALITY of a symbol that exists — it is not
        # a source of truth for existence itself. So for existence-type
        # assertions, re-run the authoritative structural verifier on the FULL
        # file (not the possibly-truncated SOURCE_CODE window built above),
        # which applies the same check tier 1 uses, and skip the semantic pass
        # when the symbol is absent. This keeps the semantic tier able only to
        # downgrade a result, never to establish existence: a symbol that is
        # genuinely present still proceeds to the quality check unchanged. Fail
        # open on an unexpected verifier error (tier 1 remains the independent
        # structural authority on its own pass).
        # Applies to every DECLARATION type, not only the two symbol types:
        # whatever mechanical criterion tier 1 owns — a file present, an import
        # declared, a pattern matched, a dependency pinned — the semantic tier
        # is a quality gate layered on it and cannot affirm the criterion
        # itself.
        #
        # Scoped to verifiers that are pure and cheap, because the precheck
        # RE-RUNS the structural verifier. Types whose verifier executes code
        # or does substantial work are excluded: running a test suite as a side
        # effect of a semantic check would duplicate the execution tier 1
        # already performed.
        # Skipped for target-based assertions: those are judged against content
        # supplied with the assertion rather than a repository file, so a
        # file-oriented structural verifier has nothing to re-check and would
        # report a failure about the wrong subject.
        # A scope type's mechanical verdict already came back with the
        # inventory the reviewer is shown, so it is the precheck; every other
        # declaration type is re-run here.
        structural_verdict = scope_verdict
        structural = None
        if (scope_verdict is None and a_type in _DECLARATION_TYPES
                and not params.get("target")):
            structural = get_verifier(a_type)
        if structural is not None:
            try:
                structural_verdict = structural.verify(params, self.project_root)
            except Exception:
                structural_verdict = None
            if structural_verdict is not None and not structural_verdict.passed:
                return {
                    "status": "fail",
                    "details": (
                        f"Tier-2 refused: the {a_type} criterion does not hold "
                        f"structurally ({structural_verdict.details}). Tier-2 is "
                        f"a semantic check and cannot affirm a structural fact — "
                        f"the structural check is the authority, and it did not "
                        f"hold."
                    ),
                }

        # The mechanical tier's own finding travels with the source for the
        # presence types: where the target is, in tier 1's words. Existence is
        # settled outside the boundary; the judge is shown the settled fact so
        # the only question left in front of it is the quality one. Absence
        # types state theirs in the template, and test_attested carries its
        # own facts block.
        if (
            structural_verdict is not None
            and structural_verdict.passed
            and a_type not in ABSENCE_TYPES
            and a_type != "test_attested"
            and structural_verdict.details
        ):
            source_code = (
                f"{source_code}\n\n--- Facts (established by the mechanical tier) ---\n"
                f"the target is present: {structural_verdict.details}"
            )

        try:
            from .tier2 import get_provider

            ev_hash = _tier2_evidence_hash(
                a_type, a_params, source_code, subject_kind,
                self.tier2_provider_name, self.tier2_model,
            )
            reviewer = f"ai:{self.tier2_provider_name}/{self.tier2_model or 'default'}"

            # Reuse a stored verdict when the evidence is unchanged: the verdict
            # is a function of the evidence, so an unchanged hash needs no judge
            # call — this is what stops a nondeterministic judge from flickering
            # a control's status between runs. The cached verdict rides on the
            # assertion pulled from the platform; absent it (older platform, or
            # a first sighting of this evidence), fall through and judge. Only
            # DECISIVE verdicts are ever cached (see the aggregation below).
            cached = assertion.get("tier2_cached") if isinstance(assertion, dict) else None
            if (
                isinstance(cached, dict)
                and cached.get("evidence_hash") == ev_hash
                and cached.get("status") in ("pass", "fail")
            ):
                return {
                    "status": cached["status"],
                    "details": "Reused the stored tier-2 verdict; the evidence is unchanged.",
                    "reasoning": str(cached.get("reasoning", "")),
                    "reviewer": "cache",
                    "tier2_evidence_hash": ev_hash,
                }

            provider = get_provider(
                self.tier2_provider_name,
                model=self.tier2_model,
                api_key=self.tier2_api_key,
                ollama_url=self.ollama_url,
            )
            # Self-consistency: run N judgments and let the SPREAD decide, so a
            # single flip cannot verify or un-verify a control. Each call loads
            # the per-type template and renders it with a fresh per-call
            # boundary token (semantically identical content). A vote is a
            # "discard" when the semantic tier declined on NOT_FOUND against a
            # passing structural check — a boundary artifact, not a quality
            # fail; existence is settled structurally, not by tier 2.
            n = self.tier2_consistency_n
            npass = nfail = ndiscard = 0
            last_pass = last_fail = last_discard = ""
            for _ in range(n):
                passed_i, reasoning_i = provider.evaluate(
                    assertion_type=a_type,
                    assertion_params=a_params,
                    source_code=source_code,
                    subject_kind=subject_kind,
                )
                if passed_i:
                    npass += 1
                    last_pass = reasoning_i
                elif (
                    structural_verdict is not None
                    and structural_verdict.passed
                    and a_type not in ABSENCE_TYPES
                    and _declared_not_found(reasoning_i)
                ):
                    ndiscard += 1
                    last_discard = reasoning_i
                else:
                    nfail += 1
                    last_fail = reasoning_i

            # Aggregate. A PASS requires EVERY judgment to pass: a cached green
            # only ever comes from a unanimous vote, so a split can never verify
            # a control (soundness). A unanimous fail is a confident fail; both
            # decisive outcomes carry the evidence hash and are cached. All
            # judgments discarding is the boundary case the single evaluation
            # discarded. Anything else is a SPLIT: reported not verified and
            # deliberately NOT cached (no evidence hash), so it is re-judged next
            # run rather than freezing a borderline verdict — a confident
            # assertion converges to a cached pass over a run or two; a genuinely
            # borderline one never caches green.
            if npass == n:
                return {"status": "pass", "details": last_pass, "reasoning": last_pass,
                        "reviewer": reviewer, "tier2_evidence_hash": ev_hash}
            if nfail == n:
                return {"status": "fail", "details": last_fail, "reasoning": last_fail,
                        "reviewer": reviewer, "tier2_evidence_hash": ev_hash}
            if ndiscard == n:
                return {
                    "status": "skipped",
                    "details": (
                        "Tier-2 verdict discarded: every judgment declined on "
                        "NOT_FOUND while the structural check confirms the target "
                        "is present. Existence is settled structurally; tier-2 "
                        "may only judge quality. The quality question is unanswered."
                        + (f" Structural check: {structural_verdict.details}."
                           if structural_verdict is not None else "")
                        + (f" Judge's reasoning: {last_discard.strip()[:1500]}"
                           if last_discard else "")
                    ),
                    "reasoning": last_discard,
                    "reviewer": reviewer,
                }
            return {
                "status": "fail",
                "details": (
                    f"REASON: BORDERLINE - {n} judgments did not unanimously affirm "
                    f"this evidence ({npass} pass / {nfail} fail"
                    + (f" / {ndiscard} inconclusive" if ndiscard else "")
                    + "). The semantic check could not confidently affirm it, so it "
                    "is recorded as not verified and re-judged on the next run "
                    "rather than caching a borderline verdict."
                    + (f" Last reasoning: {(last_fail or last_pass).strip()[:800]}"
                       if (last_fail or last_pass) else "")
                ),
                "reasoning": last_fail or last_pass,
                "reviewer": reviewer,
            }
        except ImportError as e:
            return {"status": "skipped", "details": f"Provider not available: {e}"}
        except Exception as e:
            return {"status": "fail", "details": f"Tier 2 error: {e}"}



_DECLARATION_TYPES = frozenset({
    # Types whose structural verifier answers a pure question about what the
    # source DECLARES, with no execution and no significant cost, so it is safe
    # to re-run while deciding whether the semantic tier may speak at all.
    "class_exists", "config_key_exists", "config_value_matches",
    "decorator_present", "dependency_exists", "dependency_version",
    "env_var_referenced", "file_exists", "file_hash", "function_calls",
    "function_exists", "http_header_set", "import_present",
    "middleware_registered", "module_exists", "module_instantiated",
    "no_plaintext_secret", "parameter_defined", "parameter_validated",
    "pattern_absent", "pattern_matches", "port_exists", "register_reset",
    "signal_exists", "sva_assertion_present", "test_exists", "test_attested",
    # The sound witnesses: their engine reads the scope and executes nothing,
    # and what it decides -- whether every site of a declared sink takes a
    # safe form -- is the mechanical criterion the semantic tier is layered
    # on and cannot itself affirm.
    "sink_default_deny", "typed_boundary",
    # Deliberately absent: ``error_handled`` — its verifier runs the code under
    # test, and tier 1 already owns that result. ``test_passes`` was removed
    # entirely; ``test_attested`` reads a signed statement and executes
    # nothing, so it belongs here.
})


_NOT_FOUND_DECLARATION = re.compile(
    r"^\s*REASON:\s*NOT_FOUND\s*$", re.IGNORECASE | re.MULTILINE)


def _declared_not_found(reasoning: str) -> bool:
    """True when a refusal DECLARES it could not locate the target.

    Read from the declared reason line the templates require on a NO, not
    inferred from prose: a quality refusal may legitimately describe something
    as absent ("contains no assertions") without that being a claim about the
    target's existence, and inferring intent from free text would override real
    downgrades. Absent the line — an older or third-party provider that does
    not emit one — this is False and the verdict stands, so the check can only
    ever discard a verdict that says in the protocol what it means.
    """
    return bool(_NOT_FOUND_DECLARATION.search(reasoning or ""))


def repo_slug(value: str) -> str:
    """``owner/name`` for a repository named as a slug, an HTTPS URL or an
    SSH remote (``.git`` and trailing slashes dropped, lower-cased), or
    ``""`` for an empty value. Used to compare the repository a model says
    it describes with the one the verifier is running in."""
    v = (value or "").strip()
    if not v:
        return ""
    for prefix in ("git@github.com:", "git@gitlab.com:", "https://github.com/", "https://gitlab.com/",
                   "http://github.com/", "http://gitlab.com/", "ssh://git@github.com/", "ssh://git@gitlab.com/"):
        if v.lower().startswith(prefix):
            v = v[len(prefix):]
            break
    else:
        if "://" in v:
            v = v.split("://", 1)[1].split("/", 1)[1] if "/" in v.split("://", 1)[1] else ""
    v = v.strip("/").removesuffix(".git").strip("/")
    return v.lower()


BINDING_OTHER_REPO = "other_repo"
BINDING_BOUND = "bound"
BINDING_UNBOUND = "unbound"


def model_binding(provenance_repo: str, this_repo: str, bound_assertions: int) -> str:
    """Whether a model belongs to the repository the verifier runs in.

    A model whose description provenance names another repository is
    ``other_repo``: nothing in it can be verified here and its coverage is
    not this repository's concern. One that names this repository, or has
    at least one assertion bound to it, is ``bound``: its coverage gaps are
    reported in full, including controls with no evidence at all. One with
    neither is ``unbound``: there is nothing to verify and no claim that
    this repository implements it, so its gaps are summarised in one line
    rather than one warning per control."""
    prov = repo_slug(provenance_repo)
    here = repo_slug(this_repo)
    if prov and here and prov != here:
        return BINDING_OTHER_REPO
    if (prov and prov == here) or bound_assertions > 0:
        return BINDING_BOUND
    return BINDING_UNBOUND


def _auto_detect_repo(project_root: Path) -> str:
    """Auto-detect repository name from CI environment or git remote."""
    # GitHub Actions
    gh_repo = os.environ.get("GITHUB_REPOSITORY", "")
    if gh_repo:
        return gh_repo
    # GitLab CI
    gl_repo = os.environ.get("CI_PROJECT_PATH", "")
    if gl_repo:
        return gl_repo
    # Git remote
    try:
        import subprocess
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=str(project_root),
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            for prefix in ("git@github.com:", "https://github.com/",
                           "git@gitlab.com:", "https://gitlab.com/"):
                if url.startswith(prefix):
                    return url[len(prefix):].removesuffix(".git")
    except Exception:
        pass
    return ""


_TIER2_HASH_SCHEMA = "t2v1"


def _tier2_evidence_hash(a_type, a_params, source_code, subject_kind, provider_name, model):
    """A stable hash of exactly what the tier-2 judge is shown, so a verdict can
    be keyed by its evidence and reused when the evidence is unchanged. Hashes
    the semantic inputs — assertion type, canonical params, the assembled
    SOURCE_CODE, subject kind — plus the template bytes for this type (a
    template edit re-opens the verdict), the provider and model (a judge change
    re-opens it), and a schema version. NOT the rendered prompt, which carries a
    fresh per-call boundary token and so is never equal twice."""
    import hashlib
    tmpl = ""
    try:
        tp = Path(__file__).resolve().parent / "templates" / f"tier2_{a_type}.j2"
        if tp.is_file():
            tmpl = tp.read_text(encoding="utf-8")
    except OSError:
        tmpl = ""
    payload = {
        "schema": _TIER2_HASH_SCHEMA,
        "type": a_type,
        "params": a_params if isinstance(a_params, dict) else {},
        "source": source_code or "",
        "subject_kind": subject_kind,
        "template": tmpl,
        "provider": provider_name or "",
        "model": model or "",
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _result_row(a_id: str, a_type: str, tier: int, result: dict) -> dict:
    """One submitted result. ``provenance`` rides along only when a verifier
    set it (signed-evidence types), as data rather than inside ``details``,
    so the platform's audit envelope and sufficiency inputs can carry the
    signing class without parsing prose. The two enumeration counts ride
    along the same way, and for the same reason: a claim about every site in
    a scope is worth a reader's trust only if some run says how many sites
    it decided, and a number stated in prose is not something a reader can
    act on."""
    row = {
        "assertion_id": a_id,
        "tier": tier,
        "result": result["status"],
        "details": result["details"],
        "reasoning": result.get("reasoning", ""),
        "reviewer": result.get("reviewer", f"mipiti-verify:{a_type}"),
    }
    if result.get("provenance"):
        row["provenance"] = result["provenance"]
    if result.get("evidence_hash"):
        row["evidence_hash"] = result["evidence_hash"]
    if result.get("tier2_evidence_hash"):
        row["tier2_evidence_hash"] = result["tier2_evidence_hash"]
    for fact in (*_RESULT_FACTS, *_RESULT_COUNTS):
        if result.get(fact) is not None:
            row[fact] = result[fact]
    return row


def _expiry_hint(token: str) -> str:
    """`` (expired at ...)`` when the token says so, otherwise empty.

    The validator answers "malformed or missing claims" for every rejection,
    expiry included, which sends a reader looking for a broken token when they
    have a stale one. The claim is read WITHOUT verifying the signature and is
    used only to word a message -- nothing is trusted on the strength of it,
    and an unreadable token simply adds nothing.
    """
    import base64
    import json
    import time

    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp")
        if exp and float(exp) < time.time():
            age = int(time.time() - float(exp))
            return f" (the identity token expired {age}s ago)"
    except Exception:
        pass
    return ""


def _auto_detect_oidc(audience: str = "") -> str:
    """Auto-detect OIDC token from CI environment.

    GitLab has two generations: the ``id_tokens`` job keyword (current)
    exposes a token under a name the job chooses -- ``SIGSTORE_ID_TOKEN`` is
    the convention Sigstore tooling reads -- and the older ``CI_JOB_JWT_V2``
    (removed in GitLab 17). Both are honoured, newest first.
    """
    # GitHub Actions
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if url and token:
        try:
            import httpx
            from ._tls import tls_context

            if audience:
                aud_url = f"{url}&audience={audience}" if "?" in url else f"{url}?audience={audience}"
            else:
                aud_url = url
            resp = httpx.get(aud_url, headers={"Authorization": f"Bearer {token}"}, verify=tls_context())
            resp.raise_for_status()
            return resp.json().get("value", "")
        except Exception:
            pass

    # GitLab CI (id_tokens keyword, then the retired CI_JOB_JWT_V2)
    for var in ("SIGSTORE_ID_TOKEN", "CI_JOB_JWT_V2"):
        gl_token = os.environ.get(var, "")
        if gl_token:
            return gl_token

    return ""


def _digest_files(project_root: Path, assertions: list[dict[str, Any]]) -> set[str]:
    """The repository-relative files the assertions were verified against.

    A file-scoped assertion contributes the one file it names. A scope-based
    assertion contributes every file its scope resolves to, so a witness that
    is a statement about a whole scope binds the digest to that whole scope:
    editing any file in it changes the verified code. A scope that cannot be
    resolved contributes its entries verbatim, so an unresolvable scope is
    still recorded rather than silently dropped.
    """
    from .verifiers import PathTraversalError, resolve_scope_files

    files: set[str] = set()
    root = project_root.resolve()
    for a in assertions or []:
        params = a.get("params") or {}
        named = params.get("file", "")
        if named:
            files.add(named)
        scope = params.get("scope")
        if isinstance(scope, str):
            scope = [scope]
        if not isinstance(scope, list) or not scope:
            continue
        entries = [str(e) for e in scope if isinstance(e, str) and e.strip()]
        try:
            files.update(p.relative_to(root).as_posix()
                         for p in resolve_scope_files(project_root, entries))
        except (PathTraversalError, ValueError, OSError):
            files.update(entries)
    return files


def _source_digest(project_root: Path, assertions: list[dict[str, Any]]) -> str:
    """A VCS-neutral content digest of the verified code.

    Hashes the files the assertions reference (``params["file"]``, and every
    file a scope-based assertion's ``params["scope"]`` names), so it is the
    precise "same code" identity independent of any source-control system — two
    runs whose verified files are byte-identical produce the same digest even
    under a rebase or on a different branch. Deterministic (files sorted; each
    entry binds path + content); missing/out-of-root files are recorded as such
    rather than skipped, so a deletion still changes the digest. Empty when no
    assertion is file-scoped (e.g. pattern-only globs); the server then falls back
    to the revision id."""
    files = sorted(_digest_files(project_root, assertions))
    if not files:
        return ""
    root = project_root.resolve()
    h = hashlib.sha256()
    for rel in files:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        try:
            p = (root / rel).resolve()
            if p.is_file() and p.is_relative_to(root):
                h.update(hashlib.sha256(p.read_bytes()).hexdigest().encode("ascii"))
            else:
                h.update(b"<missing>")
        except OSError:
            h.update(b"<error>")
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def _pipeline_metadata() -> dict[str, str]:
    """Build pipeline metadata via the VCS-neutral source-provenance resolver.

    Delegates provider selection (GitHub / GitLab / generic-env / local) to
    ``provenance.resolve_provenance``. The dict shape is unchanged — ``commit_sha``
    carries the opaque revision id from whatever source-control the provider uses
    — so the signed predicate stays byte-compatible while a non-git runner can now
    supply provenance via SOURCE_REVISION / SOURCE_REPO / SOURCE_BRANCH."""
    from .provenance import resolve_provenance

    return resolve_provenance().to_pipeline_dict()
