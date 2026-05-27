"""Mechanical totality check for the Config-1 key_source sub-split.

Asserts that the per-key_source sub-config partition (audit_main_*.cfg
+ their Init_main_<class>/InitBaseFor calls in audit.tla) is:

  1. TOTAL — the union of the allowed key_source sets across all
     sub-configs equals KeySources exactly. No key_source value is
     uncovered (a row whose class is missing from every sub-config
     would never be exercised by any TLC run).

  2. DISJOINT — the allowed key_source sets are pairwise disjoint.
     Overlap is wasted coverage (the same row enumerated by two
     sub-configs); it doesn't break soundness but signals a
     partition mistake.

Soundness of the partition itself rests on the per-(pkg, pins)-row
nature of every invariant in `ConfigMainInvariants` (key_source is a
property of the row; restricting allowedKS just enumerates a subset
of rows; every invariant whose premise can fire on a row's class is
still checked there). That property is intrinsic to the invariants'
shape — it's exactly what `check_audit_view_faithful.py` already
mechanically verifies as a prerequisite for the AuditView reduction;
re-asserting it here would be redundant. This check covers the
*partition* mechanics — totality + disjointness — that are unique
to the sub-split.

Layout of the things checked:

    audit.tla:
        KeySources == {KS_SIGSTORE, KS_PLATFORM, KS_WORKSPACE,
                       KS_CUSTOMER_DSSE, KS_ORPHAN, KS_LEGACY}
        Init_main_<class> == /\\ InitBaseFor({<allowedKS literals>})
                             /\\ <bundle_bind pinning>

    formal/audit_main_<class>.cfg:
        SPECIFICATION Spec_main_<class>

The script pairs each cfg's SPECIFICATION with the Init operator it
selects (Spec_main_<class> ⇒ Init_main_<class>) and reads the
literal `{...}` argument to InitBaseFor as that sub-config's
allowedKS. The union and disjointness assertions then run on the
collected allowedKS sets.

Non-vacuity is established empirically by an operator-injected gap
(e.g., removing one class from an Init_main_<class>'s allowedKS, or
deleting one of the sub-config files): the corresponding assertion
fires with a precise diagnostic naming the missing/overlapping
class. Re-run after reverting the injection to confirm the gap was
the cause.

Exit codes:
    0 — partition is total and disjoint.
    1 — totality or disjointness assertion failed; diagnostic on
        stderr names the offending key_source value(s).

The check is read-only on the spec source; no TLC invocation needed
(seconds, not minutes).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FORMAL_DIR = Path(__file__).resolve().parent
AUDIT_TLA = FORMAL_DIR / "audit.tla"
SUBCONFIG_GLOB = "audit_main_*.cfg"
# audit_main.cfg (the un-split full-domain Config-1) is intentionally
# excluded — the sub-split's totality argument is about the per-class
# Inits, not the original aggregate config.
#
# The scenario-knob cfgs (added 2026-05-27, gap #249 / #254 / #258
# backfill) are also excluded: they partition a DIFFERENT dimension
# (the orphan-results / model-only / sufficiency scenario knobs) and
# pin key_source to a single canonical class (KS_PLATFORM). They are
# not contributors to the key_source partition; their own scenario
# partition is enforced by Init pinning per-cfg.
EXCLUDED_CFGS = {
    "audit_main.cfg",
    "audit_main_orphan_results_blocked.cfg",
    "audit_main_orphan_results_allowed.cfg",
    "audit_main_model_only.cfg",
    "audit_main_sufficiency.cfg",
}


def _die(msg: str) -> None:
    sys.stderr.write(f"PARTITION TOTALITY CHECK FAILED: {msg}\n")
    sys.exit(1)


def _extract_key_sources(tla_text: str) -> set[str]:
    """Find `KeySources == { ... }` and return the set of literals.

    The TLA+ definition spans multiple lines; collect the brace-
    enclosed list and split on commas.
    """
    m = re.search(r"^KeySources\s*==\s*\{([^}]*)\}", tla_text, re.MULTILINE | re.DOTALL)
    if not m:
        _die("could not find `KeySources == { ... }` in audit.tla")
    raw = m.group(1)
    values = {token.strip() for token in raw.split(",") if token.strip()}
    if not values:
        _die("KeySources is empty — nothing to partition")
    return values


# Verdict values the Audit operator may return. Mirrors the
# enumeration in audit.tla's `Verdict == { ... }` set declaration.
# Used by the verdict-partition-totality check: every value the
# spec's `Audit` operator can produce must appear in `Verdict`
# (otherwise TLC's type check fails) AND `Verdict` must enumerate
# every value the real-code mirror in cli.py can return.
#
# Maintained as the explicit-list authoritative spec; the script
# extracts the audit.tla declaration and asserts set equality.
_EXPECTED_VERDICTS = frozenset({
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "UNVERIFIED",
    "FAILED",
    "USAGE_ERROR",
    "MODEL_ONLY",  # added 2026-05-27, gap #254 backfill
})


def _extract_verdict_values(tla_text: str) -> set[str]:
    """Find `Verdict == { ... }` and return the set of quoted
    string literals it enumerates.

    The audit.tla declaration spans multiple lines and may be
    interleaved with line comments; this extractor strips comments
    line-by-line before parsing the brace-enclosed string list.
    """
    m = re.search(
        r"^Verdict\s*==\s*\{((?:[^{}]|\{[^{}]*\})*)\}",
        tla_text,
        re.MULTILINE | re.DOTALL,
    )
    if not m:
        _die("could not find `Verdict == { ... }` in audit.tla")
    raw = m.group(1)
    # Strip TLA+ line comments (`\* ...`) so embedded text doesn't
    # confuse the literal extraction.
    cleaned_lines = []
    for line in raw.splitlines():
        idx = line.find("\\*")
        if idx >= 0:
            line = line[:idx]
        cleaned_lines.append(line)
    cleaned = " ".join(cleaned_lines)
    values = set(re.findall(r'"([^"]+)"', cleaned))
    if not values:
        _die("Verdict is empty — nothing to enumerate")
    return values


# Hardcoded mapping from specialized generator names to their fixed
# `allowedKS`. Add a new entry here when a new specialized PackageGen*
# is introduced (e.g., a future PackageGenForOrphan that pins specific
# fields). The mapping captures the contract the specialized generator
# carries — extracting it from the .tla body itself would require a
# full parser; this list is the explicit, reviewable surface.
_SPECIALIZED_GENERATORS: dict[str, frozenset[str]] = {
    # PackageGenForCdsse — bundle pinned to {ABSENT} per R12, WSSig
    # generator restricted to {KS_CUSTOMER_DSSE}. See audit.tla.
    "PackageGenForCdsse": frozenset({"KS_CUSTOMER_DSSE"}),
}


# Init operators that look like key_source-partition members
# (Init_main_<name>) but actually partition a different dimension
# (the scenario knobs — has_orphan_results / is_model_only /
# sufficiency_state). Their cfgs are already in EXCLUDED_CFGS so
# they never feed cfg_to_allowedKS, but the body-shape walk reaches
# them too. Listed here so they're skipped at extraction time and
# don't trip the `_SPECIALIZED_GENERATORS` membership check.
#
# Each entry must be paired with the corresponding EXCLUDED_CFGS
# entry (the cfg whose SPECIFICATION selects it). The two lists are
# the explicit, reviewable surface for "this Init_main_<name> is
# scenario-side, not key_source-side."
_SCENARIO_INIT_OPERATORS = frozenset({
    "Init_main_orphan_results",
    "Init_main_model_only",
    "Init_main_sufficiency",
})


def _extract_init_operators(tla_text: str) -> dict[str, set[str]]:
    """Find every `Init_main_<class>` operator and the `allowedKS` it
    enumerates over.

    Two recognized body shapes:
      - `/\\ InitBaseFor({KS_..., KS_...})` — generic per-key_source
        sub-config; allowedKS = the literal set.
      - `/\\ pkg \\in <SpecializedGenerator>` — specialized generator;
        allowedKS = the hardcoded mapping in _SPECIALIZED_GENERATORS.

    Returns {operator_name: {key_source literal, ...}}.
    """
    out: dict[str, set[str]] = {}

    # Shape 1: InitBaseFor({...}) calls.
    generic_pattern = re.compile(
        r"^(Init_main_\w+)\s*==\s*\n"
        r"\s*/\\\s*InitBaseFor\s*\(\s*\{([^}]*)\}\s*\)",
        re.MULTILINE,
    )
    for m in generic_pattern.finditer(tla_text):
        name = m.group(1)
        if name in _SCENARIO_INIT_OPERATORS:
            continue
        raw = m.group(2)
        literals = {tok.strip() for tok in raw.split(",") if tok.strip()}
        if not literals:
            _die(f"{name} calls InitBaseFor with empty set")
        out[name] = literals

    # Shape 2: `pkg \in <SpecializedGenerator>` calls — lift the
    # generator's hardcoded allowedKS from _SPECIALIZED_GENERATORS.
    specialized_pattern = re.compile(
        r"^(Init_main_\w+)\s*==\s*\n"
        r"\s*/\\\s*pkg\s*\\in\s*(\w+)",
        re.MULTILINE,
    )
    for m in specialized_pattern.finditer(tla_text):
        name = m.group(1)
        if name in _SCENARIO_INIT_OPERATORS:
            continue
        gen = m.group(2)
        if name in out:
            # Already matched by generic_pattern — Init_main_<class>
            # uses BOTH InitBaseFor and a specialized gen? That's a
            # spec inconsistency; flag rather than silently merge.
            _die(
                f"{name} matches BOTH shapes (InitBaseFor + pkg \\in {gen}). "
                f"Each Init_main_<class> must use exactly one allowedKS source."
            )
        if gen not in _SPECIALIZED_GENERATORS:
            _die(
                f"{name} uses specialized generator `{gen}` which is not in "
                f"_SPECIALIZED_GENERATORS. Add `{gen}` to that mapping with "
                f"its allowedKS (the set of key_source values its WSSig "
                f"generator enumerates over)."
            )
        out[name] = set(_SPECIALIZED_GENERATORS[gen])

    if not out:
        _die(
            "no Init_main_<class> operators found (either `InitBaseFor({...})` "
            "or `pkg \\in <SpecializedGenerator>` shape)"
        )
    return out


_SPEC_PATTERN = re.compile(r"^\s*SPECIFICATION\s+(Spec_main_\w+)\s*$", re.MULTILINE)


def _spec_to_init(spec: str) -> str:
    """Spec_main_<class> ⇒ Init_main_<class> (the mechanical pairing
    audit.tla declares: `Spec_main_X == Init_main_X /\\ [][Next]_vars`).
    """
    return spec.replace("Spec_main_", "Init_main_", 1)


def _extract_subconfig_specs() -> dict[str, str]:
    """Find every sub-config cfg file and the SPECIFICATION it selects.

    Returns {cfg_filename: SPECIFICATION_operator_name}.
    """
    out: dict[str, str] = {}
    for cfg in sorted(FORMAL_DIR.glob(SUBCONFIG_GLOB)):
        if cfg.name in EXCLUDED_CFGS:
            continue
        text = cfg.read_text(encoding="utf-8")
        m = _SPEC_PATTERN.search(text)
        if not m:
            _die(f"{cfg.name}: no SPECIFICATION Spec_main_<class> line found")
        out[cfg.name] = m.group(1)
    if not out:
        _die(f"no audit_main_*.cfg sub-configs found in {FORMAL_DIR}")
    return out


def main() -> None:
    if not AUDIT_TLA.exists():
        _die(f"{AUDIT_TLA} not found")
    tla_text = AUDIT_TLA.read_text(encoding="utf-8")

    key_sources = _extract_key_sources(tla_text)
    init_operators = _extract_init_operators(tla_text)
    subconfig_specs = _extract_subconfig_specs()

    # Resolve each cfg → its allowedKS via Spec_main_X ⇒ Init_main_X.
    cfg_to_allowedKS: dict[str, set[str]] = {}
    for cfg, spec in subconfig_specs.items():
        init = _spec_to_init(spec)
        if init not in init_operators:
            _die(
                f"{cfg}: SPECIFICATION {spec} ⇒ {init}, but no such "
                f"`{init} == InitBaseFor({{ ... }})` declaration in audit.tla. "
                f"Either rename the cfg's SPECIFICATION to match an existing "
                f"Init_main_<class>, or add the missing Init operator."
            )
        cfg_to_allowedKS[cfg] = init_operators[init]

    # 1. TOTALITY — union must equal KeySources exactly.
    union: set[str] = set()
    for ks in cfg_to_allowedKS.values():
        union |= ks
    uncovered = key_sources - union
    extra = union - key_sources
    if uncovered:
        _die(
            f"TOTALITY VIOLATED — key_source value(s) {sorted(uncovered)} "
            f"are NOT covered by any sub-config. A row of that class would "
            f"never be enumerated by any TLC run. Add the missing class to "
            f"some Init_main_<class>'s allowedKS, or add a new sub-config. "
            f"(KeySources: {sorted(key_sources)}; covered: {sorted(union)})"
        )
    if extra:
        _die(
            f"BAD allowedKS — {sorted(extra)} appear in some Init_main_<class> "
            f"but are not in KeySources. Likely a typo; this would either "
            f"silently fail TLC type-checking or expand the spec beyond "
            f"what KeySources declares. Fix the typo or update KeySources."
        )

    # 2. DISJOINTNESS — pairwise intersections must be empty.
    cfgs = sorted(cfg_to_allowedKS)
    overlaps: list[tuple[str, str, set[str]]] = []
    for i, a in enumerate(cfgs):
        for b in cfgs[i + 1 :]:
            inter = cfg_to_allowedKS[a] & cfg_to_allowedKS[b]
            if inter:
                overlaps.append((a, b, inter))
    if overlaps:
        details = "; ".join(f"{a} ∩ {b} = {sorted(inter)}" for a, b, inter in overlaps)
        _die(
            f"DISJOINTNESS VIOLATED — sub-configs share key_source value(s): "
            f"{details}. Rows of an overlapping class would be enumerated by "
            f"two sub-configs (wasted coverage). Either move the class to "
            f"exactly one Init_main_<class>'s allowedKS, or rethink the "
            f"partition shape."
        )

    print(
        f"PARTITION TOTAL + DISJOINT: {len(cfg_to_allowedKS)} sub-configs "
        f"covering {sorted(key_sources)} via:"
    )
    for cfg in cfgs:
        ks = cfg_to_allowedKS[cfg]
        print(f"  {cfg}: {sorted(ks)}")
    print("=" * 70)
    print("PARTITION SOUND (totality + disjointness mechanically verified)")

    # 3. VERDICT-VALUE PARTITION — the closed set of values
    # audit.tla's `Audit` operator may return. Asserts the audit.tla
    # `Verdict == { ... }` set equals the expected set, so:
    #   - Every value the spec mirror in tests/test_spec_invariants.py
    #     can return is declared (TLC's type system would otherwise
    #     accept an unexpected literal and trip TypeOK at run time).
    #   - No stale value remains after a verdict was retired.
    # Adding a new verdict requires updating BOTH audit.tla and
    # _EXPECTED_VERDICTS in this script in one PR — a single source
    # of staleness on either side fails the check loudly.
    verdict_values = _extract_verdict_values(tla_text)
    missing = _EXPECTED_VERDICTS - verdict_values
    extra_v = verdict_values - _EXPECTED_VERDICTS
    if missing:
        _die(
            f"VERDICT PARTITION VIOLATED — value(s) {sorted(missing)} "
            f"are expected (per _EXPECTED_VERDICTS) but NOT in audit.tla's "
            f"`Verdict` set. The spec mirror in tests/test_spec_invariants.py "
            f"can produce a verdict TLC will reject as ill-typed. Add the "
            f"value to audit.tla's `Verdict == { '{' } ... { '}' }`."
        )
    if extra_v:
        _die(
            f"VERDICT PARTITION VIOLATED — value(s) {sorted(extra_v)} appear "
            f"in audit.tla's `Verdict` set but are not in _EXPECTED_VERDICTS. "
            f"Likely a stale value left after a verdict was retired. Drop it "
            f"from audit.tla, or — if newly introduced — add it to "
            f"_EXPECTED_VERDICTS in this script."
        )
    print(
        f"VERDICT PARTITION TOTAL: {sorted(verdict_values)} "
        f"(audit.tla `Verdict` set matches _EXPECTED_VERDICTS)"
    )
    print("=" * 70)
    sys.exit(0)


if __name__ == "__main__":
    main()
