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
EXCLUDED_CFGS = {"audit_main.cfg"}


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


def _extract_init_operators(tla_text: str) -> dict[str, set[str]]:
    """Find every `Init_main_<class>` operator and the literal set it
    passes to `InitBaseFor`.

    Returns {operator_name: {key_source literal, ...}}.
    """
    pattern = re.compile(
        r"^(Init_main_\w+)\s*==\s*\n"
        r"\s*/\\\s*InitBaseFor\s*\(\s*\{([^}]*)\}\s*\)",
        re.MULTILINE,
    )
    out: dict[str, set[str]] = {}
    for m in pattern.finditer(tla_text):
        name = m.group(1)
        raw = m.group(2)
        literals = {tok.strip() for tok in raw.split(",") if tok.strip()}
        if not literals:
            _die(f"{name} calls InitBaseFor with empty set")
        out[name] = literals
    if not out:
        _die("no Init_main_<class> operators found that call InitBaseFor({...})")
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
    sys.exit(0)


if __name__ == "__main__":
    main()
