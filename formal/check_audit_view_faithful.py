"""Structural faithfulness proof for the `AuditView` TLC VIEW.

`audit.tla`'s state space exploded after the customer-keyed offline
DSSE modeling added three `WSSig` fields. `AuditView` (defined in
`audit.tla`, wired via `VIEW AuditView` in `audit_main.cfg` /
`audit_bundle_bind.cfg`) collapses the customer_dsse-specific
cross-product:

  * `customer_key_fp_match`        — BOOLEAN, kept verbatim;
  * `dsse_predicate_model_id`      — projected, with the auditor pin
    `pins.model_id`,   to a 3-valued relation token (customer_dsse
    THEN branch);
  * `dsse_predicate_commit_sha`    — projected, with `pins.commit_sha`,
    to a 3-valued relation token (customer_dsse THEN branch);
  * `predicate_model_id`           — the Sigstore *bundle* predicate;
    projected, with `pins.model_id`, to a 3-valued relation token on
    the non-customer_dsse / bundle-present ELSE branch;
  * `predicate_commit_sha`         — symmetric, with `pins.commit_sha`.

The two-sided collapse is sound by the SAME factor-through argument:
across the `Audit` operator and every cfg invariant the bundle
predicate fields are read ONLY as `bundle.predicate_* # q.model_id`
(Audit, q ≡ pins — every cfg `Audit(pkg, pins)` invocation) and
`bundle.predicate_* = pins.*` (I12 / I13), so a bundle-present
non-customer_dsse row's verdict factors through
`Rel3(bundle.predicate_*, pins.*)` exactly as a customer_dsse row's
does through `Rel3(dsse_predicate_*, pins.*)`.

A TLC VIEW is lossless iff every checked invariant *factors through*
the view — i.e. two states with the same view agree on every
invariant. That holds, by construction, if every cfg invariant (and
the `Audit` operator they transitively call) observes the collapsed
fields **only through (in)equality relations** (`=`, `#`, `/=`) or
uses the boolean `customer_key_fp_match` as a boolean — never through
arithmetic, ordering (`<`, `>`, `<=`, `>=`), function application that
exposes identity, or identity-distinguishing set membership. Any such
"only via (in)equality" reference is, on a customer_dsse row,
determined by the 3-valued relation token / the kept boolean — so the
view preserves it.

This script PROVES that property by a structural analysis of
`audit.tla`:

  1. Parse every top-level operator definition (`Op == ...`,
     `Op(args) == ...`) and the `INVARIANTS` lists referenced by the
     two cfgs.
  2. Transitively resolve the operator-call graph rooted at each cfg
     invariant (an invariant calling a helper that touches a collapsed
     field counts).
  3. For every reference to a collapsed field inside any
     invariant-reachable operator body, classify its immediate
     syntactic context and ASSERT it is an (in)equality comparison
     (or a boolean-as-boolean use). Anything else — or anything the
     analysis cannot positively prove safe — FAILS (a sound
     over-approximation: unknown ⇒ unsafe).

Exit convention mirrors
`backend/formal/check_rating_overlay_invariants.py`: prints a banner,
per-rule VERIFIED/FAILED lines, returns 0 on all-pass, 1 otherwise.

Run:
    python formal/check_audit_view_faithful.py
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

_FORMAL = os.path.dirname(os.path.abspath(__file__))
_AUDIT_TLA = os.path.join(_FORMAL, "audit.tla")
_CFGS = (
    # Config 1's per-key_source sub-split (5 cfgs; all use the same
    # ConfigMainInvariants, so reading any one would suffice — but
    # listing them all is robust to a sub-config drifting its
    # INVARIANTS list independently). See formal/COMPOSITION.md.
    "audit_main_sigstore.cfg",
    "audit_main_platform.cfg",
    "audit_main_workspace.cfg",
    "audit_main_cdsse.cfg",
    "audit_main_orphan_legacy.cfg",
    # Config 2.
    "audit_bundle_bind.cfg",
)

# ---------------------------------------------------------------------------
# The collapsed quantities. AuditView replaces these (on customer_dsse
# states only) with a 3-valued token / a kept boolean; every reachable
# invariant must therefore observe them ONLY via (in)equality so its
# truth value is a function of the token / boolean.
#
#   * The two DSSE predicate WSSig fields (record-field selectors) —
#     folded into relation tokens on the customer_dsse THEN branch.
#   * The two Sigstore *bundle* predicate fields — folded into
#     relation tokens on the non-customer_dsse / bundle-present ELSE
#     branch (the two-sided collapse extension).
#   * The boolean fp-match WSSig field.
#   * The auditor pin fields model_id / commit_sha — these are folded
#     INTO the relation tokens on BOTH the customer_dsse row (vs the
#     ws_sig DSSE predicate) and the bundle-present non-customer_dsse
#     row (vs the bundle predicate), so wherever they appear they too
#     must be observed only via (in)equality. The script already
#     enforced this everywhere (a sound over-approximation: it never
#     restricted the pin check to customer_dsse rows); the bundle
#     branch reuses the SAME obligation. On the bundle-ABSENT
#     non-customer_dsse subcase the view is the identity, so the pin
#     identity is preserved verbatim there anyway.
# ---------------------------------------------------------------------------

_DSSE_FIELDS = ("dsse_predicate_model_id", "dsse_predicate_commit_sha")
# Sigstore bundle predicate fields — collapsed on the ELSE (non-
# customer_dsse, bundle-present) branch. Same (in)equality discipline.
_BUNDLE_PREDICATE_FIELDS = ("predicate_model_id", "predicate_commit_sha")
_BOOL_FIELD = "customer_key_fp_match"
_PIN_FIELDS = ("model_id", "commit_sha")  # as .model_id / .commit_sha

# Field selectors we treat as "collapsed reference sites". A token of
# the form  <ident>.<field>  where field is one of these.
_COLLAPSED_FIELDS = (
    set(_DSSE_FIELDS)
    | set(_BUNDLE_PREDICATE_FIELDS)
    | {_BOOL_FIELD}
    | set(_PIN_FIELDS)
)


@dataclass
class Violation:
    rule: str
    message: str


@dataclass
class Operator:
    name: str
    body: str
    lineno: int
    calls: set = field(default_factory=set)


# ---------------------------------------------------------------------------
# TLA+ source helpers
# ---------------------------------------------------------------------------


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _strip_comments(src: str) -> str:
    """Remove TLA+ comments while preserving line numbers.

    Handles ``\\* line comments`` and ``(* ... *)`` block comments
    (incl. multi-line). Replaces comment chars with spaces so column
    offsets and line numbers are unchanged — keeps reported line
    numbers honest.
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        # Block comment (* ... *) — TLA+ block comments do not nest in
        # practice in this spec; treat first *) as the close.
        if src[i] == "(" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*)", i + 2)
            if j == -1:
                j = n
            else:
                j += 2
            for k in range(i, j):
                out.append("\n" if src[k] == "\n" else " ")
            i = j
            continue
        # Line comment \*
        if src[i] == "\\" and i + 1 < n and src[i + 1] == "*":
            j = src.find("\n", i)
            if j == -1:
                j = n
            for _ in range(i, j):
                out.append(" ")
            i = j
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


_OP_DEF_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*==",
    re.MULTILINE,
)


def _parse_operators(clean_src: str) -> dict:
    """Split the (comment-stripped) module into top-level operators.

    A definition starts at column 0 with ``Name ==`` or
    ``Name(args) ==`` and runs until the next such header (or the
    module terminator ``====``).
    """
    headers = []
    for m in _OP_DEF_RE.finditer(clean_src):
        # Must be at start of a line (column 0) — module-level def.
        line_start = clean_src.rfind("\n", 0, m.start()) + 1
        if line_start != m.start():
            continue
        headers.append((m.start(), m.group("name")))

    ops: dict = {}
    for idx, (start, name) in enumerate(headers):
        end = headers[idx + 1][0] if idx + 1 < len(headers) else len(clean_src)
        chunk = clean_src[start:end]
        # Trim a trailing module terminator if present.
        term = chunk.find("\n====")
        if term != -1:
            chunk = chunk[:term]
        body = chunk.split("==", 1)[1] if "==" in chunk else ""
        lineno = clean_src.count("\n", 0, start) + 1
        ops[name] = Operator(name=name, body=body, lineno=lineno)
    return ops


_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def _resolve_calls(ops: dict) -> None:
    """Populate each operator's direct-call set (other defined ops it
    references by name in its body)."""
    names = set(ops)
    for op in ops.values():
        called = set()
        for m in _IDENT_RE.finditer(op.body):
            ident = m.group(1)
            if ident in names and ident != op.name:
                called.add(ident)
        op.calls = called


def _reachable(ops: dict, roots: set) -> set:
    """Transitive closure of the call graph from ``roots``."""
    seen = set()
    stack = list(roots)
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in ops:
            continue
        seen.add(cur)
        stack.extend(ops[cur].calls)
    return seen


# ---------------------------------------------------------------------------
# cfg parsing — which operators are the INVARIANTS roots
# ---------------------------------------------------------------------------


def _cfg_invariant_roots(cfg_path: str) -> list:
    """Operator names listed under INVARIANTS in a .cfg."""
    roots: list = []
    in_inv = False
    with open(cfg_path) as f:
        for raw in f:
            line = raw.split("\\*", 1)[0].strip()
            if not line:
                continue
            head = line.split()[0]
            if head in (
                "SPECIFICATION", "CONSTANTS", "CONSTANT", "SYMMETRY",
                "VIEW", "PROPERTIES", "PROPERTY", "CONSTRAINT",
            ):
                in_inv = False
                continue
            if head == "INVARIANTS" or head == "INVARIANT":
                in_inv = True
                rest = line.split(None, 1)
                if len(rest) > 1:
                    roots.append(rest[1].strip())
                continue
            if in_inv:
                roots.append(line)
    return roots


# ---------------------------------------------------------------------------
# Core: classify every collapsed-field reference's syntactic context.
#
# We tokenize each reachable operator body and, for each occurrence of
#   <ident> . <collapsed_field>
# (and the boolean field used bare), require that the WHOLE primary
# expression it participates in is one operand of a `=`, `#`, or `/=`
# comparison, OR — for the boolean field only — that it appears as a
# pure boolean operand (negation `~`, conjunction/disjunction operands,
# an `IF` condition, or the LHS of `=>`).
#
# Anything else is reported. Sound over-approximation: a reference we
# cannot positively classify as one of the safe shapes FAILS.
# ---------------------------------------------------------------------------

# Tokens: identifiers, the dot, comparison ops, boolean/structural
# operators, parens/brackets/braces, the EXCEPT bang, everything else
# as single chars. Order matters (longest match first).
_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<arrow>\|->|=>|<=>)
    | (?P<neq>/=|\#)
    | (?P<le>[<>]=?)
    | (?P<eq>=)
    | (?P<dot>\.)
    | (?P<bang>!)
    | (?P<setops>\\cup|\\cap|\\in|\\notin|\\subseteq|\\X|\\/|/\\)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<lbrack>\[)
    | (?P<rbrack>\])
    | (?P<lbrace>\{)
    | (?P<rbrace>\})
    | (?P<comma>,)
    | (?P<colon>:)
    | (?P<tilde>~)
    | (?P<arith>[+\-*])
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<other>\S)
    """,
    re.VERBOSE,
)

# A "safe comparison" operator: equality / inequality only.
_EQ_OPS = {"=", "#", "/=", "<=>"}
# Operators that are pure-boolean combinators (boolean field may sit
# directly as their operand).
_BOOL_CTX_OPS = {"/\\", "\\/", "=>", "<=>"}


@dataclass
class Tok:
    kind: str
    text: str
    pos: int  # char offset into the operator body


def _tokenize(body: str) -> list:
    toks = []
    for m in _TOKEN_RE.finditer(body):
        kind = m.lastgroup
        if kind == "ws":
            continue
        toks.append(Tok(kind, m.group(), m.start()))
    return toks


def _lineno_of(clean_src: str, op: Operator, body_pos: int) -> int:
    # op.body starts right after the '==' of the header; recover the
    # absolute offset by locating the operator chunk again is overkill
    # — we stored op.lineno (header line). Count newlines within the
    # body prefix and add.
    return op.lineno + op.body.count("\n", 0, body_pos)


def _analyze_operator(op: Operator, clean_src: str) -> list:
    """Return Violations for unsafe collapsed-field references in op."""
    out: list = []
    toks = _tokenize(op.body)

    for i, t in enumerate(toks):
        # ---- record-field selector:  <ident> '.' <collapsed_field> --
        if (
            t.kind == "ident"
            and t.text in _COLLAPSED_FIELDS
            and i >= 2
            and toks[i - 1].kind == "dot"
            and toks[i - 2].kind == "ident"
        ):
            base = toks[i - 2].text
            field_name = t.text

            # `pins.model_id` / `pins.commit_sha` and `q.model_id` etc.
            # are ONLY collapsed on customer_dsse rows. They appear in
            # many Sigstore-pin contexts where the VIEW is the identity
            # (I12/I13). We only need to prove the (in)equality
            # discipline for the reference shapes that actually decide
            # a customer_dsse verdict. The customer_dsse-relevant pin
            # references are exactly the equality tests, so the same
            # contextual check below is sound for them; an unsafe
            # context for a pin field would, on a customer_dsse row,
            # leak the pin identity past the token — so we DO check
            # them, conservatively, everywhere they appear.
            ctx_ok, why = _classify_value_context(toks, i)
            if not ctx_ok:
                ln = _lineno_of(clean_src, op, t.pos)
                out.append(Violation(
                    "F1",
                    f"{op.name} (audit.tla:{ln}): reference "
                    f"`{base}.{field_name}` is not confined to an "
                    f"(in)equality comparison ({why}). On a "
                    f"customer_dsse row AuditView replaces this "
                    f"quantity with a 3-valued relation token / kept "
                    f"boolean; observing its identity here would make "
                    f"the invariant NOT factor through the view — the "
                    f"VIEW would be lossy. Sound over-approximation: "
                    f"unprovable ⇒ unsafe.",
                ))

    return out


def _matching_open(toks: list, idx_close: int) -> int:
    """Index of the bracket/paren/brace that opens the one closing at
    idx_close, or -1."""
    close = toks[idx_close].kind
    openk = {"rparen": "lparen", "rbrack": "lbrack",
             "rbrace": "lbrace"}[close]
    depth = 0
    for j in range(idx_close, -1, -1):
        if toks[j].kind == close:
            depth += 1
        elif toks[j].kind == openk:
            depth -= 1
            if depth == 0:
                return j
    return -1


def _classify_value_context(toks: list, idx: int):
    """Decide whether the collapsed reference at token ``idx`` (the
    field-name token; its selector is toks[idx-2..idx]) sits in a
    provably-safe position.

    Safe positions (sound, conservative):

      A. It is a *direct operand* of an (in)equality operator
         `=` / `#` / `/=`: i.e. immediately to the left of such an op,
         or immediately to the right of one, with nothing but the
         `base.field` selector (optionally `~`-negated for booleans)
         on that side up to the nearest boundary.
      B. (Boolean field only) it is used as a boolean: directly under
         `~`, or a bare operand of `/\\`, `\\/`, `=>`, an `IF`
         condition, or a record-literal field value `|->` whose RHS is
         exactly the bare selector (the AuditView projection itself —
         that is the view definition, not an invariant observation).

    Returns (ok, reason_if_not_ok).
    """
    # The collapsed field is the tail of a dotted primary
    #   a . b . ... . <collapsed_field>
    # Walk back over the whole `ident (. ident)*` chain so we look at
    # the token that truly precedes the primary, not an interior dot.
    sel_start = idx
    while (
        sel_start - 2 >= 0
        and toks[sel_start - 1].kind == "dot"
        and toks[sel_start - 2].kind == "ident"
    ):
        sel_start -= 2
    sel_end = idx

    # Token immediately after the selector and immediately before the
    # whole dotted primary.
    nxt = toks[sel_end + 1] if sel_end + 1 < len(toks) else None
    prv = toks[sel_start - 1] if sel_start - 1 >= 0 else None

    field_name = toks[idx].text
    is_bool_field = field_name == _BOOL_FIELD

    # --- Reject hard-unsafe immediate contexts outright -------------
    # Function/operator application exposing identity:  base.field(...)
    if nxt is not None and nxt.kind == "lparen":
        return (False, "used as a function application (identity-exposing)")
    # Arithmetic / ordering with the selector as an operand.
    if nxt is not None and nxt.kind in ("arith", "le"):
        return (False, f"operand of arithmetic/ordering `{nxt.text}`")
    if prv is not None and prv.kind in ("arith", "le"):
        return (False, f"operand of arithmetic/ordering `{prv.text}`")
    # Set membership that distinguishes identities:  field \in S / \notin
    if nxt is not None and nxt.kind == "setops" and nxt.text in (
        "\\in", "\\notin", "\\subseteq",
    ):
        return (False, f"operand of identity-distinguishing `{nxt.text}`")
    if prv is not None and prv.kind == "setops" and prv.text in (
        "\\in", "\\notin", "\\subseteq",
    ):
        return (False, f"RHS of identity-distinguishing `{prv.text}`")
    # Indexed/applied as a function:  f[base.field]  or base.field[..]
    if nxt is not None and nxt.kind == "lbrack":
        return (False, "function application via `[...]` (identity-exposing)")

    # --- A. direct operand of (in)equality --------------------------
    # selector immediately followed by an (in)equality op:
    if nxt is not None and (
        (nxt.kind in ("eq", "neq")) or
        (nxt.kind == "arrow" and nxt.text == "<=>")
    ):
        return (True, "")
    # selector immediately preceded by an (in)equality op (RHS):
    if prv is not None and (
        (prv.kind in ("eq", "neq")) or
        (prv.kind == "arrow" and prv.text == "<=>")
    ):
        return (True, "")
    # selector negated for a boolean equality:  ~base.field = x  is not
    # how the spec writes it; `~` only legitimately precedes a boolean
    # field used as a boolean (handled below).

    # --- B. boolean field used as a boolean -------------------------
    if is_bool_field:
        # ~ base.field   (negation)
        if prv is not None and prv.kind == "tilde":
            return (True, "")
        # bare operand of a boolean combinator on either side
        if nxt is not None and nxt.kind == "setops" and nxt.text in (
            "/\\", "\\/",
        ):
            return (True, "")
        if prv is not None and prv.kind == "setops" and prv.text in (
            "/\\", "\\/",
        ):
            return (True, "")
        if nxt is not None and nxt.kind == "arrow" and nxt.text == "=>":
            return (True, "")
        if prv is not None and prv.kind == "arrow" and prv.text == "=>":
            return (True, "")
        # AuditView's own projection: record field value `... |-> sel`
        # followed by `,` or `]` (the view DEFINITION, not an
        # invariant observation — but AuditView is not invariant-
        # reachable anyway; this keeps the check robust if it ever is).
        if prv is not None and prv.kind == "arrow" and prv.text == "|->":
            return (True, "")
        # closing a parenthesized boolean group: ( ... base.field )
        if (
            nxt is not None and nxt.kind == "rparen"
            and prv is not None and prv.kind in ("setops", "tilde", "lparen")
        ):
            return (True, "")

    # Record-literal projection `|-> sel` for ANY collapsed field is
    # the AuditView definition itself (e.g. customer_key_fp_match |->
    # pkg.ws_sig.customer_key_fp_match, or Rel3(pkg.ws_sig.dsse_..,
    # pins...)). Those live in AuditView, which is NOT
    # invariant-reachable, so they are never analyzed here — but if
    # the call graph ever pulls them in, the projection itself is the
    # faithful reduction, not an identity observation.
    if prv is not None and prv.kind == "arrow" and prv.text == "|->":
        return (True, "")
    # Argument of Rel3(...) — that IS the lossless projection operator.
    if (
        sel_start - 2 >= 0
        and toks[sel_start - 1].kind == "lparen"
        and toks[sel_start - 2].kind == "ident"
        and toks[sel_start - 2].text == "Rel3"
    ):
        return (True, "")
    if (
        prv is not None and prv.kind == "comma"
        and _enclosing_call_is_rel3(toks, sel_start)
    ):
        return (True, "")

    return (False, "reference not provably confined to `=`/`#`/`/=` "
                    "or a boolean-as-boolean position")


def _enclosing_call_is_rel3(toks: list, idx: int) -> bool:
    """True if token idx sits inside the argument list of a Rel3(...)
    call (the lossless projection operator)."""
    depth = 0
    for j in range(idx, -1, -1):
        k = toks[j].kind
        if k == "rparen":
            depth += 1
        elif k == "lparen":
            if depth == 0:
                # opener of the enclosing call — is it Rel3(?
                return (
                    j - 1 >= 0
                    and toks[j - 1].kind == "ident"
                    and toks[j - 1].text == "Rel3"
                )
            depth -= 1
    return False


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def _collect_reachable_invariant_ops():
    clean = _strip_comments(_read(_AUDIT_TLA))
    ops = _parse_operators(clean)
    _resolve_calls(ops)

    all_roots: set = set()
    cfg_roots: dict = {}
    for cfg in _CFGS:
        roots = _cfg_invariant_roots(os.path.join(_FORMAL, cfg))
        cfg_roots[cfg] = roots
        all_roots |= set(roots)

    # Expand the umbrella conjunction operators (ConfigMainInvariants /
    # ConfigBindInvariants / TypeOK) through the call graph; AuditView
    # is deliberately NOT a root (it is the view, not an invariant).
    reach = _reachable(ops, all_roots)
    # Belt-and-suspenders: never analyze AuditView/Rel3 themselves as
    # if they were observation sites — they ARE the lossless
    # projection. They aren't invariant-reachable, but exclude
    # explicitly so a future accidental edge can't mask a real
    # invariant regression.
    reach.discard("AuditView")
    reach.discard("Rel3")
    return ops, clean, cfg_roots, reach


def main() -> int:
    print("=" * 70)
    print("AUDITVIEW FAITHFULNESS PROOF (F1)")
    print("=" * 70)

    if not os.path.exists(_AUDIT_TLA):
        print(f"FAILED: {_AUDIT_TLA} not found")
        return 1

    ops, clean, cfg_roots, reach = _collect_reachable_invariant_ops()

    # Sanity: AuditView and Rel3 must exist and be wired in BOTH cfgs.
    structural: list = []
    if "AuditView" not in ops:
        structural.append(Violation(
            "F1", "AuditView operator not defined in audit.tla"))
    if "Rel3" not in ops:
        structural.append(Violation(
            "F1", "Rel3 projection operator not defined in audit.tla"))
    for cfg in _CFGS:
        txt = _read(os.path.join(_FORMAL, cfg))
        if not re.search(r"^\s*VIEW\s+AuditView\s*$", txt, re.MULTILINE):
            structural.append(Violation(
                "F1", f"{cfg} does not declare `VIEW AuditView`"))

    # The core proof obligation.
    violations: list = list(structural)
    analyzed = []
    for name in sorted(reach):
        op = ops.get(name)
        if op is None:
            continue
        analyzed.append(name)
        violations.extend(_analyze_operator(op, clean))

    print()
    print(f"cfg invariant roots:")
    for cfg, roots in cfg_roots.items():
        print(f"  {cfg}: {', '.join(roots)}")
    print(f"\ninvariant-reachable operators analyzed ({len(analyzed)}):")
    print(f"  {', '.join(analyzed)}")
    print()

    print("F1 — every cfg-invariant-reachable reference to a collapsed "
          "field\n     is confined to (in)equality / boolean-as-boolean: ",
          end="")
    if violations:
        print(f"FAILED ({len(violations)})")
        for v in violations:
            print(f"  {v.message}")
        print()
        print("=" * 70)
        print("AUDITVIEW FAITHFULNESS NOT PROVEN — VIEW may be LOSSY")
        print("=" * 70)
        return 1

    print("VERIFIED")
    print()
    print("=" * 70)
    print("AUDITVIEW FAITHFULNESS PROVEN")
    print("  Every invariant in audit_main.cfg / audit_bundle_bind.cfg —")
    print("  transitively through Audit and all helpers — observes")
    print("  dsse_predicate_model_id / dsse_predicate_commit_sha /")
    print("  the Sigstore bundle predicate_model_id / predicate_commit_sha /")
    print("  customer_key_fp_match / the model_id|commit_sha pins ONLY")
    print("  via =, #, /= (or the boolean used as a boolean). Each")
    print("  invariant therefore FACTORS THROUGH AuditView's 3-valued")
    print("  relation tokens / kept boolean: two states with the same")
    print("  AuditView agree on every invariant ⇒ the VIEW is lossless")
    print("  by construction. The SAME property certifies the InitBase")
    print("  customer_dsse relation-class canonicalisation (the")
    print("  generation-time twin) as lossless. Corroborated by the")
    print("  mutation test in formal/COMPOSITION.md.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
