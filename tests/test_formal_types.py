"""``formal/check_types.py`` runs under the ordinary test suite.

T3-T5 (templates, clauses, evidence class) need only this package. T1-T2
compare the registry with the assertion-type catalogue and run when it is
importable; otherwise the checker reports them as not established and this
test asserts that wording, so a missing catalogue is visible rather than
silently green.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "formal" / "check_types.py"


def _catalogue_path():
    """The catalogue file the checker will read, or ``None``.

    The same candidates in the same order as ``check_types._load_catalogue``:
    the installed package first, then a sibling checkout. Asking a different
    question here -- whether ANY reachable catalogue carries a name -- would
    make this test agree with the checker only where the two resolve to the
    same file, and a machine that has both an installed catalogue and a
    newer sibling checkout is exactly where they do not."""
    spec = importlib.util.find_spec("mipiti_mcp")
    candidates = [Path(p) / "assertion_types.py"
                  for p in (spec.submodule_search_locations or [])] if spec else []
    candidates.append(ROOT.parent / "mcp-server" / "src" / "mipiti_mcp" / "assertion_types.py")
    return next((c for c in candidates if c.is_file()), None)


def _catalogue_available() -> bool:
    return _catalogue_path() is not None


def _catalogue_declares(name: str) -> bool:
    """Whether the catalogue the checker reads carries a name a property
    needs (``MECHANISM_KINDS`` for T6, ``SOUNDNESS_CLASSES`` for T7,
    ``SAFE_FORMS`` for T8)."""
    path = _catalogue_path()
    return path is not None and name in path.read_text(encoding="utf-8")


def test_every_type_property_is_verified():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    if not _catalogue_available():
        missing = ["T1", "T2", "T6", "T7", "T8"]
        verified = ["T3", "T4", "T5"]
    else:
        missing = [p for p, name in (("T6", "MECHANISM_KINDS"), ("T7", "SOUNDNESS_CLASSES"),
                                     ("T8", "SAFE_FORMS"))
                   if not _catalogue_declares(name)]
        verified = [p for p in ("T1", "T2", "T6", "T7", "T8", "T3", "T4", "T5")
                    if p not in missing]
    if not missing:
        assert "ALL TYPE PROPERTIES VERIFIED" in result.stdout, result.stdout
    else:
        assert (f"TYPE PROPERTIES {', '.join(verified)} VERIFIED; "
                f"{', '.join(missing)} NOT ESTABLISHED") in result.stdout, result.stdout
    for prop in ("T3 templates", "T4 fail-closed + injection clauses", "T5 evidence class"):
        assert f"{prop} (" in result.stdout and "FAILED" not in result.stdout, result.stdout


def _checker_module():
    """``formal/check_types.py`` as a module, without running it."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_check_types", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Catalogue:
    """The two vocabulary tuples a T8 comparison reads, and no types: a
    catalogue whose published params are not part of what is compared."""

    ASSERTION_TYPES: tuple = ()

    def __init__(self, safe_forms, sink_kinds):
        self.SAFE_FORMS = tuple(safe_forms)
        self.SINK_KINDS = tuple(sink_kinds)


def test_the_sink_vocabulary_check_holds_the_two_declarations_equal():
    """T8 is only worth running if a disagreement fails it. The verifier's
    own tuples pass; a catalogue that publishes a form or a kind the engine
    does not know is caught, and so is one that drops one."""
    from mipiti_verify.languages import calls as C

    module = _checker_module()
    count, violations = module.check_t8(_Catalogue(C.SAFE_FORMS, C.SINK_KINDS))
    assert count > 0 and violations == [], violations

    _, extra_form = module.check_t8(_Catalogue(C.SAFE_FORMS + ("taint_free",), C.SINK_KINDS))
    assert any("safe form vocabulary differs" in v and "taint_free" in v for v in extra_form), extra_form

    _, missing_form = module.check_t8(_Catalogue(C.SAFE_FORMS[:-1], C.SINK_KINDS))
    assert any("safe form vocabulary differs" in v for v in missing_form), missing_form

    _, extra_kind = module.check_t8(_Catalogue(C.SAFE_FORMS, C.SINK_KINDS + ("thought",)))
    assert any("sink kind vocabulary differs" in v and "thought" in v for v in extra_kind), extra_kind
