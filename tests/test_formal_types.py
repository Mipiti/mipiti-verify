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


def _catalogue_available() -> bool:
    spec = importlib.util.find_spec("mipiti_mcp")
    if spec is not None and spec.submodule_search_locations:
        if any((Path(p) / "assertion_types.py").is_file() for p in spec.submodule_search_locations):
            return True
    return (ROOT.parent / "mcp-server" / "src" / "mipiti_mcp" / "assertion_types.py").is_file()


def test_every_type_property_is_verified():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    if _catalogue_available():
        assert "ALL TYPE PROPERTIES VERIFIED" in result.stdout, result.stdout
    else:
        assert "TYPE PROPERTIES T3, T4, T5 VERIFIED; T1, T2 NOT ESTABLISHED" in result.stdout, result.stdout
    for prop in ("T3 templates", "T4 fail-closed + injection clauses", "T5 evidence class"):
        assert f"{prop} (" in result.stdout and "FAILED" not in result.stdout, result.stdout
