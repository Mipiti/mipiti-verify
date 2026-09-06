"""``formal/check_verifiers.py`` runs under the ordinary test suite.

The checker enumerates every registered structural verifier's equivalence
classes against an independent specification, and every ``test_attested``
fact combination against a fact-derived oracle. Running it here, as a
subprocess, makes its verdict part of every CI run rather than a separate
step someone has to remember.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "formal" / "check_verifiers.py"


def test_every_verifier_property_is_verified():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL VERIFIER PROPERTIES VERIFIED" in result.stdout, result.stdout
    # Exhaustive over the registry: the checker names how many it covered.
    from mipiti_verify.verifiers import VERIFIER_REGISTRY, _load_all

    _load_all()
    assert f"Verifiers covered:   {len(VERIFIER_REGISTRY)} of {len(VERIFIER_REGISTRY)} registered" in result.stdout
