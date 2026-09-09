"""``formal/check_pipeline.py`` runs under the ordinary test suite.

The pipeline checker holds the invariants that keep a verdict honest --
no PASS on an error path, tier 2 only after tier 1, and the structural
proofs over this package's own source, among them that pattern matching
goes through the linear-time engine. It ran only as its own CI step,
which means the suite could be green while the checker was red. Running
it here puts its verdict in every run of the tests.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "formal" / "check_pipeline.py"


def test_the_pipeline_invariants_and_structural_proofs_hold():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VIOLATIONS FOUND" not in result.stdout, result.stdout
    assert "ALL VERIFICATION PIPELINE PROPERTIES HOLD" in result.stdout, result.stdout
    assert "S1-S6: AST structural proofs" in result.stdout, result.stdout
