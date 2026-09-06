"""``formal/check_evidence_records.py`` runs under the ordinary test suite.

The checker enumerates every combination of test-result, reach and
dependence record states through the real ``test_attested`` verifier and
compares the verdict and its three facts with an oracle derived from the
record states. Running it here makes the composition invariants part of
every CI run.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "formal" / "check_evidence_records.py"


def test_every_evidence_record_property_is_verified():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL EVIDENCE RECORD PROPERTIES VERIFIED" in result.stdout, result.stdout
    assert "Combinations: 17640 (exhaustive over the 8 axes)" in result.stdout, result.stdout
