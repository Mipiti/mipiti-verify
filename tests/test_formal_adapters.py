"""``formal/check_adapters.py`` runs under the ordinary test suite.

A1-A4, A6 and A7 need only this package and git. The parser arm of A2 and
A5 needs the optional ``[ast]`` extra; without it the checker reports those
checks as not established and this test asserts that wording, so the gap
is visible rather than silently green.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "formal" / "check_adapters.py"


@pytest.mark.skipif(shutil.which("git") is None, reason="the mutation gate asks git whether the tree is clean")
def test_every_adapter_property_is_verified():
    from mipiti_verify.languages.definitions import tree_sitter_available

    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=900,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    if tree_sitter_available("go"):
        assert "ALL ADAPTER PROPERTIES VERIFIED" in result.stdout, result.stdout
    else:
        assert "ADAPTER PROPERTIES VERIFIED EXCEPT" in result.stdout, result.stdout
        assert "NOT ESTABLISHED (tree-sitter-language-pack not installed)" in result.stdout, result.stdout
    for prop in ("A1 ", "A2 ", "A3 ", "A4 ", "A5 ", "A6 ", "A7 ", "A8 ", "A9 "):
        assert prop in result.stdout, result.stdout
    assert "FAILED" not in result.stdout, result.stdout
