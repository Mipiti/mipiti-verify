"""``formal/check_sound.py`` runs under the ordinary test suite.

The checker states the one direction that makes a sound witness worth
something -- the flagged set contains every unsafe site -- over a grammar of
small programs that each declare their own ground truth, and self-validates
by switching off each of the engine's enumeration features in turn. Running
it here makes its verdict part of every CI run rather than a separate step
someone has to remember.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "formal" / "check_sound.py"


def test_the_flagged_set_is_a_superset_of_the_unsafe_sites():
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL SOUND WITNESS PROPERTIES VERIFIED" in result.stdout, result.stdout
    assert "S1-S4 superset, verdict, refusal, over-approximation" in result.stdout, result.stdout


def test_the_grammar_covers_every_language_the_claim_names():
    """The banner is the claim. Pinning the languages here means a build
    that cannot read one of them, or a checker that quietly drops its
    programs, fails a test rather than printing a narrower verdict under
    the same banner."""
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    line = next(ln for ln in result.stdout.splitlines() if ln.startswith("Programs:"))
    count = int(line.split()[1])
    languages = line.split(" across ", 1)[1].split(", ")
    assert set(languages) == {
        "go", "javascript", "python", "rust", "systemverilog", "vhdl"}, line
    # A floor, not an equality: adding a program is ordinary, dropping the
    # coverage of a whole language is what this guards.
    assert count >= 40, line


def test_every_enumeration_feature_is_load_bearing():
    """A mutant that skips one feature must lose a site the ground truth
    names; a feature no program exercises fails the checker."""
    result = subprocess.run(
        [sys.executable, str(CHECKER)], cwd=ROOT, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    line = next(ln for ln in result.stdout.splitlines()
                if ln.startswith("Regression self-validation"))
    ratio = next(token for token in line.split() if "/" in token)
    caught, _, total = ratio.partition("/")
    assert total and caught == total and int(total) > 0, line
