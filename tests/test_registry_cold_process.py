"""Every registered assertion type resolves in a FRESH interpreter.

The registry is populated by importing verifier submodules. Any module in
the package may import one of them at module level for a constant, which
registers that module's types and no others. A lookup that treated a
non-empty registry as a loaded one would then answer "no verifier for this
type" for everything else -- and a verification run turns that answer into
a ``skipped`` result submitted for evidence that verifies fine.

The rest of the suite cannot see that: pytest imports many verifier
modules across many test modules into one interpreter, so by the time any
test performs a lookup the registry is complete whatever the lookup path
does. These tests therefore run in a child process that imports exactly
one entry point and nothing else.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Entry points a command-line invocation reaches first. Each is imported
# alone in the child, which is the situation the suite cannot reproduce.
ENTRY_MODULES = ["mipiti_verify.cli", "mipiti_verify.runner", "mipiti_verify.tier2"]

_CHILD = """
import json, sys
__import__(sys.argv[1])
from mipiti_verify.verifiers import get_verifier, evidence_class
expected = json.loads(sys.argv[2])
missing = [t for t in expected if get_verifier(t) is None]
unclassed = [t for t in expected if not evidence_class(t)]
print(json.dumps({"missing": missing, "unclassed": unclassed}))
"""


def _registered_types() -> list[str]:
    from mipiti_verify.verifiers import VERIFIER_REGISTRY, _load_all

    _load_all()
    return sorted(VERIFIER_REGISTRY)


def _cold_lookup(entry: str, expected: list[str]) -> dict:
    result = subprocess.run(
        [sys.executable, "-c", _CHILD, entry, json.dumps(expected)],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("entry", ENTRY_MODULES)
def test_a_fresh_process_has_a_verifier_for_every_registered_type(entry):
    expected = _registered_types()
    assert len(expected) > 2, "the reference set must be the whole registry, not one module's types"
    seen = _cold_lookup(entry, expected)
    assert seen["missing"] == [], (
        f"importing {entry} alone leaves these types unverifiable: {seen['missing']}"
    )


@pytest.mark.parametrize("entry", ENTRY_MODULES)
def test_a_fresh_process_reports_an_evidence_class_for_every_registered_type(entry):
    expected = _registered_types()
    seen = _cold_lookup(entry, expected)
    assert seen["unclassed"] == [], (
        f"importing {entry} alone leaves these types without an evidence class: {seen['unclassed']}"
    )


def test_a_registry_holding_one_module_s_types_is_not_a_loaded_registry():
    """A partially populated registry still completes on the next lookup.

    Importing one verifier module registers its own types and no others.
    The load pass records its own completion, so the lookup that follows
    imports the rest instead of reading the leftovers as the whole set.
    """
    expected = _registered_types()
    seen = _cold_lookup("mipiti_verify.verifiers.sound", expected)
    assert seen["missing"] == [], seen["missing"]
    assert seen["unclassed"] == [], seen["unclassed"]
