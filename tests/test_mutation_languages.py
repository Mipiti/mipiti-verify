"""A language an adapter mutates is a language something can check.

Rewriting a file and running the suite against it only means something if the
rewritten tree still builds: otherwise the run reports the compiler's opinion
of the mutation, not the test's dependence on the mechanism. ``checks.CHECKS``
is where that gate lives, so an adapter that admits a language absent from it
opens a branch with no exit -- the mutation is written, the check is looked up,
and the only answer available is that no check exists, for a tree that may
compile perfectly well.

These assertions are deliberately static. They compare two module-level
constants and start no toolchain, so they hold the rule on any machine,
including one where none of the compilers the checks name is installed.
"""

from __future__ import annotations

import pytest

from mipiti_verify.languages.adapters import _all_adapters
from mipiti_verify.languages.adapters.checks import CHECKS
from mipiti_verify.languages.adapters.mutation import ABORT_BODY, MUTATION_LANGUAGES


@pytest.mark.parametrize("adapter", _all_adapters(), ids=lambda a: a.__name__)
def test_every_language_an_adapter_mutates_has_a_check(adapter):
    missing = sorted(set(adapter.mutation_languages) - set(CHECKS))
    assert not missing, (
        f"{adapter.__name__} disables {missing} by source mutation, but "
        f"checks.CHECKS defines no compile or lint check for them: the mutation "
        f"would be written to disk and then refused with 'no compile check is "
        f"defined', which names neither the real reason nor a way forward"
    )


def test_the_mutation_set_is_stated_not_derived_from_the_body_table():
    """``ABORT_BODY`` answers what text disables a body; ``MUTATION_LANGUAGES``
    answers which languages get rewritten on disk. Deriving the second from the
    first makes every runtime-only entry a mutation language by accident."""
    runtime_only = sorted(set(ABORT_BODY) - set(MUTATION_LANGUAGES))
    assert runtime_only == ["javascript", "typescript"], (
        "ABORT_BODY carries bodies for both strategies; the entries that are "
        f"injected at runtime rather than written to a file are {runtime_only}"
    )
    assert not set(MUTATION_LANGUAGES) - set(ABORT_BODY), (
        "a mutation language with no body to substitute cannot be mutated"
    )


def test_javascript_is_never_disabled_by_rewriting_a_file():
    """The node adapter replaces the export through a mocking setup file, which
    needs no git checkout. No adapter may reach that mechanism by rewriting its
    source instead -- the outcome would differ with the runner, not the code."""
    for adapter in _all_adapters():
        overlap = sorted({"javascript", "typescript"} & set(adapter.mutation_languages))
        assert not overlap, f"{adapter.__name__} would source-mutate {overlap}"
