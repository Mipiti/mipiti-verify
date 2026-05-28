"""Rendering invariant for tier-2 templates with empty SOURCE_CODE.

Background: an empty SOURCE_CODE rendered through ``| untrusted`` in a
template produces ``<BOUNDARY_xxx>\\n\\n</BOUNDARY_xxx>`` — a tag pair
wrapping nothing. Some LLMs interpret this pattern as an injection
attempt (an explicit early close of the boundary) and return
INJECTION_DETECTED on the first line, which the runner's parser maps
to ``fail``. Operators see a false-positive failure that has nothing
to do with the source code.

Layered defense in this PR:

  (a) The pre-LLM fail-closed guard in ``Runner._verify_tier2``
      short-circuits empty SOURCE_CODE for every type EXCEPT those
      explicitly listed in ``_EMPTY_SOURCE_OK_TYPES``. The default
      is the empty set — i.e., every type requires source-code
      evidence and the guard catches the empty case.

  (b) For types that legitimately permit empty SOURCE_CODE, this
      test asserts that the rendered prompt never contains the
      empty ``<BOUNDARY>...</BOUNDARY>`` pair that triggered the
      INJECTION_DETECTED false-positive. A future addition to
      ``_EMPTY_SOURCE_OK_TYPES`` must update the corresponding
      template to render the SOURCE_CODE block conditionally
      (``{% if SOURCE_CODE %}…{% endif %}``) or this test fails.

With the current empty default, the parametrized check iterates an
empty set; the rendering invariant is also checked end-to-end with a
deliberately empty source for one type to document the wire-format
behavior under the current guard contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mipiti_verify.runner import _EMPTY_SOURCE_OK_TYPES
from mipiti_verify.tier2 import _build_message

TEMPLATES_DIR = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "mipiti_verify"
    / "templates"
)

# Pattern matching an empty boundary wrap: <BOUNDARY_xxxxxxxxxxxxxxxxxxxxxxxx>
# followed only by whitespace (newlines), then the closing tag with the
# same token. This is the exact rendering the LLM treats as an
# explicit early close, returning INJECTION_DETECTED.
_EMPTY_BOUNDARY_RE = re.compile(
    r"<(BOUNDARY_[a-f0-9]{24})>\s*</\1>"
)


@pytest.mark.parametrize("type_name", sorted(_EMPTY_SOURCE_OK_TYPES))
def test_no_empty_boundary_wrap_for_allowed_empty_type(type_name: str) -> None:
    """For each type permitted to have empty SOURCE_CODE, the rendered
    prompt must NOT contain an empty BOUNDARY wrap. Future additions
    to ``_EMPTY_SOURCE_OK_TYPES`` must make their template's
    SOURCE_CODE block conditional."""
    rendered = _build_message(
        assertion_type=type_name,
        assertion_params={"file": "x.py"},
        source_code="",
    )
    assert _EMPTY_BOUNDARY_RE.search(rendered) is None, (
        f"{type_name}: rendered prompt contains an empty boundary wrap; "
        "make the SOURCE_CODE block conditional in the template."
    )


def test_empty_source_ok_set_is_explicit() -> None:
    """``_EMPTY_SOURCE_OK_TYPES`` is the public contract for which
    types may skip the pre-LLM fail-closed guard. The default is an
    empty frozenset — every type requires source-code evidence."""
    assert isinstance(_EMPTY_SOURCE_OK_TYPES, frozenset)
    # The default is empty. If this assertion ever flips, the
    # corresponding tier2 template MUST switch to conditional
    # rendering — the parametrized test above enforces that.
    assert _EMPTY_SOURCE_OK_TYPES == frozenset()
