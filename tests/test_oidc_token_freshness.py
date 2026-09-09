"""The identity a run signs with is minted when it signs.

A workload identity token is short-lived, and a verification run spends as long
as its evidence takes between starting and signing its first statement. A token
taken at startup and spent at the end is therefore not a token that happens to
be old: on a repository of any size it is reliably expired by the time it is
used, and the run loses its attestation every time.

What made that hard to see is that the validator reports an expired token and a
token that was never valid with the same sentence, so the failure reads as a
malformed identity rather than a stale one.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mipiti_verify.runner import Runner


def _runner(tmp_path, **kw) -> Runner:
    return Runner(client=MagicMock(), project_root=str(tmp_path),
                  repo="o/r", reverify=False, **kw)


def test_the_token_that_signs_is_minted_after_the_one_detected_at_startup(tmp_path):
    minted = []

    def _mint(audience: str = "") -> str:
        minted.append(f"tok{len(minted)}")
        return minted[-1]

    with patch("mipiti_verify.runner._auto_detect_oidc", side_effect=_mint):
        runner = _runner(tmp_path)
        at_startup = runner.oidc_token
        at_signing = runner._fresh_oidc_token()

    assert at_startup == "tok0"
    assert at_signing == "tok1", (
        "signing reused the token detected at construction; on a run long "
        "enough to matter that token has expired"
    )


def test_the_signing_path_asks_for_a_fresh_token(tmp_path):
    """Not just the helper: the method that signs must be the one calling it."""
    with patch("mipiti_verify.runner._auto_detect_oidc", return_value="startup"):
        runner = _runner(tmp_path)
    with patch.object(runner, "_fresh_oidc_token", return_value="fresh") as fresh, \
         patch("mipiti_verify.runner.sign_verification_statement",
               return_value="{}") as sign:
        runner._sign_with_sigstore(
            model_id="m1", tier=1, content_hash="h", pipeline={}, assertions=[], results=[])
    assert fresh.called, "the signing path used a stored token"
    assert sign.call_args[0][0] == "fresh"


def test_an_explicit_token_is_used_as_given(tmp_path):
    """Re-minting a token the caller supplied would substitute an identity
    they did not choose."""
    with patch("mipiti_verify.runner._auto_detect_oidc", return_value="detected") as auto:
        runner = _runner(tmp_path, oidc_token="caller-supplied")
        assert runner._fresh_oidc_token() == "caller-supplied"
    assert not auto.called


def test_availability_is_still_settled_at_construction(tmp_path):
    """The startup detection is what lets a run know signing is possible before
    it spends minutes producing something to sign. Where no identity exists,
    signing is skipped rather than attempted and reported as a failure."""
    with patch("mipiti_verify.runner._auto_detect_oidc", return_value=""):
        runner = _runner(tmp_path)
        assert runner.oidc_token == ""
        with patch("mipiti_verify.runner.sign_verification_statement") as sign:
            assert runner._sign_with_sigstore(
                model_id="m1", tier=1, content_hash="h",
                pipeline={}, assertions=[], results=[]) == ""
        assert not sign.called


def test_a_mint_that_fails_falls_back_rather_than_dropping_the_attestation(tmp_path):
    """A fresh mint that cannot be obtained is a reason to try the token in
    hand, not a reason to sign nothing: it may still be in date."""
    with patch("mipiti_verify.runner._auto_detect_oidc", return_value="startup"):
        runner = _runner(tmp_path)
    with patch("mipiti_verify.runner._auto_detect_oidc", return_value=""):
        assert runner._fresh_oidc_token() == "startup"


def _jwt(exp: float) -> str:
    import base64, json
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


@pytest.mark.parametrize("token,expect_hint", [
    (_jwt(__import__("time").time() - 90), True),
    (_jwt(__import__("time").time() + 300), False),
    ("not-a-jwt", False),
    ("", False),
])
def test_an_expired_token_says_so(token, expect_hint):
    """The validator's one message covers every rejection, so a stale token
    reads as a broken one. The claim is read without verifying anything and
    only to word the message."""
    from mipiti_verify.runner import _expiry_hint
    assert ("expired" in _expiry_hint(token)) is expect_hint


def test_the_hint_reaches_the_message_a_reader_sees(tmp_path):
    import time
    stale = _jwt(time.time() - 42)
    with patch("mipiti_verify.runner._auto_detect_oidc", return_value=stale):
        runner = _runner(tmp_path)
    printed = []
    with patch("mipiti_verify.runner.sign_verification_statement",
               side_effect=Exception("Identity token is malformed or missing claims")), \
         patch("mipiti_verify.runner.console.print", side_effect=lambda m, *a, **k: printed.append(m)):
        assert runner._sign_with_sigstore(
            model_id="m1", tier=1, content_hash="h",
            pipeline={}, assertions=[], results=[]) == ""
    assert any("expired" in m for m in printed), printed
