"""Tests for the TUF refresh retry helper.

Public Sigstore TUF mirrors transiently return 5xx; the audit path
retries up to 3 attempts (2s / 4s backoff) on errors that look like
TUF refresh failures, and propagates non-transient errors immediately.
"""

from __future__ import annotations

import pytest

from mipiti_verify import cli


def test_retry_returns_first_success():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        return "ok"

    assert cli._call_with_tuf_retry(fn) == "ok"
    assert calls["n"] == 1


def test_retry_passes_after_one_transient(monkeypatch):
    """First call fails with TUF text; second call succeeds.

    Backoff sleep is patched out so the test runs in milliseconds.
    """
    sleep_calls: list[float] = []
    monkeypatch.setattr(cli.time, "sleep", lambda s: sleep_calls.append(s))

    state = {"n": 0}

    def fn():
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("Failed to refresh TUF metadata")
        return "ok"

    assert cli._call_with_tuf_retry(fn) == "ok"
    assert state["n"] == 2
    assert sleep_calls == [2]


def test_retry_passes_after_two_transients(monkeypatch):
    sleep_calls: list[float] = []
    monkeypatch.setattr(cli.time, "sleep", lambda s: sleep_calls.append(s))

    state = {"n": 0}

    def fn():
        state["n"] += 1
        if state["n"] < 3:
            raise RuntimeError("TUF metadata refresh failed: 503")
        return "ok"

    assert cli._call_with_tuf_retry(fn) == "ok"
    assert state["n"] == 3
    assert sleep_calls == [2, 4]


def test_retry_gives_up_after_three_attempts(monkeypatch):
    sleep_calls: list[float] = []
    monkeypatch.setattr(cli.time, "sleep", lambda s: sleep_calls.append(s))

    state = {"n": 0}

    def fn():
        state["n"] += 1
        raise RuntimeError("Failed to refresh TUF metadata")

    with pytest.raises(RuntimeError, match="TUF"):
        cli._call_with_tuf_retry(fn)

    assert state["n"] == 3
    assert sleep_calls == [2, 4]


def test_retry_does_not_retry_non_transient(monkeypatch):
    """Errors that don't look like TUF refresh failures propagate
    immediately — we don't want to mask real bugs (e.g., a malformed
    trust config, a missing module) with three pointless retries.
    """
    sleep_calls: list[float] = []
    monkeypatch.setattr(cli.time, "sleep", lambda s: sleep_calls.append(s))

    state = {"n": 0}

    def fn():
        state["n"] += 1
        raise ValueError("certificate verification failed: untrusted issuer")

    with pytest.raises(ValueError, match="certificate"):
        cli._call_with_tuf_retry(fn)

    assert state["n"] == 1
    assert sleep_calls == []
