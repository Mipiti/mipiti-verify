"""The request-path guard against httpx's own resolution, over every path of
up to three caller segments drawn from plain ids and every dot form: a path
the guard passes resolves to itself, and the guard refuses a path exactly
when one of its segments is a dot segment."""

import itertools

import httpx
import pytest

from mipiti_verify.client import MipitiClient, UnsafePath, _GuardedClient, is_dot_segment

BASE = "https://api.example.com"
ALPHABET = ["m1", "a%2e", "x..y", ".hidden", "v1.2", ".", "..", "%2e", "%2E",
            ".%2e", "%2E.", "%2e%2E", "%2E%2E", ".\t.", "%2e\n"]
DOTS = {".", "..", "%2e", "%2E", ".%2e", "%2E.", "%2e%2E", "%2E%2E", ".\t.", "%2e\n"}


def test_the_dot_forms():
    assert {s for s in ALPHABET if is_dot_segment(s)} == DOTS


@pytest.mark.parametrize("n", [1, 2, 3])
def test_a_guarded_path_resolves_to_itself_and_only_dot_segments_are_refused(n):
    guarded = _GuardedClient(base_url=BASE)
    plain = httpx.Client(base_url=BASE)
    for seq in itertools.product(ALPHABET, repeat=n):
        path = "/api/models/" + "/".join(seq) + "/x"
        has_dot = any(s in DOTS for s in seq)
        try:
            req = guarded.build_request("GET", path)
        except UnsafePath:
            assert has_dot, path
            continue
        assert not has_dot, path
        assert req.url.raw_path.decode() == path
        assert plain.build_request("GET", path).url.raw_path.decode() == path


def test_the_client_uses_the_guard():
    client = MipitiClient(api_key="k", base_url=BASE)
    with pytest.raises(UnsafePath):
        client._client.build_request("GET", "/api/models/../admin")
