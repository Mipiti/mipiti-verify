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


def test_every_path_interpolation_is_one_encoded_segment():
    """Every id a request path carries goes through _seg: read from the
    source, so a method added later cannot skip it."""
    import ast
    import pathlib

    import mipiti_verify.client as client_mod

    tree = ast.parse(pathlib.Path(client_mod.__file__).read_text())
    raw, paths = [], 0
    for node in ast.walk(tree):
        if (isinstance(node, ast.JoinedStr) and node.values
                and isinstance(node.values[0], ast.Constant)
                and str(node.values[0].value).startswith(("/", "?"))):
            paths += 1
            for part in node.values:
                if isinstance(part, ast.FormattedValue) and not (
                        isinstance(part.value, ast.Call)
                        and getattr(part.value.func, "id", "") == "_seg"):
                    raw.append(f"line {node.lineno}: {ast.unparse(part.value)}")
    assert paths >= 6 and not raw, raw


@pytest.mark.parametrize("value,encoded", [
    ("m1", "m1"), ("a/b", "a%2Fb"), ("a?b", "a%3Fb"), ("a#b", "a%23b"), ("100%", "100%25"),
])
def test_a_segment_is_encoded_whole(value, encoded):
    from mipiti_verify.client import _seg

    assert _seg(value) == encoded


@pytest.mark.parametrize("value", ["", ".", "..", "%2e%2e", ".\t."])
def test_an_empty_or_dot_segment_is_refused(value):
    from mipiti_verify.client import _seg

    with pytest.raises(UnsafePath):
        _seg(value)


_CHARS = list(".%2eE/\\?#;:@&=+ \t\nab09-_~") + ["．", "。", "／", "＼", "%2e", "%2E", "%2f", "%5c"]


def test_a_random_id_is_one_segment_sent_intact():
    """Seeded property: any id is refused (empty or a dot segment) or reaches
    the server as exactly one segment that decodes to the id."""
    import random
    from urllib.parse import unquote

    from mipiti_verify.client import _seg

    rng = random.Random(20261118)
    client = _GuardedClient(base_url=BASE)
    for _ in range(4000):
        ident = "".join(rng.choice(_CHARS) for _ in range(rng.randint(1, 6)))
        try:
            seg = _seg(ident)
        except UnsafePath:
            assert ident == "" or is_dot_segment(ident), repr(ident)
            continue
        parts = client.build_request("GET", f"/api/models/{seg}/x").url.raw_path.decode().split("/")
        assert len(parts) == 5 and parts[4] == "x" and unquote(parts[3]) == ident, repr(ident)


def test_a_random_raw_path_is_sent_as_written_or_refused():
    """Seeded property over raw, unencoded paths of 1 to 8 random segments:
    a path the guard passes is sent exactly as written, and a path httpx
    would move is refused."""
    import random
    from urllib.parse import unquote

    rng = random.Random(20261118 + 1)
    guarded = _GuardedClient(base_url=BASE)
    plain = httpx.Client(base_url=BASE)
    for _ in range(4000):
        segs = ["".join(rng.choice(_CHARS) for _ in range(rng.randint(1, 6)))
                for _ in range(rng.randint(1, 8))]
        path = "/api/models/" + "/".join(segs)
        written = unquote(path.split("?")[0].split("#")[0])
        try:
            moved = unquote(plain.build_request("GET", path).url.raw_path.decode()
                            .split("?")[0]) != written
        except httpx.InvalidURL:
            continue  # httpx refuses it itself; nothing is sent
        try:
            sent = guarded.build_request("GET", path).url.raw_path.decode().split("?")[0]
        except (UnsafePath, httpx.InvalidURL):
            continue
        assert not moved, path
        assert unquote(sent) == written, path
