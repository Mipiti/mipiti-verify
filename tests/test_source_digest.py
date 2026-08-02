"""VCS-neutral source digest: a content hash over the files the assertions check,
so the server can key tier-2 verdict stability on "the same code" without relying
on any source-control system.
"""

from mipiti_verify.runner import _source_digest


def _a(file):
    return {"params": {"file": file}}


def test_digest_over_referenced_files(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    d = _source_digest(tmp_path, [_a("a.py")])
    assert d.startswith("sha256:")


def test_digest_changes_when_content_changes(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    d1 = _source_digest(tmp_path, [_a("a.py")])
    (tmp_path / "a.py").write_text("print(2)\n")
    d2 = _source_digest(tmp_path, [_a("a.py")])
    assert d1 != d2


def test_same_content_same_digest_across_roots(tmp_path):
    # Identical verified content in two different checkouts -> same digest.
    # This is the whole point: independent of path, branch, or revision id.
    r1 = tmp_path / "r1"; r1.mkdir(); (r1 / "a.py").write_text("x\n")
    r2 = tmp_path / "r2"; r2.mkdir(); (r2 / "a.py").write_text("x\n")
    assert _source_digest(r1, [_a("a.py")]) == _source_digest(r2, [_a("a.py")])


def test_deterministic_regardless_of_assertion_order(tmp_path):
    (tmp_path / "a.py").write_text("1")
    (tmp_path / "b.py").write_text("2")
    d1 = _source_digest(tmp_path, [_a("a.py"), _a("b.py")])
    d2 = _source_digest(tmp_path, [_a("b.py"), _a("a.py")])
    assert d1 == d2


def test_no_file_scoped_assertions_returns_empty(tmp_path):
    assert _source_digest(tmp_path, [{"params": {"pattern": "**/*.py"}}]) == ""
    assert _source_digest(tmp_path, []) == ""


def test_missing_file_still_binds_its_absence(tmp_path):
    # A referenced file that doesn't exist must still affect the digest (a
    # deletion changes "the code"), and differ from the file being present.
    d_absent = _source_digest(tmp_path, [_a("gone.py")])
    (tmp_path / "gone.py").write_text("here\n")
    d_present = _source_digest(tmp_path, [_a("gone.py")])
    assert d_absent != d_present


def test_out_of_root_files_are_not_hashed(tmp_path):
    # Path traversal: a "../secret" reference must not pull outside content into
    # the digest — proven by the digest being invariant to that content.
    root = tmp_path / "root"; root.mkdir()
    (tmp_path / "secret.txt").write_text("A")
    d_a = _source_digest(root, [_a("../secret.txt")])
    (tmp_path / "secret.txt").write_text("B")
    d_b = _source_digest(root, [_a("../secret.txt")])
    assert d_a == d_b
