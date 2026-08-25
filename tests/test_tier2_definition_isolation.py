"""The semantic tier is handed the isolated definition, never the whole file.

Existence of a ``function_exists`` / ``class_exists`` target is decided by the
structural tier. The semantic tier judges only the body, so it must not be
asked to locate the symbol first: the runner cuts the definition block out of
the file and passes just that as SOURCE_CODE. When the block cannot be
isolated the runner falls back to the enclosing file.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mipiti_verify.definition_extract import extract_definition
from mipiti_verify.runner import Runner


class _CapturingProvider:
    def __init__(self):
        self.source_code = None
        self.calls = 0

    def evaluate(
        self, *, assertion_type, assertion_params, source_code,
        subject_kind="repository_file",
    ):
        self.calls += 1
        self.source_code = source_code
        return True, "Meaningful logic."


def _verify(tmp_path, provider, a_type, name, filename="svc.py"):
    runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                    tier2_provider="anthropic", repo="acme/widgets")
    with patch("mipiti_verify.tier2.get_provider", return_value=provider):
        return runner._verify_tier2({
            "id": "asrt_x", "type": a_type,
            "params": {"file": filename, "name": name},
            "repo": "acme/widgets",
        })


# --------------------------------------------------------------------------
# extract_definition
# --------------------------------------------------------------------------
PY_SRC = '''"""Module docstring."""
import os


def helper():
    return 1


@pytest.fixture
def target(a, b):
    """Doc."""
    if a:
        return b
    return None


class Holder:
    x = 1

    async def method(self):
        return await self.other()

    def other(self):
        return 2


def after():
    return 3
'''


class TestExtractPython:
    def test_function_with_decorator(self):
        block = extract_definition(PY_SRC, "function", "target")
        assert block.startswith("@pytest.fixture\ndef target(a, b):")
        assert block.rstrip().endswith("return None")
        assert "def after" not in block and "def helper" not in block

    def test_async_method(self):
        block = extract_definition(PY_SRC, "function", "method")
        assert block.strip().startswith("async def method(self):")
        assert "def other" not in block

    def test_class(self):
        block = extract_definition(PY_SRC, "class", "Holder")
        assert block.startswith("class Holder:")
        assert "def other" in block
        assert "def after" not in block

    def test_missing_symbol_is_none(self):
        assert extract_definition(PY_SRC, "function", "nope") is None
        assert extract_definition(PY_SRC, "class", "Nope") is None

    def test_kind_mismatch_is_none(self):
        assert extract_definition(PY_SRC, "class", "target") is None

    def test_empty_inputs(self):
        assert extract_definition("", "function", "x") is None
        assert extract_definition(PY_SRC, "function", "") is None


JS_SRC = """import x from 'y';

function before() { return 0; }

export async function target(req, res) {
  if (!req.user) {
    return res.status(401).end();
  }
  return next();
}

const after = () => 1;
"""

GO_SRC = """package main

func (s *Server) Target(w http.ResponseWriter, r *http.Request) {
\tif r.Header.Get("X") == "" {
\t\thttp.Error(w, "no", 400)
\t\treturn
\t}
}

type Config struct {
\tName string
}

func after() {}
"""

RUBY_SRC = """class Foo
  def target(a)
    return a if a
    nil
  end

  def after
    1
  end
end
"""


class TestExtractFallback:
    def test_js_brace_block(self):
        block = extract_definition(JS_SRC, "function", "target")
        assert block.startswith("export async function target(req, res) {")
        assert block.endswith("}")
        assert "after" not in block and "before" not in block

    def test_go_method_and_struct(self):
        fn = extract_definition(GO_SRC, "function", "Target")
        assert fn.startswith("func (s *Server) Target(")
        assert fn.endswith("}") and "type Config" not in fn
        st = extract_definition(GO_SRC, "class", "Config")
        assert st.startswith("type Config struct {")
        assert st.endswith("}") and "func after" not in st

    def test_indentation_block_for_non_brace_language(self):
        block = extract_definition(RUBY_SRC, "function", "target")
        assert block.startswith("  def target(a)")
        # The heuristic stops at the next same-indent line, so the closing
        # ``end`` is cut off; the body itself is intact and nothing that
        # follows leaks in.
        assert block == "  def target(a)\n    return a if a\n    nil"
        assert "def after" not in block

    def test_invalid_python_falls_back_to_lines(self):
        src = "def broken(:\n    pass\n\ndef target(x):\n    return x + 1\n\ndef after():\n    pass\n"
        block = extract_definition(src, "function", "target")
        assert block == "def target(x):\n    return x + 1"

    def test_oversized_block_is_capped(self):
        body = "\n".join(f"    x{i} = {i}" for i in range(4000))
        src = f"def target():\n{body}\n"
        block = extract_definition(src, "function", "target")
        assert block.endswith("... (truncated)")
        assert len(block) < 16100


# --------------------------------------------------------------------------
# runner wiring
# --------------------------------------------------------------------------
class TestRunnerHandsReviewerTheDefinition:
    def test_function_reviewer_sees_only_the_definition(self, tmp_path):
        (tmp_path / "svc.py").write_text(PY_SRC, encoding="utf-8")
        p = _CapturingProvider()
        result = _verify(tmp_path, p, "function_exists", "target")
        assert result["status"] == "pass"
        assert p.source_code.startswith("@pytest.fixture\ndef target(a, b):")
        assert "def helper" not in p.source_code
        assert "class Holder" not in p.source_code

    def test_class_reviewer_sees_only_the_definition(self, tmp_path):
        (tmp_path / "svc.py").write_text(PY_SRC, encoding="utf-8")
        p = _CapturingProvider()
        _verify(tmp_path, p, "class_exists", "Holder")
        assert p.source_code.startswith("class Holder:")
        assert "def target" not in p.source_code

    def test_definition_past_file_window_is_still_isolated(self, tmp_path):
        filler = "\n".join(f"def f{i}():\n    return {i}\n" for i in range(1500))
        src = filler + "\n\ndef target():\n    return check()\n"
        assert len(src) > 16000
        (tmp_path / "svc.py").write_text(src, encoding="utf-8")
        p = _CapturingProvider()
        _verify(tmp_path, p, "function_exists", "target")
        assert p.source_code == "def target():\n    return check()"

    def test_falls_back_to_file_when_block_cannot_be_isolated(self, tmp_path):
        # A prototype declares the symbol without opening a body, so there
        # is no block to cut: the structural tier accepts the declaration
        # and the reviewer receives the enclosing file.
        src = "int x = 1;\nint target(const char *s, size_t n);\nint y = 2;\n"
        (tmp_path / "svc.c").write_text(src, encoding="utf-8")
        p = _CapturingProvider()
        _verify(tmp_path, p, "function_exists", "target", filename="svc.c")
        assert p.calls == 1
        assert p.source_code == src

    def test_other_types_unaffected(self, tmp_path):
        (tmp_path / "svc.py").write_text(PY_SRC, encoding="utf-8")
        p = _CapturingProvider()
        runner = Runner(client=MagicMock(), project_root=str(tmp_path),
                        tier2_provider="anthropic", repo="acme/widgets")
        with patch("mipiti_verify.tier2.get_provider", return_value=p):
            runner._verify_tier2({
                "id": "asrt_y", "type": "pattern_matches",
                "params": {"file": "svc.py", "pattern": "return b"},
                "repo": "acme/widgets",
            })
        assert p.source_code == PY_SRC
