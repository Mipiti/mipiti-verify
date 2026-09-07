"""What the semantic judge is handed, so it is never asked to locate what the
mechanical tier already located.

A judge that answers "not found" against a structurally present target has
its verdict set aside, which leaves the assertion inconclusive on every push.
Nearly every such refusal traces to the prompt: a mechanism that is imported
rather than defined, so its section read "not found"; or a presence type whose
excerpt never said where the target was. These pin the inputs that close
those gaps, and that a discard, when it still happens, keeps the judge's
reasoning where an author can read it.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from mipiti_verify.runner import Runner, _mechanism_section, _reference_sites


class _Capture:
    def __init__(self, answer="YES\nfine"):
        self.calls: list[dict] = []
        self._answer = answer

    def evaluate(self, *, assertion_type, assertion_params, source_code,
                 subject_kind="repository_file"):
        self.calls.append({"type": assertion_type, "source": source_code})
        passed = self._answer.startswith("YES")
        return passed, self._answer


class TestMechanismSection:
    def test_a_defined_mechanism_shows_its_definition(self, tmp_path):
        (tmp_path / "guard.py").write_text(
            "def other():\n    pass\n\n\ndef install_guard(app):\n    app.add(guard)\n    return app\n",
            encoding="utf-8")
        section = _mechanism_section(tmp_path, "guard.py", "install_guard",
                                     (tmp_path / "guard.py").read_text())
        assert section.startswith("--- Mechanism guard.py::install_guard ---")
        assert "def install_guard(app)" in section
        assert "no definition in this file" not in section

    def test_an_imported_mechanism_shows_where_it_is_configured(self, tmp_path):
        content = (
            "from fastapi import FastAPI\n"
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "\n"
            "app = FastAPI()\n"
            "\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origin_regex=LOOPBACK,\n"
            ")\n"
        )
        (tmp_path / "app.py").write_text(content, encoding="utf-8")
        section = _mechanism_section(tmp_path, "app.py", "CORSMiddleware", content)
        assert "no definition in this file" in section
        assert "allow_origin_regex=LOOPBACK" in section, (
            "the configuration site is the only surface the judge can hold the "
            "test against, and it was not shown"
        )
        assert "definition not found in the checkout" not in section

    def test_a_symbol_nowhere_in_the_file_is_reported_as_not_found(self, tmp_path):
        content = "x = 1\n"
        (tmp_path / "m.py").write_text(content, encoding="utf-8")
        section = _mechanism_section(tmp_path, "m.py", "Absent", content)
        assert "definition not found in the checkout" in section

    def test_reference_sites_carry_line_numbers_and_context(self):
        content = "\n".join(f"line {i}" for i in range(1, 21)).replace("line 10", "use Thing here")
        sites = _reference_sites(content, "Thing", context=1)
        assert "    9  line 9" in sites
        assert "   10  use Thing here" in sites
        assert "   11  line 11" in sites
        assert "line 15" not in sites

    def test_reference_sites_match_whole_words_only(self):
        assert _reference_sites("Things are not Thing\n", "Thing")
        assert _reference_sites("Things only\n", "Thing") == ""


class TestPresenceTypesCarryTheStructuralFinding:
    def _runner(self, tmp_path):
        (tmp_path / "svc.py").write_text(
            "import os\n\n\ndef _sign_bundle():\n    return compute()\n", encoding="utf-8")
        (tmp_path / "Markdown.tsx").write_text("export const x = 1;\n", encoding="utf-8")
        return Runner(client=MagicMock(), project_root=str(tmp_path),
                      tier2_provider="anthropic", repo="acme/widgets")

    def _verify(self, runner, provider, assertion):
        with patch("mipiti_verify.tier2.get_provider", return_value=provider):
            return runner._verify_tier2(assertion)

    def test_function_exists_source_ends_with_where_tier_1_found_it(self, tmp_path):
        runner = self._runner(tmp_path)
        cap = _Capture()
        self._verify(runner, cap, {
            "id": "asrt_x", "type": "function_exists",
            "params": {"file": "svc.py", "name": "_sign_bundle"}, "repo": "acme/widgets",
        })
        source = cap.calls[0]["source"]
        assert "--- Facts (established by the mechanical tier) ---" in source
        assert "the target is present: Function '_sign_bundle' defined at line 4" in source
        assert source.index("def _sign_bundle") < source.index("--- Facts")

    def test_import_present_source_carries_the_finding_too(self, tmp_path):
        runner = self._runner(tmp_path)
        cap = _Capture()
        self._verify(runner, cap, {
            "id": "asrt_y", "type": "import_present",
            "params": {"file": "svc.py", "module": "os"}, "repo": "acme/widgets",
        })
        assert "the target is present:" in cap.calls[0]["source"]

    def test_an_absence_type_gets_no_presence_fact(self, tmp_path):
        runner = self._runner(tmp_path)
        cap = _Capture()
        self._verify(runner, cap, {
            "id": "asrt_z", "type": "pattern_absent",
            "params": {"file": "Markdown.tsx", "pattern": "rehype-?[Rr]aw"}, "repo": "acme/widgets",
        })
        assert "the target is present" not in cap.calls[0]["source"]

    def test_a_discard_keeps_the_judges_reasoning(self, tmp_path):
        runner = self._runner(tmp_path)
        result = self._verify(runner, _Capture("NO\nREASON: NOT_FOUND\nI looked for a class and saw none"), {
            "id": "asrt_x", "type": "function_exists",
            "params": {"file": "svc.py", "name": "_sign_bundle"}, "repo": "acme/widgets",
        })
        assert result["status"] == "skipped"
        assert "I looked for a class and saw none" in result["details"]
        assert "Function '_sign_bundle' defined at line 4" in result["details"]
