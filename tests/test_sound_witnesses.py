"""The two sound witnesses: what they refuse, and what carries their verdict.

``formal/check_sound.py`` proves the direction that matters -- the flagged
set contains every unsafe site -- over a grammar of programs. These tests
cover the surface around it: the declared soundness class every type
carries, the scope rules that make a pass non-vacuous, the runner plumbing
that hands tier 2 an inventory rather than a file, and the two signed
statements that upgrade the residuals a repository cannot settle.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mipiti_verify.verifiers import (
    EVIDENCE_BEHAVIORAL,
    EVIDENCE_CLASS,
    EVIDENCE_CLASSES,
    SOUNDNESS_BY_CONSTRUCTION,
    SOUNDNESS_OVER_APPROXIMATION,
    SOUNDNESS_PRESENCE,
    SOUNDNESS_RANK,
    SOUNDNESS_SCAN,
    SOUNDNESS_WITNESS,
    SOUND_CLASSES,
    PathTraversalError,
    VERIFIER_REGISTRY,
    _load_all,
    evidence_class,
    get_verifier,
    register,
    resolve_scope_files,
)

SAFE_SQL = "SELECT * FROM users WHERE id = ?"


def _params(**over):
    params = {
        "scope": ["src"],
        "sinks": [{"callee": "execute", "positions": [0]}],
        "safe_forms": ["literal", "named_constant"],
        "property": "Every statement reaches the driver as a literal.",
    }
    params.update(over)
    return params


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    _write(tmp_path, "src/db.py",
           f"def go(conn):\n    conn.execute({SAFE_SQL!r})\n")
    return tmp_path


# ---------------------------------------------------------------------------
# A. The declared class
# ---------------------------------------------------------------------------

class TestDeclaredSoundnessClass:
    def test_every_registered_type_declares_one_class(self):
        _load_all()
        assert set(EVIDENCE_CLASS) == set(VERIFIER_REGISTRY)
        assert set(EVIDENCE_CLASS.values()) <= set(EVIDENCE_CLASSES)

    def test_the_vocabulary_is_the_five_declared_classes(self):
        assert set(EVIDENCE_CLASSES) == {
            SOUNDNESS_PRESENCE, SOUNDNESS_SCAN, SOUNDNESS_WITNESS,
            SOUNDNESS_OVER_APPROXIMATION, SOUNDNESS_BY_CONSTRUCTION,
        }
        assert SOUND_CLASSES == frozenset(
            {SOUNDNESS_OVER_APPROXIMATION, SOUNDNESS_BY_CONSTRUCTION})
        assert [c for c, _ in sorted(SOUNDNESS_RANK.items(), key=lambda kv: kv[1])] == [
            SOUNDNESS_PRESENCE, SOUNDNESS_SCAN, SOUNDNESS_WITNESS,
            SOUNDNESS_OVER_APPROXIMATION, SOUNDNESS_BY_CONSTRUCTION,
        ]

    @pytest.mark.parametrize("a_type,expected", [
        ("sink_default_deny", SOUNDNESS_OVER_APPROXIMATION),
        ("typed_boundary", SOUNDNESS_BY_CONSTRUCTION),
        ("test_attested", SOUNDNESS_WITNESS),
        ("test_exists", SOUNDNESS_PRESENCE),
        ("function_exists", SOUNDNESS_PRESENCE),
        ("pattern_absent", SOUNDNESS_SCAN),
        ("no_plaintext_secret", SOUNDNESS_SCAN),
        ("register_reset", SOUNDNESS_PRESENCE),
    ])
    def test_the_class_a_type_reports(self, a_type, expected):
        assert evidence_class(a_type) == expected

    def test_a_test_file_existing_is_presence_not_a_witness(self):
        """The one inference the vocabulary removes: a test FILE, and a
        symbol inside one, prove that something exists, never that it ran."""
        for a_type in ("test_exists", "function_exists", "class_exists"):
            assert evidence_class(a_type) == SOUNDNESS_PRESENCE
            assert evidence_class(a_type) != EVIDENCE_BEHAVIORAL

    def test_a_registration_outside_the_vocabulary_is_refused(self):
        with pytest.raises(ValueError, match="not one of"):
            register("invented_type", soundness="probably_fine")
        assert "invented_type" not in VERIFIER_REGISTRY


# ---------------------------------------------------------------------------
# B. The scope makes the claim; an unreadable scope makes none
# ---------------------------------------------------------------------------

class TestScope:
    def test_a_scope_matching_nothing_fails(self, project):
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["nothing/**/*.py"]), project)
        assert not result.passed and "scope matched no files" in result.details

    def test_a_scope_entry_that_climbs_out_is_refused(self, project):
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["../*.py"]), project)
        assert not result.passed and "scope refused" in result.details

    def test_a_file_with_no_language_fails_rather_than_being_skipped(self, project):
        _write(project, "src/notes.txt", "nothing to parse\n")
        result = get_verifier("sink_default_deny").verify(_params(), project)
        assert not result.passed and "unclassifiable file in scope" in result.details

    def test_a_file_the_parser_rejects_fails(self, project):
        _write(project, "src/broken.py", "def go(conn:\n")
        result = get_verifier("sink_default_deny").verify(_params(), project)
        assert not result.passed and "unparsed" in result.details

    def test_a_link_inside_the_checkout_is_read_as_its_target(self, project):
        (project / "src" / "linked.py").symlink_to(project / "src" / "db.py")
        files = resolve_scope_files(project, ["src"])
        assert [p.name for p in files] == ["db.py"]

    def test_a_link_out_of_the_checkout_is_refused(self, project, tmp_path):
        outside = tmp_path.parent / "outside_target.py"
        outside.write_text("x = 1\n", encoding="utf-8")
        (project / "src" / "escape.py").symlink_to(outside)
        with pytest.raises(PathTraversalError):
            resolve_scope_files(project, ["src"])

    def test_a_file_too_large_to_read_is_refused_not_sampled(self, project):
        _write(project, "src/big.py", "# padding\n" * 200)
        with pytest.raises(ValueError, match="too large"):
            resolve_scope_files(project, ["src"], max_size=64)

    def test_a_scope_too_broad_is_refused(self, project):
        for i in range(4):
            _write(project, f"src/mod{i}.py", "x = 1\n")
        with pytest.raises(ValueError, match="narrow it"):
            resolve_scope_files(project, ["src"], max_files=2)

    def test_a_sink_that_never_occurs_proves_nothing(self, project):
        result = get_verifier("sink_default_deny").verify(
            _params(sinks=[{"callee": "no_such_call"}]), project)
        assert not result.passed and "do not occur in scope" in result.details


# ---------------------------------------------------------------------------
# C. Params are validated once, for both witnesses
# ---------------------------------------------------------------------------

class TestParams:
    @pytest.mark.parametrize("over,message", [
        ({"scope": []}, "'scope' must be a non-empty list"),
        ({"sinks": []}, "'sinks' must be a non-empty list"),
        ({"sinks": [{"callee": "x", "kind": "invented"}]}, "is not one of"),
        ({"safe_forms": []}, "'safe_forms' must be a non-empty subset"),
        ({"safe_forms": ["anything_goes"]}, "outside the vocabulary"),
        ({"allowlist": [{"file": "a.py", "site": "1", "callee": "execute"}]},
         "has no reason or no reviewed_by"),
        ({"allowlist": [{"file": "", "site": "0", "callee": ""}]},
         "must name file, site"),
        ({"wrappers": [{"callee": "x"}]}, "'wrappers' must be a list of callee names"),
    ])
    def test_a_malformed_param_is_refused_with_its_reason(self, project, over, message):
        result = get_verifier("sink_default_deny").verify(_params(**over), project)
        assert not result.passed and message in result.details

    def test_typed_boundary_needs_a_type_and_its_constructors(self, project):
        result = get_verifier("typed_boundary").verify(
            {"scope": ["src"], "sinks": [{"callee": "execute"}], "property": "p"}, project)
        assert not result.passed
        assert "'boundary_type' must name" in result.details
        assert "'constructors' must be" in result.details

    def test_a_scope_given_as_one_string_is_read_as_one_entry(self, project):
        result = get_verifier("sink_default_deny").verify(_params(scope="src/db.py"), project)
        assert result.passed, result.details


# ---------------------------------------------------------------------------
# D. The evidence hash binds the scope and the allowlist
# ---------------------------------------------------------------------------

class TestEvidenceHash:
    def _hash(self, project, **over):
        return get_verifier("sink_default_deny").verify(_params(**over), project).evidence_hash

    def test_editing_a_file_in_scope_changes_the_hash(self, project):
        before = self._hash(project)
        _write(project, "src/db.py", f"def go(conn):\n    conn.execute({SAFE_SQL!r})\n    pass\n")
        assert before and self._hash(project) != before

    def test_editing_the_allowlist_changes_the_hash(self, project):
        before = self._hash(project)
        after = self._hash(project, allowlist=[
            {"file": "src/db.py", "site": "2", "callee": "execute",
             "reason": "reviewed", "reviewed_by": "a.reviewer"}])
        assert after != before

    def test_the_same_scope_and_content_hash_the_same(self, project):
        assert self._hash(project) == self._hash(project)


# ---------------------------------------------------------------------------
# E. A site the reader could not read is never safe
# ---------------------------------------------------------------------------

class TestUnreadableSites:
    def test_a_language_without_a_parser_reports_every_site_unclassifiable(
            self, project, monkeypatch):
        from mipiti_verify.languages import definitions as D

        _write(project, "src/app.go",
               'package a\n\nfunc Run(db *DB) {\n\tdb.execute("SELECT 1")\n}\n')
        monkeypatch.setattr(D, "_get_parser", lambda language: None)
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/app.go"]), project)
        assert not result.passed
        assert "no parser for this file" in result.details
        assert result.facts["parser_by_file"]["src/app.go"] == "regex"

    def test_an_unreadable_site_can_still_be_allowlisted(self, project, monkeypatch):
        from mipiti_verify.languages import definitions as D

        _write(project, "src/app.go",
               'package a\n\nfunc Run(db *DB) {\n\tdb.execute("SELECT 1")\n}\n')
        monkeypatch.setattr(D, "_get_parser", lambda language: None)
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/app.go"], allowlist=[
                {"file": "src/app.go", "site": "4", "callee": "execute",
                 "reason": "read by hand in review", "reviewed_by": "a.reviewer"}]),
            project)
        assert result.passed, result.details

    def test_a_stale_exception_fails_the_run(self, project):
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[
                {"file": "src/db.py", "site": "99", "callee": "execute",
                 "reason": "reviewed", "reviewed_by": "a.reviewer"}]),
            project)
        assert not result.passed and "matches no flagged site" in result.details


# ---------------------------------------------------------------------------
# F. The runner hands tier 2 the inventory, not the files
# ---------------------------------------------------------------------------

class TestRunnerPlumbing:
    def test_the_two_types_are_scope_types_and_absence_types(self):
        from mipiti_verify.runner import _DECLARATION_TYPES, _SCOPE_TYPES
        from mipiti_verify.tier2 import ABSENCE_TYPES, fail_closed_phrases

        for a_type in ("sink_default_deny", "typed_boundary"):
            assert a_type in _SCOPE_TYPES
            assert a_type in _DECLARATION_TYPES
            assert a_type in ABSENCE_TYPES
            assert "Fail-closed rule for an ABSENCE assertion" in fail_closed_phrases(a_type)

    def test_tier_2_reads_the_inventory_the_mechanical_tier_built(self, project):
        from mipiti_verify.runner import _load_scope_inventory_source

        _write(project, "src/db.py",
               "def go(conn, name):\n    conn.execute(name)\n    conn.commit()\n")
        source, verdict = _load_scope_inventory_source(project, "sink_default_deny", _params())
        assert not verdict.passed
        assert "--- Sink inventory" in source
        assert "src/db.py:2" in source
        assert "declared sinks: execute" in source
        assert "--- Facts (established by the mechanical tier) ---" in source
        assert "parser per file: src/db.py=ast" in source

    def test_tier_2_refuses_a_witness_that_states_no_property(self, project):
        from mipiti_verify.runner import Runner

        runner = Runner(client=MagicMock(), project_root=str(project), repo="acme/widgets",
                        tier2_provider="openai")
        params = _params()
        params.pop("property")
        out = runner._verify_tier2({"id": "a1", "type": "sink_default_deny", "params": params})
        assert out["status"] == "fail" and "`property`" in out["details"]

    def test_a_scope_assertion_survives_the_changed_files_filter(self, project):
        from mipiti_verify.runner import Runner

        controls = {"CTRL-01": [
            {"id": "a_scope", "type": "sink_default_deny", "params": _params()},
        ]}
        client = MagicMock()
        client.get_pending.return_value = {"model_id": "m1", "controls": controls}
        runner = Runner(client=client, project_root=str(project), repo="acme/widgets",
                        changed_files={"app/elsewhere.py"}, reverify=False, dry_run=True)
        _, _, kept = runner._run_tier("m1", tier=1)
        assert [a["id"] for a in kept] == ["a_scope"]

    def test_the_source_digest_covers_every_file_in_scope(self, project):
        from mipiti_verify.runner import _source_digest

        assertions = [{"type": "sink_default_deny", "params": _params()}]
        before = _source_digest(project, assertions)
        assert before
        _write(project, "src/db.py", "def go(conn):\n    conn.execute('SELECT 2')\n")
        assert _source_digest(project, assertions) != before

    def test_a_scope_that_cannot_be_resolved_still_enters_the_digest(self, project):
        from mipiti_verify.runner import _source_digest

        assertions = [{"type": "sink_default_deny", "params": _params(scope=["../outside"])}]
        assert _source_digest(project, assertions)


# ---------------------------------------------------------------------------
# G. Signed statements upgrade the residuals the repository cannot settle
# ---------------------------------------------------------------------------

class TestSignedResiduals:
    def _boundary_params(self, **over):
        params = {
            "scope": ["src"],
            "sinks": [{"callee": "execute", "positions": [0]}],
            "boundary_type": "SafeSql",
            "constructors": ["SafeSql.literal"],
            "property": "The driver accepts only SafeSql.",
        }
        params.update(over)
        return params

    @pytest.fixture
    def boundary_project(self, tmp_path: Path) -> Path:
        _write(tmp_path, "src/db.py",
               "from safe import SafeSql\n\n"
               "def go(conn):\n"
               "    conn.execute(SafeSql.literal('SELECT 1'))\n")
        return tmp_path

    def test_without_a_statement_the_residual_is_stated_as_carried(self, boundary_project):
        result = get_verifier("typed_boundary").verify(
            self._boundary_params(), boundary_project)
        assert result.passed, result.details
        assert "no signed construction statement" in result.details

    def test_a_construction_statement_is_recorded_in_the_facts(
            self, boundary_project, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        commit = "b" * 40
        monkeypatch.setenv("GITHUB_SHA", commit)
        _write(boundary_project, "probes/p.py", "SafeSql(raw)\n")
        out = CliRunner().invoke(main, [
            "attest-construction", "--boundary-type", "SafeSql",
            "--probe", str(boundary_project / "probes" / "p.py"),
            "--project-root", str(boundary_project), "--commit", commit,
            "--build-cmd", "false {file}",
        ])
        assert out.exit_code == 0, out.output
        result = get_verifier("typed_boundary").verify(
            self._boundary_params(), boundary_project)
        assert "a construction statement" in result.details
        assert "1 probe(s) the toolchain refused" in result.details

    def test_a_toolchain_that_never_ran_attests_nothing(self, boundary_project):
        """A statement says the toolchain REFUSED the probe. A command that
        could not be started never refused anything, so there is nothing to
        sign and the run says so rather than recording a proof."""
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        _write(boundary_project, "probes/p.py", "SafeSql(raw)\n")
        out = CliRunner().invoke(main, [
            "attest-construction", "--boundary-type", "SafeSql",
            "--probe", str(boundary_project / "probes" / "p.py"),
            "--project-root", str(boundary_project), "--commit", "e" * 40,
            "--build-cmd", "no-such-build-tool-anywhere {file}",
        ])
        assert out.exit_code == 1, out.output
        assert "no answer" in out.output, out.output
        assert "refused by the toolchain" not in out.output, out.output

    def test_a_check_that_could_not_run_attests_nothing(self, boundary_project, monkeypatch):
        """The same for a language check that reports why it could not be
        made: no project file above the source, a timeout, an absent tool."""
        from click.testing import CliRunner

        from mipiti_verify.cli import main
        from mipiti_verify.languages.adapters import checks as CH

        _write(boundary_project, "probes/p.rs", "fn main() { SafeSql(raw); }\n")
        monkeypatch.setattr(CH, "compile_check",
                            lambda *a, **k: "no Cargo.toml above the mechanism file")
        out = CliRunner().invoke(main, [
            "attest-construction", "--boundary-type", "SafeSql",
            "--probe", str(boundary_project / "probes" / "p.rs"),
            "--project-root", str(boundary_project), "--commit", "f" * 40,
        ])
        assert out.exit_code == 1, out.output
        assert "no answer" in out.output, out.output

    def test_a_probe_that_compiles_attests_nothing(self, boundary_project):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        _write(boundary_project, "probes/p.py", "SafeSql(raw)\n")
        out = CliRunner().invoke(main, [
            "attest-construction", "--boundary-type", "SafeSql",
            "--probe", str(boundary_project / "probes" / "p.py"),
            "--project-root", str(boundary_project), "--commit", "c" * 40,
            "--build-cmd", "true {file}",
        ])
        assert out.exit_code == 1
        assert "COMPILED" in out.output
        assert not list((boundary_project / ".mipiti" / "attestations").glob("*")) \
            if (boundary_project / ".mipiti" / "attestations").is_dir() else True

    def test_an_allowlist_review_is_recorded_in_the_facts(self, project, monkeypatch):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        commit = "d" * 40
        monkeypatch.setenv("GITHUB_SHA", commit)
        _write(project, "src/db.py", "def go(conn, name):\n    conn.execute(name)\n")
        entry = {"file": "src/db.py", "site": "2", "callee": "execute",
                 "reason": "the caller passes a value from a closed enum",
                 "reviewed_by": "a.reviewer"}
        (project / "allowlist.json").write_text(json.dumps([entry]), encoding="utf-8")
        out = CliRunner().invoke(main, [
            "attest-allowlist-review", "--allowlist", str(project / "allowlist.json"),
            "--project-root", str(project), "--commit", commit,
        ])
        assert out.exit_code == 0, out.output
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[entry]), project)
        assert result.passed, result.details
        assert "an allowlist review statement" in result.details

    def test_an_entry_with_no_reviewer_is_refused(self, project):
        from click.testing import CliRunner

        from mipiti_verify.cli import main

        (project / "allowlist.json").write_text(
            json.dumps([{"file": "src/db.py", "site": "2", "callee": "execute",
                         "reason": "reviewed"}]), encoding="utf-8")
        out = CliRunner().invoke(main, [
            "attest-allowlist-review", "--allowlist", str(project / "allowlist.json"),
            "--project-root", str(project), "--commit", "e" * 40,
        ])
        assert out.exit_code == 1
        assert "reviewed_by" in out.output


# ---------------------------------------------------------------------------
# H. The mechanism fact a reader can act on
# ---------------------------------------------------------------------------

class TestMechanismFound:
    def test_the_result_carries_whether_the_mechanism_resolves(self):
        from mipiti_verify.runner import _result_row

        row = _result_row("a1", "test_attested", 1,
                          {"status": "pass", "details": "d", "mechanism_found": False})
        assert row["mechanism_found"] is False

    def test_a_result_without_the_fact_omits_it(self):
        from mipiti_verify.runner import _result_row

        row = _result_row("a1", "function_exists", 1, {"status": "pass", "details": "d"})
        assert "mechanism_found" not in row
