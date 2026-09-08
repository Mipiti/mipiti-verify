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

    def test_a_linked_file_in_the_searched_region_is_refused(self, project):
        """A link under the region is a refusal even when its target is
        elsewhere in the tree: reading the target under its own path would
        leave the path the scope named unaccounted for."""
        (project / "internal").mkdir()
        _write(project, "internal/api.py", "import subprocess\n\n\ndef go(u):\n    subprocess.run(u)\n")
        (project / "src" / "api.py").symlink_to(project / "internal" / "api.py")
        with pytest.raises(ValueError, match="link"):
            resolve_scope_files(project, ["src"])
        with pytest.raises(ValueError, match="link"):
            resolve_scope_files(project, ["src/**/*.py"])

    def test_a_linked_directory_in_the_searched_region_is_refused(self, project):
        """A pattern walk does not descend through a linked directory, so an
        unread subtree would otherwise never appear in any count."""
        (project / "other").mkdir()
        _write(project, "other/bad.py", "def go(conn, u):\n    conn.execute(\"SELECT \" + u)\n")
        (project / "src" / "linked").symlink_to(project / "other", target_is_directory=True)
        with pytest.raises(ValueError, match="link"):
            resolve_scope_files(project, ["src"])
        with pytest.raises(ValueError, match="link"):
            resolve_scope_files(project, ["src/**/*.py"])

    def test_a_witness_refuses_rather_than_passing_over_a_link(self, project):
        """The verdict, not just the resolver: an unsafe call reachable only
        through a link must never sit under a PASS."""
        (project / "other").mkdir()
        _write(project, "other/bad.py", "def go(conn, u):\n    conn.execute(\"SELECT \" + u)\n")
        (project / "src" / "linked").symlink_to(project / "other", target_is_directory=True)
        result = get_verifier("sink_default_deny").verify(_params(), project)
        assert not result.passed and "scope refused" in result.details and "link" in result.details

    def test_a_link_whose_target_is_in_scope_is_still_refused(self, project):
        """The resolver does not weigh whether the target happens to be
        named elsewhere in the scope: that is a property of the other
        entries, not of the link."""
        (project / "src" / "linked.py").symlink_to(project / "src" / "db.py")
        with pytest.raises(ValueError, match="link"):
            resolve_scope_files(project, ["src"])

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

    def test_a_scope_whose_files_are_too_large_together_is_refused(self, project):
        """The count cap and the per-file cap bound one dimension each; a
        scope inside both can still be more source than a run can hold, and
        that must arrive as a refusal rather than as a killed job."""
        for i in range(8):
            _write(project, f"src/mod{i}.py", "# padding\n" * 200)
        with pytest.raises(ValueError, match="narrow it"):
            resolve_scope_files(project, ["src"], max_total_size=4096)

    def test_a_forwarding_chain_deeper_than_the_budget_is_refused(self, project):
        """The sink set must close over the scope before any verdict rests
        on it. A budget that runs out with the set still growing means
        sites were never enumerated, so the run refuses."""
        depth = 20
        body = ["def go(conn, name):", "    conn.execute(name)"]
        chain = "\n".join(body) + "\n"
        for i in range(depth):
            chain += f"\n\ndef hop{i}(conn, name):\n    " + (
                "go(conn, name)" if i == 0 else f"hop{i - 1}(conn, name)") + "\n"
        _write(project, "src/db.py", chain)
        result = get_verifier("sink_default_deny").verify(_params(), project)
        assert not result.passed
        assert "did not close over this scope" in result.details, result.details

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

class TestRepeatedEvaluation:
    def test_the_scope_is_parsed_once_for_the_verdict_and_the_inventory(self, project):
        """Tier 1 and the inventory a semantic review is shown are the same
        statement about the same bytes, so the scope is read and parsed once
        for both rather than once each."""
        import mipiti_verify.verifiers.sound as S
        from mipiti_verify.runner import _load_scope_inventory_source

        getattr(S, "_REPORT_CACHE", {}).clear()
        parses = {"n": 0}
        real = S._parse_backend

        def counting(rel, language, content, features):
            parses["n"] += 1
            return real(rel, language, content, features)

        original = S._parse_backend
        S._parse_backend = counting
        try:
            get_verifier("sink_default_deny").verify(_params(), project)
            first = parses["n"]
            _load_scope_inventory_source(project, "sink_default_deny", _params())
        finally:
            S._parse_backend = original
        assert first > 0
        assert parses["n"] == first, f"{parses['n']} parses for {first} files"

    def test_edited_source_is_read_again(self, project):
        """The report is a statement about the files as they are now: a
        changed file is a different statement, never a remembered one."""
        import mipiti_verify.verifiers.sound as S

        getattr(S, "_REPORT_CACHE", {}).clear()
        assert get_verifier("sink_default_deny").verify(_params(), project).passed
        _write(project, "src/db.py", "def go(conn, name):\n    conn.execute(name)\n")
        assert not get_verifier("sink_default_deny").verify(_params(), project).passed


# ---------------------------------------------------------------------------
# D. The evidence hash
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
    def test_a_language_without_an_installed_parser_is_refused(self, project, monkeypatch):
        from mipiti_verify.languages import definitions as D

        _write(project, "src/app.go",
               'package a\n\nfunc Run(db *DB) {\n\tdb.execute("SELECT 1")\n}\n')
        monkeypatch.setattr(D, "_get_parser", lambda language: None)
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/app.go"]), project)
        assert not result.passed
        assert "unparsed" in result.details
        assert result.facts["parser_by_file"]["src/app.go"] == "none"

    def test_the_refusal_for_a_missing_parser_names_the_next_action(self, project, monkeypatch):
        from mipiti_verify.languages import definitions as D

        _write(project, "src/app.go",
               'package a\n\nfunc Run(db *DB) {\n\tdb.execute("SELECT 1")\n}\n')
        monkeypatch.setattr(D, "_get_parser", lambda language: None)
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/app.go"]), project)
        assert "'ast' extra" in result.details, result.details

    def test_a_call_a_name_search_would_miss_cannot_reach_a_pass(self, project, monkeypatch):
        """Without a parser the arguments at a site are unread AND the sites
        a name search does not match are uncounted, so the run is refused
        rather than passed on what a search happened to find."""
        from mipiti_verify.languages import definitions as D

        _write(project, "src/app.rb",
               'def go(conn, user)\n  sql = "SELECT \'" + user + "\'"\n  conn.exec sql\nend\n')
        monkeypatch.setattr(D, "_get_parser", lambda language: None)
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/app.rb"], sinks=[{"callee": "exec"}]), project)
        assert not result.passed, result.details

    def test_an_allowlist_cannot_suppress_an_unreadable_file(self, project, monkeypatch):
        from mipiti_verify.languages import definitions as D

        _write(project, "src/app.go",
               'package a\n\nfunc Run(db *DB) {\n\tdb.execute("SELECT 1")\n}\n')
        monkeypatch.setattr(D, "_get_parser", lambda language: None)
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/app.go"], allowlist=[
                {"file": "src/app.go", "site": "4", "callee": "execute",
                 "reason": "read by hand in review", "reviewed_by": "a.reviewer"}]),
            project)
        assert not result.passed, result.details

    def test_a_refusal_names_no_absolute_path(self, project):
        """A verdict is submitted and stored. Every path it reports is
        repository-relative, so a filesystem error contributes its reason
        and never the checkout's location on the machine that ran it."""
        import os

        blocked = _write(project, "src/blocked.py", "x = 1\n")
        os.chmod(blocked, 0o000)
        try:
            result = get_verifier("sink_default_deny").verify(_params(), project)
        finally:
            os.chmod(blocked, 0o644)
        assert not result.passed, result.details
        assert "src/blocked.py" in result.details
        assert str(project) not in result.details
        assert not any(part.startswith("/") and "/" in part[1:]
                       for part in result.details.replace("'", " ").split()), result.details

    def test_the_details_stay_inside_the_submitted_field_bound(self, project):
        """One oversized result rejects the whole batch it is submitted in,
        so the listing gives way and says how much it left out while the
        counts stay complete."""
        for i in range(400):
            _write(project, f"src/mod{i}.py",
                   "def go(conn, name):\n    conn.execute(name)\n")
        result = get_verifier("sink_default_deny").verify(_params(), project)
        assert not result.passed
        assert len(result.details) <= 5000, len(result.details)
        assert "not listed" in result.details
        assert "violations=400" in result.details
        assert result.facts["violations"] == 400

    def test_a_passing_verdict_stays_inside_the_bound_on_a_wide_scope(self, project):
        for i in range(600):
            _write(project, f"src/mod{i}.py",
                   "def go(conn):\n    conn.execute(\"SELECT 1\")\n")
        result = get_verifier("sink_default_deny").verify(
            _params(safe_forms=["literal"]), project)
        assert result.passed, result.details
        assert len(result.details) <= 5000, len(result.details)

    def test_a_stale_exception_fails_the_run(self, project):
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[
                {"file": "src/db.py", "site": "99", "callee": "execute",
                 "reason": "reviewed", "reviewed_by": "a.reviewer"}]),
            project)
        assert not result.passed and "matches no flagged site" in result.details

    def test_a_malformed_exception_list_refusal_stays_inside_the_field_bound(self, project):
        """The reasons a refusal gives follow the submission, not the scope.
        One malformed entry per exception would otherwise write a refusal
        longer than the field it is submitted in, and one oversized row
        rejects every result in the batch with it."""
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[{"file": "", "site": "0", "callee": ""} for _ in range(400)]),
            project)
        assert not result.passed
        assert len(result.details) <= 5000, len(result.details)
        assert "must name file, site" in result.details
        assert "further reason(s) not listed" in result.details


# ---------------------------------------------------------------------------
# E2. A form is admitted by what the value is, never by where it sits
# ---------------------------------------------------------------------------

class TestAdmittedForms:
    """``parameter_binding`` names a data structure written at the site. A
    structure carries its elements into the callee, so what decides is what
    it was written with -- and never that a neighbouring argument looks like
    a statement, which says nothing about what the callee runs.
    """

    def _run(self, root: Path, **over):
        return get_verifier("sink_default_deny").verify(
            _params(scope=["src"], sinks=[{"callee": "execv"}],
                    safe_forms=["literal", "named_constant", "parameter_binding"],
                    property="No command is built from data.", **over), root)

    def test_a_structure_holding_a_built_statement_is_a_violation(self, project):
        _write(project, "src/run.py",
               "import os\n\n\ndef go(user):\n"
               "    os.execv(\"/bin/sh\", [\"sh\", \"-c\", \"rm -rf \" + user])\n")
        result = self._run(project)
        assert not result.passed, result.details
        assert result.facts["violations"] == 1
        assert "src/run.py:5" in result.details
        assert "concatenation with an unsafe operand" in result.details

    def test_a_structure_holding_a_runtime_value_is_a_violation(self, project):
        _write(project, "src/run.py",
               "import os\n\n\ndef go(user):\n"
               "    os.execv(\"/bin/sh\", [\"sh\", \"-c\", user])\n")
        result = self._run(project)
        assert not result.passed, result.details
        assert "identifier 'user' is not a named constant" in result.details

    def test_a_structure_inside_a_structure_is_not_read_through(self, project):
        _write(project, "src/run.py",
               "import os\n\n\ndef go(user):\n"
               "    os.execv(\"/bin/sh\", [\"sh\", [\"-c\", user]])\n")
        result = self._run(project)
        assert not result.passed, result.details

    def test_a_structure_whose_elements_are_all_admitted_is_bound_data(self, project):
        _write(project, "src/run.py",
               "import os\n\nSHELL = \"/bin/sh\"\nSCRIPT = \"/opt/run.sh\"\n\n\n"
               "def go():\n    os.execv(SHELL, [SHELL, SCRIPT])\n")
        result = self._run(project)
        assert result.passed, result.details
        assert result.facts["safe_by_form"].get("parameter_binding") == 1

    def test_the_residual_is_stated_where_the_reviewer_reads_it(self, project):
        """What the engine does NOT read -- what a callee does with a value
        it accepts -- travels with the verdict, in the facts and in the
        block the semantic tier is shown, rather than only in prose
        somewhere else."""
        from mipiti_verify.verifiers.sound import render_facts, run_engine

        _write(project, "src/run.py",
               "import os\n\nSHELL = \"/bin/sh\"\n\n\ndef go():\n    os.execv(SHELL, [SHELL])\n")
        report = run_engine(
            _params(scope=["src"], sinks=[{"callee": "execv"}],
                    safe_forms=["literal", "named_constant", "parameter_binding"],
                    property="No command is built from data."),
            project, "sink_default_deny")
        residual = report.facts["assumptions"]["value_forms"]
        assert "never from the position it sits in" in residual
        assert "a property of the callee and is not read here" in residual
        assert residual in report.details and residual in render_facts(report)
        exceptions = report.facts["assumptions"]["review_exceptions"]
        assert "0 site(s) stand on a reviewed exception" in exceptions

    def test_the_refusal_names_the_declaration_that_states_the_shape(self, project):
        """A sink that takes bound values in a later argument is declared by
        naming the statement position, which leaves the data positions
        unguarded -- a statement about the sink the submitter makes, rather
        than one the engine infers from an argument's neighbours."""
        _write(project, "src/db.py",
               "def go(conn, uid):\n    conn.execute(\"SELECT ?\", (uid,))\n")
        refused = get_verifier("sink_default_deny").verify(
            _params(sinks=[{"callee": "execute"}],
                    safe_forms=["literal", "parameter_binding"]), project)
        assert not refused.passed, refused.details
        assert "name the statement position in 'positions'" in refused.details
        declared = get_verifier("sink_default_deny").verify(
            _params(safe_forms=["literal"]), project)
        assert declared.passed, declared.details


class TestMetaprogramming:
    def test_a_macro_body_naming_a_sink_is_an_escape(self, project):
        """A macro body is text the grammar hands over whole, so the sink
        inside it is found by matching the declared name in that text --
        through the linear-time engine, like every other pattern this
        package runs -- and the definition is flagged as an escape."""
        _write(project, "src/a.c",
               "#define RUN(x) query(x)\n\nvoid go(const char *name) {\n  RUN(name);\n}\n")
        result = get_verifier("sink_default_deny").verify(
            _params(scope=["src/a.c"], sinks=[{"callee": "query"}], safe_forms=["literal"]),
            project)
        assert not result.passed, result.details
        assert result.facts["escapes"] == 1
        assert "macro body names sink 'query'" in result.details


# ---------------------------------------------------------------------------
# E3. An exception excepts a site; it never stands in for the check
# ---------------------------------------------------------------------------

class TestReviewExceptions:
    def _entry(self, line: int, **over) -> dict:
        entry = {"file": "src/db.py", "site": str(line), "callee": "execute",
                 "reason": "the caller passes a value from a closed enum",
                 "reviewed_by": "a.reviewer"}
        entry.update(over)
        return entry

    def test_a_run_whose_every_flagged_site_is_an_exception_establishes_nothing(self, project):
        """Excepting every site the run flagged, with nothing admitted by
        form anywhere in the scope, leaves the reviewer's word carrying the
        whole witness -- the same vacuity as a scope the sinks never occur
        in, and refused for the same reason."""
        _write(project, "src/db.py",
               "def one(conn, u):\n    conn.execute(\"SELECT \" + u)\n\n\n"
               "def two(conn, u):\n    conn.execute(\"SELECT \" + u)\n")
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[self._entry(2), self._entry(6)]), project)
        assert not result.passed, result.details
        assert "establishes nothing over this scope" in result.details
        assert result.facts["allowlisted"] == 2 and result.facts["safe_by_form"] == {}

    def test_an_exception_beside_sites_admitted_by_form_still_passes(self, project):
        _write(project, "src/db.py",
               "def one(conn, u):\n    conn.execute(\"SELECT \" + u)\n\n\n"
               f"def two(conn):\n    conn.execute({SAFE_SQL!r})\n")
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[self._entry(2)]), project)
        assert result.passed, result.details
        assert result.facts["allowlisted"] == 1

    def test_more_exceptions_than_sites_examined_is_refused(self, project):
        _write(project, "src/db.py", "def one(conn, u):\n    conn.execute(\"SELECT \" + u)\n")
        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[self._entry(2), self._entry(2, callee="conn.execute")]), project)
        assert not result.passed, result.details
        assert "cannot be longer than the sites in scope" in result.details

    def test_an_exception_list_past_the_review_bound_is_refused(self, project):
        from mipiti_verify.verifiers.sound import _MAX_ALLOWLIST_ENTRIES

        result = get_verifier("sink_default_deny").verify(
            _params(allowlist=[self._entry(2) for _ in range(_MAX_ALLOWLIST_ENTRIES + 1)]),
            project)
        assert not result.passed, result.details
        assert "a reviewed exception list is bounded at" in result.details


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
        assert "parsers: 1 file(s); ast=1" in source

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
        _write(project, "src/db.py",
               "def go(conn, name):\n    conn.execute(name)\n\n\n"
               f"def fixed(conn):\n    conn.execute({SAFE_SQL!r})\n")
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


# ---------------------------------------------------------------------------
# I. The enumeration counts travel on the submitted row
# ---------------------------------------------------------------------------

# Every name a consumer can read off the tier-1 submission of a sound
# witness. A count that reaches no further than the details string, or than
# the structured facts a submission does not carry, is a count no reader can
# act on: a consumer deciding whether a claim about EVERY site rests on an
# enumeration that happened would have nothing to read but prose, and prose
# is not a fact. This set is that contract, held here so a name can never be
# required at the far end without a run stating it.
ROW_NAMES_FOR_A_SOUND_WITNESS = {
    "assertion_id", "tier", "result", "details", "reasoning", "reviewer",
    "evidence_hash", "sites", "allowlisted",
}


def _sound_row(project: Path, params: dict, a_type: str = "sink_default_deny") -> dict:
    """The row a run over ``project`` actually submits."""
    from mipiti_verify.runner import Runner, _result_row

    runner = Runner(client=MagicMock(), project_root=str(project), repo="acme/widgets")
    out = runner._verify_tier1({"id": "a1", "type": a_type, "params": params})
    return _result_row("a1", a_type, 1, out)


class TestEnumerationCountsOnTheRow:
    def test_the_row_carries_every_name_a_consumer_reads_and_no_other(self, project):
        row = _sound_row(project, _params())
        assert set(row) == ROW_NAMES_FOR_A_SOUND_WITNESS
        assert row["result"] == "pass"
        assert row["sites"] == 1
        assert row["allowlisted"] == 0

    def test_the_counts_on_the_row_are_the_ones_the_run_established(self, project):
        from mipiti_verify.verifiers.sound import run_engine

        report = run_engine(_params(), project, "sink_default_deny")
        row = _sound_row(project, _params())
        assert (row["sites"], row["allowlisted"]) == (
            report.facts["sites"], report.facts["allowlisted"])

    def test_a_run_that_refused_still_reports_what_it_examined(self, project):
        """A later run that says nothing about the counts must not be read
        against an earlier run's numbers, so every run of these types states
        its own -- the ones it refused on included."""
        _write(project, "src/db.py",
               "def go(conn, name):\n    conn.execute(name)\n")
        row = _sound_row(project, _params())
        assert row["result"] == "fail"
        assert row["sites"] == 1 and row["allowlisted"] == 0

    def test_a_run_that_examined_nothing_says_zero_rather_than_nothing(self, project):
        row = _sound_row(project, _params(sinks=[]))
        assert row["result"] == "fail"
        assert row["sites"] == 0 and row["allowlisted"] == 0

    def test_an_allowlisted_site_is_counted_apart_from_the_sites(self, project):
        _write(project, "src/db.py",
               "def go(conn, name):\n    conn.execute(name)\n\n\n"
               f"def fixed(conn):\n    conn.execute({SAFE_SQL!r})\n")
        entry = {"file": "src/db.py", "site": "2", "callee": "execute",
                 "reason": "the caller passes a value from a closed enum",
                 "reviewed_by": "a.reviewer"}
        row = _sound_row(project, _params(allowlist=[entry]))
        assert row["result"] == "pass"
        assert row["sites"] == 2 and row["allowlisted"] == 1

    def test_a_verifier_that_enumerated_nothing_states_no_count(self, project):
        _write(project, "src/app.py", "def handler():\n    return 1\n")
        row = _sound_row(project, {"file": "src/app.py", "name": "handler"},
                         a_type="function_exists")
        assert row["result"] == "pass"
        assert "sites" not in row and "allowlisted" not in row

    def test_a_count_supplied_with_the_assertion_is_not_a_count_the_run_made(self, project):
        """The number is a fact about a run, so only the run states it: a
        value carried in with the declaration is ignored, whichever way it
        would move the verdict at the far end."""
        row = _sound_row(project, _params(sites=4096, allowlisted=0))
        assert row["sites"] == 1
        row = _sound_row(project, _params(sinks=[], sites=4096, allowlisted=0))
        assert row["sites"] == 0

    def test_only_a_scope_enumeration_can_state_a_count(self):
        """The counts are read off a result's established facts, so what
        holds ``never invented`` is not that nothing else sets them today
        but that every result the package builds is accounted for. This
        walks each construction of a result and each write into an
        established fact, and names the one module a count can enter
        through. It reads constructions written literally, which is how
        every verifier in the package builds its result."""
        import ast

        import mipiti_verify

        root = Path(mipiti_verify.__file__).parent
        writers: set = set()
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            rel = path.relative_to(root).as_posix()
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and getattr(node.func, "id", "") == "VerifierResult"
                        and any(k.arg == "facts" for k in node.keywords)):
                    writers.add(rel)
                if (isinstance(node, ast.Subscript)
                        and isinstance(node.value, ast.Attribute)
                        and node.value.attr == "facts"
                        and isinstance(getattr(node, "ctx", None), ast.Store)):
                    writers.add(rel)
        assert writers == {"verifiers/sound.py"}
