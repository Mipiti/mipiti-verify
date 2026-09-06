"""Which models the verifier reports on: those bound to the repository it runs in."""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from mipiti_verify.cli import main
from mipiti_verify.runner import (
    BINDING_BOUND,
    BINDING_OTHER_REPO,
    BINDING_UNBOUND,
    model_binding,
    repo_slug,
)


def test_repo_slug_forms():
    for v in ("Mipiti/mipiti", "https://github.com/Mipiti/mipiti", "https://github.com/Mipiti/mipiti.git",
              "git@github.com:Mipiti/mipiti.git", "ssh://git@github.com/Mipiti/mipiti", "https://github.com/Mipiti/mipiti/"):
        assert repo_slug(v) == "mipiti/mipiti", v
    assert repo_slug("") == ""
    assert repo_slug("https://gitlab.com/group/sub/proj.git") == "group/sub/proj"


def test_model_binding_rules():
    assert model_binding("https://github.com/other/repo", "mipiti/mipiti", 7) == BINDING_OTHER_REPO
    assert model_binding("https://github.com/Mipiti/mipiti", "mipiti/mipiti", 0) == BINDING_BOUND
    assert model_binding("", "mipiti/mipiti", 1) == BINDING_BOUND
    assert model_binding("", "mipiti/mipiti", 0) == BINDING_UNBOUND
    # No repository known on the verifier's side: nothing can be called foreign.
    assert model_binding("https://github.com/other/repo", "", 0) == BINDING_UNBOUND


def _report(bound: int, gaps: int) -> dict:
    return {
        "tier1_pass": 0, "tier1_fail": 0, "tier1_skip": 0,
        "tier2_pass": 0, "tier2_fail": 0, "tier2_skip": 0,
        "suff_sufficient": 0, "suff_insufficient": gaps, "suff_skip": 0,
        "suff_details": [{"control_id": f"CTRL-{i:02d}", "result": "insufficient",
                          "details": "The control has no assertions, so there is no evidence that it is implemented."}
                         for i in range(gaps)],
        "tier1_run_id": "", "tier2_run_id": "", "dry_run": False, "details": [],
        "repo_bound_assertions": bound,
    }


@patch("mipiti_verify.cli.MipitiClient")
@patch("mipiti_verify.cli.Runner")
def test_run_all_reports_only_models_bound_to_this_repository(MockRunner, MockClient):
    client = MagicMock()
    client.list_models.return_value = [
        {"id": "foreign-1", "title": "Other Product"},
        {"id": "claimed-1", "title": "Claimed"},
        {"id": "loose-1", "title": "Loose"},
        {"id": "evidenced-1", "title": "Evidenced"},
    ]
    client.get_model.side_effect = lambda mid: {
        "foreign-1": {"description_provenance": {"kind": "code", "repo_url": "https://github.com/other/product"}},
        "claimed-1": {"description_provenance": {"kind": "code", "repo_url": "https://github.com/Mipiti/mipiti"}},
        "loose-1": {"description_provenance": None},
        "evidenced-1": {},
    }[mid]
    MockClient.return_value = client
    runner = MagicMock()
    runner.repo = "Mipiti/mipiti"
    runner.run.side_effect = lambda mid: {
        "claimed-1": _report(0, 3),
        "loose-1": _report(0, 118),
        "evidenced-1": _report(12, 2),
    }[mid]
    MockRunner.return_value = runner

    result = CliRunner().invoke(main, ["run", "--all", "--api-key", "k", "--output", "github"])
    out = result.output
    # The foreign model is never run.
    assert [c.args[0] for c in runner.run.call_args_list] == ["claimed-1", "loose-1", "evidenced-1"]
    assert "Skipped::describes other/product, not this repository" in out
    # The claimed model's gaps are reported even with no evidence yet.
    assert "[Claimed claimed-] Sufficiency" in out or "Sufficiency — coverage gaps (3 controls)" in out
    # The loose model gets one line, not 118 warnings.
    assert "Not bound to this repository::no evidence bound to mipiti/mipiti; 118 control(s)" in out
    assert out.count("Insufficient Coverage::") == 3 + 2
