"""Audit-pack findings section rendering.

The pack carries the full dispositioned finding set (open + remediated +
dismissed); the auditor render surfaces the live gaps and every disposition
decision (who dismissed or remediated a finding, and why). Additive: an older
pack with no findings section renders nothing and never fails the audit.
"""

from mipiti_verify import cli


def test_absent_or_empty_findings_renders_nothing(capsys):
    assert cli._render_findings({}) is False
    assert cli._render_findings({"findings": []}) is False
    assert cli._render_findings({"findings": "not-a-list"}) is False
    assert capsys.readouterr().out.strip() == ""


def test_renders_disposition_and_accountability(capsys):
    pkg = {
        "findings": [
            {
                "id": "f1", "kind": "example_requirement_coverage_gap",
                "control_id": "CTRL-1", "severity": "medium",
                "status": "discovered",
                "title": "requirement not fully covered by the stated method",
            },
            {
                "id": "f2", "kind": "example_gap", "control_id": "CTRL-2",
                "severity": "low", "status": "dismissed", "title": "accepted",
                "dismissed_by": "user-alpha", "dismissed_reason": "residual accepted",
            },
            {
                "id": "f3", "kind": "example_gap", "control_id": "CTRL-3",
                "severity": "high", "status": "remediated", "title": "fixed",
                "remediated_by": "user-beta",
            },
        ]
    }
    ret = cli._render_findings(pkg)
    out = capsys.readouterr().out

    assert ret is False                       # informational — never fails audit
    assert "1 open" in out
    assert "1 resolved" in out
    assert "1 dismissed" in out
    # Kind is prettified generically from the data, not matched to a fixed list
    assert "Example Requirement Coverage Gap" in out
    # Dismissal accountability is preserved in the render
    assert "user-alpha" in out
    assert "residual accepted" in out
    # Remediation accountability
    assert "user-beta" in out


def test_unknown_kind_still_renders(capsys):
    # A kind introduced after this build must still render (generic display).
    cli._render_findings({"findings": [
        {"id": "x", "kind": "some_future_kind", "control_id": "CTRL-9",
         "severity": "low", "status": "discovered", "title": "t"},
    ]})
    out = capsys.readouterr().out
    assert "Some Future Kind" in out
