"""The attestation payload carries the assertion and its binding, not the
platform's stored verdict state from earlier runs."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from mipiti_verify.runner import (
    ATTESTED_ASSERTION_FIELDS,
    Runner,
    attestation_assertion_records,
    compute_content_hash,
)

PULLED = {
    "id": "asrt_1",
    "control_id": "CTRL-01",
    "assumption_id": "",
    "node_id": "",
    "functional_test_id": "",
    "model_id": "m1",
    "type": "function_exists",
    "params": {"file": "svc.py", "name": "f"},
    "description": "f exists",
    "repo": "acme/widgets",
    "created_by": "u1",
    "created_at": "2026-01-01T00:00:00Z",
    "superseded_by": None,
    "tier1_status": "pass",
    "tier1_verified_at": "2026-01-02T00:00:00Z",
    "tier1_details": "Function 'f' found at line 3",
    "tier1_attested": True,
    "tier2_status": "fail",
    "tier2_verified_at": "2026-01-02T00:00:00Z",
    "tier2_details": "x" * 2000,
    "tier2_attested": True,
    "coherence_status": "pending",
    "coherence_reasoning": "",
    "deleted": False,
    "deleted_at": None,
    "deleted_by": "",
    "origin": "own",
    "inherited_from_model_id": None,
    "inherited_from_model_title": None,
}

VERDICT_STATE = {
    "superseded_by", "tier1_status", "tier1_verified_at", "tier1_details",
    "tier1_attested", "tier2_status", "tier2_verified_at", "tier2_details",
    "tier2_attested", "coherence_status", "coherence_reasoning", "deleted",
    "deleted_at", "deleted_by",
}


def test_keeps_content_binding_and_provenance():
    (rec,) = attestation_assertion_records([PULLED])
    assert rec == {k: PULLED[k] for k in ATTESTED_ASSERTION_FIELDS}
    assert rec["control_id"] == "CTRL-01"
    assert rec["repo"] == "acme/widgets"
    assert rec["origin"] == "own"


def test_drops_verdict_state():
    (rec,) = attestation_assertion_records([PULLED])
    assert not (set(rec) & VERDICT_STATE)


def test_hash_bound_fields_are_all_attested():
    for field in ("id", "type", "params", "description"):
        assert field in ATTESTED_ASSERTION_FIELDS


def test_content_hash_unchanged():
    results = [{"assertion_id": "asrt_1", "result": "pass"}]
    assert compute_content_hash([PULLED], results) == compute_content_hash(
        attestation_assertion_records([PULLED]), results
    )


def test_absent_fields_are_not_invented():
    assert attestation_assertion_records([{"id": "a", "type": "t"}]) == [
        {"id": "a", "type": "t"}
    ]


def test_run_signs_trimmed_records(tmp_path):
    (tmp_path / "svc.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    client = MagicMock()
    client.get_all_assertions.return_value = {"controls": {"CTRL-01": [PULLED]}}
    client.submit_results.return_value = {"run_id": "r"}
    client.get_verification_report.return_value = {}
    runner = Runner(client=client, project_root=str(tmp_path),
                    oidc_token="eyJ.token", repo="acme/widgets", reverify=True)
    with patch("mipiti_verify.runner.sign_verification_statement",
               return_value='{"bundle": true}') as sign:
        runner.run("m1")
    assert sign.call_count >= 1
    for call in sign.call_args_list:
        for rec in call.kwargs["assertions"]:
            assert set(rec) <= set(ATTESTED_ASSERTION_FIELDS)
            assert not (set(rec) & VERDICT_STATE)
