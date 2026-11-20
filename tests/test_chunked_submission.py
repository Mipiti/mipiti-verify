"""A tier's results go to the platform in as many submissions as their
attested payload needs: each within the payload bound, each with its own
content hash and attestation over exactly its own assertions and results
(the set the platform recomputes the hash from), each a run of its own; one
submission where everything fits, as before."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from mipiti_verify import runner as R
from mipiti_verify.runner import Runner, compute_content_hash, result_chunks


def _assertion(i: int) -> dict:
    return {"id": f"a{i:04d}", "type": "function_exists", "description": f"d{i}",
            "params": {"file": "auth.py", "name": f"f{i}"}, "control_id": "C1",
            "tier1_status": "pass", "tier2_details": "x" * 50}


def _result(i: int, details: str = "ok") -> dict:
    return {"assertion_id": f"a{i:04d}", "tier": 1, "result": "pass", "details": details}


def _payload_bytes(assertions, results) -> int:
    records = R.attestation_assertion_records(assertions)
    return sum(len(json.dumps(x, separators=(",", ":"))) for x in records + results)


def test_everything_that_fits_is_one_submission():
    assertions = [_assertion(i) for i in range(10)]
    results = [_result(i) for i in range(10)]
    assert result_chunks(assertions, results) == [(assertions, results)]


def test_chunks_keep_order_stay_in_bound_and_name_only_their_own_assertions():
    assertions = [_assertion(i) for i in range(400)]
    results = [_result(i, "y" * 3000) for i in range(400)]
    chunks = result_chunks(assertions, results, max_bytes=100_000)
    assert len(chunks) > 1
    assert [r for _a, rs in chunks for r in rs] == results
    for chunk_assertions, chunk_results in chunks:
        assert [a["id"] for a in chunk_assertions] == [r["assertion_id"] for r in chunk_results]
        assert _payload_bytes(chunk_assertions, chunk_results) <= 100_000


def test_a_result_past_the_bound_goes_alone():
    assertions = [_assertion(i) for i in range(3)]
    results = [_result(0), _result(1, "z" * 5000), _result(2)]
    chunks = result_chunks(assertions, results, max_bytes=2000)
    assert [len(rs) for _a, rs in chunks] == [1, 1, 1]


def test_each_submission_carries_its_own_hash_and_attestation(monkeypatch):
    monkeypatch.setattr(R, "SUBMISSION_PAYLOAD_BYTES", 20_000)
    assertions = [_assertion(i) for i in range(60)]
    results = [_result(i, "w" * 1000) for i in range(60)]
    client = MagicMock()
    client.key_scope = "verifier"
    client.submit_results.side_effect = [{"run_id": f"run_{k}"} for k in range(100)]
    runner = Runner(client=client, project_root=".", repo="acme/widgets", reverify=False)
    signed = []

    def attest(**kw):
        signed.append(kw)
        return "", "", "", ""
    monkeypatch.setattr(runner, "_choose_attestation", attest)
    run_ids = runner._submit_tier("m1", 1, assertions, results, {"run_id": "1"})
    calls = client.submit_results.call_args_list
    assert len(calls) > 1 and run_ids == [f"run_{k}" for k in range(len(calls))]
    submitted = [r for c in calls for r in c.kwargs["results"]]
    assert submitted == results
    for call, sig in zip(calls, signed):
        mine = call.kwargs["results"]
        own = [a for a in assertions if a["id"] in {r["assertion_id"] for r in mine}]
        # The hash the platform recomputes from this submission's results.
        assert call.kwargs["content_hash"] == compute_content_hash(own, mine)
        assert sig["content_hash"] == call.kwargs["content_hash"]
        assert sig["results"] == mine
        assert [a["id"] for a in sig["assertions"]] == [a["id"] for a in own]


def test_the_report_names_every_run_and_the_first_as_before(tmp_path):
    (tmp_path / "auth.py").write_text("def verify_token():\n    pass\n")
    client = MagicMock()
    client.key_scope = "verifier"
    client.get_pending.side_effect = [
        {"model_id": "m1", "controls": {"C1": [{
            "id": "asrt_001", "type": "function_exists", "repo": "acme/widgets",
            "params": {"file": "auth.py", "name": "verify_token"}}]}},
        {"model_id": "m1", "controls": {}},
    ]
    client.submit_results.return_value = {"run_id": "run_1"}
    report = Runner(client=client, project_root=str(tmp_path), repo="acme/widgets",
                    reverify=False).run("m1")
    assert report["tier1_run_id"] == "run_1" and report["tier1_run_ids"] == ["run_1"]
    assert report["tier2_run_id"] == "" and report["tier2_run_ids"] == []
