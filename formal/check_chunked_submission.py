"""The runner's chunked submission is ChunkedSubmission.tla.

``ChunkedSubmission.tla`` states how a tier's results are gathered into
submissions; ``ChunkedSubmissionProofs.tla`` proves Partition, Bounded,
HashBinds and AllSubmitted for every number of results, size and bound. This
checker ties the shipped code to the module:

1. **The module, transcribed and explored.** Every state the module reaches
   at ``N`` results, sizes ``1..MAX_SIZE`` and bound ``BOUND`` (the count is
   compared with TLC's: ``STATES``), each checked against the four
   properties.
2. **The code, from every finished state.** For each state with ``done``,
   results are built whose cost (``runner.payload_cost``) is the module's
   size times ``SCALE`` exactly, and the real ``result_chunks`` and
   ``Runner._submit_tier`` (with a recording client) are run with the bound
   ``BOUND * SCALE``. The submissions must be exactly the module's closed
   chunks, in order, each with the content hash computed over its own
   assertions alone and an attestation over the same.
3. **Regressions.** A chunker that never splits, a submitter that hashes every
   assertion, and one that drops the last chunk must each fail step 2.

Run from the repository root: ``python formal/check_chunked_submission.py``.
"""

from __future__ import annotations

import contextlib
import itertools
import sys
from collections import deque
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mipiti_verify import runner as R  # noqa: E402

N = 5
MAX_SIZE = 6
BOUND = 5
SCALE = 1000
#: TLC's distinct states at ChunkedSubmission.cfg's constants.
STATES = 54432
#: The hash a submission must carry, as the platform recomputes it: taken
#: here, before any regression replaces the runner's.
_CONTENT_HASH = R.compute_content_hash


# --- The module, transcribed ----------------------------------------------------------

def init_states():
    for size in itertools.product(range(1, MAX_SIZE + 1), repeat=N):
        yield (size, 1, 1, 0, (), (), (), (), False)


def close(s):
    size, nxt, lo, used, clo, chi, total, sent, done = s
    return (clo + (lo,), chi + (nxt - 1,), total + (used,),
            sent + (tuple(range(lo, nxt)),))


def successors(s):
    size, nxt, lo, used, clo, chi, total, sent, done = s
    out = []
    if not done and nxt <= N:
        if lo < nxt and used + size[nxt - 1] > BOUND:
            c = close(s)
            out.append((size, nxt + 1, nxt, size[nxt - 1], *c, False))
        else:
            out.append((size, nxt + 1, lo, used + size[nxt - 1], clo, chi, total, sent, False))
    if not done and nxt == N + 1:
        if lo < nxt:
            c = close(s)
            out.append((size, nxt, nxt, 0, *c, True))
        else:
            out.append((size, nxt, lo, used, clo, chi, total, sent, True))
    return out


def explore() -> list:
    seen = set()
    queue = deque()
    for s in init_states():
        seen.add(s)
        queue.append(s)
    order = []
    while queue:
        s = queue.popleft()
        order.append(s)
        for t in successors(s):
            if t not in seen:
                seen.add(t)
                queue.append(t)
    return order


def properties(s) -> list:
    size, nxt, lo, used, clo, chi, total, sent, done = s
    problems = []
    chunks = list(zip(clo, chi)) + ([(lo, nxt - 1)] if lo < nxt else [])
    flat = [i for a, b in chunks for i in range(a, b + 1)]
    if flat != list(range(1, nxt)):
        problems.append("Partition")
    totals = list(total) + ([used] if lo < nxt else [])
    for (a, b), t in zip(chunks, totals):
        if not (t <= BOUND or a == b):
            problems.append("Bounded")
    for k, (a, b) in enumerate(zip(clo, chi)):
        if sent[k] != tuple(range(a, b + 1)):
            problems.append("HashBinds")
    if done and lo != N + 1:
        problems.append("AllSubmitted")
    return problems


# --- The code -------------------------------------------------------------------------

def _assertion(i: int) -> dict:
    return {"id": f"a{i:02d}", "type": "function_exists", "description": f"assertion {i}",
            "params": {"file": "auth.py", "name": f"f{i}"}, "control_id": "C1",
            "tier1_status": "pass"}


def _results(sizes) -> tuple[list, list]:
    """Assertions and results whose payload costs are ``SCALE`` times the
    module's sizes, exactly."""
    assertions = [_assertion(i) for i in range(1, len(sizes) + 1)]
    records = {r["id"]: r for r in R.attestation_assertion_records(assertions)}
    results = []
    for i, s in enumerate(sizes, start=1):
        bare = {"assertion_id": f"a{i:02d}", "tier": 1, "result": "pass", "details": ""}
        base = R.payload_cost(bare, records[bare["assertion_id"]])
        result = {**bare, "details": "x" * (s * SCALE - base)}
        assert R.payload_cost(result, records[result["assertion_id"]]) == s * SCALE
        results.append(result)
    return assertions, results


def code_submissions(sizes) -> list:
    """``[(result indices, content hash, attested assertion ids)]`` as the
    real runner submits them."""
    assertions, results = _results(sizes)
    client = MagicMock()
    client.key_scope = "verifier"
    client.submit_results.side_effect = [{"run_id": f"r{k}"} for k in range(len(results) + 1)]
    runner = R.Runner(client=client, project_root=".", repo="acme/widgets", reverify=False)
    attested = []

    def attest(**kw):
        attested.append([a["id"] for a in kw["assertions"]])
        return "", "", "", ""
    runner._choose_attestation = attest
    with _bound(BOUND * SCALE):
        runner._submit_tier("m1", 1, assertions, results, {"run_id": "1"})
    out = []
    for call, ids in zip(client.submit_results.call_args_list, attested):
        mine = call.kwargs["results"]
        idx = tuple(int(r["assertion_id"][1:]) for r in mine)
        out.append((idx, call.kwargs["content_hash"], ids))
    return out


@contextlib.contextmanager
def _bound(n: int):
    real = R.SUBMISSION_PAYLOAD_BYTES
    R.SUBMISSION_PAYLOAD_BYTES = n
    try:
        yield
    finally:
        R.SUBMISSION_PAYLOAD_BYTES = real


def check_state(s) -> list:
    size, nxt, lo, used, clo, chi, total, sent, done = s
    problems = [f"module {p} fails at {s}" for p in properties(s)]
    if not done:
        return problems
    assertions, results = _results(size)
    by_id = {a["id"]: a for a in assertions}
    want = [tuple(range(a, b + 1)) for a, b in zip(clo, chi)]
    got = code_submissions(size)
    if [g[0] for g in got] != want:
        problems.append(f"sizes {size}: submitted {[g[0] for g in got]}, the module {want}")
        return problems
    for idx, content_hash, ids in got:
        own = [by_id[f"a{i:02d}"] for i in idx]
        mine = [results[i - 1] for i in idx]
        if content_hash != _CONTENT_HASH(own, mine):
            problems.append(f"sizes {size}: chunk {idx} hashed other than its own assertions")
        if ids != [a["id"] for a in own]:
            problems.append(f"sizes {size}: chunk {idx} attested {ids}")
    return problems


@contextlib.contextmanager
def _mutant(name: str):
    if name == "no_split":
        real = R.result_chunks
        R.result_chunks = lambda assertions, results, max_bytes=None: (
            [(assertions, results)] if results else [])
        try:
            yield
        finally:
            R.result_chunks = real
    elif name == "all_assertions":
        real_hash = R.compute_content_hash
        everyone: list = []

        def hash_all(assertions, results):
            return real_hash(everyone or assertions, results)
        real_chunks = R.result_chunks

        def chunks(assertions, results, max_bytes=None):
            everyone[:] = assertions
            return real_chunks(assertions, results, max_bytes)
        R.compute_content_hash, R.result_chunks = hash_all, chunks
        try:
            yield
        finally:
            R.compute_content_hash, R.result_chunks = real_hash, real_chunks
    else:  # drop_last
        real = R.result_chunks
        R.result_chunks = lambda assertions, results, max_bytes=None: (
            real(assertions, results, max_bytes)[:-1] or real(assertions, results, max_bytes))
        try:
            yield
        finally:
            R.result_chunks = real


MUTANTS = ("no_split", "all_assertions", "drop_last")


def main() -> int:
    states = explore()
    problems = []
    if len(states) != STATES:
        problems.append(f"the transcription reaches {len(states)} states, TLC {STATES}")
    finished = [s for s in states if s[-1]]
    for s in states:
        problems += check_state(s)
        if len(problems) > 40:
            break
    caught = 0
    for name in MUTANTS:
        with _mutant(name):
            found = next((p for s in finished for p in check_state(s)), None)
        if found:
            caught += 1
        else:
            problems.append(f"regression {name} was not caught")
    print(f"chunked submission: {len(states)} module states, {len(finished)} finished and "
          f"driven through the runner, {caught}/{len(MUTANTS)} regressions caught, "
          f"{len(problems)} problems")
    for p in problems[:40]:
        print("  " + p)
    if not problems:
        print("THE CHUNKED SUBMISSION IS THE MODULE")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
