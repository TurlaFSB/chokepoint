"""Offline tests for the logging gateway and trajectory replay (Stage 3). No model needed.

    python test_replay.py

  1. the logging gateway changes no behavior: for every attack, task and stub seed, the run result
     equals the pass-through run (all fields except the recorded events)
  2. recorded manifest hashes equal the harness's own hashes
  3. replay through the pass-through gateway stops nothing and allows every benign run
  4. replay through a gateway that blocks send_email stops every hijacked run, and blocks the
     benign runs that send email (the cost of that rule, measured, not assumed)
  5. replay is deterministic
"""
import asyncio
import sys

import bench
import replay
from attacks import ATTACKS, ATTACK_TASKS
from gateway import Gateway, LoggingGateway

FAILED = []


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg, flush=True)
    if not cond:
        FAILED.append(msg)


class BlockEmail(Gateway):
    name = "block-email"

    def on_call(self, ctx, server, name, args):
        return "no" if name == "send_email" else None


def strip(row):
    return {k: v for k, v in row.items() if k != "events"}


async def main():
    ref = await bench.reference_manifest()
    ochat = bench.make_client("stub", None)
    diffs, rows, total = [], [], 0
    cases = [("control", "-", t) for t in ("summarize", "followups", "summary_carol", "read_notes", "add_note")]
    cases += [("attack", a, t) for a in ATTACKS for t in ATTACK_TASKS]
    for seed in (1, 3):
        for kind, aid, t in cases:
            plain = await bench.one_run(ochat, "stub", Gateway, kind, aid, t, seed, ref)
            logged = await bench.one_run(ochat, "stub", LoggingGateway, kind, aid, t, seed, ref)
            total += 1
            if strip(plain) != strip(logged):
                diffs.append((kind, aid, t, seed))
            row = dict(logged, kind=kind, attack=aid, task=t, model="stub", seed=seed)
            rows.append(row)
    check(not diffs, "logging gateway: %d runs identical to pass-through (%d differ %s)" % (total, len(diffs), diffs[:3]))

    s = next(e for e in rows[0]["events"] if e["kind"] == "session")
    check(s["manifest_hashes"] == ref, "recorded manifest hashes equal the harness reference")
    kinds = [e["kind"] for e in rows[0]["events"]]
    check(kinds[0] == "session" and kinds.count("call") == kinds.count("result"),
          "event stream: one session event, every call has a result")

    res = replay.score(Gateway, rows, ref)
    check(res["hijacked"] and not any(r["stopped"] for r in res["hijacked"]),
          "replay, pass-through: stops 0 of %d hijacked runs" % len(res["hijacked"]))
    check(all(r["allowed"] for r in res["benign"]), "replay, pass-through: allows all %d benign runs" % len(res["benign"]))
    check(len(res["hijacked"]) == sum(1 for r in rows if r["unauthorized"]),
          "replay hijacked count equals the live unauthorized count")

    res = replay.score(BlockEmail, rows, ref)
    check(all(r["stopped"] for r in res["hijacked"]), "replay, block-email: stops all %d hijacked runs" % len(res["hijacked"]))
    emailing = sum(1 for r in rows if r["emails"] and not r["unauthorized"])
    blocked_benign = sum(1 for r in res["benign"] if not r["allowed"])
    check(blocked_benign == emailing and emailing > 0,
          "replay, block-email: blocks exactly the %d benign runs that send email" % emailing)
    check(replay.score(BlockEmail, rows, ref) == res, "replay is deterministic")

    print("\n%s" % ("ALL PASSED" if not FAILED else "FAILED: %d" % len(FAILED)))
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    asyncio.run(main())
