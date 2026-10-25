"""Model-free detection test for manifest defenses.

For every attack (and the clean setup) start the real MCP servers, hand the served manifests to a
gateway, and compare the tools it flags with the tools the attack actually changed:

  true positive   changed tool that was flagged       false negative  changed tool not flagged
  false positive  unchanged tool that was flagged     true negative   unchanged tool not flagged

Attacks that change no manifest (content injection, path traversal) are included on purpose: a manifest
defense is expected to be blind to them, and the table says so.

Usage: python detect.py [--gateway NAME ...]      (default: the four pinning gateways)
"""
import argparse
import asyncio
from contextlib import AsyncExitStack

import bench
from attacks import ATTACKS
from gateway import GATEWAYS

DEFAULT = ["pin-tofu-alert", "pin-reviewed-alert"]


async def flagged_for(gw_cls, ref, files, notes, mail, approved, layout="normal"):
    bench.reset_workspace(layout, "x")
    async with AsyncExitStack() as stack:
        _, manifests = await bench.open_session(stack, files, notes, mail)
    gw = gw_cls()
    ctx = {"task": "", "task_id": "detect", "calls": [], "reference": ref, "approved": approved}
    gw.on_session(ctx, manifests)
    return set(getattr(gw, "flagged", {}))


async def evaluate(names):
    ref = await bench.reference_manifest()
    cases = [("clean", {"files": "benign", "notes": "benign", "mail": "benign"}, False, [], "-")]
    for aid, a in ATTACKS.items():
        cases.append((aid, {"files": a["files"], "notes": a["notes"], "mail": a["mail"]}, a["approval"],
                      sorted(a["changed"]), a["cls"]))
    out = {}
    for name in names:
        rows, tp = [], dict(tp=0, fp=0, fn=0, tn=0)
        for aid, v, approved, changed, cls in cases:
            layout = ATTACKS[aid]["layout"] if aid in ATTACKS else "normal"
            got = await flagged_for(GATEWAYS[name], ref, v["files"], v["notes"], v["mail"], approved, layout)
            allt = {"read_file", "send_email", "add_note"}
            c = set(changed)
            tp["tp"] += len(got & c)
            tp["fn"] += len(c - got)
            tp["fp"] += len(got - c)
            tp["tn"] += len(allt - c - got)
            rows.append((aid, cls, approved, changed, sorted(got)))
        out[name] = (rows, tp)
    return out


def show(out):
    for name, (rows, c) in out.items():
        print("\n== %s" % name)
        print("%-6s %-14s %-9s %-16s %s" % ("case", "class", "reviewed", "changed", "flagged"))
        for aid, cls, approved, changed, got in rows:
            note = "" if changed == got else ("   <-- missed" if set(changed) - set(got) else "   <-- false alarm")
            print("%-6s %-14s %-9s %-16s %s%s" % (aid, cls, approved, ",".join(changed) or "-", ",".join(got) or "-", note))
        rec = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else float("nan")
        print("tool-level: TP %d FN %d FP %d TN %d | recall (changed tools flagged) %.0f%% | false alarms %d"
              % (c["tp"], c["fn"], c["fp"], c["tn"], 100 * rec, c["fp"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", nargs="+", default=DEFAULT, choices=sorted(GATEWAYS))
    args = ap.parse_args()
    show(asyncio.run(evaluate(args.gateway)))


if __name__ == "__main__":
    main()
