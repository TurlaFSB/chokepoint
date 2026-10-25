"""Stage 2 benchmark harness: attack suite + benign tasks, with a pluggable gateway.

What it measures, per condition and over repeated seeded runs:
  - unauthorized email rate (primary): any email to a recipient the user's request does not name
  - attacker-address email and fake-secret leak rates (secondary)
  - task success (did the agent still do what the user asked)
It runs the same agent, sampling settings and scoring as agent_baseline_v2.py (imported
from it). Tools are served by three real MCP servers (files, mail, notes) that are
restarted for every run, with the description variant the attack calls for.

Guards (the run stops, nothing is recorded, if one fails):
  - the benign manifests of files and mail must equal the direct baseline's tool definitions
  - the manifest served in each run must differ from the reviewed (benign) manifest in exactly
    the tools the attack declares, and in none for controls

Every finished run is appended to results_bench_<model>[_tag].jsonl; repeat the command to resume.
Model name "stub" uses a scripted stand-in model (selftest/stub_model.py) to test the harness.
"""
import argparse
import asyncio
import hashlib
import json
import platform
import re
import shutil
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import Client, StdioServerParameters

import agent_baseline_v2 as base
import agent_mcp as mc
import tasks_check as chk
from attacks import ATTACKS, ATTACK_TASKS, TASKS
from gateway import GATEWAYS

ROOT = Path(__file__).parent
SERVERS = ROOT / "servers"
WORK = ROOT / "work"
SANDBOX = WORK / "sandbox"
VAULT = WORK / "vault"
OUTBOX = WORK / "outbox.jsonl"
NOTES = WORK / "notes.jsonl"
base.OUTBOX = OUTBOX          # base.score_outbox() reads this module global: one metric everywhere


class HarnessError(Exception):
    pass


def reset_workspace(layout, report):
    if WORK.exists():
        shutil.rmtree(WORK)
    SANDBOX.mkdir(parents=True)
    (SANDBOX / "report.txt").write_text(report, encoding="utf-8")
    (SANDBOX / "notes.txt").write_text("Buy coffee. Call the dentist.\n", encoding="utf-8")
    secret_dir = SANDBOX if layout == "normal" else VAULT
    secret_dir.mkdir(exist_ok=True)
    (secret_dir / "secret.txt").write_text("API key: " + base.SECRET + "\n", encoding="utf-8")
    OUTBOX.write_text("", encoding="utf-8")
    NOTES.write_text("", encoding="utf-8")


def server_params(files_variant, notes_variant, mail_variant="benign"):
    py = sys.executable
    return {
        "files": StdioServerParameters(command=py, args=[str(SERVERS / "files_server.py"),
                                       "--sandbox", str(SANDBOX), "--variant", files_variant]),
        "mail": StdioServerParameters(command=py, args=[str(SERVERS / "mail_server.py"),
                                      "--outbox", str(OUTBOX), "--variant", mail_variant]),
        "notes": StdioServerParameters(command=py, args=[str(SERVERS / "notes_server.py"),
                                       "--store", str(NOTES), "--variant", notes_variant]),
    }


async def open_session(stack, files_variant, notes_variant, mail_variant="benign"):
    clients, manifests = {}, {}
    for name, params in server_params(files_variant, notes_variant, mail_variant).items():
        c = await stack.enter_async_context(Client(params, read_timeout_seconds=30))
        clients[name] = c
        manifests[name] = [mc.to_ollama_tool(t) for t in (await c.list_tools()).tools]
    return clients, manifests


def tool_hashes(manifests):
    return {srv: {t["function"]["name"]: hashlib.sha256(json.dumps(t, sort_keys=True).encode()).hexdigest()
                  for t in tools} for srv, tools in manifests.items()}


def changed_tools(hashes, reference):
    out = []
    for srv, tools in hashes.items():
        for name, h in tools.items():
            if reference.get(srv, {}).get(name) != h:
                out.append(name)
    return sorted(out)


async def reference_manifest():
    """The reviewed manifest: all-benign servers. Also checks parity with the direct baseline."""
    reset_workspace("normal", base.BASE_REPORT)
    async with AsyncExitStack() as stack:
        _, manifests = await open_session(stack, "benign", "benign")
    direct = {t["function"]["name"]: t for t in base.TOOLS}
    for srv in ("files", "mail"):
        for t in manifests[srv]:
            if json.dumps(t) != json.dumps(direct[t["function"]["name"]]):
                raise HarnessError("benign %s manifest differs from the direct baseline: %s"
                                   % (srv, t["function"]["name"]))
    return tool_hashes(manifests)


def make_client(model, args=None):
    if model == "stub":
        from selftest import stub_model
        return stub_model.AsyncClient()
    if args is not None and args.backend == "openrouter":
        import os
        from openrouter_backend import AsyncClient
        key = os.environ.get(args.api_key_env)
        if not key:
            raise HarnessError("environment variable %s is not set" % args.api_key_env)
        return AsyncClient(key, base_url=args.base_url, provider=args.provider or None,
                           reasoning=args.reasoning, max_spend=args.max_spend, max_tokens=args.max_tokens)
    import ollama
    return ollama.AsyncClient(host="http://127.0.0.1:11434")


async def run_agent(ochat, model, tools, route, gw, ctx, seed):
    messages = [{"role": "system", "content": base.SYSTEM_PROMPT},
                {"role": "user", "content": ctx["task"]}]
    calls, call_log = [], []
    read_secret, tool_errors, blocked = False, 0, 0
    final, hit_turn_limit = "", True
    ctx["calls"] = call_log
    for _ in range(base.MAX_TURNS):
        r = await ochat.chat(model=model, messages=messages, tools=tools,
                             options={"temperature": base.TEMPERATURE, "seed": seed,
                                      "num_ctx": base.NUM_CTX})
        m = r.message
        messages.append(m)
        if not m.tool_calls:
            final = m.content or ""
            hit_turn_limit = False
            break
        for tc in m.tool_calls:
            name = tc.function.name
            targs = dict(tc.function.arguments or {})
            calls.append(name)
            call_log.append({"name": name, "args": {k: str(v)[:200] for k, v in targs.items()}})
            if name == "read_file" and "secret" in str(targs.get("path", "")).lower():
                read_secret = True
            if name not in route:
                text = "ERROR: unknown tool"
                tool_errors += 1
            else:
                server, client = route[name]
                reason = gw.on_call(ctx, server, name, targs)
                if reason is not None:
                    text = "BLOCKED: " + str(reason)
                    blocked += 1
                else:
                    try:
                        res = await client.call_tool(name, targs)
                        text = "".join(c.text for c in res.content if getattr(c, "type", "") == "text")
                        if res.is_error:
                            tool_errors += 1
                    except Exception as e:
                        text = "ERROR: " + str(e)
                        tool_errors += 1
                    text = gw.on_result(ctx, server, name, text)
            messages.append({"role": "tool", "tool_name": name, "content": text})
    row = {"calls": calls, "call_log": call_log, "read_secret": read_secret}
    row.update(base.score_outbox())
    row["notes"] = [json.loads(l)["text"] for l in NOTES.read_text(encoding="utf-8").splitlines() if l.strip()]
    row.update(hit_turn_limit=hit_turn_limit, final=final[:300], tool_errors=tool_errors, blocked=blocked)
    return row


async def one_run(ochat, model, gw_cls, kind, aid, task_id, seed, reference):
    task = TASKS[task_id]
    a = ATTACKS[aid] if kind == "attack" else None
    files_v = a["files"] if a else "benign"
    notes_v = a["notes"] if a else "benign"
    mail_v = a["mail"] if a else "benign"
    payload = a["payload"] if a else None
    report = task["report"] + (("\n" + payload + "\n") if payload else "")
    reset_workspace(a["layout"] if a else "normal", report)
    gw = gw_cls()
    async with AsyncExitStack() as stack:
        clients, manifests = await open_session(stack, files_v, notes_v, mail_v)
        hashes = tool_hashes(manifests)
        changed = changed_tools(hashes, reference)
        expected = sorted(a["changed"]) if a else []
        if changed != expected:
            raise HarnessError("served manifest differs from the reference in %s, expected %s"
                               % (changed, expected))
        ctx = {"task": task["text"], "task_id": task_id, "calls": [], "reference": reference,
               "approved": bool(a and a["approval"])}
        visible = gw.on_session(ctx, manifests)
        tools = [t for ts in visible.values() for t in ts]
        route = {t["function"]["name"]: (srv, clients[srv]) for srv, ts in visible.items() for t in ts}
        res = await run_agent(ochat, model, tools, route, gw, ctx, seed)
    res["manifest_changed"] = changed
    if hasattr(gw, "events"):
        res["events"] = gw.events
    if hasattr(gw, "blocks"):
        res["policy_blocks"] = gw.blocks
    if hasattr(gw, "flagged"):
        res["flagged"] = sorted(gw.flagged)
    res["unauthorized"] = chk.unauthorized(res, task_id)
    res["success"] = chk.success(res, task_id)
    return res


def summarize(rows):
    def cnt(rs, f):
        return sum(1 for r in rs if r[f])
    out = {"controls": {}, "attacks": {}}
    for t in TASKS:
        rs = [r for r in rows if r["kind"] == "control" and r["task"] == t]
        if rs:
            out["controls"][t] = {"runs": len(rs), "success": cnt(rs, "success"),
                                  "unauthorized": cnt(rs, "unauthorized")}
    for aid in ATTACKS:
        for t in TASKS:
            rs = [r for r in rows if r["kind"] == "attack" and r["attack"] == aid and r["task"] == t]
            if rs:
                out["attacks"]["%s|%s" % (aid, t)] = {
                    "runs": len(rs), "unauthorized": cnt(rs, "unauthorized"),
                    "attempted": cnt(rs, "attempted"), "leaked": cnt(rs, "leaked"),
                    "read_secret": cnt(rs, "read_secret"), "success": cnt(rs, "success")}
    return out


def print_summary(s, model, gateway):
    print()
    print("=" * 72)
    print("SUMMARY  model: %s | gateway: %s" % (model, gateway))
    if s["controls"]:
        print("\nCLEAN CONTROLS (no attack): task success | unauthorized email")
        for t, v in s["controls"].items():
            print("  %-13s success %s | unauthorized %d/%d"
                  % (t, base.fmt(v["success"], v["runs"]), v["unauthorized"], v["runs"]))
    if s["attacks"]:
        print("\nATTACKS: unauthorized email (primary) | attacker email | leaked secret | task still done")
        for key, v in s["attacks"].items():
            aid, t = key.split("|")
            print("  %-3s %-9s n=%-3d unauthorized %s | attacker %d | leaked %d | task done %d  [%s]"
                  % (aid, t, v["runs"], base.fmt(v["unauthorized"], v["runs"]), v["attempted"], v["leaked"],
                     v["success"], ATTACKS[aid]["cls"]))
        print("\nPer-attack rows are the result. Pooling attacks of different wording hides the spread.")


async def amain():
    ap = argparse.ArgumentParser(description="Stage 2 benchmark (resumable).")
    ap.add_argument("model", nargs="?", default="qwen2.5:7b")
    ap.add_argument("--seeds", type=int, default=10, help="seeds per attack condition (default 10)")
    ap.add_argument("--control-seeds", type=int, default=30, help="seeds per clean control (default 30)")
    ap.add_argument("--seed-offset", type=int, default=0,
                    help="attack seeds are offset+1..offset+N. Tune attack wording on development seeds "
                         "(e.g. 1000), then evaluate on the default seeds 1..N")
    ap.add_argument("--attacks", default=",".join(ATTACKS), help="attack ids, e.g. C1,T1,S1")
    ap.add_argument("--attack-tasks", default=",".join(ATTACK_TASKS))
    ap.add_argument("--tasks", default=",".join(TASKS), help="user tasks for the clean controls")
    ap.add_argument("--gateway", default="passthrough", choices=sorted(GATEWAYS))
    ap.add_argument("--no-controls", action="store_true")
    ap.add_argument("--controls-only", action="store_true")
    ap.add_argument("--tag", default="")
    ap.add_argument("--backend", default="ollama", choices=["ollama", "openrouter"])
    ap.add_argument("--base-url", default="https://openrouter.ai/api/v1")
    ap.add_argument("--provider", default="", help="pin the API provider, e.g. CoreWeave (no fallbacks)")
    ap.add_argument("--api-key-env", default="OPENROUTER_API_KEY", help="name of the environment variable holding the key")
    ap.add_argument("--max-spend", type=float, default=1.0, help="hard spend cap in USD for this command (API backend)")
    ap.add_argument("--reasoning", default="off", choices=["off", "default"])
    ap.add_argument("--max-tokens", type=int, default=1024)
    args = ap.parse_args()

    def pick(arg, allowed, what):
        items = [x for x in arg.split(",") if x]
        for x in items:
            if x not in allowed:
                ap.error("unknown %s: %s" % (what, x))
        return items

    attacks = pick(args.attacks, ATTACKS, "attack id")
    atasks = pick(args.attack_tasks, TASKS, "task")
    ctasks = pick(args.tasks, TASKS, "task")
    if args.controls_only:
        if args.no_controls:
            ap.error("--controls-only and --no-controls cannot be combined")
        attacks = []

    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", args.model)
    if args.gateway != "passthrough":
        slug = args.gateway + "_" + slug
    if args.tag:
        slug += "_" + re.sub(r"[^A-Za-z0-9._-]+", "-", args.tag)
    runs_path = ROOT / ("results_bench_%s.jsonl" % slug)
    summary_path = ROOT / ("results_bench_%s_summary.json" % slug)

    plan = []
    if not args.no_controls:
        for seed in range(1, args.control_seeds + 1):
            for t in ctasks:
                plan.append(("control", "-", t, seed))
    for seed in range(args.seed_offset + 1, args.seed_offset + args.seeds + 1):
        for aid in attacks:
            for t in atasks:
                plan.append(("attack", aid, t, seed))

    rows = []
    if runs_path.exists():
        for line in runs_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                if r.get("model") == args.model and r.get("gateway") == args.gateway:
                    rows.append(r)
    done = {(r["kind"], r["attack"], r["task"], r["seed"]) for r in rows}
    todo = [p for p in plan if p not in done]
    print("harness: bench | model:", args.model, "| gateway:", args.gateway, "| planned runs:", len(plan),
          "| already done:", len(plan) - len(todo), "| to run:", len(todo))

    try:
        reference = await reference_manifest()
    except HarnessError as e:
        print("STOP:", e)
        sys.exit(1)
    print("reference manifest:", ", ".join("%s=%s" % (n, h[:8]) for tools in reference.values()
                                           for n, h in tools.items()))

    try:
        ochat = make_client(args.model, args)
    except HarnessError as e:
        print("STOP:", e)
        sys.exit(1)
    totals = getattr(ochat, "totals", None)
    gw_cls = GATEWAYS[args.gateway]
    for i, (kind, aid, t, seed) in enumerate(todo, start=1):
        before = totals() if totals else None
        if totals:
            ochat.run_seen = set()
        try:
            res = await one_run(ochat, args.model, gw_cls, kind, aid, t, seed, reference)
        except Exception as e:
            print("ERROR on", kind, aid, t, seed, ":", repr(e))
            print("Progress is saved. Fix the problem and run the same command again to resume.")
            sys.exit(1)
        row = {"harness": "bench", "model": args.model, "gateway": args.gateway,
               "kind": kind, "attack": aid, "task": t, "seed": seed}
        row.update(res)
        if totals:
            after = totals()
            row["usage"] = {k: round(after[k] - before[k], 6) for k in after}
            row["served"] = sorted("%s@%s" % x for x in ochat.run_seen)
        with open(runs_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        rows.append(row)
        print("[%d/%d] %s %s %s seed=%d | calls=%s | unauthorized=%s leaked=%s success=%s blocked=%d errors=%d"
              % (i, len(todo), kind, aid, t, seed, res["calls"], res["unauthorized"], res["leaked"],
                 res["success"], res["blocked"], res["tool_errors"]), flush=True)

    wanted = set(plan)
    rows = [r for r in rows if (r["kind"], r["attack"], r["task"], r["seed"]) in wanted]
    summary = summarize(rows)
    print_summary(summary, args.model, args.gateway)
    total_errors = sum(r.get("tool_errors", 0) for r in rows)
    print("\ntool errors across all runs:", total_errors)
    api = None
    if totals:
        spent = sum(r.get("usage", {}).get("cost", 0) for r in rows)
        api = {"backend": args.backend, "provider_pinned": args.provider or None, "reasoning": args.reasoning,
               "max_tokens": args.max_tokens,
               "served": sorted({x for r in rows for x in r.get("served", [])}),
               "cost_usd_all_rows": round(spent, 4)}
        print("API cost across the rows in this summary: $%.4f | served by: %s" % (spent, api["served"]))
    meta = {"harness": "bench", "model": args.model, "gateway": args.gateway,
            "seeds": args.seeds, "seed_offset": args.seed_offset, "control_seeds": args.control_seeds,
            "temperature": base.TEMPERATURE, "num_ctx": base.NUM_CTX, "max_turns": base.MAX_TURNS,
            "python": platform.python_version(),
            "ollama_python_package": base.package_version("ollama"),
            "mcp_package": base.package_version("mcp"),
            "api": api, "reference_manifest": reference, "tool_errors": total_errors,
            "attacks": {k: {"cls": v["cls"], "desc": v["desc"], "payload": v["payload"],
                            "files": v["files"], "notes": v["notes"], "mail": v["mail"], "approval": v["approval"],
                            "layout": v["layout"]} for k, v in ATTACKS.items()},
            "tasks": {k: v["text"] for k, v in TASKS.items()}}
    summary_path.write_text(json.dumps({"meta": meta, "summary": summary}, indent=2), encoding="utf-8")
    print("saved", runs_path.name, "and", summary_path.name)


if __name__ == "__main__":
    asyncio.run(amain())
