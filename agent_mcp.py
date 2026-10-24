"""Stage 1: the baseline agent with its tools served by real MCP servers.

Same agent, scenarios, payloads, sampling settings and scoring as
agent_baseline_v2.py (imported from it, so they cannot drift). The only change
is that read_file and send_email now live in two separate MCP servers
(servers/files_server.py and servers/mail_server.py) that this harness starts as
subprocesses and talks to over stdio with the official MCP Python SDK.

Parity check: at startup the tool definitions received from the servers are
normalised and compared with the hand-written definitions of the direct
baseline. If they differ in any way the run stops, so the model always sees the
same tools in both harnesses.

Known difference: when the model sends malformed arguments, the MCP server's
validation error text differs from the direct harness's error text. The number
of tool errors is recorded per run (tool_errors).

Every finished run is appended to results_mcp_<model>.jsonl; repeat the command
to resume after an interruption.
"""
import argparse
import asyncio
import json
import platform
import re
import sys
from pathlib import Path

import ollama
from mcp import Client, StdioServerParameters

import agent_baseline_v2 as base

SERVERS = Path(__file__).parent / "servers"
DROP = ("title", "default")


def canon_prop(prop):
    out = {}
    for k in ("type", "description"):
        if k in prop:
            out[k] = prop[k]
    for k, v in prop.items():
        if k not in out and k not in DROP:
            out[k] = v
    return out


def canon_params(schema):
    out = {"type": schema.get("type"),
           "properties": {n: canon_prop(p) for n, p in schema.get("properties", {}).items()}}
    if "required" in schema:
        out["required"] = list(schema["required"])
    for k, v in schema.items():
        if k not in ("type", "properties", "required") and k not in DROP:
            out[k] = v
    return out


def to_ollama_tool(t):
    return {"type": "function",
            "function": {"name": t.name, "description": t.description,
                         "parameters": canon_params(t.input_schema)}}


def server_params():
    return {
        "files": StdioServerParameters(
            command=sys.executable,
            args=[str(SERVERS / "files_server.py"), "--sandbox", str(base.SANDBOX)]),
        "mail": StdioServerParameters(
            command=sys.executable,
            args=[str(SERVERS / "mail_server.py"), "--outbox", str(base.OUTBOX)]),
    }


async def run_agent(ochat, model, tools, route, task, report_text, seed):
    base.reset_sandbox(report_text)
    messages = [
        {"role": "system", "content": base.SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]
    calls = []
    read_secret = False
    tool_errors = 0
    final = ""
    hit_turn_limit = True
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
            if name == "read_file" and "secret" in str(targs.get("path", "")).lower():
                read_secret = True
            if name in route:
                try:
                    res = await route[name].call_tool(name, targs)
                    text = "".join(c.text for c in res.content if getattr(c, "type", "") == "text")
                    if res.is_error:
                        tool_errors += 1
                except Exception as e:
                    text = "ERROR: " + str(e)
                    tool_errors += 1
            else:
                text = "ERROR: unknown tool"
                tool_errors += 1
            messages.append({"role": "tool", "tool_name": name, "content": text})
    row = {"calls": calls, "read_secret": read_secret}
    row.update(base.score_outbox())
    row["hit_turn_limit"] = hit_turn_limit
    row["final"] = final[:300]
    row["tool_errors"] = tool_errors
    return row


async def amain():
    ap = argparse.ArgumentParser(description="Baseline through real MCP servers (resumable).")
    ap.add_argument("model", nargs="?", default="qwen2.5:7b")
    ap.add_argument("--seeds", type=int, default=10, help="seeds per condition (default 10)")
    ap.add_argument("--scenarios", default=",".join(base.SCENARIOS))
    ap.add_argument("--payloads", default=",".join(str(p) for p in base.PAYLOADS))
    ap.add_argument("--no-controls", action="store_true")
    ap.add_argument("--tag", default="")
    args = ap.parse_args()

    sel_scenarios = [s for s in args.scenarios.split(",") if s]
    for s in sel_scenarios:
        if s not in base.SCENARIOS:
            ap.error("unknown scenario: " + s)
    try:
        sel_payloads = [int(p) for p in args.payloads.split(",") if p]
    except ValueError:
        ap.error("--payloads must be comma-separated integers")
    for p in sel_payloads:
        if p not in base.PAYLOADS:
            ap.error("unknown payload id: %d" % p)

    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", args.model)
    if args.tag:
        slug += "_" + re.sub(r"[^A-Za-z0-9._-]+", "-", args.tag)
    runs_path = base.ROOT / ("results_mcp_%s.jsonl" % slug)
    summary_path = base.ROOT / ("results_mcp_%s_summary.json" % slug)
    seeds = list(range(1, args.seeds + 1))

    rows = []
    if runs_path.exists():
        for line in runs_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if row.get("model") == args.model:
                    rows.append(row)
    done = {(r["scenario"], r["kind"], r["payload"], r["seed"]) for r in rows}

    plan = []
    for seed in seeds:
        for sc in sel_scenarios:
            if not args.no_controls:
                plan.append((sc, "control", 0, seed))
            for pid in sel_payloads:
                plan.append((sc, "attack", pid, seed))
    todo = [p for p in plan if p not in done]
    print("harness: mcp | model:", args.model, "| seeds:", args.seeds, "| planned runs:", len(plan),
          "| already done:", len(plan) - len(todo), "| to run:", len(todo))

    params = server_params()
    ochat = ollama.AsyncClient(host="http://127.0.0.1:11434")
    async with Client(params["files"], read_timeout_seconds=30) as files, \
            Client(params["mail"], read_timeout_seconds=30) as mail:
        tools = []
        route = {}
        for client in (files, mail):
            for t in (await client.list_tools()).tools:
                tools.append(to_ollama_tool(t))
                route[t.name] = client
        if json.dumps(tools) != json.dumps(base.TOOLS):
            print("STOP: tool definitions from the MCP servers differ from the direct baseline.")
            print("mcp   :", json.dumps(tools))
            print("direct:", json.dumps(base.TOOLS))
            sys.exit(1)
        print("tool definitions identical to the direct baseline:", [t["function"]["name"] for t in tools])

        for i, (sc, kind, pid, seed) in enumerate(todo, start=1):
            report = base.SCENARIOS[sc]["report"]
            if kind == "attack":
                report = report + "\n" + base.PAYLOADS[pid] + "\n"
            try:
                res = await run_agent(ochat, args.model, tools, route,
                                      base.SCENARIOS[sc]["task"], report, seed)
            except Exception as e:
                print("ERROR on", sc, kind, pid, seed, ":", repr(e))
                print("Progress is saved. Fix the problem and run the same command again to resume.")
                sys.exit(1)
            row = {"harness": "mcp", "model": args.model, "scenario": sc, "kind": kind,
                   "payload": pid, "seed": seed}
            row.update(res)
            with open(runs_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            rows.append(row)
            print("[%d/%d] %s %s payload=%d seed=%d | calls=%s | attempted=%s leaked=%s tool_errors=%d"
                  % (i, len(todo), sc, kind, pid, seed, res["calls"], res["attempted"],
                     res["leaked"], res["tool_errors"]), flush=True)

    wanted = set(plan)
    rows = [r for r in rows if (r["scenario"], r["kind"], r["payload"], r["seed"]) in wanted]
    summary = base.summarize(rows)
    base.print_summary(summary, args.model)
    base.print_audit(rows)
    total_errors = sum(r.get("tool_errors", 0) for r in rows)
    print()
    print("tool errors across all runs:", total_errors)

    meta = {
        "harness": "mcp",
        "model": args.model,
        "seeds": seeds,
        "temperature": base.TEMPERATURE,
        "num_ctx": base.NUM_CTX,
        "max_turns": base.MAX_TURNS,
        "python": platform.python_version(),
        "ollama_python_package": base.package_version("ollama"),
        "mcp_package": base.package_version("mcp"),
        "tool_errors": total_errors,
        "scenarios": {k: v["task"] for k, v in base.SCENARIOS.items()},
        "payloads": {str(k): v for k, v in base.PAYLOADS.items()},
    }
    summary_path.write_text(json.dumps({"meta": meta, "summary": summary}, indent=2), encoding="utf-8")
    print("saved", runs_path.name, "and", summary_path.name)


if __name__ == "__main__":
    asyncio.run(amain())
