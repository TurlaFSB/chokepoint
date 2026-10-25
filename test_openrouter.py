"""Offline tests for the API backend. A local mock server plays the API; no network, no key, no cost.

    python test_openrouter.py
"""
import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import bench
import openrouter_backend as ob
from gateway import Gateway
from selftest import stub_model

FAILED = []
STATE = {"requests": [], "cost": 0.001, "provider": "CoreWeave", "fail_first": 0, "calls": 0}


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg, flush=True)
    if not cond:
        FAILED.append(msg)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        STATE["requests"].append((dict(self.headers), body))
        STATE["calls"] += 1
        if STATE["fail_first"] > 0:
            STATE["fail_first"] -= 1
            self.send_response(429)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        # decide with the scripted stub, then answer in the OpenAI format
        r = stub_model.chat(model=body["model"], messages=body["messages"], tools=body["tools"],
                            options={"seed": body["seed"]})
        m = r.message
        msg = {"role": "assistant", "content": m.content or None}
        if m.tool_calls:
            msg["tool_calls"] = [{"id": "call_%d_%d" % (STATE["calls"], i), "type": "function",
                                  "function": {"name": tc.function.name,
                                               "arguments": json.dumps(tc.function.arguments)}}
                                 for i, tc in enumerate(m.tool_calls)]
        out = {"model": body["model"], "provider": STATE["provider"],
               "choices": [{"message": msg}],
               "usage": {"prompt_tokens": 1000, "completion_tokens": 50, "cost": STATE["cost"]}}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def client(port, **kw):
    kw.setdefault("backoff", 0.01)
    return ob.AsyncClient("test-key", base_url="http://127.0.0.1:%d" % port, provider="CoreWeave", **kw)


async def main(port):
    TOOLS = [{"type": "function", "function": {"name": "read_file", "description": "d",
              "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]
    # 1. round trip and request format
    c = client(port)
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "Please summarize report.txt for me."}]
    r = await c.chat(model="m", messages=msgs, tools=TOOLS, options={"temperature": 0.7, "seed": 5})
    tc = r.message.tool_calls[0]
    check(tc.function.name == "read_file" and tc.function.arguments == {"path": "report.txt"},
          "tool call parsed into name + argument dict")
    msgs.append(r.message)
    msgs.append({"role": "tool", "tool_name": "read_file", "content": "Q3 Report."})
    await c.chat(model="m", messages=msgs, tools=TOOLS, options={"temperature": 0.7, "seed": 5})
    hdr, body = STATE["requests"][0]
    check(hdr.get("Authorization") == "Bearer test-key", "API key sent as bearer token")
    check(body["provider"] == {"order": ["CoreWeave"], "allow_fallbacks": False}, "provider pinned, no fallbacks")
    check(body["reasoning"] == {"enabled": False} and body["seed"] == 5 and body["temperature"] == 0.7,
          "reasoning off, seed and temperature passed")
    _, body2 = STATE["requests"][1]
    asst, tool = body2["messages"][2], body2["messages"][3]
    check(isinstance(asst["tool_calls"][0]["function"]["arguments"], str)
          and tool["tool_call_id"] == asst["tool_calls"][0]["id"],
          "assistant tool call replayed with JSON-string arguments; tool result carries the matching id")
    check(abs(c.cost - 0.002) < 1e-9 and c.tokens_in == 2000 and c.calls == 2, "cost and tokens accumulated")

    # 2. spend cap
    STATE["cost"] = 0.4
    c = client(port, max_spend=1.0)
    n = 0
    try:
        for _ in range(6):
            await c.chat(model="m", messages=msgs[:2], tools=TOOLS, options={"temperature": 0.7, "seed": 5})
            n += 1
    except ob.BudgetExceeded:
        pass
    check(n == 3, "spend cap stops the 4th call after 3 x $0.40 against a $1.00 cap (made %d)" % n)
    STATE["cost"] = 0.001

    # 3. provider mismatch
    STATE["provider"] = "SomeoneElse"
    try:
        await client(port).chat(model="m", messages=msgs[:2], tools=TOOLS, options={"temperature": 0.7, "seed": 5})
        check(False, "reply from another provider is rejected")
    except ob.ProviderMismatch:
        check(True, "reply from another provider is rejected")
    STATE["provider"] = "CoreWeave"

    # 4. retry on 429
    STATE["fail_first"] = 2
    before = STATE["calls"]
    await client(port).chat(model="m", messages=msgs[:2], tools=TOOLS, options={"temperature": 0.7, "seed": 5})
    check(STATE["calls"] - before == 3, "two 429 replies are retried, third succeeds")

    # 5. end to end through the harness, same scripted behaviour as the offline stub
    ref = await bench.reference_manifest()
    c = client(port)
    res = await bench.one_run(c, "m", Gateway, "attack", "C1", "summarize", 3, ref)
    check(res["unauthorized"] and res["leaked"], "harness over the API backend: obeying seed is an unauthorized leak")
    res = await bench.one_run(c, "m", Gateway, "attack", "C1", "summarize", 1, ref)
    check(not res["unauthorized"], "harness over the API backend: non-obeying seed sends nothing")
    res = await bench.one_run(c, "m", Gateway, "control", "-", "followups", 1, ref)
    check(res["success"] and not res["unauthorized"], "harness over the API backend: clean task succeeds")

    print("\n%s" % ("ALL PASSED" if not FAILED else "FAILED: %d" % len(FAILED)))
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    asyncio.run(main(srv.server_address[1]))
