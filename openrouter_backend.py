"""Chat backend for OpenAI-compatible APIs (written for OpenRouter), same interface as ollama.AsyncClient.

bench.py only calls  await client.chat(model=..., messages=..., tools=..., options={...})  and reads
.message.content / .message.tool_calls[i].function.name / .arguments, so this class can replace the
Ollama client without touching the harness.

Safeguards:
  - the API key is read from an environment variable and never written anywhere
  - a hard spend cap: the next call raises BudgetExceeded once the cost reported by the API
    (usage.cost; token prices as fallback) reaches max_spend
  - when a provider is pinned, requests forbid fallbacks and a reply served by any other provider
    raises ProviderMismatch
  - 429 and 5xx replies are retried with backoff; anything else stops the run (progress is saved)
"""
import asyncio
import json

import httpx


class BudgetExceeded(Exception):
    pass


class ProviderMismatch(Exception):
    pass


class _Fn:
    def __init__(self, name, arguments):
        self.name, self.arguments = name, arguments


class _TC:
    def __init__(self, name, arguments):
        self.function = _Fn(name, arguments)


class _Msg:
    def __init__(self, content, tool_calls, raw):
        self.content, self.tool_calls, self.raw = content, tool_calls, raw


class _Resp:
    def __init__(self, message):
        self.message = message


def to_openai_messages(messages):
    """Harness messages (dicts, plus _Msg objects returned by chat) -> OpenAI chat format.
    Tool results carry no id in the harness, so ids are matched in order to the preceding tool calls."""
    out, pending = [], []
    for m in messages:
        if isinstance(m, dict):
            if m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": pending.pop(0) if pending else "call_unknown",
                            "content": m["content"]})
            else:
                out.append({"role": m["role"], "content": m["content"]})
        else:
            out.append(m.raw)
            pending = [tc["id"] for tc in m.raw.get("tool_calls") or []]
    return out


class AsyncClient:
    def __init__(self, api_key, base_url="https://openrouter.ai/api/v1", provider=None, reasoning="off",
                 max_spend=None, max_tokens=1024, price_in=0.15e-6, price_out=0.65e-6,
                 retries=4, backoff=2.0, timeout=120):
        if not api_key:
            raise ValueError("no API key")
        self.api_key, self.base_url, self.provider = api_key, base_url.rstrip("/"), provider
        self.reasoning, self.max_spend, self.max_tokens = reasoning, max_spend, max_tokens
        self.price_in, self.price_out = price_in, price_out
        self.retries, self.backoff = retries, backoff
        self.http = httpx.AsyncClient(timeout=timeout)
        self.cost, self.tokens_in, self.tokens_out, self.calls = 0.0, 0, 0, 0
        self.seen = set()

    def totals(self):
        return {"cost": self.cost, "tokens_in": self.tokens_in, "tokens_out": self.tokens_out, "calls": self.calls}

    async def _post(self, body):
        headers = {"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"}
        last = None
        for attempt in range(self.retries):
            try:
                r = await self.http.post(self.base_url + "/chat/completions", headers=headers, json=body)
                if r.status_code == 429 or r.status_code >= 500:
                    last = "HTTP %d" % r.status_code
                else:
                    return r
            except httpx.TransportError as e:
                last = repr(e)
            await asyncio.sleep(self.backoff * (2 ** attempt))
        raise RuntimeError("API unavailable after %d tries (%s)" % (self.retries, last))

    async def chat(self, model, messages, tools, options):
        if self.max_spend is not None and self.cost >= self.max_spend:
            raise BudgetExceeded("spent %.4f of the %.4f cap" % (self.cost, self.max_spend))
        body = {"model": model, "messages": to_openai_messages(messages), "tools": tools,
                "temperature": options["temperature"], "seed": options["seed"],
                "max_tokens": self.max_tokens, "usage": {"include": True}}
        if self.provider:
            body["provider"] = {"order": [self.provider], "allow_fallbacks": False}
        if self.reasoning == "off":
            body["reasoning"] = {"enabled": False}
        r = await self._post(body)
        data = r.json()
        if r.status_code != 200 or "error" in data:
            raise RuntimeError("API error %d: %s" % (r.status_code, str(data.get("error", data))[:300]))
        served = data.get("provider")
        if self.provider and served and served != self.provider:
            raise ProviderMismatch("served by %s, pinned to %s" % (served, self.provider))
        self.seen.add((data.get("model"), served))
        usage = data.get("usage") or {}
        tin, tout = int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
        cost = usage.get("cost")
        self.cost += float(cost) if cost is not None else tin * self.price_in + tout * self.price_out
        self.tokens_in += tin
        self.tokens_out += tout
        self.calls += 1
        msg = data["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            a = tc["function"].get("arguments")
            if isinstance(a, str):
                try:
                    a = json.loads(a) if a.strip() else {}
                except ValueError:
                    a = {"_unparsed": a}
            calls.append(_TC(tc["function"]["name"], a if isinstance(a, dict) else {"_value": a}))
        raw = {"role": "assistant", "content": msg.get("content"), "tool_calls": msg.get("tool_calls")}
        if not raw["tool_calls"]:
            del raw["tool_calls"]
        return _Resp(_Msg(msg.get("content") or "", calls or None, raw))
