"""Gateway interface between the agent and its tool servers.

Stage 2 only ships the pass-through gateway (no defense). The hooks exist so that
every later defense runs inside the same harness, against the same attacks and tasks:

  on_session(ctx, manifests)          sees the tool manifests of all servers at connect time
                                      and returns the manifests the model may see
                                      ({server: [tool, ...]}; drop a tool to hide it)
  on_call(ctx, server, name, args)    return None to allow the call, or a reason string to block it
  on_result(ctx, server, name, text)  may rewrite the tool output before the model sees it

ctx is a dict: task (user text), task_id, calls (call log so far), reference (the reviewed
manifest hashes, {server: {tool: sha256}}) and approved (True if a reviewed manifest exists
for this run, i.e. a rug pull; False if the client sees this manifest for the first time).
"""


class Gateway:
    name = "passthrough"

    def on_session(self, ctx, manifests):
        return manifests

    def on_call(self, ctx, server, name, args):
        return None

    def on_result(self, ctx, server, name, text):
        return text


class LoggingGateway(Gateway):
    """Records every event of a run and changes nothing (Stage 3).

    Events are plain dicts, stored in the result row (`events`), so that a run can be replayed
    through any other gateway without a model (replay.py) and turned into detection logs later.
    Event kinds:
      session  full tool manifests offered to the model, their hashes, task id, whether a reviewed manifest exists
      call     server, tool, full arguments, in the order the model made them
      result   server, tool, the tool output (first 2000 characters), its length and sha256
    `t` is seconds since the session started (wall clock, so it differs between runs).
    """
    name = "logging"

    def __init__(self):
        import time
        self.events = []
        self._time = time
        self._t0 = time.monotonic()

    def _event(self, kind, **fields):
        self.events.append({"i": len(self.events), "t": round(self._time.monotonic() - self._t0, 4),
                            "kind": kind, **fields})

    def on_session(self, ctx, manifests):
        import hashlib
        import json
        hashes = {srv: {t["function"]["name"]: hashlib.sha256(json.dumps(t, sort_keys=True).encode()).hexdigest()
                        for t in tools} for srv, tools in manifests.items()}
        self._event("session", task_id=ctx["task_id"], approved=ctx["approved"],
                    manifests=manifests, manifest_hashes=hashes)
        return manifests

    def on_call(self, ctx, server, name, args):
        self._event("call", server=server, tool=name, args=dict(args))
        return None

    def on_result(self, ctx, server, name, text):
        import hashlib
        self._event("result", server=server, tool=name, result=text[:2000], result_len=len(text),
                    result_sha=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest())
        return text


GATEWAYS = {"passthrough": Gateway, "logging": LoggingGateway}
