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


def manifest_hashes(manifests):
    """sha256 of every tool definition (name, description, parameter schema), {server: {tool: hash}}."""
    import hashlib
    import json
    return {srv: {t["function"]["name"]: hashlib.sha256(json.dumps(t, sort_keys=True).encode()).hexdigest()
                  for t in tools} for srv, tools in manifests.items()}


class PinningGateway(LoggingGateway):
    """Manifest pinning (Stage 4): compare every served tool definition with a pinned hash.

    source  "reviewed"  pins come from a reviewed allowlist (ctx["reference"]). Any tool whose hash differs,
                        and any tool that is not on the allowlist, is flagged. Catches poisoning that was
                        present from the first day, but needs a review step.
            "tofu"      trust on first use. Without a previously approved manifest (ctx["approved"] False) the
                        first manifest is accepted and pinned, so a tool poisoned from the start is NOT
                        flagged. With one (a rug pull) a changed hash is flagged.
    mode    "alert"     record alerts, change nothing.
            "block"     also hide flagged tools from the model and refuse calls to them.

    Pinning sees tool definitions only. It cannot see what a server does (the path-traversal bug) or what a
    document says (content injection): those manifests are unchanged.
    """
    source = "reviewed"
    mode = "alert"

    def __init__(self):
        super().__init__()
        self.flagged = {}

    @property
    def name(self):
        return "pin-%s-%s" % (self.source, self.mode)

    def on_session(self, ctx, manifests):
        super().on_session(ctx, manifests)
        got = manifest_hashes(manifests)
        first_sight = self.source == "tofu" and not ctx["approved"]
        for srv, tools in got.items():
            for tool, h in tools.items():
                if first_sight:
                    continue  # accepted and pinned now
                pin = ctx["reference"].get(srv, {}).get(tool)
                if pin is None:
                    reason = "tool not on the reviewed allowlist"
                elif pin != h:
                    reason = "definition differs from the pinned hash"
                else:
                    continue
                self.flagged[tool] = reason
                self._event("alert", rule="manifest-pin", server=srv, tool=tool, reason=reason,
                            pinned=pin, served=h, action="block" if self.mode == "block" else "alert")
        if self.mode == "block":
            return {srv: [t for t in tools if t["function"]["name"] not in self.flagged]
                    for srv, tools in manifests.items()}
        return manifests

    def on_call(self, ctx, server, name, args):
        super().on_call(ctx, server, name, args)
        if self.mode == "block" and name in self.flagged:
            return "tool definition changed since it was reviewed (" + name + ")"
        return None


class PinReviewedAlert(PinningGateway):
    source, mode = "reviewed", "alert"


class PinReviewedBlock(PinningGateway):
    source, mode = "reviewed", "block"


class PinTofuAlert(PinningGateway):
    source, mode = "tofu", "alert"


class PinTofuBlock(PinningGateway):
    source, mode = "tofu", "block"


GATEWAYS = {"passthrough": Gateway, "logging": LoggingGateway,
            "pin-reviewed-alert": PinReviewedAlert, "pin-reviewed-block": PinReviewedBlock,
            "pin-tofu-alert": PinTofuAlert, "pin-tofu-block": PinTofuBlock}
