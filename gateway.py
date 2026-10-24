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


GATEWAYS = {"passthrough": Gateway}
