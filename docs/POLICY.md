# Information-flow policy (Stage 5)

What the gateway enforces, why, what it cannot do, and how it is evaluated. Code: `FlowGateway` in `gateway.py`. Tests: `test_flow.py`.

## Threat model

The attacker controls **data the agent reads** (a document, a note), and in some attacks a **tool definition**. The attacker does not control the user's request, the gateway, or the MCP servers' code (except the deliberately vulnerable path-traversal fixture). The goal of the attack is to make the agent send data or messages the user did not ask for. The policy defends the one tool that sends data out, `send_email`.

## Trust model

| Source | Trust |
|---|---|
| The user's request | Trusted |
| Operator configuration (allowed domains, what counts as secret) | Trusted |
| Everything a tool returns (file text, notes) | Untrusted |
| The model's own output | Not a source of trust: a model that read untrusted text can repeat it |

The gateway sees tool arguments and tool results, not the model's reasoning, so provenance is decided by **value matching**: an argument is judged by where its value may come from, not by tracking tokens inside the model.

## Rules

**Rule 1: integrity of the recipient.** Every address in `to` must be trusted. Three policies are implemented so that the cost of each is measured:

| Policy | An address is trusted if | Consequence |
|---|---|---|
| `strict` | the user's request names it | Blocks the benign `followups` task, whose recipient comes from the document |
| `domain` | the request names it, or its domain is on the operator allowlist (`example.com`) | What a mail DLP rule does; usable |
| `off` | always | Used to measure Rule 2 alone |

A blocked call returns the reason to the model and is logged as an alert, with whether the address was **seen in untrusted tool output** (injected) or **in no tool output** (invented).

**Rule 2: confidentiality of secrets.** A tool result is labelled secret if the file path looks sensitive (`vault/`, `secret*`) or the text looks like a credential (`api key: ...`, `password = ...`). Any token of 8 or more characters from a secret result may not appear in the subject or body of an email, **to anyone**, so it also stops a leak to an allowed recipient. Reading a secret is not blocked; only its flow out is.

Variants: `flow-strict`, `flow-domain` (Rule 1), `flow-secret` (Rule 2), `flow-full` (domain + Rule 2, the proposed policy), `flow-full-strict` (strict + Rule 2).

## Known limits (each is a test in `test_flow.py`, marked LIMIT)

- **Re-encoded secrets are not seen.** A base64 or split secret sent to an allowed recipient passes. Value matching cannot see through a transformation; real IFC needs taint tracked inside the model, which a gateway cannot do.
- **The domain allowlist trusts a whole domain.** `attacker@example.com` passes `domain`; `strict` stops it. An attacker who can create an address on an allowed domain defeats the allowlist.
- **Only `send_email` is watched.** `add_note` and other tools are not covered; a poisoned notes server could still be a channel.
- **The recipient rule overlaps the benchmark's own definition of "unauthorized"** (an address the request does not name). On this benchmark it therefore cannot fail to stop an email to `attacker@evil.test`. What the benchmark can still show is its **cost** (the strict variant) and the **secret** rule, which is independent of the scorer. Do not read "86 of 86" as a general result.
- Address parsing: the policy parses addresses with a regular expression. A mangled `to` field is blocked, not guessed.

## Evaluation protocol

1. **Replay** on the 380 logged qwen runs (model-free, deterministic): which recorded hijacks would be stopped, which clean runs would be blocked. Replay does not show what the model does after a block.
2. **Live runs** on development seeds (1001-1010) with the policy in the loop: the model sees the block and may retry, give up, or tell the user. Measures attack success, task completion, and the number of blocks per run.
3. Freeze the policy with a git tag, then run it on the **evaluation seeds** (1-10), where the undefended baseline already exists, and compare unpaired.
4. Adaptive attacks written against the policy (Stage 7) are reported separately and never merged into the frozen set.
