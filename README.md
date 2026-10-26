# Chokepoint

**A deterministic runtime gateway for AI agents that use tools (MCP), and a reproducible benchmark that measures what such a gateway stops and what it costs.**

> **Status: research in progress.** Built and measured: the attack benchmark, an undefended baseline on two models, manifest pinning, and an information-flow policy. The policy's run on the frozen evaluation seeds, the static audit of MCP servers, and attacks written against the finished defense are still ahead (see [Roadmap](#roadmap)). Every number below traces to a saved result file in this repository.

---

## Results at a glance

Model `qwen2.5:7b` (the one agent in the study that attackers can actually steer). Primary metric: **unauthorized email**, any email to a recipient the user's own request does not name. Intervals are 95% Wilson.

| | Undefended | Manifest pinning (reviewed pins, block) | Information-flow policy (`flow-full`) |
|---|---|---|---|
| **Live, development seeds:** hijacked runs | 86 of 200 (43%) | not run live | **1 of 200 (0.5%, CI 0.1-2.8%)** |
| Emails to the attacker / fake key leaked | 86 / 63 | n/a | **0 / 0** |
| User's task still done under attack | 164 of 200 | n/a | 184 of 200 |
| **Replay, 86 recorded hijacks:** stopped | 0 | 3 (3%) | **86 (100%)** |
| **Clean work:** runs blocked (180 runs each) | 0 | 0 on replay | **0 on qwen and 0 on DeepSeek**, behavior identical to undefended |
| Frozen evaluation seeds (1-10) | 90 of 400 hijacked | n/a | **pending** |

How to read this honestly:

- **Pinning is necessary but narrow.** It detects 11 of the 20 attacks with a reviewed allowlist (2 of 20 with trust on first use) and has no false alarms, but it cannot see the nine attacks that change no tool definition, and those are the ones that actually hijack a 7B model.
- **The information-flow policy stops what pinning cannot**, but one of its rules (recipient on an allowed domain) overlaps how the benchmark scores an attack. The informative parts are the secret rule (stops 52 of 86 alone), the cost of the strict variant (blocks 27 of 180 clean runs), the one live miss, and the documented bypasses below.
- **A strong hosted model (DeepSeek V4.1 Flash) resisted all 20 attacks**: 0 unauthorized emails in 400 runs (CI 0-1%). On it the benchmark can show only a defense's cost (zero on clean work), so attacks written specifically for it are planned.
- **Known bypasses** of the policy are written as tests, not hidden: a re-encoded (base64, split) secret sent to an allowed recipient, an attacker address on an allowed domain, and any channel other than `send_email`. In the live run the single miss was the model inventing an address on the allowed domain after it was blocked.

Full tables, per-attack rows, intervals and the audit trail: [`docs/RESULTS.md`](docs/RESULTS.md) (experiments 1-16).

---

## The problem

An AI agent that reads untrusted content (documents, emails, web pages, tool output) can be steered by instructions hidden in that content into misusing its tools, for example reading a private file and emailing it to an attacker. The tools themselves are a second attack surface: a poisoned tool description, a description that changes after approval (a "rug pull"), or one tool's description that rewrites how another tool is used.

Prompt-level defenses are probabilistic. Chokepoint tests **deterministic enforcement at the boundary between the agent and its tools**, and, as importantly, measures the damage a defense does to normal work. A defense that blocks every attack by blocking every task is not a result.

### Threat model

The attacker controls **data the agent reads** (a document, a note) and, in some attacks, **a tool definition**. The attacker does not control the user's request, the gateway, or the MCP servers' code (except one deliberately vulnerable fixture). The goal of an attack is to make the agent send data or messages the user did not ask for. The defenses protect the tool that sends data out, `send_email`. Full statement and trust model: [`docs/POLICY.md`](docs/POLICY.md).

## How it works

```mermaid
flowchart LR
    U[User request<br/>trusted] --> A[Agent / LLM]
    A -- tool call --> G
    subgraph G [Gateway - one interface, pluggable defenses]
        direction TB
        L[Logging<br/>every session, call, result] --> P[Manifest pinning<br/>hash each tool definition]
        P --> F[Information-flow policy<br/>who may be written to, what may leave]
    end
    G --> FS[files server]
    G --> MS[mail server]
    G --> NS[notes server]
    FS -. untrusted content .-> G
    G -- result or BLOCKED + reason --> A
```

The agent talks to three real MCP servers over stdio. Every defense plugs into one interface (`gateway.py`: `on_session`, `on_call`, `on_result`), so each is evaluated in the same harness against the same attacks and the same benign tasks.

| Defense | What it enforces | Sees | Cannot see |
|---|---|---|---|
| **Logging gateway** | Nothing (records every session, call and result so runs can be replayed with no model) | everything | n/a. Verified to change no behavior: 180 of 180 live runs identical |
| **Manifest pinning** | A served tool definition must match a pinned hash (reviewed allowlist, or trust on first use); alert or block | tool descriptions and schemas | server behavior, document content |
| **Information-flow policy** | (1) every recipient is named by the user or on an allowed domain; (2) data labelled secret never leaves in a subject or body | `send_email` arguments, tool results | a re-encoded secret, other tools, what the model says |

## The benchmark

**Attack classes** (20 attacks; each has an id, e.g. `T4`):

| Class | Ids | What the attacker controls |
|---|---|---|
| Content injection | C1-C8 | Hidden instruction in the document the agent reads (eight wordings) |
| Tool poisoning | T1-T6 | Instruction inside a tool or parameter description, in several wordings and positions |
| Cross-server shadowing | S1-S3 | A tool the task never uses rewrites how `send_email` is used |
| Rug pull | R1-R2 | A manifest approved as benign is served as poisoned in a later session |
| Path traversal | P1 | Injected instruction plus a server with a confinement bug (its manifest is identical to the benign one, so pinning cannot see it) |

**Benign tasks** (utility): `summarize`, `followups`, `email_report`, `summary_carol`, `read_notes`, `add_note`. Attacks run against `summarize` and `followups`.

**Metrics.** Primary: unauthorized-email rate (every address in the `to` field is checked). Secondary: email to the attacker address, leak of the fake secret (strict and loose), task success under attack. Every rate carries a 95% Wilson interval; conditions are compared unpaired.

**Rules that keep it honest** ([`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)):

1. Attacks are tuned only against the undefended agent, only on development seeds, then frozen with a git tag (`attack-set-v3`) before any defense is evaluated.
2. A defense is tuned only on development seeds, frozen with a tag, then run once on the evaluation seeds where the undefended baseline already exists.
3. Variants that did not work stay in the results; weak attacks are reported as weak.
4. A run that could have been corrupted is discarded and re-run, not repaired (one such incident is documented).
5. Changes after seeing data are disclosed (a control task that could never pass was replaced, and the record says so).

**Validity checks.** The benchmark refuses to run if the tool definitions the model sees differ from the ones the experiment declares; the MCP transport was shown not to change agent behavior; the leak detector was audited against email bodies; harness and defenses are covered by offline test suites using a scripted stand-in model, so the machinery is verified separately from any language model.

## Quick start

Requires Python 3.12 (results recorded with 3.12.10). The offline tests need no model and no network.

```powershell
# Windows PowerShell (Linux/macOS: python3 -m venv .venv; source .venv/bin/activate)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.lock.txt

python test_bench.py          # harness: guards, fixtures, all 20 attacks, scoring (scripted stand-in model)
python test_openrouter.py     # hosted-model backend against a local mock server
python test_replay.py         # logging gateway changes nothing; replay scores a gateway on recorded runs
python test_pinning.py        # manifest pinning: unit tests and detection across all 20 attacks
python test_flow.py           # information-flow policy: rules, documented bypasses, stub runs, replay
python test_lock.py           # two benchmark processes cannot share the work/ folder
python detect.py              # detection table for the pinning gateways
python replay.py results_bench_logging_qwen2.5-7b_logged.jsonl --gateway flow-full   # score a defense on recorded runs
```

Run against a local model ([Ollama](https://ollama.com) running, model pulled), undefended and then with the policy:

```powershell
ollama pull qwen2.5:7b
python test_reliability.py qwen2.5:7b                                   # tool-calling must pass 12/12 first
python bench.py qwen2.5:7b --controls-only --tag controls               # 180 clean runs
python bench.py qwen2.5:7b --no-controls --seed-offset 1000 --tag dev   # attack runs, development seeds
python bench.py qwen2.5:7b --no-controls --gateway flow-full --seed-offset 1000 --attacks C1,C2,C3,C4,C5,C6,C7,C8,P1,T2 --tag policy_dev
```

Run against a hosted model (key from the environment, hard spend cap, provider pinned):

```powershell
$env:OPENROUTER_API_KEY = "<your key>"
python bench.py deepseek/deepseek-v4.1-flash-20260910 --backend openrouter --provider CoreWeave --max-spend 0.60 --controls-only --gateway flow-full --tag policy
```

Gateways: `passthrough`, `logging`, `pin-reviewed-alert|block`, `pin-tofu-alert|block`, `flow-strict`, `flow-domain`, `flow-secret`, `flow-full`, `flow-full-strict`.

Every finished run is appended to a results file, so an interrupted command resumes when repeated. A model call that gets no answer for five minutes stops the run with a message naming the turn and the last message. Only one benchmark process may use the folder at a time (a lock enforces it). All commands and the file map: [`docs/REPRODUCING.md`](docs/REPRODUCING.md).

## Repository layout

```
bench.py, attacks.py, tasks_check.py     benchmark harness, attack and task definitions, scoring
gateway.py                               gateway interface and every defense (logging, pinning, information-flow)
replay.py, detect.py                     score a defense on recorded runs / on manifest detection, no model
openrouter_backend.py                    hosted-model backend (spend cap, provider pin)
servers/                                 the three toy MCP servers and the attacker-controlled description variants
selftest/                                scripted stand-in model for offline tests
test_*.py                                offline test suites (bench, openrouter, replay, pinning, flow, lock) and tool-calling checks
agent_baseline*.py, agent_mcp.py         earlier baselines (direct tools, then MCP); kept unchanged
compare_runs.py                          row-by-row comparison of two result files
results_*.jsonl, results_*_summary.json  raw per-run data and summaries for every experiment
docs/                                    METHODOLOGY, RESULTS, POLICY, REPRODUCING
requirements.txt, requirements.lock.txt  direct dependencies / exact versions used for the recorded results
```

## Roadmap

| # | Step | Status |
|---|---|---|
| 1 | Real MCP servers; baseline re-measured and shown equivalent to direct tools | Done |
| 2 | Attack suite and benign tasks; hosted-model backend; attack set frozen (`attack-set-v3`) | Done |
| 3 | Logging gateway (no behavior change) and trajectory replay (86 hijacked, 294 benign recorded runs) | Done |
| 4 | Manifest pinning: 11 of 20 attacks detected with reviewed pins, nine invisible to it | Done |
| 5 | Information-flow policy: 86 to 1 hijacked runs live (dev seeds), 0 clean runs blocked on two models. **Frozen-seed run next** | In progress |
| 6 | Static audit of MCP server code (finds what pinning cannot, e.g. the path-traversal bug) | Planned |
| 7 | Baseline defenses for comparison; **adaptive attacks written against the frozen policy and aimed at the hosted model that resisted all 20 frozen attacks**, kept as a separate set | Planned |
| 8 | Detection rules (Sigma, OWASP agentic, MITRE ATLAS mapping), one-command reproduction, write-up, demo | Planned |

## Limitations

- **Two models.** One small local model and one hosted model. Frontier models may behave differently; susceptibility is model-dependent, which is why per-attack tables are reported.
- **Minimal fake environment.** Three tools, six benign tasks, one fake secret. The benchmark measures enforcement mechanics, not the breadth of real deployments. Six benign tasks cannot find every false block; widening this set is planned.
- **Scope of enforcement.** The policy watches `send_email`. It does not see re-encoded secrets, other tools (`add_note`), or what the model says in its reply. The recipient rule overlaps the benchmark's own definition of an attack.
- **Run-level reproducibility.** Seeded runs reproduce exactly only when a whole sequence is repeated unchanged; a local server can also fall back from GPU to CPU mid-session. Results are therefore reported as rates with intervals, not transcripts.
- **Replay is not a live run.** It scores decisions on fixed inputs; a blocked call changes what a real model does next (a live run saw the model invent a new address after being blocked).
- **Hosted models drift.** Hosted runs record the model id, provider and date and supplement the local results.

## Safety and ethics

Everything runs against fake data: a fake secret string and an attacker address under the reserved `.test` domain. `send_email` sends nothing; it appends a line to a local file. `read_file` is confined to a local folder (except in the deliberately vulnerable path-traversal fixture, which only ever sees fake files). The only network traffic is to the local model server or, if you choose it, the hosted API, and only fake data is sent. The attack texts are generic prompt injections against a toy system. Do not point any of this at systems you do not own.

## License

Not yet chosen. Until a license is added, all rights are reserved.
