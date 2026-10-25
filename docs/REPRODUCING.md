# Reproducing the results

## Environment

- Python 3.12 (recorded with 3.12.10), Windows PowerShell commands shown; on Linux/macOS replace the activation line with `source .venv/bin/activate`.
- `requirements.lock.txt` pins the exact versions used for the recorded results (for example `mcp==2.3.0`, `ollama==0.6.3`); `requirements.txt` lists direct dependencies only.
- Local runs: [Ollama](https://ollama.com) listening on `127.0.0.1:11434`. If `OLLAMA_HOST` is set to `0.0.0.0` the Python client may fail to connect; unset it.
- Recorded on one Windows machine with a 6 GB GPU; partial CPU offload may affect run-level determinism (see METHODOLOGY section 9).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.lock.txt
```

## 1. Offline checks (no model, no network)

```powershell
python test_bench.py          # 37 checks on the harness
python test_openrouter.py     # 13 checks on the API backend (local mock server)
```

## 2. Candidate-model check

A model is used only if it passes tool calling.

```powershell
ollama pull qwen2.5:7b
python test_tools.py qwen2.5:7b
python test_reliability.py qwen2.5:7b      # 12 prompts, must be 12/12 with 0 false tool calls
```

## 3. Experiments

Every command appends each finished run to its results file and resumes if repeated. `--tag` keeps a run in its own files.

| Experiment | Command | Runs | Output |
|---|---|---|---|
| Baseline v1 | `python agent_baseline.py qwen2.5:7b` | 24 | `results_baseline_v1.json` |
| Baseline v2 (direct tools) | `python agent_baseline_v2.py qwen2.5:7b` | 180 | `results_baseline_v2_qwen2.5-7b.jsonl` |
| Leak-check audit | `python agent_baseline_v2.py qwen2.5:7b --scenarios followups --payloads 1,5,7 --no-controls --tag audit` | 30 | `..._audit.jsonl` |
| MCP baseline | `python agent_mcp.py qwen2.5:7b` | 180 | `results_mcp_qwen2.5-7b.jsonl` |
| MCP clean controls | `python agent_mcp.py qwen2.5:7b --seeds 30 --controls-only --tag controls` | 60 | `results_mcp_qwen2.5-7b_controls.jsonl` |
| Stage 2 clean controls | `python bench.py qwen2.5:7b --controls-only --tag controls` | 180 | `results_bench_qwen2.5-7b_controls.jsonl` |
| Stage 2 development run 1 | `python bench.py qwen2.5:7b --no-controls --seed-offset 1000 --tag dev` | 300 (the first 15 attacks) | `results_bench_qwen2.5-7b_dev.jsonl` |
| Stage 2 development run 2 | `python bench.py qwen2.5:7b --no-controls --seed-offset 1000 --attacks T4,T5,T6,S3,R2 --tag dev2` | 100 | `results_bench_qwen2.5-7b_dev2.jsonl` |
| Hosted model, clean controls | see below | 180 | `results_bench_deepseek-...-20260910_controls.jsonl` |

Development run 1 was made before attacks T4-T6, S3 and R2 existed; running the current default attack list produces a superset of it.

Row-by-row comparison of two result files: `python compare_runs.py a.jsonl b.jsonl`.

## 4. Hosted model (OpenRouter)

```powershell
$env:OPENROUTER_API_KEY = "<your key>"     # never written to a file or to results
python bench.py deepseek/deepseek-v4.1-flash-20260910 --backend openrouter --provider CoreWeave --max-spend 0.60 --controls-only --tag controls
python bench.py deepseek/deepseek-v4.1-flash-20260910 --backend openrouter --provider CoreWeave --max-spend 0.60 --no-controls --seed-offset 1000 --tag dev
```

- Provider pinned with fallbacks forbidden; a reply from another provider stops the run.
- `--max-spend` is a hard per-command cap; each row stores its cost, tokens and the serving model and provider.
- Reasoning off by default (`--reasoning default` to enable), 1024 token generation cap, temperature 0.7, seed passed (not guaranteed by hosted models).
- Measured cost so far: about $0.00015 per clean run and $0.0005 per attack run.

## 5. Reading a results file

One JSON object per run. Main fields: `kind` (control or attack), `attack`, `task`, `seed`, `calls` and `call_log`, `emails_log` (recipient, subject, body of every email), `unauthorized`, `attempted`, `leaked`, `leaked_loose`, `success`, `blocked`, `tool_errors`, `manifest_changed`, and for hosted runs `usage` and `served`. The `_summary.json` next to it holds the aggregate and the full settings (model, versions, seeds, attack texts, reference manifest hashes).
