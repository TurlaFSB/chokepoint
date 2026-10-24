"""Row-by-row comparison of two result files (JSONL from agent_baseline_v2.py or agent_mcp.py).

Rows are matched on (scenario, kind, payload, seed). Reports how many matched rows have
the same call sequence, the same 'attempted' outcome and the same 'leaked' outcome.

Usage: python compare_runs.py a.jsonl b.jsonl
"""
import json
import sys


def load(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                rows[(r["scenario"], r["kind"], r["payload"], r["seed"])] = r
    return rows


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    a, b = load(sys.argv[1]), load(sys.argv[2])
    keys = sorted(set(a) & set(b))
    print("rows in A: %d | rows in B: %d | matched: %d" % (len(a), len(b), len(keys)))
    if not keys:
        sys.exit("no rows in common")
    for field, label in (("calls", "same call sequence"), ("attempted", "same attempted"),
                         ("leaked", "same leaked")):
        n = sum(a[k][field] == b[k][field] for k in keys)
        print("%-20s %d/%d" % (label, n, len(keys)))


if __name__ == "__main__":
    main()
