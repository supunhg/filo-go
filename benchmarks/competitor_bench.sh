#!/usr/bin/env bash
# competitor_bench.sh — lightweight wall-clock comparison of filo-go vs binwalk
# on a small synthesized corpus. Times each invocation N times via Python's
# perf_counter and prints a median + speedup table.
#
# Usage:  benchmarks/competitor_bench.sh [RUNS] [CORPUS_DIR]
#   RUNS        — repetitions per (tool, file) pair (default 3)
#   CORPUS_DIR  — directory containing the test files (default /tmp/bench-corpus)
#
# Build first:  go build -o /tmp/filo-go ./cmd/filo

set -e

RUNS="${1:-3}"
CORPUS="${2:-/tmp/bench-corpus}"
FILO="${FILO_BIN:-/tmp/filo-go}"

if [[ ! -x "$FILO" ]]; then
  echo "filo-go binary not found at $FILO" >&2
  echo "build with: go build -o /tmp/filo-go ./cmd/filo" >&2
  exit 1
fi
for t in binwalk python3; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 1; }
done
if [[ ! -d "$CORPUS" ]]; then
  echo "corpus dir not found: $CORPUS" >&2
  exit 1
fi

# Files to bench (override with FILES env var, space-separated)
FILES="${FILES:-large.png large.zip random-10mb.bin}"

cd "$CORPUS"

python3 - "$RUNS" "$FILO" $FILES <<'PY'
import subprocess, sys, os

runs = int(sys.argv[1])
filo = sys.argv[2]
files = sys.argv[3:]

def median_ms(cmd, n):
    ts = []
    for _ in range(n):
        t0 = __import__("time").perf_counter()
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ts.append((__import__("time").perf_counter() - t0) * 1000.0)
    ts.sort()
    return ts[n // 2]  # median of n

rows = []
for f in files:
    size = os.path.getsize(f)
    filo_ms = median_ms([filo, "analyze", f], runs)
    bw_ms   = median_ms(["binwalk", "--quiet", f], runs)
    speedup = bw_ms / filo_ms if filo_ms > 0 else float("inf")
    rows.append((f, size, filo_ms, bw_ms, speedup))

name_w = max(len(r[0]) for r in rows)
print(f"Tool: {filo} (analyze)   vs   binwalk --quiet")
print(f"Corpus: {os.getcwd()}    Runs per cell: {runs}    Median reported")
print()
print(f"{'file':<{name_w}}  {'size':>11}  {'filo-go':>10}  {'binwalk':>10}  {'speedup':>9}")
print(f"{'-'*name_w}  {'-'*11}  {'-'*10}  {'-'*10}  {'-'*9}")
for f, sz, fms, bms, sp in rows:
    sz_s = f"{sz:,}B"
    if sz > 1024 * 1024:
        sz_s = f"{sz/1024/1024:.1f}MB"
    elif sz > 1024:
        sz_s = f"{sz/1024:.1f}KB"
    print(f"{f:<{name_w}}  {sz_s:>11}  {fms:>8.1f}ms  {bms:>8.1f}ms  {sp:>7.2f}x")
PY
