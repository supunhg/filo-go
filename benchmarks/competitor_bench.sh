#!/usr/bin/env bash
# competitor_bench.sh — lightweight wall-clock comparison of filo-go vs
# binwalk (signature scanning) and vs Unix tools (sha256sum, strings).
# Times each invocation N times via Python's perf_counter and prints
# median + speedup tables, one per competitor group.
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
for t in binwalk sha256sum strings python3; do
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

def fmt_size(n):
    if n > 1024 * 1024: return f"{n/1024/1024:.1f}MB"
    if n > 1024:        return f"{n/1024:.1f}KB"
    return f"{n:,}B"

def speedup(fms, oms):
    return oms / fms if fms > 0 else float("inf")

rows = []
for f in files:
    size = os.path.getsize(f)
    filo_ms = median_ms([filo, "analyze", f], runs)
    bw_ms   = median_ms(["binwalk", "--quiet", f], runs)
    sha_ms  = median_ms(["sha256sum", f], runs)
    str_ms  = median_ms(["strings", f], runs)
    rows.append((f, size, filo_ms, bw_ms, sha_ms, str_ms))

name_w = max(len(r[0]) for r in rows)
print(f"Tool: {filo} (analyze)   vs   binwalk --quiet, sha256sum, strings")
print(f"Corpus: {os.getcwd()}    Runs per cell: {runs}    Median reported")
print()

# Section 1: vs binwalk (signature scanning)
print(f"=== vs binwalk (signature scanning) ===")
print(f"{'file':<{name_w}}  {'size':>11}  {'filo-go':>10}  {'binwalk':>10}  {'speedup':>9}")
print(f"{'-'*name_w}  {'-'*11}  {'-'*10}  {'-'*10}  {'-'*9}")
for f, sz, fms, bms, _sha, _str in rows:
    sp = speedup(fms, bms)
    print(f"{f:<{name_w}}  {fmt_size(sz):>11}  {fms:>8.1f}ms  {bms:>8.1f}ms  {sp:>7.2f}x")
print()

# Section 2: vs Unix tools (hashing, string extraction)
print(f"=== vs Unix tools (hashing, string extraction) ===")
print(f"{'file':<{name_w}}  {'size':>11}  {'filo-go':>10}  {'sha256sum':>10}  {'strings':>10}")
print(f"{'-'*name_w}  {'-'*11}  {'-'*10}  {'-'*10}  {'-'*10}")
for f, sz, fms, _bw, sha, stri in rows:
    print(f"{f:<{name_w}}  {fmt_size(sz):>11}  {fms:>8.1f}ms  {sha:>8.1f}ms  {stri:>8.1f}ms")
print()

# Per-file winner highlights (Unix tools section)
print("=== per-file highlights (Unix tools) ===")
for f, sz, fms, _bw, sha, stri in rows:
    hsp = speedup(fms, sha)
    ssp = speedup(fms, stri)
    print(f"  {f}: hash speedup {hsp:6.2f}x  |  string-extract speedup {ssp:6.2f}x")
PY
