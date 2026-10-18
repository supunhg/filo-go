# Performance

Numbers below were measured on 2026-10-18 on an Intel Core i7-13700 under Windows 11, with
filo built from `main` by Go 1.25. All timings include process start-up and reading the file
from a warm OS cache. They will differ on your hardware, so please reproduce them before
quoting them.

## Signature scanning

`filo scan` looks for 44 formats in a single pass. It finds candidates by their first two bytes,
then validates each one structurally.

| Measurement | Result |
|---|---|
| `BenchmarkScanRandom` (16 MiB of random bytes, in memory) | **1.15 GB/s** |
| `filo scan` on a 512 MiB random file (end to end) | **0.61 s** |

Random data is close to the worst case: it produces the most candidate matches that then fail
validation. Reproduce with:

```bash
go test ./internal/signature -run '^$' -bench ScanRandom
```

## Hashing

`filo hash` reads the file once in 1 MiB chunks and runs every requested algorithm in its own
goroutine, so several digests cost about as much as the slowest one.

512 MiB file:

| Command | Time |
|---|---|
| `filo hash -a sha256` | **0.28 s** |
| `certutil -hashfile big.bin SHA256` | 0.45 s |
| `sha256sum big.bin` (Git for Windows coreutils) | 1.23 s |
| `filo hash -a md5` | 0.55 s |
| `filo hash -a md5,sha1,sha256` | **0.55 s** (all three in the time of MD5 alone) |

Go's SHA-256 uses the CPU's SHA extensions where available. MD5 can't be parallelised within a
single stream, so it is the slowest digest.

## Known gaps

- **Strings.** `filo strings` was 2-3× slower than GNU `strings` in the June 2026 measurements
  below. It has not been re-measured since.
- **Memory.** `analyze`, `scan` and `extract` read the whole file into memory. Streaming for
  multi-gigabyte images is on the [roadmap](ROADMAP.md).

## Historical comparison (June 2026)

[`benchmarks/results/2026-06-10.md`](../benchmarks/results/2026-06-10.md) compares filo v0.4
with binwalk 2.4.3 (the Python version) on small files. Most of filo's lead there (3.9 ms against
757 ms for a 5 KB PNG) is Python's start-up time, not scanning speed. binwalk has since been
rewritten in Rust (v3), and filo's scanner has been replaced, so those numbers do not describe
either tool today. [`benchmarks/competitor_bench.sh`](../benchmarks/competitor_bench.sh) can
re-run the comparison.
