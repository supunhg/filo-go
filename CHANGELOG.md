# Changelog

All notable changes to filo-go are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-06-10

### Highlights

- **Test coverage**: 46.7% → 65.9% across all `internal/...` packages. Previously-0% greenfield packages (pe, elf, macho, packing, ml, nsrl) and low-coverage packages (archive-bomb, metadata, firmware, pcap) all now covered.
- **Measured benchmarks**: `benchmarks/competitor_bench.sh` is the single source of truth. Measured **14x–217x speedup vs binwalk** on a 3-file synthesized corpus (PNG 193.86x, ZIP 216.78x, random 10MB 13.94x). Earlier synthesized "6x–10,873x" claims in README.md and docs/PERFORMANCE.md are removed.
- **OOXML metadata extraction** (PR #12): real bytes-based extractor for `core.xml` / `app.xml` / `custom.xml` from DOCX/XLSX/PPTX zips. Wired into `filo office --metadata`. Fixed two latent parser bugs (`AppProperties.XMLName` was `Application` not `Properties`; `CustomProperty.Value` only matched `vt:blob` not `vt:lpwstr`).
- **Embedded VBA macro extraction** (PR #13): scans for `word|xl|ppt/vbaProject.bin` inside OOXML zips and runs the OLE2 macro detector against it. Coverage on `internal/office` 47.6% → 84.3%.
- **Honest perf docs**: `docs/PERFORMANCE.md` no longer claims filo-go is faster than `sha256sum` / `strings`. The dedicated `filo-go hash` and `filo-go strings` subcommands are documented as slower than the C primitives (0.4x–0.9x) for those primitive operations; the headline result is integrated analysis vs binwalk.
- **Web showcase**: `../filo-go-web` BENCHMARKS + SPEEDUP_HIGHLIGHTS arrays now show the measured 193.86x / 216.78x / 13.94x numbers (commits `c3a692e`, `825a7f8`). Browser-verified at `http://localhost:4000/`.

### Added

- `internal/office/ExtractOOXMLFromBytes` / `DetectOOXMLBytes` (in-memory OOXML analysis)
- `internal/office/ExtractVBAProjectBytes` / `ExtractVBAProject` (vbaProject.bin extraction)
- `benchmarks/competitor_bench.sh` (lightweight Python-timed competitor benchmark)
- `benchmarks/results/2026-06-10.{md,json}` (first measured report)
- `internal/executable/{pe,elf,macho,packing}` full test coverage
- `internal/{ml,nsrl,firmware,metadata,pcap}` full test coverage
- `plugins/archive-bomb` full test coverage
- Log2 fix in `plugins/archive-bomb/main.go` (replaced buggy integer-only halving count with `math.Log2`)

### Changed

- README.md: replaced synthesized "6x to 10,873x" claims with measured 14x–217x numbers; added link to `benchmarks/results/2026-06-10.md`
- docs/PERFORMANCE.md: replaced Unix Tools section with measured numbers + honest "slower" finding
- docs/ROADMAP.md: refreshed per-package coverage table, marked v0.4.0 milestones
- License badge: MIT → Apache 2.0
- MCP server version: 0.2.0 → 0.3.0

### Known limitations (post-v0.4.0 backlog)

- `filo-go strings` is ~2x slower than GNU `strings(1)` on the 10MB corpus. The structural gap is Go vs C + per-string output formatting; a streaming-writer optimization narrowed it but did not close it. Tracked but not in v0.4.0.
- `filo-go hash` is ~0.8x the speed of `sha256sum`. Same Go-vs-C structural reason. Tracked but not in v0.4.0.
- binwalk parity gap: YAFFS extraction (last unchecked filesystem).
- ExifTool parity gap: ICC profiles, Maker notes, write capability.
- YARA parity gap: module imports, external variables.
- Beyond-parity features: PDF report export, interactive HTML reports.
- Phase 3 enterprise (REST API, gRPC, Docker, SIEM integration) is explicitly deferred.

## [0.3.0] - 2026-06-09

### Changed
- License: MIT → Apache License 2.0 (matching LICENSE file).
- MCP server `serverInfo.version` bumped from `0.2.0` → `0.3.0`.
- README license badge updated to reflect the Apache 2.0 license.
- `.gitignore` cleaned up (removed stray `continue.sh` line).

### Documentation
- `docs/ROADMAP.md` updated: real overall test coverage is **46.7%** (was overstated as 61.6%).
- Coverage targets in the roadmap table refreshed against measured values from `go test -coverprofile`.

### CI / Tooling
- Added a `golangci-lint` job scaffolding in `.github/workflows/ci.yml`. It is gated with `if: false` so it does not block the build until the linter is provisioned in the environment. Flip the condition to enable it.

### Notes
- v0.3.0 is the first release on the `dev` branch. Phase C (test coverage push) and Phase D (feature completion: OOXML metadata, PDF report export, interactive HTML report, YAFFS extraction) remain on the roadmap and will land in subsequent releases.

[Unreleased]: https://github.com/supunhg/filo-go/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/supunhg/filo-go/compare/v0.2.0...v0.3.0
