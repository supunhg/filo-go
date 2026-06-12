# Changelog

All notable changes to filo-go are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-06-12

### Fixed

- **REST API**: Fixed hardcoded version (was 0.4.0, now uses dynamic version from CLI)
- **REST API**: Added HTTP server timeouts (ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout) and MaxHeaderBytes to prevent slow-loris attacks
- **REST API**: Fixed double I/O in upload endpoint (no longer reads file twice)
- **REST API**: Added request body size limit (32MB) on all endpoints
- **REST API**: Added path traversal protection with optional allowed root directory
- **CLI**: Fixed flaky `TestDDCommand` by resetting flag values between test runs
- **CLI**: Added `--port` flag alias for `filo api` command (alongside `--addr`)
- **CLI**: Directory input now returns clear error for analyze, hash, strings, entropy, meta, executable commands
- **CLI**: `filo lineage` without args now shows helpful usage message instead of silence
- **CLI**: Added `filo plugins install` subcommand (alias for `load`)
- **CLI**: Implemented `filo carve` (wires existing carver engine), `filo profile` (performance profiling), `filo teach` (ML training database)
- **Security**: Added //nosec comments to justify MD5/SHA1 use for forensic identification (NSRL)
- **Security**: Fixed top 10 unhandled errors (file.Close, os.Remove, os.MkdirAll, json.Encode, etc.)

### Changed

- **REST API**: NewServer now requires version parameter; added NewServerWithRoot for restricted file access
- **Tests**: All API tests updated to pass version parameter

### Security

- Path traversal prevention in REST API file endpoints
- Request body size limits on all REST API endpoints
- HTTP server hardening with explicit timeouts

## [0.5.0] - 2026-06-11

### Highlights

- **REST API server**: Full HTTP API with 10 endpoints (analyze, hash, strings, crypto, stego, metadata, batch, upload). Start with `filo api --addr :8080`.
- **Docker support**: Multi-stage Dockerfile, docker-compose.yml, non-root user, health checks.
- **Interactive HTML reports**: Self-contained HTML with drill-down sections, real-time filtering, entropy visualization charts, and security dashboard.
- **Streaming analysis**: Memory-efficient chunked processing for files >100MB without loading entirely into memory.
- **Caching layer**: BoltDB-based analysis caching with SHA256 file hashing and TTL support.
- **YARA module imports**: PE, ELF, Mach-O module structs for YARA rule context.
- **YARA external variables**: SetVariable/GetVariable for rule customization.
- **YAFFS extraction**: Complete binwalk parity with YAFFS1/YAFFS2 filesystem detection and extraction.
- **PDF report export**: Basic PDF generation for forensic reports.
- **Test coverage**: 65.9% → **79.6%** across all `internal/...` packages.
- **Zero lint issues**: All golangci-lint issues resolved.

### Added

- `internal/api/` - REST API server with 10 endpoints
- `internal/api/server.go` - HTTP server with analyze, hash, strings, crypto, stego, metadata, batch, upload endpoints
- `internal/api/server_test.go` - 13 API tests
- `internal/cache/cache.go` - BoltDB-based caching layer
- `internal/cache/cache_test.go` - 11 cache tests
- `internal/analyzer/stream.go` - Streaming analysis for large files
- `internal/analyzer/stream_test.go` - 7 streaming tests
- `internal/export/interactive.go` - Interactive HTML report generation
- `internal/export/interactive_test.go` - 5 interactive report tests
- `internal/export/pdf.go` - PDF report generation
- `internal/export/exporter_test.go` - PDF export tests
- `internal/firmware/yaffs.go` - YAFFS1/YAFFS2 detection and extraction
- `internal/cli/api.go` - `filo api` command for REST API server
- `Dockerfile` - Multi-stage Docker build
- `docker-compose.yml` - Docker Compose with API and MCP services
- `.dockerignore` - Docker build exclusions
- YARA module imports: `PEInfo`, `ELFInfo`, `MachOInfo` structs
- YARA external variables: `SetVariable`, `GetVariable`, `Rule.AddVariable`
- 50+ new CLI integration tests for batch, carve, extract, meta, stego, firmware, office, evtx, registry, sigma, timeline, config, executable, sqlite, repair
- Comprehensive tests for analyzer (schema, entropy viz, Print), container (ExtractTo, nested ZIP), sqlite (varint, WAL, record types), sigma (keyword matching, builtin rules), timeline (Print, edge cases)

### Changed

- `internal/cli/root.go`: Version 0.3.0 → 0.4.0, `SilenceErrors: false`
- `.github/workflows/ci.yml`: Enabled golangci-lint job (removed `if: false` gate)
- `.golangci.yml`: Updated for v2 format with govet, ineffassign, staticcheck, misspell, unconvert
- `go.mod`: Updated dependencies
- All lint issues resolved (tagged switches, unnecessary conversions, empty branches, error capitalization, etc.)

### Fixed

- `internal/executable/macho/macho.go`: Error string capitalization ("Fat" → "fat")
- `internal/firmware/yaffs.go`: uint16 comparison, unnecessary fmt.Sprintf
- `internal/export/pdf.go`: Unnecessary fmt.Sprintf
- `internal/firmware/{cramfs,jffs2,squashfs}.go`: Unnecessary fmt.Sprintf
- `internal/entropy/visualization.go`: Tagged switch, removed fmt.Sprintf
- `internal/executable/pe/pe.go`: Tagged switches (3 locations)
- `internal/export/html.go`: Tagged switch
- `internal/metadata/extractor.go`: Tagged switch
- `internal/pcap/analyzer.go`: Simplified append loop
- `internal/carver/extractor.go`: Unnecessary type conversion
- `internal/cli/meta.go`: Simplified nil check
- `internal/executable/analyzer.go`: Simplified nil check

### Coverage Summary

| Package | Coverage |
|---------|----------|
| ml, sigma, timeline | 100% |
| nsrl | 98.2% |
| repair | 98.0% |
| executable/packing | 96.0% |
| executable/pe | 95.3% |
| entropy | 94.5% |
| formats | 93.0% |
| export | 92.9% |
| config | 90.7% |
| mcp | 88.0% |
| pcap | 85.9% |
| office | 84.3% |
| plugins | 82.1% |
| strings | 81.7% |
| batch | 81.2% |
| executable | 80.6% |
| hashing | 80.0% |
| **Overall** | **79.6%** |

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
