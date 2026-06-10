# Changelog

All notable changes to filo-go are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
