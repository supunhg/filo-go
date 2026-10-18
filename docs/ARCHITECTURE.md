# Architecture

A map for contributors. Everything lives under `internal/`, so nothing is a public Go API yet.

```
cmd/filo           main: runs the CLI and prints errors
internal/cli       one file per command (cobra); flag parsing and output only
```

## Core

| Package | Responsibility |
|---|---|
| `signature` | The signature table and scanner. Each entry pairs magic bytes with a validator that parses the header, rejects look-alikes and computes the file's size. `Scan` finds embedded files in one pass; `Identify` classifies data at offset 0. |
| `analyzer` | `analyze`: combines `signature`, fallback detectors (`h2non/filetype`, `gabriel-vasile/mimetype`, the YAML database in `formats`), entropy, structural checks and `crypto` into one `Result`. |
| `crypto` | Encryption evidence: known containers, Shannon entropy, a chi-square randomness test, ECB patterns. |
| `carver` | `extract`, `hex`, `search`, `dd`. Extraction uses `signature` for boundaries. |
| `hashing` | Single-pass, parallel multi-algorithm hashing. |
| `entropy`, `strings`, `metadata` | The analyses their names describe. |
| `formats` | Loader for the YAML format definitions in `/formats`. |

## Interfaces

| Package | Responsibility |
|---|---|
| `api` | REST server. All file access goes through `pathguard`. |
| `mcp` | Model Context Protocol server over stdio. Never writes anything but protocol messages to stdout. |
| `pathguard` | Confines client-supplied paths to a root (symlink-safe). |

## Cross-cutting

| Package | Responsibility |
|---|---|
| `safeio` | Safe archive entry names and size-limited decompression. Required for any code that extracts or decompresses untrusted data. |
| `term` | Whether to emit ANSI colors (TTY detection, `--color`, `NO_COLOR`). All colored output goes through `term.C`. |
| `version` | Build metadata injected by `-ldflags` (falls back to Go build info). |

## Format analyzers

`executable` (with `pe`, `elf`, `macho`, `packing`), `office`, `sqlite`, `pcap`, `evtx`,
`registry`, `container`, `firmware`, `stego`, `repair`, `sigma`, `yara`, `timeline`.

## Experimental and auxiliary

`ml` (heuristic scoring, not a trained model), `lineage`, `nsrl`, `cache`, `config`, `plugins`
(Go `plugin` package; Linux and macOS only), `batch`, `export` (SARIF, HTML, PDF reports).

## Conventions

- Parsers take `[]byte` and must not panic on malformed input.
- Human-readable printing lives in `Print` helpers or the `cli` package; JSON output uses
  struct tags and must stay stable.
- Tests use real encoder output where possible (Go's `image/*`, `archive/*` and `compress/*`
  packages), plus a random-data check for every detection.
