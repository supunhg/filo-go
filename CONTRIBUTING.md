# Contributing to filo

Thanks for helping. Bug reports, new format signatures, test fixtures and
documentation fixes are all welcome.

## The one rule: accuracy first

filo is used to make decisions about evidence. A wrong answer is worse than no
answer, so every detection must be backed by a test that shows it finds the
real thing **and** does not fire on unrelated data. Prefer reporting what can
be measured ("the data is statistically random") over guessing ("AES-256").

## Getting started

You need Go (the version in `go.mod` or newer) and, optionally,
[golangci-lint](https://golangci-lint.run) v2 and
[GoReleaser](https://goreleaser.com) v2.

```bash
git clone https://github.com/supunhg/filo-go.git
cd filo-go
make build      # ./filo
make test       # go test ./...
make lint       # golangci-lint run
make help       # all targets
```

## Making a change

1. For anything larger than a small fix, open an issue first so we can agree on
   the approach.
2. Create a branch from `main`.
3. Write tests. Bug fixes need a test that fails without the fix.
4. Run `make test lint` locally. CI runs the tests on Linux, macOS and Windows,
   plus the linters, a release dry run and a Docker build.
5. Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for any
   user-visible change, and mark breaking changes as such.
6. Open a pull request and fill in the template.

### Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org): `feat:`,
`fix:`, `security:`, `perf:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`.
Release notes are generated from them. Keep the subject under about 70
characters and explain *why* in the body.

### Code style

- `gofmt` and `goimports` (local prefix `github.com/supunhg/filo-go`);
  `make fmt` applies both.
- Parsers must never panic on malformed input. Bounds-check before every slice
  and treat sizes read from a file as untrusted.
- Anything that decompresses or extracts untrusted data must use
  `internal/safeio` (size limits, safe entry names).
- Human-readable output goes through `internal/term` for color; JSON output
  must stay stable or be called out as a breaking change.

## Adding a file signature

Signatures live in [`internal/signature/formats.go`](internal/signature/formats.go).
Each entry pairs a magic number with a validator that parses enough of the
header to reject look-alikes, and computes the file's size when the format
records it.

1. Add an entry to `sigs` and write a `check...` function. Validate fields that
   random data is unlikely to satisfy: checksums, version numbers, enum
   values, offsets that must point inside the data.
2. Add a case to `TestIdentify` using output from a real encoder (the Go
   standard library has many) or a minimal hand-built header.
3. Run `go test ./internal/signature`. `TestScanRandomDataHasNoFalsePositives`
   must still pass: if your magic is short, tighten the validator.

## Reporting bugs

Use the [bug report form](https://github.com/supunhg/filo-go/issues/new/choose).
If the bug depends on a specific file, attach it only if it is safe and legal
to share; otherwise describe it or share the first few hundred bytes from
`filo hex FILE`.

Security vulnerabilities should **not** be reported in public issues; see
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
