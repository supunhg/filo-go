# Security policy

filo parses untrusted, often deliberately malicious, files. We treat bugs that
let a crafted file or request harm the person running filo as security
vulnerabilities.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub security advisories](https://github.com/supunhg/filo-go/security/advisories/new).

Include the version (`filo version`), the command or request you ran, and a
proof-of-concept file or steps to reproduce. You can expect an acknowledgement
within 72 hours and an initial assessment within a week. We will credit you in
the advisory unless you prefer otherwise.

## Supported versions

Security fixes are released for the latest minor version. Until 1.0, please
upgrade to the newest release.

## In scope

- Crashes, hangs or excessive memory or disk use caused by a crafted input file
- Writing files outside the requested output directory (for example through
  archive entry names or symlinks)
- Reading files outside the configured `--root` through the REST API or the
  MCP server, or bypassing the API's token authentication
- Code execution of any kind

## Out of scope

- Detection accuracy (missed or wrong format identification): please open a
  normal issue
- Running `filo api` with `--insecure-no-auth` on an untrusted network
- Running `filo mcp` without `--root` and having an agent read files the user
  can already read

## Hardening notes for operators

- `filo api` listens on `127.0.0.1` by default and refuses other addresses
  without a bearer token. Put TLS in front of it with a reverse proxy when it
  is exposed.
- Always pass `--root` to `filo api` and `filo mcp` to confine file access.
- Run extraction commands (`extract`, `carve`, `firmware -x`) on untrusted
  samples inside a container or VM.
