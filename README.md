# filo

**Fast, single-binary file forensics.** Identify any file by its structure, find what is
hidden inside it, and extract it, from the terminal, a script, an HTTP API or an AI agent.

[![CI](https://github.com/supunhg/filo-go/actions/workflows/ci.yml/badge.svg)](https://github.com/supunhg/filo-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/supunhg/filo-go)](https://goreportcard.com/report/github.com/supunhg/filo-go)
[![Release](https://img.shields.io/github/v/release/supunhg/filo-go?sort=semver)](https://github.com/supunhg/filo-go/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

```console
$ filo scan cat.png
DECIMAL      HEXADECIMAL  SIZE       DESCRIPTION
------------------------------------------------------------------------------
0            0x0          284 B      PNG image, 64 x 64, 8-bit RGB
284          0x11C        140 B      ZIP archive, first entry "flag.txt" (deflate), 1 entry

$ filo analyze cat.png
  Detected Format: png
  Description: PNG image, 64 x 64, 8-bit RGB
  ...
  Structural issues:
    ⚠  140 byte(s) appended after the end of the PNG data at offset 0x11C

$ filo extract cat.png -o out
  out/png_0.png    Format: png  Size: 284 bytes  Offset: 0x0
  out/zip_284.zip  Format: zip  Size: 140 bytes  Offset: 0x11C
```

## Why filo

- **Answers you can trust.** Every signature is checked against the format's real header
  structure (and checksums, where the format has them) before it is reported, so random bytes
  don't turn into phantom gzip streams. The test suite scans 8 MiB of random data and fails on
  a single false positive. Encryption is reported as evidence (known containers, a chi-square
  randomness test), never as a guessed cipher.
- **One static binary.** No Python, no libmagic, no Perl. Linux, macOS, Windows and FreeBSD
  on amd64 and arm64.
- **Fast.** Signature scanning runs at about 1.1 GB/s in a single pass. Hashing streams the file
  once and computes every digest in parallel. See [performance](docs/PERFORMANCE.md).
- **Built for automation.** JSON output, a hardened REST API, and a
  [Model Context Protocol](https://modelcontextprotocol.io) server so AI agents such as Claude
  can investigate files directly.
- **Safe on hostile input.** Archive extraction blocks path traversal and links, and every
  decompressor is size-limited against decompression bombs.

## Install

```bash
go install github.com/supunhg/filo-go/cmd/filo@latest
```

Starting with v0.6.0, each [release](https://github.com/supunhg/filo-go/releases) ships:

- archives for Linux, macOS, Windows and FreeBSD;
- `.deb`, `.rpm` and `.apk` packages;
- a container image: `docker run --rm -v "$PWD:/data:ro" ghcr.io/supunhg/filo scan /data/firmware.bin`.

Every artifact has a checksum, an SBOM and a signed build-provenance attestation
(`gh attestation verify <file> --repo supunhg/filo-go`).

To build from source: `git clone https://github.com/supunhg/filo-go && cd filo-go && make build`.

## Usage

```bash
filo analyze sample.bin          # identify, hash, entropy, embedded files, structural issues
filo scan firmware.bin           # every embedded file and filesystem, with offsets and sizes
filo extract firmware.bin -o out # carve out everything scan finds (decompresses gzip/bzip2/xz)
filo hash -a sha256 *.iso        # coreutils-compatible output; md5, sha1, sha2, sha3
filo strings -n 8 malware.exe    # printable strings with offsets
filo entropy packed.bin          # entropy graph: spot compressed or encrypted regions
filo hex -o 0x1F85 -l 64 file    # colored hex dump
filo meta photo.jpg              # EXIF, XMP, IPTC
```

`analyze`, `scan`, `hash`, `strings`, `meta` and the format analyzers take `--json`. Colors switch off automatically when output is piped
(`--color=always|never` and `NO_COLOR` also work).

### Commands

**Core:** these are stable, tested and the focus of development.

| Command | What it does |
|---|---|
| `analyze` | Identify a file from its contents and report hashes, entropy, embedded files, truncation, appended data, encryption containers, CPU architecture and metadata |
| `scan` | Find embedded files anywhere in a binary, like binwalk |
| `extract` | Write every embedded file to disk |
| `hash` | MD5, SHA-1, SHA-256/512, SHA3-256/512 in one pass |
| `strings` | ASCII and UTF-16 strings with offsets |
| `entropy` | Entropy graph |
| `hex`, `search`, `dd` | Hex dump, text/hex pattern search, raw byte extraction |
| `meta` | Image metadata (EXIF, XMP, IPTC) |
| `mcp` | MCP server for AI agents |
| `api` | REST API server |

**Format-specific analyzers:** these work, but cover a subset of each format.

| Command | What it does |
|---|---|
| `executable` | PE, ELF and Mach-O headers and sections, PE imports, packer hints |
| `office` | OOXML metadata and VBA macro extraction; legacy OLE2 detection |
| `sqlite` | Tables and schema of SQLite databases |
| `pcap` | Flows, protocols and HTTP objects from PCAP/PCAPNG captures |
| `evtx`, `registry` | Windows event logs and registry hives |
| `batch` | Analyze every file in a directory in parallel |

**Experimental:** these are rough. Output and flags may change, and results need checking by hand.

`carve`, `repair`, `stego`, `firmware` (identifies SquashFS, CramFS, JFFS2 and YAFFS images
but does not yet unpack them; use `scan`/`extract` for embedded images), `sigma`, `timeline`,
`lineage`, `teach`, `profile`, `plugins` (Go plugins, Linux and macOS only).

## Supported formats

`scan`, `extract` and `analyze` recognise **44 formats**, each validated beyond its magic bytes:

| Category | Formats |
|---|---|
| Images | PNG, JPEG, GIF, BMP, TIFF, ICO, WebP |
| Audio and video | WAV, AVI, FLAC, Ogg, MP3 (ID3), Matroska/WebM, MP4/MOV/HEIF (ISO-BMFF) |
| Documents | PDF, OLE2 (Office 97-2003, MSI), RTF, PEM |
| Archives and compression | ZIP, gzip, bzip2, XZ, Zstandard, LZ4, LZMA, 7-Zip, RAR 4/5, tar, cpio, CAB |
| Executables and bytecode | ELF, PE, Mach-O (incl. universal), Java class, Android DEX, WebAssembly |
| Firmware and filesystems | SquashFS, CramFS, JFFS2, UBI, UBIFS, U-Boot legacy images, device trees |
| Databases | SQLite 3 |

Run `filo scan --format <name>` to search for specific ones. Missing a format?
[Request it](https://github.com/supunhg/filo-go/issues/new/choose), or see
[CONTRIBUTING.md](CONTRIBUTING.md#adding-a-file-signature) to add it.

## AI agents (MCP)

`filo mcp` runs a Model Context Protocol server on stdio. Its ten tools are all read-only:
`analyze`, `scan`, `hash`, `strings`, `crypto`, `stego`, `metadata`, `container`, `sqlite`
and `batch`.

```bash
# Claude Code
claude mcp add filo -- filo mcp --root /path/to/case
```

```json
{
  "mcpServers": {
    "filo": { "command": "filo", "args": ["mcp", "--root", "/path/to/case"] }
  }
}
```

`--root` limits which files the agent can read. Use it whenever the agent may process untrusted
content, which could try to steer it into reading other files.

## REST API

```bash
filo api --root ./evidence                       # http://127.0.0.1:8080
curl -s localhost:8080/api/scan -d '{"path": "firmware.bin"}'
curl -s localhost:8080/api/upload -F file=@sample.bin
```

The server is locked down by default:

- it binds to localhost;
- it refuses other addresses unless you set a bearer token (`--token` or `FILO_API_TOKEN`);
- endpoints that take a file path only serve files inside `--root`.

See [docs/API.md](docs/API.md) for every endpoint and the Docker Compose setup.

## Accuracy and limitations

filo would rather say "unknown" than guess. Known limitations:

- **Encryption.** Modern ciphertext is indistinguishable from random data, so no tool can name
  the cipher. filo reports containers it can identify and whether the data is statistically
  random.
- **Unknown sizes.** Some formats don't record their own length (gzip, XZ, tar, raw MP3). For
  these, `scan` shows the size as `-`, and `extract` decompresses the stream or takes data up to
  a size cap.
- **Memory.** Files are currently read into memory, so very large disk images need RAM to match.
  Streaming is on the [roadmap](docs/ROADMAP.md).
- **Format analyzers.** The format-specific commands parse the common structures, not every
  edge case of each specification.

Found a wrong answer? Please [report it](https://github.com/supunhg/filo-go/issues/new/choose).
Accuracy bugs are the top priority.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md); adding a file signature
is a good first change. Please report security issues privately as described in
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
