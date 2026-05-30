# filo-go

**Forensic Intelligence & Learning Operator** - Go implementation

> *"When you need to know not just what something is, but why it's that, and how to fix it."*

A high-performance file forensics platform for security professionals. Analyzes unknown binaries, detects formats, repairs corrupted files, and tracks hash lineage.

> **Note:** This is a complete rewrite of the original [Python filo](https://github.com/supunhg/filo) (now archived). The Go port delivers the same forensic capabilities with significantly better performance, single-binary deployment, and zero runtime dependencies.

## Features

- **File Format Detection**: 87 YAML format definitions + magic bytes + content analysis
- **Steganography Detection**: PNG LSB extraction, JPEG/PDF/GIF trailing data
- **Crypto Analysis**: AES/DES/ECB detection, OpenSSL/PGP format recognition
- **File Repair**: PNG, JPEG, PDF, ZIP repair strategies
- **Container Analysis**: ZIP, 7z, RAR, TAR, GZ with recursive nesting
- **Batch Processing**: Parallel analysis at 19,000+ files/sec
- **Lineage Tracking**: Chain of custody with BoltDB storage
- **MCP Server**: AI-assisted analysis via JSON-RPC

## Installation

```bash
# From source
git clone https://github.com/supunhg/filo-go
cd filo-go
go build -o filo ./cmd/filo/

# Using Go
go install github.com/supunhg/filo-go/cmd/filo@latest
```

## Usage

```bash
# Analyze a file
filo analyze suspicious.bin

# Detect steganography
filo stego image.png

# Batch process directory
filo batch ./evidence/ --workers 8

# Repair corrupted file
filo repair --format=png broken.bin

# Extract strings
filo strings binary.exe -n 8

# Extract metadata
filo meta photo.jpg

# Start MCP server
filo mcp
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `analyze` | Analyze file format and security indicators |
| `stego` | Detect steganography in images |
| `batch` | Batch analyze directories |
| `repair` | Repair corrupted files |
| `carve` | Carve embedded files from disk images |
| `strings` | Extract printable strings |
| `extract` | Extract nested archives |
| `pcap` | Analyze network captures |
| `meta` | Extract image metadata |
| `formats` | List format database |
| `lineage` | Track file transformation history |
| `mcp` | Start MCP server for AI tools |

## Development

```bash
# Build
make build

# Test
make test

# Release
make release
```

## Architecture

```
cmd/filo/           # CLI entrypoint
internal/
  analyzer/         # Core detection engine
  formats/          # YAML format database
  stego/            # Steganography detection
  crypto/           # Encryption detection
  container/        # Archive analysis
  repair/           # File repair engine
  carver/           # File carving
  batch/            # Parallel processing
  strings/          # String extraction
  pcap/             # Network analysis
  metadata/         # EXIF/PNG/PDF metadata
  lineage/          # Chain of custody
  yara/             # YARA scanning
  office/           # Office macro detection
  mcp/              # MCP server
  ml/               # ML detection
  export/           # JSON/SARIF/CSV export
```

## License

Apache License 2.0
