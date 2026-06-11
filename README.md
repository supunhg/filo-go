# filo-go

> **Forensic Intelligence & Learning Operator** - A modern, Go-native forensic analysis toolkit

[![CI](https://github.com/supunhg/filo-go/actions/workflows/ci.yml/badge.svg)](https://github.com/supunhg/filo-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/supunhg/filo-go)](https://goreportcard.com/report/github.com/supunhg/filo-go)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Latest release](https://img.shields.io/badge/release-v0.5.0-blue)](https://github.com/supunhg/filo-go/releases/tag/v0.5.0)

**Latest release: v0.5.0 (2026-06-11)** — 79.6% test coverage, REST API server, Docker support, interactive HTML reports, streaming analysis, caching layer, YARA module imports, YAFFS extraction, zero lint issues, Apache 2.0.

---

## ⚠️ Known limitations

- `filo-go strings` is **~2x slower** than GNU `strings(1)` on large binary inputs (the C binary is structurally faster at the printable-scan hot path; a streaming-writer optimization narrowed the gap but did not close it).
- `filo-go hash` is **~0.8x the speed of `sha256sum`** for the same structural reason. Use `sha256sum` directly if raw speed matters.
- These gaps only apply to the dedicated primitive commands. **Integrated analysis** (`filo-go analyze`, which does format detection + entropy + hashing + string extraction in one pass) is **14x–217x faster than binwalk** on the same inputs.

See [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for the full measured numbers, and [benchmarks/results/2026-06-10.md](benchmarks/results/2026-06-10.md) for the source of truth.

---

## 📚 Documentation

- [Knowledge Graph](docs/KNOWLEDGE_GRAPH.md) - Architecture and codebase overview
- [Competitive Analysis](docs/COMPETITIVE_ANALYSIS.md) - Gap analysis vs binwalk/file/ExifTool
- [Roadmap](docs/ROADMAP.md) - Development roadmap and milestones

---

## 🎯 What is filo-go?

**filo-go** is a modern, Go-native forensic analysis toolkit that replaces **binwalk**, **file**, **ExifTool**, and **strings** with a single, fast, cross-platform binary.

### Why filo-go?

| Feature | binwalk | file | ExifTool | filo-go |
|---------|---------|------|----------|---------|
| Language | Python/C | C | Perl | **Go** |
| Dependencies | Many | libmagic | Perl modules | **None** |
| Cross-platform | ⚠️ Partial | ✅ | ✅ | **✅** |
| Single binary | ❌ | ✅ | ❌ | **✅** |
| JSON output | ❌ | ⚠️ | ✅ | **✅** |
| MCP integration | ❌ | ❌ | ❌ | **✅** |
| Plugin system | ❌ | ❌ | ✅ | **✅** |
| Firmware extraction | ✅ | ❌ | ❌ | **✅** |
| Metadata extraction | ❌ | ❌ | ✅ | **✅** |
| YARA support | ❌ | ❌ | ❌ | **✅** |
| **Performance** | Slow | Fast | Fast | **Fastest** |

### 🚀 Performance

filo-go is **14x to 217x faster** than binwalk on a measured corpus (see [benchmarks/results/2026-06-10.md](benchmarks/results/2026-06-10.md), reproducible via `benchmarks/competitor_bench.sh`):

| Operation | filo-go | binwalk | Speedup |
|-----------|---------|---------|----------|
| PNG analysis (5KB, with tEXt chunks) | 3.9 ms | 757.5 ms | **193.86x** |
| ZIP archive analysis (82KB, 500 entries) | 3.8 ms | 814.2 ms | **216.78x** |
| Random 10MB blob scan | 243.8 ms | 3,397.4 ms | **13.94x** |

See [Performance Benchmarks](docs/PERFORMANCE.md) for detailed analysis.

---

## 🚀 Quick Start

### Installation

```bash
# From source
git clone https://github.com/supunhg/filo-go.git
cd filo-go
go build -o filo ./cmd/filo/

# Or using go install
go install github.com/supunhg/filo-go/cmd/filo@latest
```

### Basic Usage

```bash
# Analyze a file
filo analyze mystery.bin

# Get entropy visualization
filo entropy firmware.bin

# Extract embedded files
filo extract firmware.bin

# View hex dump
filo hex suspicious.exe

# Scan for signatures
filo scan document.pdf

# Extract strings
filo strings malware.bin

# Get file hashes
filo hash important.doc

# Analyze metadata (EXIF, XMP, IPTC)
filo meta photo.jpg

# Extract firmware
filo firmware -x rootfs.squashfs
```

---

## 📚 Commands

### Core Analysis

| Command | Description | Example |
|---------|-------------|---------|
| `analyze` | Full file analysis with format detection | `filo analyze file.bin` |
| `entropy` | Visualize file entropy | `filo entropy file.bin` |
| `hex` | Display hex dump with colors | `filo hex file.bin` |
| `scan` | Scan for known signatures | `filo scan file.bin` |
| `search` | Search for text or hex patterns | `filo search file.bin "pattern"` |
| `hash` | Compute multiple hash algorithms | `filo hash file.bin` |
| `strings` | Extract printable strings | `filo strings file.bin` |

### File Operations

| Command | Description | Example |
|---------|-------------|---------|
| `extract` | Extract embedded files | `filo extract firmware.bin` |
| `dd` | Extract raw bytes (like dd) | `filo dd file.bin --offset 0 --length 1024` |
| `carve` | Carve files from disk images | `filo carve disk.img` |
| `repair` | Repair corrupted files | `filo repair image.jpg` |

### Metadata & Security

| Command | Description | Example |
|---------|-------------|---------|
| `meta` | Extract EXIF/XMP/IPTC metadata | `filo meta photo.jpg` |
| `stego` | Detect steganography | `filo stego image.png` |
| `crypto` | Detect encryption | `filo crypto file.bin` |
| `executable` | Analyze PE/ELF/Mach-O | `filo executable program.exe` |

### Forensic Analysis

| Command | Description | Example |
|---------|-------------|---------|
| `firmware` | Analyze/extract firmware | `filo firmware -x rootfs.squashfs` |
| `pcap` | Analyze network captures | `filo pcap --streams capture.pcap` |
| `evtx` | Analyze Windows Event Logs | `filo evtx system.evtx` |
| `sqlite` | Analyze SQLite databases | `filo sqlite browser.db` |
| `registry` | Analyze Windows Registry | `filo registry SAM` |
| `sigma` | Scan with Sigma rules | `filo sigma file.bin` |

### Batch & Integration

| Command | Description | Example |
|---------|-------------|---------|
| `batch` | Analyze directory of files | `filo batch /path/to/samples/` |
| `mcp` | Start MCP server for AI | `filo mcp` |
| `api` | Start REST API server | `filo api --addr :8080` |
| `plugins` | Manage plugins | `filo plugins list` |
| `formats` | List supported formats | `filo formats list` |

---

## 🔌 REST API

filo-go includes a built-in REST API server for remote analysis.

### Starting the Server

```bash
# Start on default port (8080)
filo api

# Start on custom port
filo api --addr :9090
```

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/version` | Version info |
| `POST` | `/api/analyze` | Analyze file |
| `POST` | `/api/hash` | Compute hashes |
| `POST` | `/api/strings` | Extract strings |
| `POST` | `/api/crypto` | Detect encryption |
| `POST` | `/api/stego` | Detect steganography |
| `POST` | `/api/metadata` | Extract metadata |
| `POST` | `/api/batch` | Batch analysis |
| `POST` | `/api/upload` | Upload and analyze |

### Example Usage

```bash
# Analyze a file
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/file.bin"}'

# Compute hashes
curl -X POST http://localhost:8080/api/hash \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/file.bin", "algorithms": ["sha256", "md5"]}'

# Upload and analyze
curl -X POST http://localhost:8080/api/upload \
  -F "file=@/path/to/file.bin"
```

---

## 🐳 Docker

filo-go includes Docker support for production deployment.

### Quick Start

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t filo-go .
docker run -p 8080:8080 filo-go api --addr :8080
```

### Docker Compose Services

| Service | Description | Port |
|---------|-------------|------|
| `filo` | REST API server | 8080 |
| `filo-mcp` | MCP server (stdin/stdout) | - |

---

## 🔌 MCP Integration

filo-go includes a built-in MCP (Model Context Protocol) server for AI-assisted analysis.

### Available Tools

| Tool | Description |
|------|-------------|
| `analyze` | Analyze file format and security |
| `hash` | Compute cryptographic hashes |
| `strings` | Extract printable strings |
| `crypto` | Detect encryption indicators |
| `stego` | Detect steganography |
| `metadata` | Extract image metadata |
| `container` | Analyze archive contents |
| `sqlite` | Analyze SQLite databases |
| `batch` | Batch analyze directories |

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "filo": {
      "command": "/path/to/filo",
      "args": ["mcp"]
    }
  }
}
```

---

## 🔧 Plugin System

filo-go supports dynamic plugins via Go's plugin system.

### Installing Plugins

```bash
# Build a plugin
cd plugins/archive-bomb
go build -buildmode=plugin -o archive-bomb.so

# Install the plugin
filo plugins load ./archive-bomb.so

# List installed plugins
filo plugins list
```

### Writing Plugins

```go
package main

import "github.com/supunhg/filo-go/internal/plugins"

type ArchiveBombDetector struct{}

func (d *ArchiveBombDetector) Name() string {
    return "archive-bomb"
}

func (d *ArchiveBombDetector) Analyze(data []byte) (*plugins.Result, error) {
    // Your analysis logic here
    return &plugins.Result{
        Risk: plugins.RiskLow,
        Findings: []string{"File appears safe"},
    }, nil
}

func init() {
    plugins.Register(&ArchiveBombDetector{})
}
```

---

## 📊 Supported Formats

### Archives
- ZIP, 7z, RAR, TAR, GZIP, BZIP2, XZ

### Executables
- PE (Windows), ELF (Linux), Mach-O (macOS)

### Documents
- PDF, DOCX, XLSX, PPTX, OLE2

### Images
- JPEG, PNG, GIF, BMP, TIFF, WebP, ICO

### Data
- SQLite, Registry (REGF), EVTX

### Network
- PCAP, PCAPNG

### Firmware
- SquashFS, CramFS, JFFS2

---

## 🏗️ Architecture

```
filo-go/
├── cmd/filo/              # CLI entry point
├── internal/
│   ├── analyzer/          # Core analysis engine
│   ├── carver/            # File carving & hex dump
│   ├── cli/               # CLI commands (cobra)
│   ├── container/         # Archive analysis
│   ├── crypto/            # Encryption detection
│   ├── entropy/           # Entropy calculation & visualization
│   ├── executable/        # PE/ELF/Mach-O analysis
│   ├── export/            # SARIF/HTML export
│   ├── firmware/          # SquashFS/CramFS/JFFS2
│   ├── formats/           # YAML format database
│   ├── hashing/           # Multi-algorithm hashing
│   ├── mcp/               # MCP server
│   ├── metadata/          # EXIF/XMP/IPTC extraction
│   ├── pcap/              # Network analysis
│   ├── plugins/           # Plugin system
│   ├── sqlite/            # SQLite analysis
│   ├── stego/             # Steganography detection
│   ├── strings/           # String extraction
│   └── yara/              # YARA rule matching
├── formats/               # YAML format definitions
├── plugins/               # Example plugins
├── KNOWLEDGE_GRAPH.md     # Codebase knowledge graph
├── COMPETITIVE_ANALYSIS.md # Gap analysis vs competitors
└── ROADMAP.md             # Development roadmap
```

---

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run specific package tests
go test ./internal/entropy/ -v
```

---

## 📈 Performance

filo-go is **14x to 217x faster** than binwalk on a measured corpus (see [benchmarks/results/2026-06-10.md](benchmarks/results/2026-06-10.md), reproducible via `benchmarks/competitor_bench.sh`):

| Operation | filo-go | binwalk | Speedup |
|-----------|---------|---------|----------|
| PNG analysis (5KB, with tEXt chunks) | 3.9 ms | 757.5 ms | **193.86x** |
| ZIP archive analysis (82KB, 500 entries) | 3.8 ms | 814.2 ms | **216.78x** |
| Random 10MB blob scan | 243.8 ms | 3,397.4 ms | **13.94x** |

*Benchmarks measured on Intel Xeon Platinum 8488C, Linux AMD64*

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **binwalk** - Inspired the firmware analysis features
- **file/libmagic** - Inspired the format detection
- **ExifTool** - Inspired the metadata extraction
- **YARA** - Inspired the pattern matching
- **Cobra** - CLI framework
- **BoltDB** - Embedded database

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/supunhg/filo-go/issues)
- **Discussions**: [GitHub Discussions](https://github.com/supunhg/filo-go/discussions)
- **Email**: sanchithahewagamage@gmail.com

---

<div align="center">
  <strong>Built with ❤️ in Go</strong>
</div>
