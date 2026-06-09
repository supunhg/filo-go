# filo-go Knowledge Graph

> **Last Updated:** 2024-12-09  
> **Version:** 0.2.0  
> **Total LOC:** ~25,000  
> **Test Coverage:** ~35%

---

## 📊 Project Overview

**filo-go** is a Go-native forensic analysis toolkit that replaces multiple Python/C tools with a single, fast, cross-platform binary.

### Key Metrics
- **Commands:** 35+
- **Packages:** 25+
- **Tests:** 300+
- **Format Definitions:** 30+
- **MCP Tools:** 9

---

## 🏗️ Architecture

### Core Modules

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                            │
│  (cobra commands: analyze, entropy, hex, scan, etc.)       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Analysis Engine                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ analyzer │ │ entropy  │ │ strings  │ │ metadata │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  stego   │ │  crypto  │ │  container│ │  formats │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Specialized Modules                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ firmware │ │  pcap    │ │  evtx    │ │  sqlite  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ registry │ │  sigma   │ │   yara   │ │ executable│       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Integration Layer                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │   mcp    │ │ plugins  │ │  export  │ │  repair  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Package Dependencies

### External Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/etcd-io/bbolt` - Embedded database
- `github.com/sirupsen/logrus` - Logging
- `github.com/fatih/color` - Terminal colors

### Internal Package Graph

```
cmd/filo/
    └── internal/cli/
            ├── analyzer
            │     ├── formats
            │     ├── entropy
            │     ├── strings
            │     └── metadata
            ├── carver
            │     └── entropy
            ├── container
            ├── crypto
            ├── entropy
            ├── executable/
            │     ├── elf
            │     ├── pe
            │     └── packing
            ├── export
            ├── firmware
            ├── formats
            ├── hashing
            ├── mcp
            ├── metadata
            ├── pcap
            ├── plugins
            ├── sqlite
            ├── stego
            ├── strings
            └── yara
```

---

## 🔄 Data Flow

### Analysis Pipeline

```
Input File
    │
    ▼
┌─────────────────┐
│  File Reading   │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  Format Detection│
└─────────────────┘
    │
    ├──→ Signatures (YAML database)
    ├──→ Magic bytes
    └──→ Heuristics
    │
    ▼
┌─────────────────┐
│  Deep Analysis   │
└─────────────────┘
    │
    ├──→ Entropy calculation
    ├──→ String extraction
    ├──→ Metadata extraction
    ├──→ Security analysis
    └──→ Embedded file detection
    │
    ▼
┌─────────────────┐
│  Result Format   │
└─────────────────┘
    │
    ├──→ Text (default)
    ├──→ JSON
    ├──→ SARIF
    └──→ HTML
```

### Entropy Visualization

```
Input File
    │
    ▼
┌─────────────────┐
│  Read Chunks    │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  Calculate      │
│  Shannon        │
│  Entropy        │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  ASCII Graph    │
│  Rendering      │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  Terminal       │
│  Output         │
└─────────────────┘
```

---

## 🧩 Key Components

### 1. Format Database (`internal/formats/`)

- **YAML-based format definitions**
- **30+ formats** (archives, executables, documents, images)
- **Signature matching** with confidence scores
- **Extensible** - add new formats via YAML

### 2. Entropy Visualization (`internal/entropy/`)

- **Shannon entropy** calculation
- **ASCII graph** visualization
- **MiniViz** for quick overview
- **Interpretation** of entropy levels

### 3. MCP Server (`internal/mcp/`)

- **JSON-RPC 2.0** protocol
- **9 tools** for AI integration
- **Claude Desktop** compatible
- **Extensible** tool registration

### 4. Plugin System (`internal/plugins/`)

- **Go plugin** support (.so files)
- **Dynamic loading** at runtime
- **Hook-based** architecture
- **Thread-safe** registration

### 5. Firmware Extraction (`internal/firmware/`)

- **SquashFS** - Full support
- **CramFS** - Full support
- **JFFS2** - Full support
- **Extensible** for more formats

---

## 📊 Module Coverage

| Module | LOC | Tests | Coverage | Status |
|--------|-----|-------|----------|--------|
| analyzer | 800 | 15 | 41.6% | ✅ |
| entropy | 450 | 20 | 85.1% | ✅ |
| strings | 300 | 22 | 81.7% | ✅ |
| metadata | 600 | 18 | 40.0% | ✅ |
| formats | 400 | 25 | 93.0% | ✅ |
| crypto | 250 | 9 | 74.3% | ✅ |
| container | 350 | 20 | 52.4% | ✅ |
| stego | 300 | 14 | 40.4% | ✅ |
| export | 500 | 12 | 86.8% | ✅ |
| hashing | 200 | 14 | 80.0% | ✅ |
| firmware | 400 | 10 | 60.0% | ✅ |
| yara | 500 | 15 | 50.0% | ✅ |
| pcap | 300 | 8 | 22.4% | ⚠️ |
| sqlite | 250 | 12 | 17.9% | ⚠️ |
| plugins | 200 | 22 | 100% | ✅ |

---

## 🔌 Extension Points

### 1. Adding New Formats

Create a YAML file in `formats/`:

```yaml
format: new_format
version: "1.0"
mime:
  - application/x-new-format
category: custom
confidence_weight: 0.95
extensions:
  - ext
description: New format description
signatures:
  - offset: 0
    hex: "DE AD BE EF"
    description: Magic bytes
    weight: 1.0
```

### 2. Adding New CLI Commands

Create a new file in `internal/cli/`:

```go
package cli

import "github.com/spf13/cobra"

var newCmd = &cobra.Command{
    Use:   "new",
    Short: "New command",
    RunE:  runNew,
}

func init() {
    rootCmd.AddCommand(newCmd)
}

func runNew(cmd *cobra.Command, args []string) error {
    // Implementation
    return nil
}
```

### 3. Adding New MCP Tools

Extend `internal/mcp/server.go`:

```go
func (s *Server) handleNewTool(params map[string]interface{}) (interface{}, error) {
    // Implementation
    return result, nil
}

func init() {
    RegisterTool("new_tool", "Description", schema, handler)
}
```

### 4. Adding New Plugins

Create a plugin in `plugins/`:

```go
package main

import "github.com/supunhg/filo-go/internal/plugins"

type MyPlugin struct{}

func (p *MyPlugin) Name() string { return "my-plugin" }
func (p *MyPlugin) Analyze(data []byte) (*plugins.Result, error) {
    // Implementation
    return &plugins.Result{}, nil
}

func init() {
    plugins.Register(&MyPlugin{})
}
```

---

## 🎯 Command Reference

### Analysis Commands

| Command | Description | Key Flags |
|---------|-------------|-----------|
| `analyze` | Full file analysis | `--json`, `--deep` |
| `entropy` | Entropy visualization | `--mini`, `--width`, `--height` |
| `hex` | Hex dump | `--offset`, `--length`, `--color` |
| `scan` | Signature scan | `--format`, `--verbose` |
| `search` | Pattern search | `--hex`, `--text`, `--offset` |
| `hash` | Compute hashes | `--algorithm`, `--all` |
| `strings` | Extract strings | `--min-length`, `--encoding` |

### Extraction Commands

| Command | Description | Key Flags |
|---------|-------------|-----------|
| `extract` | Extract embedded files | `--recursive`, `--format` |
| `dd` | Extract raw bytes | `--offset`, `--length`, `--count` |
| `carve` | Carve files | `--type`, `--depth` |
| `firmware` | Extract firmware | `--extract`, `--output` |

### Metadata Commands

| Command | Description | Key Flags |
|---------|-------------|-----------|
| `meta` | Extract metadata | `--all`, `--sus`, `--json` |
| `stego` | Detect steganography | `--all`, `--extract` |
| `crypto` | Detect encryption | `--verbose` |
| `executable` | Analyze executables | `--deep`, `--strings` |

### Forensic Commands

| Command | Description | Key Flags |
|---------|-------------|-----------|
| `pcap` | Analyze captures | `--streams`, `--extract`, `--proto` |
| `evtx` | Analyze event logs | `--json` |
| `sqlite` | Analyze databases | `--json` |
| `registry` | Analyze registry | `--json` |
| `sigma` | Scan with rules | `--rules` |

### Integration Commands

| Command | Description | Key Flags |
|---------|-------------|-----------|
| `batch` | Batch analysis | `--workers`, `--recursive` |
| `mcp` | Start MCP server | (none) |
| `plugins` | Manage plugins | `list`, `load`, `info` |
| `formats` | List formats | `--category` |

---

## 🔧 Configuration

### Config File Locations

1. **Environment variables**: `FILO_*`
2. **Project local**: `.filo.yaml`
3. **User config**: `~/.config/filo/config.yaml`
4. **Built-in defaults**

### Example Config

```yaml
analysis:
  max_file_size: 100MB
  timeout: 30s
  
output:
  format: json
  colors: true
  
plugins:
  directory: ~/.filo/plugins
  
mcp:
  enabled: true
  tools:
    - analyze
    - hash
    - strings
```

---

## 🚀 Performance Optimization

### Parallel Processing

- **Batch analysis**: Uses goroutines for parallel file processing
- **Configurable workers**: `--workers N` flag
- **Pipeline architecture**: Overlaps I/O and computation

### Memory Management

- **Streaming analysis**: Processes large files in chunks
- **Bounded buffers**: Limits memory usage
- **Early termination**: Stops on timeout or error

### Caching

- **Format detection**: Caches results for repeated files
- **Hash computation**: Reuses partial results
- **Plugin loading**: Caches loaded plugins

---

## 🧪 Testing Strategy

### Unit Tests

- **Package-level tests**: Each package has its own tests
- **Table-driven tests**: Consistent test patterns
- **Mock data**: Test files for each format

### Integration Tests

- **CLI tests**: Test command execution
- **End-to-end tests**: Full analysis pipeline
- **Performance tests**: Benchmark critical paths

### Test Coverage Targets

| Package | Current | Target |
|---------|---------|--------|
| Core | 41.6% | 80% |
| Metadata | 40.0% | 70% |
| Firmware | 60.0% | 80% |
| Overall | 35% | 60% |

---

## 🔮 Future Roadmap

### Phase 1: Feature Parity (Current)
- ✅ binwalk features
- ✅ file features
- ✅ ExifTool features
- ✅ YARA features

### Phase 2: Beyond Parity
- [ ] Memory forensics
- [ ] Network file extraction
- [ ] OOXML metadata
- [ ] HTML reports

### Phase 3: Enterprise
- [ ] Distributed analysis
- [ ] API server mode
- [ ] SIEM integration
- [ ] Evidence chain

---

## 📚 References

- [Go Documentation](https://pkg.go.dev/github.com/supunhg/filo-go)
- [Cobra Documentation](https://pkg.go.dev/github.com/spf13/cobra)
- [MCP Specification](https://spec.modelcontextprotocol.io)
- [YARA Documentation](https://yara.readthedocs.io)

---

*This document should be updated as the codebase evolves.*
