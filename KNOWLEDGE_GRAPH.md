# filo-go Knowledge Graph

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLI Layer (cobra)                          │
│  analyze batch carve config evtx executable extract formats hash    │
│  lineage mcp meta pcap profile registry repair sigma sqlite stego   │
│  strings teach timeline version                                     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                        Core Analysis Engine                         │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  analyzer   │  │  executable │  │   stego     │                 │
│  │  (965 LOC)  │  │  (479 LOC)  │  │  (466 LOC)  │                 │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                 │
│         │                │                │                          │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐                 │
│  │  formats    │  │  elf/pe/    │  │  image pkg  │                 │
│  │  (300 LOC)  │  │  macho      │  │  (stdlib)   │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                      Forensic Modules                                │
│                                                                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │ sqlite  │ │  evtx   │ │registry │ │  pcap   │ │ sigma   │     │
│  │ (625)   │ │ (182)   │ │ (242)   │ │ (210)   │ │ (200)   │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
│                                                                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │  yara   │ │ crypto  │ │metadata │ │repair   │ │container│     │
│  │ (267)   │ │ (178)   │ │ (340)   │ │ (259)   │ │ (387)   │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
└─────────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│                     Infrastructure Layer                             │
│                                                                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │entropy  │ │ hashing │ │lineage  │ │ batch   │ │ export  │     │
│  │ (110)   │ │ (90)    │ │ (283)   │ │ (178)   │ │ (100)   │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
│                                                                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐                  │
│  │  ml     │ │  mcp    │ │ strings │ │ timeline│                  │
│  │ (245)   │ │ (396)   │ │ (285)   │ │ (122)   │                  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Module Dependency Graph

### Core Dependencies (who imports whom)

```
analyzer ──────► formats
       └──────► entropy (NEW)

executable ────► pe, elf, macho, packing
       └──────► entropy (via each sub-package)

stego ─────────► (std lib only: image, bytes, regexp)

container ─────► (std lib only: archive/zip, tar, gzip)

crypto ────────► entropy (NEW)

ml ────────────► entropy (NEW)

strings ───────► entropy (NEW)

batch ─────────► analyzer

mcp ───────────► analyzer, batch, crypto

repair ────────► (std lib only)

sqlite ────────► (std lib only)

lineage ───────► bbolt

yara ──────────► (std lib only)

sigma ──────────► (std lib only)

pcap ──────────► (std lib only)

evtx ──────────► (std lib only)

registry ──────► (std lib only)

metadata ──────► (std lib only)

export ────────► (std lib only)

hashing ───────► golang.org/x/crypto/sha3
```

## Data Flow Analysis

### File Analysis Pipeline
```
File Path
    │
    ▼
os.ReadFile(data)
    │
    ▼
analyzer.Analyze(data, filePath, opts)
    │
    ├──► entropy.Calculate(data)          → result.Entropy
    ├──► entropy.Interpret(result.Entropy) → result.EntropyLabel
    ├──► filetype.Match(data)             → result.PrimaryFormat
    ├──► mimetype.Detect(data)            → result.PrimaryMIME
    ├──► detectArchitecture(data)         → result.Architecture
    ├──► detectCrypto(data)               → result.CryptoIndicators
    ├──► detectPolyglots(data)            → result.Polyglots
    ├──► fingerprintTool(data)            → result.ToolFingerprint
    │
    ├──► [optional] crypto.Analyze(data)  → crypto.Result
    ├──► [optional] metadata.Extract(data)→ metadata.Result
    ├──► [optional] stego.Detect(data)    → stego.Result
    └──► [optional] executable.Analyze()  → executable.Result
```

### Executable Analysis Pipeline
```
data []byte
    │
    ▼
executable.DetectFormat(data) → Format (PE/ELF/MachO)
    │
    ├──► pe.Analyze(data)    → pe.Result (sections, imports, TLS, debug)
    │      └──► entropy.Calculate() per section
    │
    ├──► elf.Analyze(data)   → elf.Result (sections, segments, security)
    │      └──► entropy.Calculate() per section
    │
    ├──► macho.Analyze(data) → macho.Result (load commands, dylibs)
    │
    └──► packing.Detect()    → packing.Result (UPX, VMProtect, etc.)
           └──► entropy.Calculate() per section
```

## Key Abstractions

### Result Types (the data contracts)
| Package | Result Type | Key Fields |
|---------|-------------|------------|
| analyzer | `Result` | PrimaryFormat, Confidence, Entropy, SHA256 |
| executable | `Result` | Format, PE/ELF/MachO, Packing, Suspicious |
| stego | `Result` | Methods[], Flags[] |
| sqlite | `Result` | Header, Tables[], WAL, DeletedRecords |
| crypto | `Result` | Detected, Confidence, CipherHints, ECB |
| container | `Result` | Format, Entries[], Nested[] |
| repair | `Result` | Success, Strategy, Changes[] |
| metadata | `Result` | Metadata map, Suspicious[] |
| yara | `Result` | Matches[], RuleCount |
| sigma | `Match[]` | Rule, Evidence[] |
| pcap | `Result` | Protocols, HTTPRequests, Flags |
| evtx | `Result` | Events[], Flags[] |
| registry | `Result` | Keys[], Artifacts[] |

### Shared Types
```go
// entropy.Chunk - used by analyzer, stego (indirectly)
type Chunk struct {
    Offset  int64   `json:"offset"`
    Entropy float64 `json:"entropy"`
}

// Evidence - used by analyzer, executable
type Evidence struct {
    Source     string  `json:"source"`
    Confidence float64 `json:"confidence"`
    Details    string  `json:"details"`
}
```

## Test Coverage Map

| Package | Tests | Coverage | Priority |
|---------|-------|----------|----------|
| analyzer | ✅ | 41.6% | - |
| entropy | ✅ | 85.1% | - |
| executable | ✅ | 22.4% | - |
| sqlite | ❌ | 0% | 🔴 HIGH |
| stego | ❌ | 0% | 🔴 HIGH |
| crypto | ❌ | 0% | 🟡 MEDIUM |
| container | ❌ | 0% | 🟡 MEDIUM |
| repair | ❌ | 0% | 🟡 MEDIUM |
| metadata | ❌ | 0% | 🟡 MEDIUM |
| mcp | ❌ | 0% | 🟡 MEDIUM |
| yara | ❌ | 0% | 🟢 LOW |
| sigma | ❌ | 0% | 🟢 LOW |
| batch | ❌ | 0% | 🟢 LOW |
| All others | ❌ | 0% | 🟢 LOW |

## Code Quality Issues (Fixed ✅ / Remaining ⚠️)

### Fixed
- ✅ 6 duplicate `calculateEntropy` → shared `entropy` package
- ✅ 6 duplicate `min` → Go built-in
- ✅ MCP `toolHash` bug (was hashing only 16 bytes)
- ✅ `Result.JSON()` incomplete serialization
- ✅ Duplicate `executable` command registration

### Remaining
- ⚠️ No `formats/` YAML directory in repo
- ⚠️ `export` module is a stub (CSV/SARIF not implemented)
- ⚠️ `ml` detector is rule-based, not real ML
- ⚠️ `sigma` engine is keyword-only, not field-based
- ⚠️ `pcap` parser lacks TCP reassembly
- ⚠️ `evtx` parser is skeletal
- ⚠️ `registry` parser doesn't recurse child keys
- ⚠️ `office` parser only handles OLE2, not OOXML

## Strategic Position

### Unique Differentiators
1. **MCP Server** - Only forensic tool with native MCP integration
2. **SQLite Forensics** - Deep B-tree parsing, WAL detection, deleted records
3. **Executable Analysis** - PE/ELF/Mach-O with security feature detection
4. **Steganography** - LSB extraction with CTF flag detection
5. **Single Binary** - Go compilation, zero runtime dependencies

### Competitive Landscape
| Tool | Stars | Language | Strengths |
|------|-------|----------|-----------|
| binwalk | 30k+ | Python/C | Firmware extraction |
| foremost | 2k+ | C | File carving |
| YARA | 7k+ | C | Pattern matching |
| digler | 1.2k | Go | Disk forensics |
| **filo-go** | 0 | **Go** | **MCP + comprehensive analysis** |

## Next Actions (Priority Order)

### Phase 1: Credibility (Week 1)
1. Add `formats/` YAML directory with 20+ format definitions
2. Add tests for `sqlite` parser (your strongest module)
3. Add tests for `stego` detector
4. Fix `export` module (SARIF output for GitHub Code Scanning)

### Phase 2: Differentiation (Week 2-3)
5. Expand MCP server with HTTP/SSE transport
6. Add more MCP tools (all 24 CLI commands)
7. Create benchmark suite against binwalk/file/yara
8. Write CTF writeup using filo-go

### Phase 3: Community (Week 4+)
9. Add CONTRIBUTING.md
10. Create Docker image
11. Add plugin system for custom analyzers
12. Publish to pkg.go.dev
