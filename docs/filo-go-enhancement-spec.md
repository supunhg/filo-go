# filo-go Enhancement Specification

**Project:** filo-go (Forensic Intelligence & Learning Operator)
**Version:** 1.0.0 (Target)
**Date:** June 3, 2026
**Status:** Draft

---

## Executive Summary

filo-go aims to become the **definitive all-in-one file forensics platform** for security professionals. This specification outlines enhancements to transform the current implementation into a comprehensive tool that replaces multiple specialized tools (file, binwalk, exiftool, strings, YARA, etc.) with a single, high-performance binary.

### Vision Statement

> "One binary to analyze them all" — Replace the fragmented forensics toolchain with a unified, AI-powered platform that delivers best-in-class format detection, deep analysis, and actionable intelligence at unprecedented speed.

### Target Users

- **Security Researchers:** Malware analysis, threat hunting, incident response
- **Penetration Testers:** Reconnaissance, exploitation support, report generation
- **Students & Educators:** Learning forensics concepts, CTF challenges, training
- **Developers:** Build security validation into CI/CD pipelines
- **Incident Responders:** Rapid triage, evidence collection, forensic imaging

---

## 1. Core Philosophy & Principles

### 1.1 Design Principles

| Principle | Description |
|-----------|-------------|
| **Speed First** | Raw performance is non-negotiable. Single files in <100ms, batch thousands/sec |
| **Zero Dependencies** | Self-contained static binary, no runtime dependencies, air-gapped capable |
| **Progressive Disclosure** | Simple by default, powerful when needed. Don't overwhelm beginners |
| **AI-Native** | AI integration is the killer differentiator, not an afterthought |
| **Configurable Per-User** | Users choose their preferred output style, not us |
| **Community-Driven** | YAML-driven format definitions enable community contributions |

### 1.2 Non-Goals (Out of Scope)

- Real-time streaming analysis (focus on file-based analysis)
- Full disk forensic imaging (leave to specialized tools like FTK Imager)
- Network traffic capture (analyze existing captures, don't capture)
- GUI/web interface (CLI-first, TUI optional later)

---

## 2. Feature Specifications

### 2.1 Format Coverage (Priority)

#### 2.1.1 Executables — PE/ELF/Mach-O

**Current State:** Basic architecture detection only

**Target Capabilities:**

```yaml
executables:
  pe:
    - Import/Export table parsing
    - Section analysis (entropy, permissions, packing indicators)
    - Resource extraction (icons, manifests, embedded files)
    - TLS callback detection
    - Debug directory analysis
    - Certificate/signature verification
    - Packing detection (UPX, ASPack, Themida, VMProtect)
    - String decryption heuristics
  
  elf:
    - Dynamic linking analysis (PLT/GOT)
    - Symbol table parsing
    - Section flag analysis (NX, PIE, RELRO)
    - GOT overwrite detection
    - Stripped binary analysis
    - Build ID and notes extraction
    - Core dump analysis support
  
  macho:
    - Fat/universal binary support
    - Load command parsing
    - Code signature analysis
    - Entitlements extraction
    - Swift metadata detection
```

**Implementation Priority:** HIGH (Critical for malware analysis)

#### 2.1.2 Databases — SQLite/Registry Hives

**Current State:** Registry parser exists but limited

**Target Capabilities:**

```yaml
databases:
  sqlite:
    - Schema extraction (tables, columns, indexes)
    - WAL journal detection
    - Deleted record recovery
    - Browser artifact parsing (Chrome, Firefox, Safari)
    - Forensic timeline from timestamps
    - Cipher key extraction (encrypted DBs)
    - Common artifact templates:
      - Chrome History/cookies/downloads
      - Firefox places.sqlite
      - Safari history.db
      - WhatsApp/Telegram caches
  
  registry:
    - Complete hive parsing (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
    - UserAssist entry decoding
    - MRU list analysis
    - Shimcache/parser cache extraction
      - Amcache.hve analysis
      - Service persistence detection
      - Network connection artifacts
      - USB device history
```

**Implementation Priority:** HIGH (Essential for Windows forensics)

#### 2.1.3 Network Captures — PCAP/PCAPNG

**Current State:** Basic PCAP analyzer exists

**Target Capabilities:**

```yaml
pcap:
  protocol_analysis:
    - Layer 2/3/4 protocol dissection
    - HTTP request/response reconstruction
    - DNS query logging and anomaly detection
    - TLS/SSL handshake analysis
    - DHCP fingerprinting
    - ARP spoofing detection
  
  artifact_extraction:
    - HTTP file extraction (images, documents, executables)
    - SMTP attachment extraction
    - FTP file recovery
    - TFTP stream reconstruction
    - DNS tunneling detection
  
  security_analysis:
    - Beacon detection (C2 callbacks)
    - Lateral movement patterns
    - Credential harvesting attempts
    - Data exfiltration indicators
    - Known malicious IP/domain matching
```

**Implementation Priority:** MEDIUM-HIGH (Network forensics essential)

#### 2.1.4 Disk Images — ISO/DD/DMG

**Current State:** Not implemented

**Target Capabilities:**

```yaml
disk_images:
  formats:
    - Raw DD images
    - ISO9660/UDF (CD/DVD images)
    - Apple DMG (including sparse bundles)
    - VMDK/VHD (virtual disks)
  
  analysis:
    - Partition table detection (MBR, GPT)
    - Filesystem identification (NTFS, FAT32, ext4, APFS, HFS+)
    - Deleted file recovery (basic)
    - Metadata timeline extraction
    - Hidden partition detection
    - Slack space analysis
  
  extraction:
    - Selective file extraction by path/pattern
    - Recursive extraction with depth control
    - Metadata-only mode (fast)
```

**Implementation Priority:** MEDIUM (Disk forensics workflow)

### 2.2 Speed Optimization Strategy

#### 2.2.1 Performance Targets

| Metric | Current | Target | Rationale |
|--------|---------|--------|-----------|
| Single file analysis | ~200ms | <100ms | Interactive feel |
| Batch processing (1000 files) | ~5s | <1s | Real-time feedback |
| Batch processing (10,000 files) | ~50s | <5s | Enterprise scale |
| Memory usage (single file) | ~50MB | <20MB | Constrained environments |
| Binary size | ~15MB | <10MB | Distribution efficiency |

#### 2.2.2 Optimization Techniques

```yaml
performance:
  io_optimization:
    - Memory-mapped file reading for large files
    - Streaming analysis (don't load entire file into memory)
    - Prefetching and read-ahead for batch operations
  
  parallelism:
    - Goroutine pool with configurable worker count
    - Per-format parallel pipelines
    - Lock-free data structures where possible
  
  caching:
    - Format detection result caching (same bytes = same result)
    - Frequently-used format profile caching
    - LRU cache for repeated file analysis
  
  algorithms:
    - Bit-level operations for signature matching
    - SIMD-accelerated entropy calculation (where Go supports)
    - Early termination on high-confidence matches
```

### 2.3 AI Integration (Core Differentiator)

#### 2.3.1 MCP Server Enhancement

**Current State:** Basic JSON-RPC with 5 tools

**Target Capabilities:**

```yaml
mcp:
  tools:
    - analyze: Enhanced with AI explanations
    - explain: Natural language explanation of findings
    - compare: Side-by-side file comparison
    - hunt: Search for patterns across file corpus
    - correlate: Find relationships between files
    - recommend: Suggest next analysis steps
    - report: Generate markdown/HTML reports
  
  ai_features:
    - Contextual explanations ("This PE is suspicious because...")
    - Pattern recognition across multiple files
    - Natural language queries ("Is this malware?")
    - Threat intelligence correlation
    - MITRE ATT&CK mapping
    - Remediation recommendations
```

#### 2.3.2 AI Workflow Examples

```bash
# Example 1: Natural language query
filo analyze malware.exe --explain
# Output: "This is a UPX-packed PE executable targeting x64 Windows..."

# Example 2: Pattern hunting
filo hunt ./suspicious/ --pattern "beaconing"
# Output: Found 3 files with C2-like callback patterns...

# Example 3: Correlation
filo correlate file1.exe file2.dll
# Output: These files share 87% code similarity, likely from same malware family...

# Example 4: Report generation
filo report ./evidence/ --format markdown --output report.md
```

#### 2.3.3 Local vs. Cloud AI

```yaml
ai_deployment:
  local:
    - Embedded lightweight models for offline analysis
    - Rule-based explanations for common patterns
    - Template-based report generation
  
  cloud:
    - Optional cloud AI for complex analysis
    - Privacy-first: user controls what leaves their machine
    - Fallback to local if cloud unavailable
  
  hybrid:
    - Local for speed, cloud for depth
    - User-configurable per analysis type
```

### 2.4 Configuration System

#### 2.4.1 Config File Location

```
~/.config/filo/config.yaml          # XDG standard
~/.filo/config.yaml                 # Fallback
./.filo.yaml                        # Project-local config
```

#### 2.4.2 Configuration Schema

```yaml
# ~/.config/filo/config.yaml
version: 1

# User preferences
user:
  role: security_researcher        # student | developer | pentester | researcher | ir_responder
  experience: intermediate         # beginner | intermediate | expert

# Output configuration
output:
  format: terminal                 # terminal | json | sarif | csv | all
  verbosity: normal                # quiet | normal | verbose | debug
  colors: auto                     # auto | always | never
  progress_bars: true
  emoji: true

# Analysis defaults
analysis:
  default_depth: standard          # quick | standard | deep | maximum
  auto_deep_on_suspicion: true     # Automatically deep-analyze suspicious files
  max_file_size: 100MB             # Skip files larger than this
  timeout: 30s                     # Per-file analysis timeout

# Format priorities
formats:
  enable:
    - executables
    - databases
    - network
    - disk_images
    - containers
    - office
    - multimedia
  disable: []                      # Explicitly disable specific formats

# AI configuration
ai:
  enabled: true
  provider: local                  # local | openai | anthropic | custom
  api_key: ""                      # Only needed for cloud providers
  explanation_level: detailed      # minimal | detailed | educational
  mitre_mapping: true
  threat_intel: true

# Integration
integrations:
  yara_rules_path: ~/.config/filo/rules/
  sigma_rules_path: ~/.config/filo/sigma/
  format_definitions_path: ~/.config/filo/formats/

# Performance
performance:
  workers: auto                    # auto | 1-N
  memory_limit: 512MB
  cache_enabled: true
  cache_size: 100MB

# Output paths
paths:
  reports: ~/filo-reports/
  exports: ~/filo-exports/
  lineage_db: ~/.local/share/filo/lineage.db
```

### 2.5 Enhanced CLI Output

#### 2.5.1 Output Modes

```yaml
output_modes:
  default:
    - Color-coded terminal output
    - Structured tables for tabular data
    - Progress indicators for long operations
    - Emoji indicators for quick scanning (✅ ⚠️ ❌ 🔍)
  
  verbose:
    - Detailed evidence breakdown
    - Full hex dumps where relevant
    - Complete detection reasoning
    - Raw data previews
  
  explain:
    - AI-powered explanations
    - "Why is this suspicious?" answers
    - MITRE ATT&CK technique mapping
    - Remediation recommendations
  
  machine:
    - JSON/SARIF/CSV output
    - Structured for parsing
    - Suitable for CI/CD pipelines
```

#### 2.5.2 Visual Enhancements

```yaml
terminal_ui:
  colors:
    format: cyan
    confidence_high: green
    confidence_medium: yellow
    confidence_low: red
    evidence: purple
    warnings: yellow_bold
  
  tables:
    style: rounded                 # rounded | sharp | heavy | none
    alignment: left
  
  progress:
    bar: true
    spinner: true
    percentage: true
  
  summary:
    emoji: true
    one_line_summary: true
    detailed_breakdown: optional
```

---

## 3. Architecture Specifications

### 3.1 Module Structure

```
cmd/filo/                    # CLI entrypoint
internal/
  analyzer/                  # Core detection engine
  formats/                   # YAML format database
  stego/                     # Steganography detection
  crypto/                    # Encryption detection
  container/                 # Archive analysis
  repair/                    # File repair engine
  carver/                    # File carving
  batch/                     # Parallel processing
  strings/                   # String extraction
  pcap/                      # Network analysis
  metadata/                  # EXIF/PNG/PDF metadata
  lineage/                   # Chain of custody
  yara/                      # YARA scanning
  office/                    # Office macro detection
  mcp/                       # MCP server
  ml/                        # ML detection
  export/                    # JSON/SARIF/CSV export
  
  # NEW MODULES (Phase 1)
  executables/               # PE/ELF/Mach-O deep analysis
    pe/                      # Windows PE parser
    elf/                     # ELF parser
    macho/                   # Mach-O parser
    packing/                 # Packing detection
  
  databases/                 # Database analysis
    sqlite/                  # SQLite parser
    registry/                # Windows Registry parser
  
  disk/                      # Disk image analysis
    partition/               # Partition table parsing
    filesystem/              # Filesystem parsing
  
  # NEW MODULES (Phase 2)
  ai/                        # AI integration layer
    explanations/            # Natural language explanations
    patterns/                # Pattern recognition
    recommendations/         # Next-step suggestions
  
  config/                    # Configuration management
    loader/                  # Config file loading
    validator/               # Config validation
    defaults/                # Default values
```

### 3.2 Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Layer                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ analyze │  │  batch  │  │  hunt   │  │ report  │           │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘           │
└───────┼────────────┼────────────┼────────────┼──────────────────┘
        │            │            │            │
        ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Orchestration Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Config    │  │   Router    │  │   Output    │            │
│  │   Manager   │  │   (Format)  │  │   Formatter │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
        │            │            │            │
        ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Analysis Engine                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ Format  │  │ Crypto  │  │  Stego  │  │   AI    │           │
│  │Detect   │  │Analysis │  │Detection│  │ Engine  │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │  PE/ELF │  │ SQLite  │  │  PCAP   │  │ Disk    │           │
│  │  Parse  │  │  Parse  │  │  Parse  │  │  Parse  │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
└─────────────────────────────────────────────────────────────────┘
        │            │            │            │
        ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Storage Layer                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   BoltDB    │  │   Cache     │  │   Reports   │            │
│  │  (Lineage)  │  │   (Results) │  │   (Output)  │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Performance Architecture

```go
// Conceptual performance architecture
type AnalysisPipeline struct {
    // Streaming IO
    mmapReader    *MmapReader      // Memory-mapped file access
    chunkSize     int              // Configurable chunk size
    
    // Parallel processing
    workerPool    *WorkerPool      // Goroutine pool
    semaphore     chan struct{}     // Concurrency limiter
    
    // Caching
    formatCache   *LRUCache        // Format detection cache
    resultCache   *LRUCache        // Full result cache
    
    // Early termination
    confidenceThreshold float64    // Stop if confidence > threshold
    
    // Memory management
    memoryLimit   int64            // Per-analysis memory limit
    streamingMode bool             // Process in chunks
}
```

---

## 4. Testing Strategy

### 4.1 CI/CD Quality Gates

```yaml
testing:
  levels:
    unit:
      coverage_threshold: 80%
      run_on: every_commit
      timeout: 5m
    
    integration:
      test_corpus: true
      run_on: every_commit
      timeout: 15m
    
    performance:
      benchmark_tracking: true
      regression_detection: true
      run_on: every_pr
      timeout: 10m
    
    security:
      fuzzing: true
      gosec: true
      run_on: every_pr
      timeout: 20m
  
  quality_gates:
    - All unit tests pass
    - Coverage >= 80%
    - No performance regression > 10%
    - No security vulnerabilities (high/critical)
    - Linting passes (golangci-lint)
    - Build succeeds on all platforms
```

### 4.2 Test Corpus Strategy

```yaml
test_corpus:
  categories:
    - name: "Known Good"
      files: legitimate_samples
      purpose: "Ensure no false positives"
    
    - name: "Known Malicious"
      files: malware_samples
      purpose: "Ensure detection works"
    
    - name: "Edge Cases"
      files: truncated, corrupted, polyglot
      purpose: "Test robustness"
    
    - name: "Performance"
      files: large_files
      purpose: "Benchmark performance"
  
  sources:
    - VirusShare (with permission)
    - CICIDS2017 (network captures)
    - Digital Corpora (disk images)
    - Custom CTF challenges
  
  management:
    - Git LFS for large files
    - Automated download scripts
    - Versioned test cases
    - Community contributions via PR
```

### 4.3 Fuzzing Strategy

```yaml
fuzzing:
  targets:
    - format_detection
    - pe_parsing
    - elf_parsing
    - sqlite_parsing
    - registry_parsing
    - pcap_parsing
  
  tools:
    - go-fuzz
    - oss-fuzz integration
    - custom corpus generation
  
  duration:
    - unit_fuzz: 30s per test
    - regression_fuzz: 1h weekly
    - continuous_fuzz: 24h monthly
```

---

## 5. Distribution & Packaging

### 5.1 Binary Distribution

```yaml
distribution:
  formats:
    - name: "Self-contained binary"
      platforms: [linux, darwin, windows]
      arch: [amd64, arm64]
      size_target: "<10MB"
      compression: upx (optional)
    
    - name: "Homebrew tap"
      repository: "supunhg/filo-go"
      platforms: [darwin, linux]
    
    - name: "Go install"
      command: "go install github.com/supunhg/filo-go/cmd/filo@latest"
    
    - name: "GitHub Releases"
      auto_release: true
      checksum: sha256
      signatures: cosign
  
  versioning:
    scheme: semver
    tags: v1.0.0, v1.0.1, v1.1.0
    changelog: auto-generated
```

### 5.2 Documentation Requirements

```yaml
documentation:
  getting_started:
    - Installation guide (all platforms)
    - Quick start tutorial
    - First analysis walkthrough
  
  user_guide:
    - Command reference
    - Format support matrix
    - Configuration guide
    - AI integration guide
  
  developer_guide:
    - Architecture overview
    - Contributing guidelines
    - Adding new formats
    - Testing guide
  
  forensics_guide:
    - Common analysis workflows
    - Use case examples
    - Best practices
    - Case studies
  
  formats:
    - Supported formats list
    - Format definition schema
    - Adding custom formats
```

---

## 6. Implementation Phases

### Phase 1: Foundation (Months 1-3)

**Goal:** Solidify core and expand format coverage

```yaml
phase_1:
  priorities:
    - PE/ELF/Mach-O deep analysis
    - SQLite database parsing
    - Enhanced registry parsing
    - Performance optimization
    - Configuration system
  
  deliverables:
    - v0.5.0: Executable analysis
    - v0.6.0: Database analysis
    - v0.7.0: Performance targets met
    - v0.8.0: Configuration system
  
  success_metrics:
    - Single file analysis <100ms
    - PE/ELF parsing matches YARA capabilities
    - SQLite artifact extraction works
    - Config file loads correctly
```

### Phase 2: Intelligence (Months 4-6)

**Goal:** AI integration and advanced analysis

```yaml
phase_2:
  priorities:
    - Enhanced MCP server
    - AI explanation engine
    - Pattern recognition
    - Network analysis enhancement
    - Disk image support
  
  deliverables:
    - v0.9.0: Enhanced MCP
    - v1.0.0-rc1: AI explanations
    - v1.0.0-rc2: Pattern recognition
    - v1.0.0: Stable release
  
  success_metrics:
    - MCP tools provide useful AI insights
    - Pattern detection finds real malware patterns
    - Disk images parse correctly
    - No regressions from v0.x
```

### Phase 3: Ecosystem (Months 7-9)

**Goal:** Community and ecosystem growth

```yaml
phase_3:
  priorities:
    - Community contribution guides
    - Format definition repository
    - Integration partnerships
    - Advanced reporting
    - Enterprise features
  
  deliverables:
    - v1.1.0: Community formats
    - v1.2.0: Advanced reporting
    - v1.3.0: Enterprise features
  
  success_metrics:
    - 10+ community-contributed formats
    - 100+ GitHub stars
    - 5+ integration partners
    - Active contributor community
```

---

## 7. Success Metrics

### 7.1 Technical Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Single file analysis time | <100ms | P95 latency |
| Batch throughput | 10,000+ files/sec | Benchmark |
| Memory usage (single file) | <20MB | Peak RSS |
| Binary size | <10MB | Build artifact |
| Test coverage | >80% | Code coverage |
| Format support | 100+ formats | Format count |

### 7.2 User Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| GitHub stars | 1,000+ | GitHub API |
| Monthly downloads | 10,000+ | GitHub Releases |
| Active contributors | 20+ | GitHub contributors |
| Community formats | 50+ | Format definitions |
| Documentation pages | 100+ | Doc site |

### 7.3 Quality Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| False positive rate | <1% | Test corpus |
| False negative rate | <5% | Test corpus |
| Security vulnerabilities | 0 critical | SAST/DAST |
| Performance regression | <10% | Benchmark tracking |
| Breaking changes | 0 per minor | Semantic versioning |

---

## 8. Open Source Strategy

### 8.1 Community Guidelines

```yaml
community:
  governance:
    - Maintainer: @supunhg
    - Contributors: Open to all
    - Decision process: RFC for major changes
  
  contributing:
    - Code of conduct: Contributor Covenant
    - PR process: Required reviews, CI checks
    - Issue templates: Bug, feature, format request
    - Discussion forum: GitHub Discussions
  
  recognition:
    - Contributors listed in README
    - Format contributors credited
    - Release notes mention contributors
    - Annual contributor awards
```

### 8.2 Licensing

```
License: Apache License 2.0
- Commercial use allowed
- Modification allowed
- Distribution allowed
- Patent protection
- Private use allowed
- Attribution required
```

### 8.3 Marketing Strategy

```yaml
marketing:
  channels:
    - GitHub (primary)
    - Twitter/X (announcements)
    - Reddit (r/netsec, r/ReverseEngineering)
    - Hacker News (launch)
    - Security conferences (DEF CON, BSides)
  
  content:
    - Blog posts (analysis techniques)
    - Video tutorials
    - Conference talks
    - Case studies
  
  partnerships:
    - Security tool vendors
    - Training platforms
    - Academic institutions
    - Open source projects
```

---

## 9. Risk Assessment

### 9.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Performance targets not met | High | Medium | Profile early, optimize continuously |
| Format parsing bugs | High | Medium | Fuzzing, extensive test corpus |
| AI integration complexity | Medium | High | Start simple, iterate |
| Binary size growth | Low | High | UPX compression, build optimization |

### 9.2 Community Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Low adoption | High | Medium | Focus on unique value, marketing |
| Contributor burnout | Medium | Low | Sustainable pace, recognition |
| Forking | Low | Low | Good governance, community involvement |
| Maintainer leaving | High | Low | Bus factor, documentation |

### 9.3 Legal Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Malware sample distribution | High | Low | Legal review, proper licensing |
| Patent infringement | High | Low | Patent search, defensive publication |
| Export control violations | High | Low | Legal compliance review |

---

## 10. Appendices

### Appendix A: Format Support Matrix

| Category | Format | Current | Phase 1 | Phase 2 | Phase 3 |
|----------|--------|---------|---------|---------|---------|
| Executables | PE | Basic | ✅ Full | ✅ Full | ✅ Full |
| Executables | ELF | Basic | ✅ Full | ✅ Full | ✅ Full |
| Executables | Mach-O | Basic | ✅ Full | ✅ Full | ✅ Full |
| Databases | SQLite | ❌ | ✅ Full | ✅ Full | ✅ Full |
| Databases | Registry | Partial | ✅ Full | ✅ Full | ✅ Full |
| Network | PCAP | Basic | ✅ Enhanced | ✅ Full | ✅ Full |
| Network | PCAPNG | ❌ | ✅ Full | ✅ Full | ✅ Full |
| Disk | DD/RAW | ❌ | ✅ Full | ✅ Full | ✅ Full |
| Disk | ISO | ❌ | ✅ Full | ✅ Full | ✅ Full |
| Disk | DMG | ❌ | ✅ Full | ✅ Full | ✅ Full |
| Containers | ZIP | ✅ | ✅ | ✅ | ✅ |
| Containers | TAR | ✅ | ✅ | ✅ | ✅ |
| Containers | 7z | Partial | ✅ | ✅ | ✅ |
| Containers | RAR | Partial | ✅ | ✅ | ✅ |
| Office | DOCX | Basic | ✅ | ✅ | ✅ |
| Office | XLSX | Basic | ✅ | ✅ | ✅ |
| Office | PPTX | Basic | ✅ | ✅ | ✅ |
| Multimedia | PNG | ✅ | ✅ | ✅ | ✅ |
| Multimedia | JPEG | ✅ | ✅ | ✅ | ✅ |
| Multimedia | GIF | ✅ | ✅ | ✅ | ✅ |
| Multimedia | PDF | ✅ | ✅ | ✅ | ✅ |

### Appendix B: CLI Command Reference (Enhanced)

```bash
# Analysis commands
filo analyze <file>              # Analyze single file
filo analyze <file> --deep       # Deep analysis mode
filo analyze <file> --explain    # AI-powered explanation
filo analyze <file> --json       # JSON output

# Batch commands
filo batch <directory>           # Batch analyze directory
filo batch <directory> --workers 8  # Parallel workers
filo batch <directory> --format csv  # Export format

# Specialized commands
filo pe <file>                   # PE-specific analysis
filo elf <file>                  # ELF-specific analysis
filo sqlite <file>               # SQLite analysis
filo registry <hive>             # Registry hive analysis
filo pcap <file>                 # Network capture analysis
filo disk <image>                # Disk image analysis

# Utility commands
filo strings <file>              # Extract strings
filo hash <file>                 # Compute hashes
filo meta <file>                 # Extract metadata
filo repair <file>               # Repair corrupted file
filo stego <file>                # Steganography detection

# AI commands
filo hunt <directory> --pattern "suspicious"  # Pattern hunting
filo correlate <file1> <file2>   # File correlation
filo report <directory>          # Generate report

# System commands
filo config                      # Show configuration
filo formats                     # List supported formats
filo version                     # Show version
```

### Appendix C: Configuration Examples

**Example 1: Security Researcher Config**

```yaml
# ~/.config/filo/config.yaml
version: 1
user:
  role: security_researcher
  experience: expert
output:
  format: terminal
  verbosity: verbose
  colors: always
analysis:
  default_depth: deep
  auto_deep_on_suspicion: true
ai:
  enabled: true
  explanation_level: detailed
  mitre_mapping: true
```

**Example 2: Student Config**

```yaml
# ~/.config/filo/config.yaml
version: 1
user:
  role: student
  experience: beginner
output:
  format: terminal
  verbosity: normal
  colors: auto
analysis:
  default_depth: standard
  auto_deep_on_suspicion: false
ai:
  enabled: true
  explanation_level: educational
  mitre_mapping: false
```

**Example 3: CI/CD Config**

```yaml
# .filo.yaml (project root)
version: 1
output:
  format: json
  verbosity: quiet
analysis:
  default_depth: quick
  timeout: 10s
integrations:
  yara_rules_path: ./rules/
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-06-03 | Buffy | Initial specification |

---

*This document is a living specification and will be updated as the project evolves.*
