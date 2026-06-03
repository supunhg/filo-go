# filo-go Long-Term Development Roadmap

**Project:** filo-go (Forensic Intelligence & Learning Operator)
**Created:** June 3, 2026
**Current Version:** 0.1.0
**Target Version:** 1.0.0+

---

## Vision

> "One binary to analyze them all" — Replace the fragmented forensics toolchain with a unified, AI-powered platform that delivers best-in-class format detection, deep analysis, and actionable intelligence at unprecedented speed.

---

## Current State (v0.1.0)

### What Exists

| Module | Status | Notes |
|--------|--------|-------|
| Core Analyzer | ✅ Working | Format detection, entropy, embedded objects, contradictions |
| PE/ELF/Mach-O | ✅ Working | Deep analysis with sections, imports, security features |
| Steganography | ✅ Working | PNG LSB, JPEG/PDF/GIF trailing data |
| Crypto Detection | ✅ Working | AES/DES, ECB mode, OpenSSL/PGP formats |
| File Repair | ✅ Working | PNG, JPEG, PDF, ZIP repair strategies |
| Container Analysis | ✅ Working | ZIP, 7z, RAR, TAR, GZ with recursive nesting |
| Batch Processing | ✅ Working | Parallel analysis |
| Lineage Tracking | ✅ Working | Chain of custody with BoltDB |
| MCP Server | ✅ Working | Basic JSON-RPC with 5 tools |
| Export | ✅ Working | JSON, SARIF, CSV (basic) |
| CLI Commands | ✅ Working | 18+ commands including executable analysis |
| Packing Detection | ✅ Working | 15+ packers + heuristic analysis |
| YARA Scanner | ✅ Working | Simplified rule parsing |
| Sigma Engine | ✅ Working | Basic rule evaluation |
| EVTX Parser | ✅ Working | Windows event log parsing |
| Registry Parser | ✅ Working | Basic hive parsing |
| Timeline | ✅ Working | Event aggregation and sorting |
| ML Detection | ✅ Working | Basic entropy/ngram-based detection |
| Metadata Extraction | ✅ Working | EXIF, PNG, PDF metadata |
| Strings | ✅ Working | Printable string extraction |
| NSRL Matching | ✅ Working | Hash-based lookup |
| Hashing | ✅ Working | SHA-256 computation |
| Office Macros | ✅ Working | Basic macro detection |
| PCAP Analysis | ✅ Working | Basic packet analysis |

### What Doesn't Exist Yet

| Feature | Priority | Phase |
|---------|----------|-------|
| Configuration system | HIGH | 1 |
| SQLite database parser | HIGH | 1 |
| Enhanced registry parser | HIGH | 1 |
| Performance optimization | HIGH | 1 |
| AI explanation engine | HIGH | 2 |
| Enhanced MCP server | HIGH | 2 |
| Disk image analysis | MEDIUM | 2 |
| CI/CD pipeline | HIGH | 1 |
| Test corpus | HIGH | 1 |
| Documentation site | MEDIUM | 2 |
| Community contribution guides | MEDIUM | 3 |
| Plugin/extension system | LOW | 3 |

---

## Development Phases

### Phase 1: Foundation (Months 1-3)

**Goal:** Solidify core, expand format coverage, establish quality infrastructure

#### Sprint 1.1: Quality Infrastructure (Weeks 1-2)

```
Branch: feat/ci-cd-pipeline
```

| Task | Priority | Est. |
|------|----------|------|
| Set up GitHub Actions CI/CD | P0 | 1d |
| Add golangci-lint configuration | P0 | 0.5d |
| Create Makefile targets for test/lint/build | P0 | 0.5d |
| Set up test coverage reporting | P1 | 0.5d |
| Create CONTRIBUTING.md | P1 | 1d |
| Create .github/ISSUE_TEMPLATE | P1 | 0.5d |
| Set up release automation with goreleaser | P1 | 1d |

**Deliverable:** CI/CD pipeline running on all PRs

#### Sprint 1.2: Configuration System (Weeks 3-4)

```
Branch: feat/config-system
```

| Task | Priority | Est. |
|------|----------|------|
| Design config schema (YAML) | P0 | 1d |
| Implement config loader with XDG support | P0 | 2d |
| Add config validation | P0 | 1d |
| Create config CLI command | P1 | 0.5d |
| Add project-local config (.filo.yaml) | P1 | 0.5d |
| Add environment variable overrides | P2 | 0.5d |

**Deliverable:** `~/.config/filo/config.yaml` with all settings from spec

#### Sprint 1.3: SQLite Parser (Weeks 5-6)

```
Branch: feat/sqlite-parser
```

| Task | Priority | Est. |
|------|----------|------|
| Implement SQLite file format parser | P0 | 3d |
| Extract schema (tables, columns, indexes) | P0 | 1d |
| WAL journal detection | P1 | 0.5d |
| Deleted record recovery (basic) | P1 | 1d |
| Browser artifact templates (Chrome, Firefox) | P2 | 2d |
| Create `filo sqlite` CLI command | P0 | 0.5d |

**Deliverable:** `filo sqlite browser.db` extracts history, cookies, downloads

#### Sprint 1.4: Enhanced Registry Parser (Weeks 7-8)

```
Branch: feat/enhanced-registry
```

| Task | Priority | Est. |
|------|----------|------|
| Complete SAM hive parsing | P0 | 2d |
| SYSTEM hive parsing (services, boot) | P0 | 2d |
| USER hive parsing (MRU, typed URLs) | P1 | 1d |
| Amcache.hve analysis | P1 | 1d |
| UserAssist entry decoding | P2 | 1d |
| USB device history extraction | P2 | 1d |

**Deliverable:** Full Windows registry forensics

#### Sprint 1.5: Test Corpus & Coverage (Weeks 9-10)

```
Branch: feat/test-corpus
```

| Task | Priority | Est. |
|------|----------|------|
| Create test data generation scripts | P0 | 2d |
| Build PE/ELF/Mach-O test corpus | P0 | 2d |
| Add SQLite test database generator | P0 | 1d |
| Achieve 80% code coverage | P0 | 2d |
| Add fuzz tests for parsers | P1 | 2d |
| Performance benchmark suite | P1 | 1d |

**Deliverable:** Comprehensive test suite with 80%+ coverage

#### Sprint 1.6: Performance Optimization (Weeks 11-12)

```
Branch: feat/performance-optimization
```

| Task | Priority | Est. |
|------|----------|------|
| Profile hot paths | P0 | 1d |
| Implement memory-mapped file reading | P0 | 2d |
| Add LRU cache for format detection | P0 | 1d |
| Optimize batch processing pipeline | P1 | 2d |
| Binary size optimization (UPX) | P2 | 0.5d |
| Add performance regression tests | P1 | 1d |

**Deliverable:** <100ms single file, <1s for 1000 files

#### Phase 1 Milestone

```yaml
version: v0.5.0
features:
  - Configuration system (XDG, YAML, project-local)
  - SQLite database analysis
  - Enhanced Windows registry forensics
  - CI/CD pipeline with quality gates
  - 80%+ test coverage
  - Performance targets met
```

---

### Phase 2: Intelligence (Months 4-6)

**Goal:** AI integration, advanced analysis, enhanced networking

#### Sprint 2.1: AI Explanation Engine (Weeks 13-15)

```
Branch: feat/ai-explanations
```

| Task | Priority | Est. |
|------|----------|------|
| Design explanation engine architecture | P0 | 1d |
| Implement local rule-based explanations | P0 | 3d |
| Add MITRE ATT&CK mapping | P0 | 2d |
| Create explain mode CLI output | P0 | 1d |
| Add remediation recommendations | P1 | 2d |
| Pattern recognition across files | P2 | 3d |

**Deliverable:** `filo analyze malware.exe --explain` shows AI-powered analysis

#### Sprint 2.2: Enhanced MCP Server (Weeks 16-18)

```
Branch: feat/enhanced-mcp
```

| Task | Priority | Est. |
|------|----------|------|
| Add analyze tool with AI explanations | P0 | 2d |
| Add explain tool for NL queries | P0 | 2d |
| Add compare tool for file comparison | P1 | 2d |
| Add hunt tool for pattern search | P1 | 2d |
| Add correlate tool for relationship mapping | P2 | 2d |
| Add report generation tool | P1 | 2d |

**Deliverable:** Full AI-powered MCP server with 10+ tools

#### Sprint 2.3: Enhanced PCAP Analysis (Weeks 19-20)

```
Branch: feat/enhanced-pcap
```

| Task | Priority | Est. |
|------|----------|------|
| HTTP request/response reconstruction | P0 | 2d |
| DNS query logging and anomaly detection | P0 | 2d |
| TLS/SSL handshake analysis | P1 | 1d |
| HTTP file extraction | P1 | 2d |
| Beacon detection (C2 callbacks) | P2 | 2d |
| DNS tunneling detection | P2 | 1d |

**Deliverable:** Deep network forensics capabilities

#### Sprint 2.4: Disk Image Analysis (Weeks 21-23)

```
Branch: feat/disk-image-analysis
```

| Task | Priority | Est. |
|------|----------|------|
| Raw DD image support | P0 | 2d |
| ISO9660/UDF parsing | P0 | 2d |
| Partition table detection (MBR, GPT) | P0 | 1d |
| Filesystem identification | P1 | 2d |
| Apple DMG support | P1 | 2d |
| Basic deleted file recovery | P2 | 2d |

**Deliverable:** `filo disk evidence.dd` analyzes disk images

#### Sprint 2.5: Documentation & Tutorials (Weeks 24-26)

```
Branch: feat/documentation
```

| Task | Priority | Est. |
|------|----------|------|
| Set up documentation site (mdbook) | P0 | 2d |
| Write installation guide | P0 | 1d |
| Create quick start tutorial | P0 | 1d |
| Write command reference | P0 | 2d |
| Create forensics workflow guides | P1 | 3d |
| Add video tutorials | P2 | 5d |

**Deliverable:** Comprehensive documentation site

#### Phase 2 Milestone

```yaml
version: v1.0.0-rc1
features:
  - AI explanation engine with MITRE mapping
  - Enhanced MCP server with NL queries
  - Deep PCAP analysis with file extraction
  - Disk image analysis (DD, ISO, DMG)
  - Comprehensive documentation
```

---

### Phase 3: Ecosystem (Months 7-9)

**Goal:** Community growth, advanced features, enterprise readiness

#### Sprint 3.1: Community Infrastructure (Weeks 27-29)

```
Branch: feat/community
```

| Task | Priority | Est. |
|------|----------|------|
| Create format definition repository | P0 | 2d |
| Write format contributor guide | P0 | 1d |
| Set up GitHub Discussions | P0 | 0.5d |
| Create first community format pack | P1 | 3d |
| Add format validation tooling | P1 | 2d |
| Set up contributor recognition system | P2 | 1d |

**Deliverable:** Community-ready contribution workflow

#### Sprint 3.2: Advanced Reporting (Weeks 30-32)

```
Branch: feat/advanced-reporting
```

| Task | Priority | Est. |
|------|----------|------|
| Markdown report generation | P0 | 2d |
| HTML report with interactive charts | P1 | 3d |
| SARIF output for security tools | P0 | 1d |
| Batch report aggregation | P1 | 2d |
| Custom report templates | P2 | 2d |
| Timeline visualization | P2 | 2d |

**Deliverable:** Professional forensics reports

#### Sprint 3.3: Integration Ecosystem (Weeks 33-35)

```
Branch: feat/integrations
```

| Task | Priority | Est. |
|------|----------|------|
| YARA rule compilation from source | P0 | 2d |
| Sigma rule backend support | P0 | 2d |
| Threat intelligence feed integration | P1 | 3d |
| Splunk/ELK export format | P1 | 2d |
| API key management for cloud services | P2 | 1d |
| Webhook notifications | P2 | 1d |

**Deliverable:** Enterprise integration capabilities

#### Sprint 3.4: Advanced Analysis (Weeks 36-38)

```
Branch: feat/advanced-analysis
```

| Task | Priority | Est. |
|------|----------|------|
| Cross-file correlation engine | P0 | 3d |
| Campaign detection across samples | P1 | 3d |
| Automated malware family classification | P1 | 3d |
| Behavioral analysis framework | P2 | 5d |
| Code similarity detection | P2 | 3d |

**Deliverable:** Advanced threat intelligence capabilities

#### Sprint 3.5: Polish & Release (Weeks 39-42)

```
Branch: feat/v1.0-polish
```

| Task | Priority | Est. |
|------|----------|------|
| Performance audit and optimization | P0 | 2d |
| Security audit | P0 | 2d |
| Accessibility improvements | P1 | 1d |
| Internationalization (i18n) | P2 | 3d |
| Plugin system design | P2 | 3d |
| Release preparation | P0 | 2d |

**Deliverable:** Production-ready v1.0.0

#### Phase 3 Milestone

```yaml
version: v1.0.0
features:
  - Community format contributions
  - Advanced reporting (HTML, interactive)
  - Enterprise integrations (Splunk, ELK)
  - Cross-file correlation
  - Production-ready release
```

---

## Technical Architecture Evolution

### Current Architecture

```
cmd/filo/           # CLI entrypoint
internal/
  analyzer/         # Core detection engine
  executable/       # PE/ELF/Mach-O analysis (NEW)
    pe/
    elf/
    macho/
    packing/
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

### Target Architecture (v1.0.0)

```
cmd/filo/
internal/
  analyzer/         # Core detection engine
  executable/       # PE/ELF/Mach-O (enhanced)
  config/           # Configuration management (NEW)
    loader/
    validator/
    defaults/
  databases/        # Database analysis (NEW)
    sqlite/
    registry/       # Enhanced
  disk/             # Disk image analysis (NEW)
    partition/
    filesystem/
  network/          # Network analysis (enhanced)
    pcap/
    protocols/
  ai/               # AI integration (NEW)
    explanations/
    patterns/
    recommendations/
  formats/
  stego/
  crypto/
  container/
  repair/
  carver/
  batch/
  strings/
  metadata/
  lineage/
  yara/
  office/
  mcp/              # Enhanced
  ml/               # Enhanced
  export/           # Enhanced
```

---

## Performance Targets

| Metric | v0.1.0 | v0.5.0 | v1.0.0 |
|--------|--------|--------|--------|
| Single file analysis | ~200ms | <100ms | <50ms |
| Batch (1000 files) | ~5s | <1s | <500ms |
| Batch (10,000 files) | ~50s | <5s | <2s |
| Memory (single file) | ~50MB | <20MB | <10MB |
| Binary size | ~15MB | <12MB | <10MB |
| Test coverage | 30% | 80% | 90% |
| Format support | 20+ | 50+ | 100+ |

---

## Quality Gates

Every PR must pass:

```yaml
quality_gates:
  - All unit tests pass
  - Coverage >= 80%
  - No performance regression > 10%
  - No security vulnerabilities (high/critical)
  - Linting passes (golangci-lint)
  - Build succeeds on all platforms (linux, darwin, windows)
  - No breaking changes (unless major version bump)
  - Documentation updated (if API changes)
```

---

## Branching Strategy

```
main          ← Stable releases only
  │
  └── dev     ← Integration branch
        │
        ├── feat/config-system
        ├── feat/sqlite-parser
        ├── feat/ai-explanations
        └── ...
```

### Workflow

1. Create feature branch from `dev`
2. Implement changes with tests
3. Open PR to `dev`
4. CI/CD runs quality gates
5. Code review required
6. Merge to `dev` (squash or merge commit)
7. Create new feature branch from `dev`

### Release Process

1. Create release branch from `dev`
2. Final QA and testing
3. Create PR to `main`
4. Tag release (v0.5.0, v1.0.0, etc.)
5. GitHub Actions builds and publishes binaries
6. Update documentation

---

## Risk Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Scope creep | High | High | Strict phase adherence, feature flags |
| Performance regression | Medium | Medium | Benchmark suite, CI monitoring |
| Format parsing bugs | High | Medium | Fuzzing, test corpus, community testing |
| AI integration complexity | Medium | High | Start simple, iterate, modular design |
| Community adoption | High | Medium | Marketing, documentation, conferences |
| Maintainer burnout | High | Low | Sustainable pace, contributor recognition |

---

## Success Metrics

### Technical

| Metric | v0.5.0 | v1.0.0 |
|--------|--------|--------|
| GitHub stars | 100+ | 1,000+ |
| Monthly downloads | 1,000+ | 10,000+ |
| Active contributors | 5+ | 20+ |
| Test coverage | 80% | 90% |
| Format support | 50+ | 100+ |
| Performance (1K files) | <1s | <500ms |

### Community

| Metric | v0.5.0 | v1.0.0 |
|--------|--------|--------|
| Community formats | 5+ | 50+ |
| Documentation pages | 20+ | 100+ |
| Conference talks | 1+ | 5+ |
| Blog posts | 3+ | 15+ |
| Integration partners | 1+ | 5+ |

---

## Next Immediate Steps

1. **This Week:** Commit all current executable analysis work to feature branch
2. **Next Week:** Set up CI/CD pipeline (Sprint 1.1)
3. **Week 3:** Start configuration system (Sprint 1.2)
4. **Week 5:** Begin SQLite parser (Sprint 1.3)

---

## Appendix: Quick Reference

### Build Commands

```bash
# Development
make dev                    # Run in development mode
make build                  # Build binary
make test                   # Run all tests
make lint                   # Run linter
make test-coverage          # Generate coverage report

# Release
make release                # Full release
make snapshot               # Snapshot build

# Testing
go test ./...               # All tests
go test -race ./...         # Race detector
go test -fuzz=FuzzParse ./...  # Fuzz testing
```

### Key CLI Commands

```bash
# Core analysis
filo analyze <file>          # Analyze file
filo analyze <file> --deep   # Deep analysis
filo executable <file>       # Executable analysis
filo batch <dir>             # Batch analyze

# Future (Phase 1-2)
filo config                  # Configuration
filo sqlite <db>             # SQLite analysis
filo registry <hive>         # Registry analysis
filo disk <image>            # Disk image analysis
filo hunt <dir> --pattern X  # Pattern hunting
filo report <dir>            # Generate report
```

---

*This roadmap is a living document. Update quarterly based on progress and community feedback.*
