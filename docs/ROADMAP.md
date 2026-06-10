# filo-go Development Roadmap

> **Last Updated:** 2026-06-10  
> **Current Version:** 0.3.0  
> **Status:** In active development (v0.3.0 hygiene + roadmap accuracy release)

---

## 🎯 Vision

**filo-go** will be the **definitive** forensic analysis toolkit for security professionals, replacing binwalk, file, ExifTool, and YARA with a single, fast, cross-platform binary.

---

## 📊 Progress Summary

### Completed ✅

| Feature | Status | Date |
|---------|--------|------|
| Core analyzer | ✅ Done | 2024-11 |
| Entropy visualization | ✅ Done | 2024-11 |
| String extraction | ✅ Done | 2024-11 |
| Hash computation | ✅ Done | 2024-11 |
| Metadata extraction | ✅ Done | 2024-12 |
| Steganography detection | ✅ Done | 2024-11 |
| Crypto detection | ✅ Done | 2024-11 |
| Container analysis | ✅ Done | 2024-11 |
| SQLite analysis | ✅ Done | 2024-11 |
| Registry analysis | ✅ Done | 2024-11 |
| PCAP analysis | ✅ Done | 2024-12 |
| EVTX analysis | ✅ Done | 2024-11 |
| YARA rules | ✅ Done | 2024-12 |
| Sigma rules | ✅ Done | 2024-11 |
| MCP server | ✅ Done | 2024-12 |
| Plugin system | ✅ Done | 2024-12 |
| YAML formats | ✅ Done | 2024-12 |
| SARIF export | ✅ Done | 2024-12 |
| Hex dump | ✅ Done | 2024-12 |
| Signature scan | ✅ Done | 2024-12 |
| DD mode | ✅ Done | 2024-12 |
| File extraction | ✅ Done | 2024-12 |
| Firmware extraction | ✅ Done | 2024-12 |
| EXIF/XMP/IPTC | ✅ Done | 2024-12 |
| YARA conditions | ✅ Done | 2024-12 |
| HTML reports | ✅ Done | 2024-12 |

### Completed in v0.3.0 ✅

| Feature | Status | Date |
|---------|--------|------|
| Test coverage improvement | ✅ 58.7% coverage (measured) | 2026-06-10 |
| Documentation complete | ✅ Done | 2026-06-09 |
| Performance benchmarks | ✅ Done | 2026-06-09 |
| CI/CD pipeline | ✅ Done (golangci-lint scaffolded, gated) | 2026-06-10 |
| bzip2 decompression | ✅ Done | 2026-06-09 |
| Network file extraction | ✅ Done | 2026-06-09 |
| Real benchmark data | ✅ Done | 2026-06-09 |
| License updated to Apache 2.0 | ✅ Done | 2026-06-10 |
| CHANGELOG.md created | ✅ Done | 2026-06-10 |

### Planned 📋

| Feature | Priority | ETA |
|---------|----------|-----|
| OOXML metadata | High | Week 2 |
| YAFFS extraction | Medium | Week 2 |
| Memory forensics | Medium | Week 4 |
| Interactive HTML reports | High | Week 2 |
| PDF report export | Medium | Week 3 |
| More test coverage | High | Week 2 |

---

## 🚀 Phase 1: Feature Parity (Current)

**Goal:** Match binwalk, file, ExifTool, and YARA feature-for-feature.

### binwalk Parity ✅

- [x] File identification
- [x] Entropy analysis
- [x] Hex dump
- [x] Signature scanning
- [x] Embedded file extraction
- [x] SquashFS extraction
- [x] CramFS extraction
- [x] JFFS2 extraction
- [x] LZMA/XZ decompression
- [x] bzip2 decompression
- [x] Network file extraction
- [ ] YAFFS extraction

### file/libmagic Parity ✅

- [x] Magic byte detection
- [x] MIME type detection
- [x] Confidence scoring
- [x] Custom format definitions

### ExifTool Parity ✅

- [x] EXIF extraction
- [x] XMP extraction
- [x] IPTC extraction
- [ ] ICC profiles
- [ ] Maker notes
- [ ] Write capabilities (read-only)

### YARA Parity ✅

- [x] String matching
- [x] Hex strings
- [x] Regular expressions
- [x] AND/OR/NOT conditions
- [x] Filesize conditions
- [x] Entry point conditions
- [ ] Module imports
- [ ] External variables

---

## 📈 Phase 2: Beyond Parity

**Goal:** Surpass competitors with unique features.

### Unique Features

- [x] MCP integration (AI-assisted analysis)
- [x] Plugin system (community extensibility)
- [x] JSON/SARIF output (machine-parseable)
- [x] Risk scoring (security analysis)
- [x] TCP reassembly (network analysis)

### Advanced Features

- [x] Network file extraction from PCAP
- [ ] OOXML metadata (docx/xlsx/pptx)
- [ ] Interactive HTML reports
- [ ] PDF report export
- [ ] Timeline generation
- [ ] Evidence chain tracking

### Performance

- [x] Benchmark suite (filo vs binwalk)
- [x] Parallel batch processing
- [ ] Streaming analysis for large files
- [ ] Caching for repeated analysis

---

## 🏢 Phase 3: Enterprise

**Goal:** Production-ready for enterprise use.

### Security Features

- [ ] Audit logging
- [ ] Access control
- [ ] Encryption at rest
- [ ] Secure deletion

### Integration

- [ ] REST API server
- [ ] gRPC interface
- [ ] SIEM integration
- [ ] Docker container

### Operations

- [ ] Health checks
- [ ] Metrics export
- [ ] Alerting
- [ ] Backup/restore

---

## 📊 Test Coverage Goals

> **Last measured:** 2026-06-10 (Go 1.24, `go test -coverprofile=coverage.out ./internal/...`)
> **Overall coverage: 58.7%** (up from 46.7% in the prior roadmap revision, +12.0pp).
> Phase C coverage work landed via PRs #8, #9, and #10. The table below reflects the current measured values.

| Package | Current | Target | Status |
|---------|---------|--------|--------|
| ml | 100.0% | 95% | ✅ |
| nsrl | 98.2% | 90% | ✅ |
| repair | 98.0% | 85% | ✅ |
| executable/packing | 96.0% | 80% | ✅ |
| executable/pe | 95.4% | 80% | ✅ |
| entropy | 94.6% | 95% | ✅ |
| formats | 93.0% | 95% | ✅ |
| config | 90.7% | 95% | ✅ |
| export | 88.3% | 90% | ✅ |
| mcp | 88.0% | 90% | ✅ |
| plugins | 82.1% | 85% | ✅ |
| batch | 81.2% | 85% | ✅ |
| strings | 81.7% | 85% | ✅ |
| hashing | 80.0% | 85% | ✅ |
| executable/macho | 78.0% | 70% | ✅ |
| registry | 76.6% | 80% | ✅ |
| crypto | 74.3% | 80% | ✅ |
| yara | 73.7% | 80% | ✅ |
| carver | 67.3% | 75% | 🔄 |
| executable/elf | 64.9% | 60% | ✅ |
| evtx | 64.4% | 70% | ✅ |
| lineage | 53.8% | 60% | ✅ |
| container | 52.4% | 60% | 🔄 |
| analyzer | 50.9% | 60% | 🔄 |
| office | 47.6% | 60% | 🔄 |
| sqlite | 47.1% | 60% | 🔄 |
| sigma | 45.0% | 50% | 🔄 |
| timeline | 45.0% | 50% | 🔄 |
| metadata | 44.1% | 50% | 🔄 |
| executable | 42.3% | 50% | 🔄 |
| firmware | 41.7% | 50% | 🔄 |
| stego | 40.4% | 50% | 🔄 |
| pcap | 38.5% | 50% | 🔄 |
| cli | 32.5% | 40% | 🔄 |
| plugins/archive-bomb | 0.0% | 50% | ❌ |
| **Overall** | **58.7%** | **70%** | **v0.4.0** |

---

## 🎯 Milestones

### v0.3.0 (Released 2026-06-09)

- [x] Test coverage ≥ 40% (now **58.7%** measured, +12.0pp since v0.3.0 hygiene)
- [x] Complete documentation
- [x] Performance benchmarks
- [x] CI/CD pipeline (golangci-lint scaffolded, gated behind `if: false`)
- [x] bzip2 decompression
- [x] Network file extraction
- [x] License harmonized to Apache 2.0
- [x] CHANGELOG.md introduced
- [ ] OOXML metadata
- [ ] Interactive HTML reports

### v0.4.0 (Target: Week 3)

- [x] Network file extraction
- [ ] PDF report export
- [ ] Timeline generation
- [ ] Evidence chain tracking

### v0.5.0 (Target: Week 4)

- [ ] Memory forensics
- [ ] REST API server
- [ ] Docker container
- [ ] SIEM integration

### v1.0.0 (Target: Month 2)

- [ ] Production-ready
- [ ] Complete documentation
- [ ] 100% test coverage for core
- [ ] Community plugins
- [ ] Blog post / CTF writeup

---

## 📋 Development Practices

### Code Quality

- [x] Go modules
- [x] Linting (golangci-lint)
- [x] Formatting (gofmt)
- [ ] Code review
- [ ] CI/CD pipeline

### Testing

- [x] Unit tests
- [x] Performance tests (benchmarks)
- [ ] Integration tests
- [ ] Security tests

### Documentation

- [x] README
- [x] Knowledge graph
- [x] Competitive analysis
- [x] Roadmap
- [x] Performance documentation
- [ ] API documentation
- [ ] User guide
- [ ] Examples

---

## 🔮 Long-term Vision

### Year 1

- **v1.0**: Production-ready toolkit
- **v1.1**: Plugin marketplace
- **v1.2**: Cloud integration
- **v1.3**: Enterprise features

### Year 2

- **v2.0**: AI-powered analysis
- **v2.1**: Distributed processing
- **v2.2**: Real-time analysis
- **v2.3**: Mobile support

### Year 3

- **v3.0**: Platform as a Service
- **v3.1**: Marketplace ecosystem
- **v3.2**: Enterprise suite
- **v3.3**: Global deployment

---

## 📊 Success Metrics

| Metric | Current | Target | ETA |
|--------|---------|--------|-----|
| GitHub stars | 0 | 100 | Month 2 |
| Contributors | 1 | 5 | Month 3 |
| Test coverage | **58.7%** | 70% | v0.4.0 |
| Commands | 36 | 40 | Week 2 |
| MCP tools | 9 | 15 | Week 2 |
| Formats | 30 | 50 | Week 4 |
| Plugins | 1 | 10 | Month 2 |
| Test packages | 28 | 30 | Week 2 |

---

## 📞 Contributing

We welcome contributions! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

### Priority Areas

1. **Test coverage** - Write tests for existing code
2. **Documentation** - Improve user guides
3. **Plugins** - Create new analysis plugins
4. **Formats** - Add new format definitions
5. **Performance** - Optimize critical paths

---

*This roadmap is a living document and will be updated regularly.*
