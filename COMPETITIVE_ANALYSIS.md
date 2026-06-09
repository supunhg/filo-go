# filo-go: Competitive Gap Analysis & Development Roadmap

> **Last Updated:** 2024-12-09  
> **Status:** Active Development  
> **Goal:** Replace binwalk + file as the go-to forensic analysis toolkit

---

## 📊 Executive Summary

| Metric | filo-go | binwalk | file/libmagic | ExifTool | YARA |
|--------|---------|---------|---------------|----------|------|
| Language | Go | Python/C | C | Perl | C |
| Binary Size | ~15MB | N/A (Python) | ~1MB | ~2MB | ~1MB |
| Dependencies | None | Many | libmagic | Many | libyara |
| Speed | ⚡ Fast | 🐌 Slow | ⚡ Fast | 🐌 Slow | ⚡ Fast |
| Extensibility | ✅ Plugins | ✅ Plugins | ❌ | ✅ Plugins | ✅ Rules |
| MCP Integration | ✅ | ❌ | ❌ | ❌ | ❌ |
| Windows Support | ✅ | ⚠️ | ⚠️ | ✅ | ✅ |
| Active Maintained | ✅ | ⚠️ | ✅ | ✅ | ✅ |

---

## 🔴 Critical Issues (Fix Immediately)

### 1. Stub Implementations

| Module | Status | Issue |
|--------|--------|-------|
| `pcap` CLI | ❌ STUB | `Not yet implemented` message |
| `evtx` parser | ⚠️ PARTIAL | Simplified chunk parsing, misses real events |
| `office` analyzer | ⚠️ PARTIAL | Only OLE2, no OOXML (docx/xlsx/pptx) |
| `pcap` analyzer | ⚠️ PARTIAL | No TCP reassembly in main analyzer |
| `ml` detector | ⚠️ STUB | Claims ML but is rule-based |
| `sigma` engine | ⚠️ PARTIAL | Keyword-only, no field matching |

### 2. Missing Core Features

| Feature | binwalk has | filo-go has |
|---------|-------------|-------------|
| Recursive extraction | ✅ | ⚠️ Partial |
| Entropy graph | ✅ | ✅ |
| File carving | ✅ | ✅ Basic |
| Signature database | ✅ Extensive | ⚠️ 30 formats |
| DD mode | ✅ | ❌ |
| Quiet mode | ✅ | ❌ |
| JSON output | ❌ | ✅ |

### 3. CLI Issues

```bash
# These commands need work:
filo pcap file.pcap     # STUB - not implemented
filo evtx file.evtx     # PARTIAL - misses events
filo office file.docx   # PARTIAL - no OOXML
filo teach file.bin     # STUB - ML not implemented
```

---

## 🟡 Major Gaps (Fix This Week)

### 1. Format Support

| Format | binwalk | filo-go | Notes |
|--------|---------|---------|-------|
| ZIP | ✅ | ✅ | |
| TAR.GZ | ✅ | ✅ | |
| 7z | ✅ | ⚠️ | No extraction |
| RAR | ✅ | ⚠️ | No extraction |
| XZ | ✅ | ⚠️ | Detection only |
| BZ2 | ✅ | ⚠️ | Detection only |
| LZMA | ✅ | ❌ | |
| SquashFS | ✅ | ❌ | |
| CramFS | ✅ | ❌ | |
| JFFS2 | ✅ | ❌ | |
| YAFFS | ✅ | ❌ | |
| UBIFS | ✅ | ❌ | |
| Cpio | ✅ | ❌ | |
| DTB | ✅ | ❌ | |

**Priority:** Add extraction for 7z, RAR, XZ, BZ2

### 2. Entropy Visualization

Current implementation is good but missing:

| Feature | binwalk | filo-go |
|---------|---------|---------|
| ASCII graph | ✅ | ✅ |
| Color output | ✅ | ✅ |
| PNG export | ✅ | ❌ |
| Interactive HTML | ❌ | ❌ |
| Block analysis | ✅ | ❌ |
| Suspicious regions | ✅ | ⚠️ Basic |

### 3. Output Formats

| Format | binwalk | filo-go |
|--------|---------|---------|
| Plain text | ✅ | ✅ |
| JSON | ❌ | ✅ |
| CSV | ❌ | ✅ |
| SARIF | ❌ | ✅ |
| HTML report | ❌ | ❌ |
| PDF report | ❌ | ❌ |

---

## 🟢 Nice to Have (Next Sprint)

### 1. Advanced Features

| Feature | Description | Priority |
|---------|-------------|----------|
| DD mode | Raw byte extraction at offset | High |
| Signature scanning | Scan for known signatures | High |
| Firmware detection | Identify firmware type | Medium |
| Architecture detection | ARM, MIPS, x86, etc. | Medium |
| Crypto detection | AES, RSA, etc. | Medium |
| Steganography | LSB, DCT, etc. | Medium |
| Memory forensics | Volatility-like | Low |
| Registry analysis | Full hive parsing | Low |

### 2. Visual Improvements

| Feature | Current | Needed |
|---------|---------|--------|
| Progress bars | ❌ | ✅ |
| Color output | ⚠️ Some | ✅ Consistent |
| Tables | ❌ | ✅ |
| Headers | ⚠️ Basic | ✅ Styled |
| Icons/Emoji | ⚠️ Some | ✅ Consistent |
| Interactive mode | ❌ | ✅ |

---

## 📋 Development Roadmap

### Phase 1: Foundation (Current Sprint)

- [ ] Fix PCAP CLI stub
- [ ] Complete EVTX parser
- [ ] Add OOXML support (docx/xlsx/pptx)
- [ ] Add extraction for 7z, RAR, XZ, BZ2
- [ ] Fix all `return nil, nil` patterns
- [ ] Add missing unit tests

### Phase 2: Parity with binwalk (Next Sprint)

- [ ] DD mode for raw extraction
- [ ] Recursive extraction
- [ ] Signature database expansion (100+ formats)
- [ ] Entropy block analysis
- [ ] PNG export for entropy graphs
- [ ] Quiet/verbose modes
- [ ] Progress indicators

### Phase 3: Beyond binwalk (Month 2)

- [ ] Interactive HTML reports
- [ ] PDF export
- [ ] Plugin marketplace
- [ ] Memory forensics
- [ ] Full registry analysis
- [ ] Network traffic extraction

### Phase 4: Enterprise (Month 3)

- [ ] Distributed analysis
- [ ] Cloud storage native (S3/GCS)
- [ ] Evidence chain (blockchain)
- [ ] Team collaboration
- [ ] SIEM integration
- [ ] API server mode

---

## 🎯 Competitive Advantages

### What Makes filo-go Unique

1. **Single Binary** - No dependencies, no Python, no libmagic
2. **MCP Integration** - AI-assisted analysis (unique!)
3. **Plugin System** - Community extensibility
4. **Go Performance** - 10-100x faster than Python
5. **Cross-Platform** - Windows, Linux, macOS
6. **Modern Output** - JSON, SARIF, HTML
7. **Developer Friendly** - Clean API, good docs

### Marketing Angles

```
"binwalk is 10 years old. It's time for a modern replacement."

"filo-go: binwalk for the AI era"

"Single binary. No dependencies. 100x faster."

"The forensic toolkit that talks to your AI assistant"
```

---

## 📈 Progress Tracker

### Completed ✅

- [x] Core analyzer
- [x] Entropy calculation
- [x] String extraction
- [x] Hash computation
- [x] Metadata extraction
- [x] Steganography detection
- [x] SQLite analysis
- [x] Registry analysis (basic)
- [x] PCAP analysis (basic)
- [x] EVTX analysis (basic)
- [x] MCP server (9 tools)
- [x] Plugin system
- [x] TCP reassembly
- [x] YAML format definitions (30)
- [x] SARIF export
- [x] Entropy visualization

### In Progress 🔄

- [ ] Full PCAP CLI
- [ ] OOXML support
- [ ] 7z/RAR extraction
- [ ] HTML reports

### Not Started ❌

- [ ] Memory forensics
- [ ] Cloud native
- [ ] Distributed analysis
- [ ] Plugin marketplace
- [ ] Interactive mode
- [ ] PDF export

---

## 🏆 Success Metrics

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Format support | 30 | 100+ | 🟡 |
| Test coverage | 18% | 50% | 🟡 |
| CLI commands | 28 | 35 | 🟡 |
| MCP tools | 9 | 15 | 🟡 |
| Documentation | Basic | Complete | 🔴 |
| Benchmarks | None | vs binwalk | 🔴 |
| Community | 0 | 100 stars | 🔴 |

---

## 🔧 Quick Wins (Do These First)

1. **Fix PCAP CLI** - Replace stub with real implementation
2. **Add DD mode** - Simple but useful
3. **Progress bars** - Makes batch operations usable
4. **Quiet mode** - For scripting
5. **JSON output everywhere** - Already have the infrastructure

---

## 📚 Reference: binwalk Features

```
binwalk firmware.bin          # Scan for embedded files
binwalk -e firmware.bin       # Extract embedded files  
binwalk -E firmware.bin       # Entropy analysis
binwalk -W firmware.bin       # Hex dump
binwalk -t firmware.bin       # Scan for file types
binwalk -M firmware.bin       # Recursive extraction
binwalk -R "\x89PNG" file     # Raw byte search
binwalk --dd="zip:zip" file   # Extract specific type
```

**filo-go equivalents:**
```
filo analyze firmware.bin     # Scan for embedded files
filo extract firmware.bin     # Extract embedded files
filo entropy firmware.bin     # Entropy analysis
filo strings firmware.bin     # Extract strings
filo batch ./firmware/        # Batch analysis
filo carve firmware.bin       # File carving
```

---

*This document should be updated as features are added or gaps are closed.*
