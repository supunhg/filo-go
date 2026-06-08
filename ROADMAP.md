# filo-go Strategic Roadmap

## 🎯 Vision
Make filo-go the **Go-native forensic toolkit** with **AI integration**.

---

## Phase 1: MCP Differentiation (This Week)

### 1.1 Fix MCP Server
- [ ] Add proper tool descriptions for Claude Desktop
- [ ] Fix JSON schema for tool parameters
- [ ] Add streaming support for large files
- [ ] Test with Claude Desktop app

### 1.2 Add MCP Tools
- [ ] `analyze_file` - Full forensic analysis
- [ ] `extract_strings` - String extraction with options
- [ ] `compute_hashes` - Multi-algorithm hashing
- [ ] `detect_stego` - Steganography detection
- [ ] `query_sqlite` - SQLite database queries
- [ ] `analyze_registry` - Windows Registry analysis
- [ ] `scan_sigma` - Sigma rule scanning
- [ ] `extract_metadata` - Image metadata extraction

### 1.3 MCP Documentation
- [ ] Claude Desktop integration guide
- [ ] Example prompts for forensic analysis
- [ ] Video walkthrough

---

## Phase 2: binwalk Replacement (Next Week)

### 2.1 Entropy Visualization
- [ ] ASCII art entropy graph
- [ ] Color output for terminal
- [ ] PNG export option

### 2.2 Extraction Improvements
- [ ] Recursive extraction
- [ ] Carve by file signature
- [ ] DD mode for raw extraction

### 2.3 Benchmarks
- [ ] vs binwalk (Python)
- [ ] vs file/libmagic
- [ ] vs ExifTool
- [ ] Benchmark suite with real firmware

---

## Phase 3: All-in-One Toolkit (Week 3)

### 3.1 Fix Stubs
- [ ] Office document analysis (OOXML)
- [ ] PE imports/resources
- [ ] ELF symbol extraction
- [ ] PCAP TCP reassembly

### 3.2 Integration Tests
- [ ] Test with real malware samples (safe)
- [ ] Test with CTF challenges
- [ ] Test with forensic images

### 3.3 Documentation
- [ ] README with screenshots
- [ ] CONTRIBUTING.md
- [ ] CTF writeup
- [ ] Blog post: "AI-Powered Forensics"

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| GitHub Stars | 0 | 100 |
| MCP Tools | 4 | 8+ |
| Test Coverage | 15% | 40% |
| Commands Working | 18/24 | 24/24 |
| Documentation | Minimal | Complete |
