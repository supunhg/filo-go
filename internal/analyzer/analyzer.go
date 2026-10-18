package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/supunhg/filo-go/internal/crypto"
	"github.com/supunhg/filo-go/internal/signature"

	"github.com/gabriel-vasile/mimetype"
	"github.com/h2non/filetype"

	"github.com/supunhg/filo-go/internal/entropy"
	"github.com/supunhg/filo-go/internal/formats"
	"github.com/supunhg/filo-go/internal/term"
)

// Options controls analysis behavior.
type Options struct {
	// DeepScan, NoML and YaraRules are accepted for API compatibility but
	// currently have no effect on Analyze.
	DeepScan bool
	NoML     bool
	// AllEvidence is reserved for future use.
	AllEvidence bool
	// AllEmbedded also reports signatures found inside other embedded files.
	AllEmbedded bool
	ExplainMode bool
	EntropyViz  bool
	YaraRules   []string
	FormatsDir  string
}

// Result holds the full analysis output.
type Result struct {
	FilePath           string           `json:"file_path"`
	FileName           string           `json:"file_name"`
	FileSize           int64            `json:"file_size"`
	SHA256             string           `json:"sha256"`
	Entropy            float64          `json:"entropy"`
	EntropyLabel       string           `json:"entropy_label"`
	PrimaryFormat      string           `json:"primary_format"`
	PrimaryMIME        string           `json:"primary_mime"`
	Description        string           `json:"description,omitempty"`
	Confidence         float64          `json:"confidence"`
	AlternativeFormats []Alternative    `json:"alternative_formats,omitempty"`
	Evidence           []Evidence       `json:"evidence,omitempty"`
	EmbeddedObjects    []EmbeddedObject `json:"embedded_objects,omitempty"`
	Contradictions     []string         `json:"contradictions,omitempty"`
	Architecture       *ArchInfo        `json:"architecture,omitempty"`
	CryptoIndicators   *CryptoInfo      `json:"crypto_indicators,omitempty"`
	ToolFingerprint    *FingerprintInfo `json:"tool_fingerprint,omitempty"`
	Polyglots          []PolyglotInfo   `json:"polyglots,omitempty"`
	YARAMatches        []YARAMatch      `json:"yara_matches,omitempty"`
	EntropyChunks      []EntropyChunk   `json:"entropy_chunks,omitempty"`
}

// Alternative represents another possible format.
type Alternative struct {
	Format     string  `json:"format"`
	MIME       string  `json:"mime"`
	Confidence float64 `json:"confidence"`
}

// Evidence represents a single detection signal.
type Evidence struct {
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Details    string  `json:"details"`
}

// EmbeddedObject is a file found inside another file.
type EmbeddedObject struct {
	Offset      int64   `json:"offset"`
	Format      string  `json:"format"`
	Description string  `json:"description,omitempty"`
	Confidence  float64 `json:"confidence"`
	// Size is 0 when the embedded format does not record its length.
	Size int64 `json:"size,omitempty"`
}

// ArchInfo holds CPU architecture details.
type ArchInfo struct {
	Bits    int    `json:"bits"`
	Endian  string `json:"endian"`
	Machine string `json:"machine"`
	Format  string `json:"format"`
}

// CryptoInfo holds encryption detection results. See the crypto package for
// what each field means and why ciphers cannot be named from bytes alone.
type CryptoInfo struct {
	Detected     bool     `json:"detected"`
	Confidence   float64  `json:"confidence"`
	Verdict      string   `json:"verdict,omitempty"`
	ChiSquare    float64  `json:"chi_square,omitempty"`
	Container    string   `json:"container,omitempty"`
	Details      []string `json:"details,omitempty"`
	ECBSuspected bool     `json:"ecb_suspected,omitempty"`
}

// FingerprintInfo holds tool creation info.
type FingerprintInfo struct {
	Producer string `json:"producer,omitempty"`
	OS       string `json:"os,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Date     string `json:"date,omitempty"`
}

// PolyglotInfo describes a dual-format file.
type PolyglotInfo struct {
	Format1 string  `json:"format1"`
	Format2 string  `json:"format2"`
	Risk    string  `json:"risk"`
	Score   float64 `json:"score"`
}

// YARAMatch is a YARA rule hit.
type YARAMatch struct {
	Rule      string            `json:"rule"`
	Tags      []string          `json:"tags,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	Strings   []string          `json:"strings,omitempty"`
	Namespace string            `json:"namespace"`
}

// EntropyChunk is a segment for entropy visualization.
type EntropyChunk = entropy.Chunk

// Analyze performs full file analysis.
func Analyze(data []byte, filePath string, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{}
	}

	fileName := filepath.Base(filePath)
	result := &Result{
		FilePath: filePath,
		FileName: fileName,
		FileSize: int64(len(data)),
	}

	result.SHA256 = computeSHA256(data)
	result.Entropy = entropy.Calculate(data)
	result.EntropyLabel = entropy.Interpret(result.Entropy)

	if opts.EntropyViz {
		result.EntropyChunks = entropy.Chunks(data, 256)
	}

	detectFileType(data, result, opts)
	detectEmbeddedObjects(data, result, opts)
	detectContradictions(data, result)
	detectArchitecture(data, result)
	detectCrypto(data, result)
	detectPolyglots(data, result)
	fingerprintTool(data, result)

	if opts.ExplainMode {
		result.Evidence = append(result.Evidence, Evidence{
			Source:     "entropy_analysis",
			Confidence: result.Confidence,
			Details:    fmt.Sprintf("Entropy: %.2f bits/byte (%s)", result.Entropy, result.EntropyLabel),
		})
	}

	return result, nil
}

// detectFileType identifies the file format using multiple strategies.
func detectFileType(data []byte, r *Result, opts *Options) {
	// Strategy 1: validated signatures (magic bytes plus a structural check)
	if m, ok := signature.Identify(data); ok {
		r.PrimaryFormat = m.Format
		r.PrimaryMIME = m.MIME
		r.Description = m.Description
		r.Confidence = 0.95
		r.Evidence = append(r.Evidence, Evidence{
			Source:     "signature",
			Confidence: 0.95,
			Details:    "Validated header: " + m.Description,
		})
		return
	}

	// Strategy 2: h2non/filetype (magic bytes only)
	kind, _ := filetype.Match(data)
	if kind.MIME.Value != "" {
		r.PrimaryFormat = kind.Extension
		r.PrimaryMIME = kind.MIME.Value
		r.Confidence = 0.9
		r.Evidence = append(r.Evidence, Evidence{
			Source:     "magic_bytes",
			Confidence: 0.9,
			Details:    fmt.Sprintf("Magic byte signature match: %s (%s)", kind.Extension, kind.MIME.Value),
		})
		return
	}

	// Strategy 3: YAML format database (signature matching)
	if opts != nil && opts.FormatsDir != "" {
		if db, err := loadFormats(opts.FormatsDir); err == nil {
			results := db.Match(data)
			if len(results) > 0 {
				best := results[0]
				r.PrimaryFormat = best.Format.Format
				if len(best.Format.MIME) > 0 {
					r.PrimaryMIME = best.Format.MIME[0]
				}
				r.Confidence = best.Confidence
				r.Evidence = append(r.Evidence, Evidence{
					Source:     "yaml_signatures",
					Confidence: best.Confidence,
					Details:    fmt.Sprintf("YAML signature match: %s (%s)", best.Format.Format, strings.Join(best.MatchedSigs, ", ")),
				})
				return
			}
		}
	}

	// Strategy 4: mimetype (content-aware, good for text)
	mime := mimetype.Detect(data)
	if mime != nil && mime.String() != "application/octet-stream" {
		ext := mime.Extension()
		if ext != "" {
			ext = strings.TrimPrefix(ext, ".")
		}
		r.PrimaryFormat = ext
		r.PrimaryMIME = mime.String()
		r.Confidence = 0.85
		r.Evidence = append(r.Evidence, Evidence{
			Source:     "content_detection",
			Confidence: 0.85,
			Details:    fmt.Sprintf("Content-based detection: %s (%s)", ext, mime.String()),
		})
		return
	}

	// Fallback: unknown
	r.PrimaryFormat = "unknown"
	r.PrimaryMIME = "application/octet-stream"
	r.Confidence = 0.0
}

// detectEmbeddedObjects finds files hidden inside the data, skipping the
// file's own header at offset 0.
func detectEmbeddedObjects(data []byte, r *Result, opts *Options) {
	matches := signature.Scan(data, signature.Options{IncludeNested: opts.AllEmbedded, Limit: maxEmbedded + 1})
	for _, m := range matches {
		if m.Offset == 0 {
			continue
		}
		if len(r.EmbeddedObjects) == maxEmbedded {
			break
		}
		r.EmbeddedObjects = append(r.EmbeddedObjects, EmbeddedObject{
			Offset:      m.Offset,
			Format:      m.Format,
			Description: m.Description,
			Confidence:  0.9,
			Size:        m.Size,
		})
	}
}

// maxEmbedded caps how many embedded objects Analyze reports. The scan
// command lists every match.
const maxEmbedded = 256

// detectContradictions reports structural problems with the file's own
// format: truncation, missing trailers and data appended after the end.
func detectContradictions(data []byte, r *Result) {
	m, ok := signature.Identify(data)
	if !ok {
		return
	}
	d := m.Description
	switch {
	case strings.Contains(d, "truncated"):
		r.Contradictions = append(r.Contradictions, fmt.Sprintf("%s is truncated: the end-of-file marker is missing", strings.ToUpper(m.Format)))
	case strings.Contains(d, "missing %%EOF"):
		r.Contradictions = append(r.Contradictions, "PDF is missing its %%EOF marker")
	case strings.Contains(d, "no central directory"):
		r.Contradictions = append(r.Contradictions, "ZIP has no End of Central Directory record (truncated or damaged)")
	case strings.Contains(d, "bad IHDR CRC"):
		r.Contradictions = append(r.Contradictions, "PNG header checksum does not match")
	}
	if m.Size > 0 && m.Size < int64(len(data)) {
		extra := int64(len(data)) - m.Size
		r.Contradictions = append(r.Contradictions, fmt.Sprintf("%d byte(s) appended after the end of the %s data at offset 0x%X", extra, strings.ToUpper(m.Format), m.Size))
	}
}

// detectArchitecture detects CPU architecture for executables.
func detectArchitecture(data []byte, r *Result) {
	if len(data) < 20 {
		return
	}

	// ELF
	if data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46 {
		class := data[4]
		dataEnc := data[5]
		machine := uint16(data[18]) | uint16(data[19])<<8

		bits := 32
		if class == 2 {
			bits = 64
		}
		endian := "little"
		if dataEnc == 2 {
			endian = "big"
		}
		machineName := elfMachineName(machine)

		r.Architecture = &ArchInfo{
			Bits:    bits,
			Endian:  endian,
			Machine: machineName,
			Format:  "ELF",
		}
		return
	}

	// PE
	if data[0] == 0x4D && data[1] == 0x5A {
		peOffset := int64(data[0x3C]) | int64(data[0x3D])<<8 | int64(data[0x3E])<<16 | int64(data[0x3F])<<24
		if peOffset+24 < int64(len(data)) {
			machine := uint16(data[peOffset+4]) | uint16(data[peOffset+5])<<8
			bits := 32
			if machine == 0x8664 || machine == 0xAA64 {
				bits = 64
			}
			r.Architecture = &ArchInfo{
				Bits:    bits,
				Endian:  "little",
				Machine: peMachineName(machine),
				Format:  "PE",
			}
		}
		return
	}

	// Mach-O
	if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA) ||
		(data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED) ||
		(data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED) ||
		(data[0] == 0xBE && data[1] == 0xBA && data[2] == 0xFE) {
		is64 := data[0] == 0xCF || data[0] == 0xBE
		endian := "big"
		if data[0] == 0xFE || data[0] == 0xCF {
			endian = "little"
		}
		r.Architecture = &ArchInfo{
			Bits:   boolToInt(is64, 64, 32),
			Endian: endian,
			Format: "Mach-O",
		}
	}
}

// detectCrypto reports encryption containers, and randomness for files whose
// format could not be identified (a recognised format is not encrypted as a
// whole, even when parts of it have high entropy).
func detectCrypto(data []byte, r *Result) {
	c := crypto.Analyze(data)
	if c.Container == "" && (r.PrimaryFormat != "unknown" || !c.Detected) {
		return
	}
	r.CryptoIndicators = &CryptoInfo{
		Detected:     c.Detected,
		Confidence:   c.Confidence,
		Verdict:      string(c.Verdict),
		ChiSquare:    c.ChiSquare,
		Container:    c.Container,
		Details:      c.Details,
		ECBSuspected: c.ECBSuspected,
	}
}

// detectPolyglots finds dual-format files.
func detectPolyglots(data []byte, r *Result) {
	if len(data) < 16 {
		return
	}

	patterns := []struct {
		magic1 []byte
		magic2 []byte
		name1  string
		name2  string
		risk   string
	}{
		{
			[]byte{0x47, 0x49, 0x46, 0x38},
			[]byte{0x50, 0x4B, 0x03, 0x04},
			"GIF", "ZIP", "MEDIUM",
		},
		{
			[]byte{0x89, 0x50, 0x4E, 0x47},
			[]byte{0x50, 0x4B, 0x03, 0x04},
			"PNG", "ZIP", "MEDIUM",
		},
		{
			[]byte{0x25, 0x50, 0x44, 0x46},
			[]byte{0x2F, 0x4A, 0x61, 0x76},
			"PDF", "JavaScript", "HIGH",
		},
	}

	for _, p := range patterns {
		if bytes.HasPrefix(data, p.magic1) {
			idx := findBytes(data[1:], p.magic2)
			if idx >= 0 {
				r.Polyglots = append(r.Polyglots, PolyglotInfo{
					Format1: p.name1,
					Format2: p.name2,
					Risk:    p.risk,
					Score:   0.85,
				})
			}
		}
	}
}

// fingerprintTool identifies creation tool.
func fingerprintTool(data []byte, r *Result) {
	if len(data) < 4 {
		return
	}

	// ZIP fingerprinting
	if data[0] == 0x50 && data[1] == 0x4B {
		madeBy := uint16(data[4]) | uint16(data[5])<<8
		osType := madeBy >> 8
		toolHint := ""
		switch osType {
		case 0:
			toolHint = "FAT/DOS"
		case 3:
			toolHint = "Unix"
		case 7:
			toolHint = "Macintosh"
		case 10:
			toolHint = "NTFS"
		default:
			toolHint = fmt.Sprintf("OS code %d", osType)
		}
		r.ToolFingerprint = &FingerprintInfo{
			OS:       toolHint,
			Producer: "ZIP archive",
		}
	}

	// PDF fingerprinting
	if data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46 {
		producers := []string{"Adobe", "Microsoft", "LibreOffice", "iText", "FPDF", "wkhtmltopdf", "Chromium"}
		for _, p := range producers {
			idx := strings.Index(string(data), p)
			if idx >= 0 {
				r.ToolFingerprint = &FingerprintInfo{
					Producer: p,
				}
				break
			}
		}
	}
}

// --- Utility Functions ---

func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

var (
	formatsMu    sync.Mutex
	formatsCache = map[string]*formats.Database{}
)

// loadFormats parses a YAML format directory once per process.
func loadFormats(dir string) (*formats.Database, error) {
	formatsMu.Lock()
	defer formatsMu.Unlock()
	if db, ok := formatsCache[dir]; ok {
		return db, nil
	}
	db, err := formats.NewDatabase(dir)
	if err != nil {
		return nil, err
	}
	formatsCache[dir] = db
	return db, nil
}

func findBytes(data, pattern []byte) int {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j, b := range pattern {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func boolToInt(b bool, trueVal, falseVal int) int {
	if b {
		return trueVal
	}
	return falseVal
}

func elfMachineName(machine uint16) string {
	names := map[uint16]string{
		0x01: "AT&T WE 32100", 0x02: "SPARC", 0x03: "x86", 0x04: "Motorola 68000",
		0x05: "Motorola 88000", 0x06: "Intel MCU", 0x07: "Intel 80860", 0x08: "MIPS R3000",
		0x09: "IBM System/370", 0x0A: "MIPS R3000 LE", 0x14: "PowerPC", 0x15: "PowerPC 64-bit",
		0x16: "IBM S390", 0x17: "IBM S390 (old)", 0x24: "NEC V800", 0x25: "Fujitsu FR20",
		0x26: "TRW Ruby", 0x27: "Hannoni Parallel", 0x28: "SuperH", 0x29: "SPARC9",
		0x2A: "STMicroelectronics", 0x2B: "Toyota RC/processor", 0x2C: "STMicroelectronics ST100",
		0x2D: "Advanced Logic Corp", 0x2E: "Alpha (old)", 0x30: "Panasonic Mips", 0x31: "NEC v30",
		0x32: "Broadcom VideoCore", 0x33: "Tensilica Xtensa", 0x36: "nMOS 16-bit", 0x37: "Sony DSP",
		0x39: "Siemens PCM", 0x3C: "MIPS R10000 LE", 0x40: "Arm AArch64", 0x41: "ARM 32-bit",
		0x42: "SHARC", 0x44: "Renesas/Hitachi H8/300", 0x45: "Renesas/Hitachi H8/300H",
		0x46: "Renesas H8S", 0x47: "Renesas H8/500", 0x48: "MIPS R2000 BE", 0x49: "MIPS R2000 LE",
		0x4A: "MIPS R3000 BE", 0x4B: "MIPS R3000 LE", 0x50: "Motorola PowerPC",
		0x51: "PowerPC 64-bit LE", 0x52: "IBM 9076", 0x53: "IBM RS/6000 PPC", 0x54: "RSVd",
		0x55: "LSI Logic DSP", 0x56: "Fujitsu F2MC16", 0x57: "Texas Instruments C6000 DSP",
		0x58: "Digital Equipment Corp", 0x5A: "Hitachi DSP", 0x5B: "Renencas/Hitachi H8/300",
		0x5C: "Renencas/Hitachi H8/300H", 0x5D: "Renencas H8S", 0x5E: "Renencas H8/500",
		0x60: "Infinifox", 0x61: "Alpha AXP", 0x62: "Infinifox (old)", 0x63: "Panasonic M16",
		0x64: "NEC x86-64", 0x65: "Panasonic A10", 0x66: "STMicroelectronics ST19",
		0x67: "Digital VAX", 0x68: "Axis Communications", 0x69: "Infineon Technologies",
		0x6A: "Element 14 64-bit DSP", 0x6B: "LSI Logic 16-bit", 0x6C: "TMS320C6000",
		0x6D: "NMips", 0x6E: "Motorola DSP56XXX", 0x6F: "Freescale DSP56XXX", 0x70: "Star MC",
		0x71: "AMD x86-64", 0x72: "Sony PSP", 0x73: "Panasonic MN10300", 0x74: "Matsushita MN10200",
		0x75: "ARM NDS / RISC-V", 0x76: "AMDGPU", 0x77: "ARMv8-M", 0x78: "SPARC V9",
		0x79: "Siemens TriCore", 0x7A: "Renesas/Argonaut RISC", 0x7B: "HG/Tech RISC",
		0x7C: "S390 (old)", 0x7D: "IBM Moirai", 0x7E: "H8/300H (old)", 0x7F: "ARM 64-bit LE",
		0x80: "STMicroelectronics ST200", 0x81: "MicroBlaze", 0x82: "CUDA", 0x83: "AMDGPU",
		0x84: "Kalimba", 0x85: "40-bit c4x", 0x86: "Digital CNV", 0x87: "OpenRISC 1000",
		0x88: "Renesas/Altos H8/300", 0x89: "Altera Nios II", 0x8A: "Crazyhorse ARMv7",
		0x8B: "NMips (old)", 0x8C: "Motorola MCore", 0x8D: "Renesas H8/300H", 0x8E: "ARMv7-M",
		0x8F: "RISC-V", 0x90: "Lanai", 0x91: "Linux ABI", 0x92: "Tilera TILE64",
		0x93: "Tilera TILEPro", 0x94: "NVIDIA CUDA", 0x95: "Tilera TILE-Gx", 0x96: "CloudFlare NF",
		0x97: "Microchip AVR", 0x98: "Fujitsu FR-V", 0x99: "Qualcomm Hexagon", 0x9A: "Motorola 860",
		0x9B: "Samsung S390x", 0x9C: "STMicroelectronics ST100", 0x9D: "RISC-V 64-bit",
		0x9E: "WDC x4", 0x9F: "RISC-V 32-bit", 0xA0: "RISC-V 128-bit", 0xA1: "MIPS R6",
		0xA2: "Motorola ColdFire", 0xA3: "MCore", 0xA4: "Renesas M32R", 0xA5: "Renesas MN10300",
		0xA6: "Matsushita MN10200", 0xA7: "PicoJava", 0xA8: "OpenRISC 32-bit", 0xA9: "ARMv7-R",
		0xAA: "ARMv7-M", 0xAB: "S12Z", 0xAC: "PowerPC LE", 0xAD: "STMicroelectronics ST20",
		0xAE: "NDS32", 0xAF: "eBPF", 0xB0: "ARC (Argonaut RISC)", 0xB1: "H8/300H",
		0xB2: "SPARC V9 (LE)", 0xB3: "TILEPro64", 0xB4: "MIPS16", 0xB5: "Fujitsu FR60",
		0xB6: "TILE-Gx 64", 0xB7: "TILE64", 0xB8: "PowerPC SPE", 0xB9: "MIPS R3000",
		0xBA: "AMDGPU", 0xBB: "SPARC64", 0xBC: "MIPS R10000", 0xBD: "Motorola 68HC12",
		0xBE: "Motorola M68HC11", 0xBF: "ARMv7-M (old)", 0xC0: "STMicroelectronics ST19",
		0xC1: "PowerPC 64", 0xC2: "MIPS R5900", 0xC3: "MIPS R12000", 0xC4: "Motorola XC6888",
		0xC5: "ARMv7-A LE", 0xC6: "ARMv7-A BE", 0xC7: "MIPS R14000", 0xC8: "MIPS R8000",
		0xC9: "Motorola RCE", 0xCA: "NEC V850", 0xCB: "MIPS R3000 LE", 0xCC: "MIPS R10000 BE",
		0xCD: "NEC V850x", 0xCE: "Fujitsu FR20", 0xCF: "FR-V", 0xD0: "SPARC V8",
		0xD1: "Renesas/NEC v850", 0xD2: "Renesas v850x", 0xD3: "Renesas v850x2",
		0xD4: "Renesas H8/500", 0xD5: "Renesas H8/300H", 0xD6: "Renesas H8S", 0xD7: "Renesas H8/300",
		0xD8: "PowerPC LE", 0xD9: "PowerPC 64 LE", 0xDA: "Renesas/NEC v850", 0xDB: "NEC STK2000",
		0xDC: "Renesas M32C", 0xDD: "Renesas M16C", 0xDE: "Renesas M32C (old)", 0xDF: "Renesas M32R",
		0xE0: "Renesas M16C (old)", 0xE1: "Renesas M32C (old)", 0xE2: "SPARC M8",
		0xE3: "RISC-V (old)", 0xE4: "RISC-V (old)", 0xE5: "MIPS R16000", 0xE6: "AMDGPU",
		0xE7: "Renesas R8C", 0xE8: "SPARC M9", 0xE9: "Renesas R32C", 0xEA: "Renesas H8/300H (old)",
		0xEB: "Renesas H8S (old)", 0xEC: "Renesas H8/500 (old)", 0xED: "Renesas H8/300 (old)",
		0xEE: "Renesas v850 (old)", 0xEF: "Renesas v850x (old)", 0xF0: "Renesas v850x2 (old)",
		0xF1: "Renesas M32C (old)", 0xF2: "Renesas M16C (old)", 0xF3: "Renesas M32R (old)",
		0xF4: "Renesas M32C (old)", 0xF5: "Renesas M16C (old)", 0xF6: "Renesas M32C (old)",
		0xF7: "Renesas M16C (old)", 0xF8: "Renesas M32C (old)", 0xF9: "Renesas M16C (old)",
		0xFA: "Renesas M32C (old)", 0xFB: "Renesas M16C (old)", 0xFC: "Renesas M32C (old)",
		0xFD: "Renesas M16C (old)", 0xFE: "Renesas M32C (old)", 0xFF: "Renesas M16C (old)",
	}
	if name, ok := names[machine]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", machine)
}

func peMachineName(machine uint16) string {
	names := map[uint16]string{
		0x014C: "x86", 0x0200: "Intel Itanium (IA-64)", 0x8664: "x86-64",
		0x01C0: "ARM (Thumb-2)", 0x01C4: "ARM Little-Endian", 0xAA64: "ARM64 (AArch64)",
		0x0EBC: "EFI Byte Code", 0x9041: "Mitsubishi M32R Little-Endian", 0x0266: "MIPS16",
		0x0366: "MIPS FPU", 0x0466: "MIPS16 FPU", 0x01F0: "PowerPC Little-Endian",
		0x01F1: "PowerPC with floating point support", 0x0166: "MIPS R4000 Little-Endian",
		0x01A2: "Hitachi SH3", 0x01A3: "Hitachi SH3 DSP", 0x01A6: "Hitachi SH4",
		0x01A8: "Hitachi SH5", 0x01C2: "ARM or Thumb (interworking)", 0x01D3: "Matsushita AM33",
		0x01F2: "PowerPC with floating point support", 0x0284: "Digital Alpha AXP",
	}
	if name, ok := names[machine]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", machine)
}

// --- Print Methods ---

func (r *Result) Print() {
	fmt.Println()
	fmt.Printf("  %s%sFile Analysis:%s %s\n", term.C(term.Bold), term.C(term.Cyan), term.C(term.Reset), r.FileName)
	fmt.Println()
	fmt.Printf("  %sDetected Format:%s %s%s%s\n", term.C(term.Bold), term.C(term.Reset), term.C(term.Green), r.PrimaryFormat, term.C(term.Reset))
	if r.Description != "" {
		fmt.Printf("  %sDescription:%s %s\n", term.C(term.Bold), term.C(term.Reset), r.Description)
	}
	fmt.Printf("  %sMIME Type:%s %s\n", term.C(term.Bold), term.C(term.Reset), r.PrimaryMIME)
	fmt.Printf("  %sConfidence:%s %.1f%%\n", term.C(term.Bold), term.C(term.Reset), r.Confidence*100)
	fmt.Println()
	fmt.Printf("  %sFile Size:%s %d bytes\n", term.C(term.Bold), term.C(term.Reset), r.FileSize)
	fmt.Printf("  %sSHA256:%s %s\n", term.C(term.Bold), term.C(term.Reset), r.SHA256)
	fmt.Printf("  %sEntropy:%s %s\n", term.C(term.Bold), term.C(term.Reset), entropy.Bar(r.Entropy, 40))
	fmt.Println()

	if len(r.Evidence) > 0 {
		fmt.Printf("  %sDetection Evidence:%s\n", term.C(term.Bold), term.C(term.Reset))
		for _, e := range r.Evidence {
			fmt.Printf("    %s%s%s (confidence: %.1f%%)%s\n", term.C(term.Magenta), e.Source, term.C(term.Reset), e.Confidence*100, term.C(term.Reset))
			fmt.Printf("      %s\n", e.Details)
		}
		fmt.Println()
	}

	if r.Architecture != nil {
		fmt.Printf("  %sCPU Architecture:%s\n", term.C(term.Bold), term.C(term.Reset))
		fmt.Printf("    %s%s%s (%d-bit, %s-endian)\n", term.C(term.Blue), r.Architecture.Machine, term.C(term.Reset), r.Architecture.Bits, r.Architecture.Endian)
		fmt.Printf("    Format: %s\n", r.Architecture.Format)
		fmt.Println()
	}

	if c := r.CryptoIndicators; c != nil && c.Detected {
		fmt.Printf("  %sEncryption:%s\n", term.C(term.Bold), term.C(term.Reset))
		if c.Container != "" {
			fmt.Printf("    %s%s%s\n", term.C(term.Yellow), c.Container, term.C(term.Reset))
			for _, d := range c.Details {
				fmt.Printf("      %s\n", d)
			}
		} else {
			fmt.Printf("    %sContent is statistically random%s (chi-square %.1f): encrypted, random or strongly compressed\n", term.C(term.Yellow), term.C(term.Reset), c.ChiSquare)
		}
		if c.ECBSuspected {
			fmt.Printf("    %sRepeated 16-byte blocks suggest ECB-mode encryption%s\n", term.C(term.Red), term.C(term.Reset))
		}
		fmt.Println()
	}

	if len(r.Contradictions) > 0 {
		fmt.Printf("  %sStructural issues:%s\n", term.C(term.Bold), term.C(term.Reset))
		for _, c := range r.Contradictions {
			fmt.Printf("    %s⚠  %s%s\n", term.C(term.Red), c, term.C(term.Reset))
		}
		fmt.Println()
	}

	if len(r.EmbeddedObjects) > 0 {
		fmt.Printf("  %sEmbedded Objects:%s\n", term.C(term.Bold), term.C(term.Reset))
		for _, e := range r.EmbeddedObjects {
			size := "size unknown"
			if e.Size > 0 {
				size = fmt.Sprintf("%d bytes", e.Size)
			}
			fmt.Printf("    0x%08X  %s%s%s  %s (%s)\n", e.Offset, term.C(term.Magenta), e.Format, term.C(term.Reset), e.Description, size)
		}
		fmt.Println()
	}

	if r.ToolFingerprint != nil {
		fmt.Printf("  %sTool Fingerprint:%s\n", term.C(term.Bold), term.C(term.Reset))
		if r.ToolFingerprint.Producer != "" {
			fmt.Printf("    Producer: %s\n", r.ToolFingerprint.Producer)
		}
		if r.ToolFingerprint.OS != "" {
			fmt.Printf("    OS: %s\n", r.ToolFingerprint.OS)
		}
		if r.ToolFingerprint.Tool != "" {
			fmt.Printf("    Tool: %s\n", r.ToolFingerprint.Tool)
		}
		fmt.Println()
	}
}

// JSON returns the full analysis result as JSON.
func (r *Result) JSON() string {
	data, err := json.Marshal(r)
	if err != nil {
		// Fallback to minimal JSON on error
		return fmt.Sprintf(`{"file_path":"%s","file_name":"%s","error":"json marshal failed"}`,
			r.FilePath, r.FileName)
	}
	return string(data)
}
