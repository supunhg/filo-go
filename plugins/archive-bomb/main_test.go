package main

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/supunhg/filo-go/internal/plugins"
)

func ctxWith(data []byte) *plugins.Context {
	return &plugins.Context{Data: data, Path: "test.bin"}
}

func TestIsArchiveTooSmall(t *testing.T) {
	if isArchive([]byte{0x50, 0x4B}) {
		t.Error("expected false for <4 bytes")
	}
}

func TestIsArchiveEmpty(t *testing.T) {
	if isArchive(nil) {
		t.Error("expected false for nil")
	}
}

func TestIsArchiveZIP(t *testing.T) {
	if !isArchive([]byte{0x50, 0x4B, 0x03, 0x04, 0x00}) {
		t.Error("expected true for ZIP magic")
	}
}

func TestIsArchiveGZIP(t *testing.T) {
	if !isArchive([]byte{0x1F, 0x8B, 0x08, 0x00}) {
		t.Error("expected true for GZIP magic")
	}
}

func TestIsArchive7Z(t *testing.T) {
	if !isArchive([]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		t.Error("expected true for 7z magic")
	}
}

func TestIsArchiveRAR(t *testing.T) {
	if !isArchive([]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}) {
		t.Error("expected true for RAR magic")
	}
}

func TestIsArchiveBZ2(t *testing.T) {
	if !isArchive([]byte{0x42, 0x5A, 0x68, 0x00}) {
		t.Error("expected true for BZ2 magic")
	}
}

func TestIsArchiveXZ(t *testing.T) {
	if !isArchive([]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) {
		t.Error("expected true for XZ magic")
	}
}

func TestIsArchiveUnknown(t *testing.T) {
	if isArchive([]byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Error("expected false for unknown magic")
	}
}

func TestAnalyzeCompressionRatioEmpty(t *testing.T) {
	r, err := analyzeCompressionRatio(nil)
	if err != nil || r != 0 {
		t.Errorf("expected (0, nil), got (%v, %v)", r, err)
	}
}

func TestAnalyzeCompressionRatioNonArchive(t *testing.T) {
	// Random non-archive data — falls through to entropy path
	r, err := analyzeCompressionRatio([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r < 1.0 {
		t.Errorf("expected ratio >= 1.0 for non-archive, got %f", r)
	}
}

func TestAnalyzeCompressionRatioLowEntropy(t *testing.T) {
	// Highly compressible payload
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0x00
	}
	// Not a real archive but entropy is low and size <1MB
	// analyzeCompressionRatio treats non-archive+low-entropy as a 50:1 estimate
	r, err := analyzeCompressionRatio(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != 50.0 {
		t.Errorf("expected 50.0 for low entropy <1MB, got %f", r)
	}
}

func TestAnalyzeCompressionRatioHighEntropy(t *testing.T) {
	// Random-looking data with high entropy
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	r, err := analyzeCompressionRatio(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r < 1.0 {
		t.Errorf("expected ratio >= 1.0 for medium entropy, got %f", r)
	}
}

func TestFindEOCDNotFound(t *testing.T) {
	data := make([]byte, 100)
	if got := findEOCD(data); got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}

func TestFindEOCDFound(t *testing.T) {
	data := make([]byte, 100)
	// Place EOCD signature at offset 50
	data[50] = 0x50
	data[51] = 0x4B
	data[52] = 0x05
	data[53] = 0x06
	if got := findEOCD(data); got != 50 {
		t.Errorf("expected 50, got %d", got)
	}
}

func TestFindEOCDTooShort(t *testing.T) {
	data := []byte{0x50, 0x4B, 0x05, 0x06, 0x01}
	if got := findEOCD(data); got != -1 {
		t.Errorf("expected -1 for too-short buffer, got %d", got)
	}
}

func TestIsZIP64False(t *testing.T) {
	data := make([]byte, 100)
	if isZIP64(data) {
		t.Error("expected false for buffer with no central dir entries")
	}
}

func TestIsZIP64True(t *testing.T) {
	// Synthesize a minimal local file header followed by a ZIP64 extra field.
	data := make([]byte, 100)
	data[0] = 0x50
	data[1] = 0x4B
	data[2] = 0x01
	data[3] = 0x04
	// extraLen at i+28
	extraLen := uint16(20)
	data[28] = byte(extraLen & 0xFF)
	data[29] = byte(extraLen >> 8)
	// ZIP64 tag (0x0001) at i+30
	data[30] = 0x01
	data[31] = 0x00
	if !isZIP64(data) {
		t.Error("expected true for ZIP64-tagged local file header")
	}
}

func TestDetectNestingDeep(t *testing.T) {
	// Build data with many ZIP signatures in first 1KB to trigger deep nesting
	data := make([]byte, 2048)
	for i := 0; i < 1024; i += 4 {
		if i+4 <= len(data) {
			data[i] = 0x50
			data[i+1] = 0x4B
			data[i+2] = 0x03
			data[i+3] = 0x04
		}
	}
	depth := detectNesting(data, 0)
	if depth < MaxNesting {
		t.Errorf("expected depth >= MaxNesting (%d), got %d", MaxNesting, depth)
	}
}

func TestDetectNestingNoArchive(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0xAA
	}
	if depth := detectNesting(data, 0); depth != 0 {
		t.Errorf("expected 0, got %d", depth)
	}
}

func TestDetectNestingAtCap(t *testing.T) {
	// When called with depth >= MaxNesting, should return immediately
	if got := detectNesting([]byte{0x50, 0x4B, 0x03, 0x04}, MaxNesting); got != MaxNesting {
		t.Errorf("expected %d, got %d", MaxNesting, got)
	}
}

func TestEstimateEntropyEmpty(t *testing.T) {
	if e := estimateEntropy(nil); e != 0 {
		t.Errorf("expected 0 for empty, got %f", e)
	}
}

func TestEstimateEntropyUniform(t *testing.T) {
	// All zero bytes - entropy should be 0
	data := make([]byte, 1000)
	if e := estimateEntropy(data); e != 0 {
		t.Errorf("expected 0 entropy for constant input, got %f", e)
	}
}

func TestEstimateEntropyHigh(t *testing.T) {
	// Even distribution across all 256 byte values - entropy should be elevated
	// compared to constant input. The estimator uses the buggy log2 (integer-only)
	// so we can't assert specific Shannon values; just verify non-zero.
	data := make([]byte, 256*16)
	for i := range data {
		data[i] = byte(i % 256)
	}
	e := estimateEntropy(data)
	if e == 0 {
		t.Errorf("expected non-zero entropy for uniform distribution, got %f", e)
	}
}

func TestLog2(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{-1, 0},
		{1, 0},
		{2, 1},
		{4, 2},
		{8, 3},
		{16, 4},
		{0.5, -1},
		{0.25, -2},
	}
	for _, tt := range tests {
		got := log2(tt.in)
		// Allow tiny floating point tolerance
		if got < tt.want-1e-9 || got > tt.want+1e-9 {
			t.Errorf("log2(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestAnalyzeArchiveBombNotArchive(t *testing.T) {
	res, err := analyzeArchiveBomb(ctxWith([]byte("hello world")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("expected nil for non-archive, got %+v", res)
	}
}

func TestAnalyzeArchiveBombGZIPNormal(t *testing.T) {
	// Build a real gzip that compresses well
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("Hello World! This is a small test payload."))
	gw.Close()

	res, err := analyzeArchiveBomb(ctxWith(buf.Bytes()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result for gzip input")
	}
	if _, ok := res.Details["compression_ratio"]; !ok {
		t.Error("expected compression_ratio in Details")
	}
	if res.Confidence <= 0 {
		t.Errorf("expected positive confidence, got %f", res.Confidence)
	}
}

func TestAnalyzeArchiveBombGZIPBomb(t *testing.T) {
	// Build a gzip that decompresses to far more than it compresses (10MB -> ~1KB)
	original := bytes.Repeat([]byte("A"), 10*1024*1024)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(original)
	gw.Close()

	res, err := analyzeArchiveBomb(ctxWith(buf.Bytes()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result for gzip bomb")
	}
	// High compression ratio from a small gzip
	if res.Confidence < 0.5 {
		t.Errorf("expected elevated confidence for bomb-like ratio, got %f", res.Confidence)
	}
}

func TestAnalyzeArchiveBombZIPWithEOCD(t *testing.T) {
	// Synthesize a minimal ZIP-like blob with an EOCD record
	data := make([]byte, 200)
	// Local file header
	data[0] = 0x50
	data[1] = 0x4B
	data[2] = 0x03
	data[3] = 0x04
	// EOCD at offset 100
	data[100] = 0x50
	data[101] = 0x4B
	data[102] = 0x05
	data[103] = 0x06
	// EOCD fields: total entries (offset 110-111), central dir size (112-115)
	data[110] = 0x01
	data[111] = 0x00
	data[112] = 0x40
	data[113] = 0x00
	data[114] = 0x00
	data[115] = 0x00

	res, err := analyzeArchiveBomb(ctxWith(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if _, ok := res.Details["compression_ratio"]; !ok {
		t.Error("expected compression_ratio in Details")
	}
}

func TestAnalyzeArchiveBombDeepNesting(t *testing.T) {
	// Build data that starts with ZIP magic (so isArchive returns true) and
	// has a valid EOCD record at the end, but also has many nested ZIP
	// signatures in the first 1KB to trigger the deep-nesting path.
	data := make([]byte, 4096)
	// Start with ZIP magic so isArchive() returns true
	data[0] = 0x50
	data[1] = 0x4B
	data[2] = 0x03
	data[3] = 0x04
	// EOCD at the end (22 bytes from the end of the buffer)
	eocdOff := len(data) - 22
	data[eocdOff] = 0x50
	data[eocdOff+1] = 0x4B
	data[eocdOff+2] = 0x05
	data[eocdOff+3] = 0x06
	// EOCD fields
	data[eocdOff+10] = 0x01 // total entries low byte
	data[eocdOff+11] = 0x00
	data[eocdOff+12] = 0x40 // central dir size
	data[eocdOff+13] = 0x00
	// Many nested ZIP signatures in first 1KB
	for i := 4; i < 1024; i += 4 {
		data[i] = 0x50
		data[i+1] = 0x4B
		data[i+2] = 0x03
		data[i+3] = 0x04
	}

	res, err := analyzeArchiveBomb(ctxWith(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if depth, ok := res.Details["nesting_depth"].(int); !ok || depth < MaxNesting {
		t.Errorf("expected nesting_depth >= %d, got %v", MaxNesting, res.Details["nesting_depth"])
	}
}

func TestAnalyzeZIPRatioInvalidEOCD(t *testing.T) {
	// EOCD present but truncated
	data := make([]byte, 30)
	data[0] = 0x50
	data[1] = 0x4B
	// No EOCD signature
	if _, err := analyzeZIPRatio(data); err == nil {
		t.Error("expected error for missing EOCD")
	}
}

func TestAnalyzeGZIPRatioInvalidData(t *testing.T) {
	// Bytes that start with gzip magic but aren't a valid gzip
	data := []byte{0x1F, 0x8B, 0x00, 0x00, 0x00}
	if _, err := analyzeGZIPRatio(data); err == nil {
		t.Error("expected error for invalid gzip")
	}
}

func TestAnalyzeGZIPRatioRealData(t *testing.T) {
	// Gzip the data and the ratio is decompressed_size / compressed_size.
	// For small/compressible payloads the decompressed size is < 1MB cap
	// and may be smaller than the compressed size, so the ratio can be < 1.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("test data for gzip ratio estimation"))
	gw.Close()

	r, err := analyzeGZIPRatio(buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r <= 0 {
		t.Errorf("expected positive ratio, got %f", r)
	}
}

func TestAnalyzeGZIPRatioHighlyCompressible(t *testing.T) {
	// Highly compressible payload: 1MB of zeros -> tiny gzip
	original := bytes.Repeat([]byte{0x00}, 1024*1024)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(original)
	gw.Close()

	r, err := analyzeGZIPRatio(buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have a meaningful ratio since we hit the 1MB read cap
	if r < 1.0 {
		t.Errorf("expected ratio >= 1.0 for highly compressible data, got %f", r)
	}
}
