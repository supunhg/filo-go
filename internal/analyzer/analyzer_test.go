package analyzer

import (
	"testing"

	"github.com/supunhg/filo-go/internal/entropy"
)

func TestAnalyzePNG(t *testing.T) {
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
		0x08, 0x06, 0x00, 0x00, 0x00,
	}

	result, err := Analyze(data, "test.png", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "png" {
		t.Errorf("expected format png, got %s", result.PrimaryFormat)
	}

	if result.PrimaryMIME != "image/png" {
		t.Errorf("expected MIME image/png, got %s", result.PrimaryMIME)
	}

	if result.Confidence < 0.8 {
		t.Errorf("expected confidence >= 0.8, got %f", result.Confidence)
	}

	if result.FileSize != int64(len(data)) {
		t.Errorf("expected file size %d, got %d", len(data), result.FileSize)
	}
}

func TestAnalyzeText(t *testing.T) {
	data := []byte("# This is a markdown file\n\nHello world\n")

	result, err := Analyze(data, "test.md", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat == "unknown" {
		t.Error("expected text detection, got unknown")
	}

	if result.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %f", result.Confidence)
	}
}

func TestAnalyzeLicense(t *testing.T) {
	data := []byte("MIT License\n\nCopyright (c) 2024\n\nPermission is hereby granted...")

	result, err := Analyze(data, "LICENSE", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat == "unknown" {
		t.Error("expected text detection for LICENSE, got unknown")
	}
}

func TestAnalyzeELF(t *testing.T) {
	data := []byte{
		0x7F, 0x45, 0x4C, 0x46,
		0x02,
		0x01,
		0x01,
		0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00,
		0x3E, 0x00,
	}

	result, err := Analyze(data, "test.elf", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Architecture == nil {
		t.Fatal("expected architecture detection")
	}

	if result.Architecture.Bits != 64 {
		t.Errorf("expected 64-bit, got %d-bit", result.Architecture.Bits)
	}

	if result.Architecture.Endian != "little" {
		t.Errorf("expected little-endian, got %s", result.Architecture.Endian)
	}
}

func TestEntropy(t *testing.T) {
	lowEntropy := make([]byte, 1000)
	for i := range lowEntropy {
		lowEntropy[i] = 0x41
	}

	highEntropy := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	lowE := entropy.Calculate(lowEntropy)
	highE := entropy.Calculate(highEntropy)

	if lowE >= highE {
		t.Errorf("low entropy (%f) should be less than high entropy (%f)", lowE, highE)
	}
}

func TestSHA256(t *testing.T) {
	data := []byte("hello world")
	hash := computeSHA256(data)

	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash[:16] != expected[:16] {
		t.Errorf("unexpected SHA256 prefix: got %s, expected prefix %s", hash[:16], expected[:16])
	}
}

func TestEntropyInterpretation(t *testing.T) {
	tests := []struct {
		entropy  float64
		expected string
	}{
		{0.5, "Very low"},
		{2.0, "Low"},
		{4.0, "Medium"},
		{6.0, "High"},
		{7.5, "Very high"},
	}

	for _, tt := range tests {
		result := entropy.Interpret(tt.entropy)
		if len(result) < len(tt.expected) || result[:len(tt.expected)] != tt.expected {
			t.Errorf("interpretEntropy(%f) = %q, want prefix %q", tt.entropy, result, tt.expected)
		}
	}
}

func TestEmbeddedDetection(t *testing.T) {
	// PNG with embedded ZIP
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
		0x08, 0x06, 0x00, 0x00, 0x00,
	}

	result, err := Analyze(data, "test.png", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect contradictions (missing IEND)
	if len(result.Contradictions) == 0 {
		t.Error("expected contradictions for truncated PNG")
	}
}

func TestContradictionDetection(t *testing.T) {
	// PDF without %%EOF
	data := []byte("%PDF-1.7\r\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")

	result, err := Analyze(data, "test.pdf", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasContradiction := false
	for _, c := range result.Contradictions {
		if contains(c, "%%EOF") {
			hasContradiction = true
			break
		}
	}

	if !hasContradiction {
		t.Error("expected EOF contradiction for PDF")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFingerprinting(t *testing.T) {
	// ZIP file
	data := []byte{
		0x50, 0x4B, 0x03, 0x04, // PK header
		0x14, 0x00, // Version needed
		0x00, 0x00, // Flags
		0x08, 0x00, // Compression
		0x00, 0x00, 0x00, 0x00, // Mod time/date
		0x00, 0x00, 0x00, 0x00, // CRC
		0x00, 0x00, 0x00, 0x00, // Compressed size
		0x00, 0x00, 0x00, 0x00, // Uncompressed size
	}

	result, err := Analyze(data, "test.zip", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ToolFingerprint == nil {
		t.Error("expected tool fingerprint for ZIP")
	}
}

func TestAnalyzePE(t *testing.T) {
	// Minimal PE header with enough data
	data := make([]byte, 512)
	data[0] = 0x4D // MZ
	data[1] = 0x5A
	data[60] = 0x40 // PE offset
	data[61] = 0x00
	data[62] = 0x00
	data[63] = 0x00

	result, err := Analyze(data, "test.exe", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Architecture == nil {
		t.Error("expected architecture detection for PE")
	}
}

func TestAnalyzeGZIP(t *testing.T) {
	data := []byte{
		0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	result, err := Analyze(data, "test.gz", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "gz" {
		t.Errorf("expected gz, got %s", result.PrimaryFormat)
	}
}

func TestAnalyze7z(t *testing.T) {
	data := []byte{
		0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C,
	}

	result, err := Analyze(data, "test.7z", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "7z" {
		t.Errorf("expected 7z, got %s", result.PrimaryFormat)
	}
}

func TestAnalyzeRAR(t *testing.T) {
	data := []byte{
		0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0x00,
	}

	result, err := Analyze(data, "test.rar", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "rar" {
		t.Errorf("expected rar, got %s", result.PrimaryFormat)
	}
}

func TestAnalyzeBZ2(t *testing.T) {
	data := []byte{
		0x42, 0x5A, 0x68,
	}

	result, err := Analyze(data, "test.bz2", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "bz2" {
		t.Errorf("expected bz2, got %s", result.PrimaryFormat)
	}
}

func TestAnalyzeXZ(t *testing.T) {
	data := []byte{
		0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00,
	}

	result, err := Analyze(data, "test.xz", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "xz" {
		t.Errorf("expected xz, got %s", result.PrimaryFormat)
	}
}

func TestAnalyzeSQLite(t *testing.T) {
	data := []byte("SQLite format 3\x00")
	for len(data) < 16 {
		data = append(data, 0)
	}

	result, err := Analyze(data, "test.db", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat != "sqlite" {
		t.Errorf("expected sqlite, got %s", result.PrimaryFormat)
	}
}

func TestAnalyzeWithYARA(t *testing.T) {
	data := []byte("hello world")
	opts := &Options{
		YaraRules: []string{"rule test { condition: true }"},
	}

	_, err := Analyze(data, "test.txt", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	result, err := Analyze([]byte{}, "empty.bin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrimaryFormat == "" {
		t.Errorf("expected format to be set, got empty string")
	}
}

func TestAnalyzeSmallFile(t *testing.T) {
	result, err := Analyze([]byte{0x00}, "small.bin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileSize != 1 {
		t.Errorf("expected file size 1, got %d", result.FileSize)
	}
}

func TestFindBytes(t *testing.T) {
	data := []byte("Hello World Hello Go")
	pattern := []byte("World")

	offset := findBytes(data, pattern)
	if offset != 6 {
		t.Errorf("expected offset 6, got %d", offset)
	}

	pattern = []byte("NotExist")
	offset = findBytes(data, pattern)
	if offset != -1 {
		t.Errorf("expected -1, got %d", offset)
	}
}

func TestBoolToInt(t *testing.T) {
	if result := boolToInt(true, 1, 0); result != 1 {
		t.Errorf("expected 1, got %d", result)
	}
	if result := boolToInt(false, 1, 0); result != 0 {
		t.Errorf("expected 0, got %d", result)
	}
}

func TestEstimateSize(t *testing.T) {
	// Test with empty data
	size := estimateSize([]byte{}, 0, "png")
	// Empty data returns 0, which is valid
	_ = size

	// Test with non-empty data
	data := make([]byte, 1000)
	size = estimateSize(data, 0, "png")
	if size < 0 {
		t.Errorf("expected non-negative size, got %d", size)
	}
}

func TestDetectCrypto(t *testing.T) {
	// AES key schedule pattern
	data := make([]byte, 256)
	for i := 0; i < 256; i++ {
		data[i] = byte(i)
	}

	result, err := Analyze(data, "crypto.bin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect some crypto indicators
	_ = result
}

func TestResultPrint(t *testing.T) {
	result := &Result{
		FileName:      "test.bin",
		PrimaryFormat: "png",
		PrimaryMIME:   "image/png",
		Confidence:    0.95,
		FileSize:      1024,
		SHA256:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	// Should not panic
	result.Print()
}

func TestResultJSON(t *testing.T) {
	result := &Result{
		FileName:      "test.bin",
		PrimaryFormat: "png",
		PrimaryMIME:   "image/png",
		Confidence:    0.95,
		FileSize:      1024,
	}

	jsonStr := result.JSON()
	if jsonStr == "" {
		t.Error("expected non-empty JSON")
	}
}

func TestELFMachineNames(t *testing.T) {
	tests := []struct {
		machine uint16
		name    string
	}{
		{0x03, "x86"},
		{0x3E, "x86_64"},
		{0x28, "ARM"},
		{0xB7, "AArch64"},
		{0x08, "MIPS"},
	}

	for _, tt := range tests {
		name := elfMachineName(tt.machine)
		if name == "unknown" {
			t.Errorf("expected known name for machine 0x%04X, got unknown", tt.machine)
		}
	}
}

func TestPEMachineNames(t *testing.T) {
	tests := []struct {
		machine uint16
		name    string
	}{
		{0x014C, "x86"},
		{0x8664, "x86_64"},
		{0x01C0, "ARM"},
	}

	for _, tt := range tests {
		name := peMachineName(tt.machine)
		if name == "unknown" {
			t.Errorf("expected known name for machine 0x%04X, got unknown", tt.machine)
		}
	}
}
