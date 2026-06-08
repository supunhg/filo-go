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
