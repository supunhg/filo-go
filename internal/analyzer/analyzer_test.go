package analyzer

import (
	"testing"
)

func TestAnalyzePNG(t *testing.T) {
	// Minimal PNG header
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, // 16x16
		0x08, 0x06, 0x00, 0x00, 0x00, // 8-bit RGBA
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
		0x7F, 0x45, 0x4C, 0x46, // ELF magic
		0x02,       // 64-bit
		0x01,       // Little-endian
		0x01,       // ELF version 1
		0x00,       // System V ABI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
		0x02, 0x00, // ET_EXEC
		0x3E, 0x00, // x86-64
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
	// Low entropy (repeated bytes)
	lowEntropy := make([]byte, 1000)
	for i := range lowEntropy {
		lowEntropy[i] = 0x41
	}

	// High entropy (random bytes)
	highEntropy := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	lowE := computeEntropy(lowEntropy)
	highE := computeEntropy(highEntropy)

	if lowE >= highE {
		t.Errorf("low entropy (%f) should be less than high entropy (%f)", lowE, highE)
	}
}

func TestSHA256(t *testing.T) {
	data := []byte("hello world")
	hash := computeSHA256(data)

	// SHA256 of "hello world"
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
		result := interpretEntropy(tt.entropy)
		if len(result) < len(tt.expected) || result[:len(tt.expected)] != tt.expected {
			t.Errorf("interpretEntropy(%f) = %q, want prefix %q", tt.entropy, result, tt.expected)
		}
	}
}
