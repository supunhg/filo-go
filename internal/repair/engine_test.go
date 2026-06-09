package repair

import (
	"testing"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpeg"},
		{"PDF", []byte{0x25, 0x50, 0x44, 0x46}, "pdf"},
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04}, "zip"},
		{"Unknown", []byte{0x00, 0x00, 0x00, 0x00}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat(tt.data)
			if got != tt.want {
				t.Errorf("detectFormat() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRepair(t *testing.T) {
	// Test with nil data - should return empty result
	result, err := Repair(nil, "test.png", nil)
	if err != nil {
		t.Errorf("Repair() error = %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}

	// Test with empty data - should return empty result
	result, err = Repair([]byte{}, "test.png", nil)
	if err != nil {
		t.Errorf("Repair() error = %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestValidatePNG(t *testing.T) {
	// Test with valid PNG header and IHDR chunk
	validPNG := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08, 0x02, // Bit depth: 8, Color type: 2
		0x00, 0x00, 0x00, // Compression, Filter, Interlace
	}
	if !validatePNG(validPNG) {
		t.Error("Expected true for valid PNG")
	}

	// Test with invalid PNG
	invalidPNG := []byte{0x00, 0x00, 0x00, 0x00}
	if validatePNG(invalidPNG) {
		t.Error("Expected false for invalid PNG")
	}

	// Test with PNG header but no IHDR
	partialPNG := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if validatePNG(partialPNG) {
		t.Error("Expected false for PNG without IHDR")
	}
}

func TestGenerateMinimalPNG(t *testing.T) {
	png := generateMinimalPNG()
	if len(png) == 0 {
		t.Error("Expected non-empty PNG")
	}

	// Check PNG header
	if png[0] != 0x89 || png[1] != 0x50 {
		t.Error("Invalid PNG header")
	}
}
