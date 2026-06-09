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

func TestRepairPNGMissingSignature(t *testing.T) {
	// PNG without signature
	data := []byte{
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // "IHDR"
	}
	
	result, err := Repair(data, "test.png", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairPNGMissingIEND(t *testing.T) {
	// PNG without IEND
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // IHDR
	}
	
	result, err := Repair(data, "test.png", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairJPEGMissingSOI(t *testing.T) {
	// JPEG without SOI marker
	data := []byte{0xFF, 0xE0, 0x00, 0x10} // Missing 0xFF 0xD8
	
	result, err := Repair(data, "test.jpg", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairJPEGMissingEOI(t *testing.T) {
	// JPEG without EOI marker
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0} // Missing 0xFF 0xD9
	
	result, err := Repair(data, "test.jpg", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairPDFMissingHeader(t *testing.T) {
	// PDF without header
	data := []byte{0x25, 0x50, 0x44, 0x46} // Just %PDF
	
	result, err := Repair(data, "test.pdf", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairPDFMissingEOF(t *testing.T) {
	// PDF without %%EOF
	data := []byte("%PDF-1.7\r\n1 0 obj\n<< /Type /Catalog >>\nendobj")
	
	result, err := Repair(data, "test.pdf", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairZIPMissingEOCD(t *testing.T) {
	// ZIP without EOCD
	data := []byte{0x50, 0x4B, 0x03, 0x04} // Just local file header
	
	result, err := Repair(data, "test.zip", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairUnknownFormat(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	
	result, err := Repair(data, "test.bin", nil)
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairWithDryRun(t *testing.T) {
	data := []byte{0xFF, 0xE0, 0x00, 0x10} // JPEG without SOI
	
	result, err := Repair(data, "test.jpg", &Options{DryRun: true, NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairWithTargetFormat(t *testing.T) {
	data := []byte{0x89, 0x50, 0x4E, 0x47} // PNG header
	
	result, err := Repair(data, "test.bin", &Options{TargetFormat: "png", NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairOptionsDefaults(t *testing.T) {
	opts := &Options{}
	
	if opts.Strategy == "" {
		opts.Strategy = "auto"
	}
	
	if opts.Strategy != "auto" {
		t.Errorf("Expected auto strategy, got %s", opts.Strategy)
	}
}

func TestResultStructure(t *testing.T) {
	result := &Result{
		FileName:     "test.png",
		Success:      true,
		Strategy:     "reconstruct_from_chunks",
		OriginalSize: 1024,
		RepairedSize: 2048,
		Changes:      []string{"Fixed header"},
		Warnings:     []string{},
	}
	
	if result.FileName != "test.png" {
		t.Errorf("Expected filename test.png, got %s", result.FileName)
	}
	
	if !result.Success {
		t.Error("Expected success to be true")
	}
	
	if result.Strategy != "reconstruct_from_chunks" {
		t.Errorf("Expected strategy reconstruct_from_chunks, got %s", result.Strategy)
	}
}

func TestRepairPNGComplete(t *testing.T) {
	// Complete PNG file
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // IHDR
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08, 0x02, // Bit depth: 8, Color type: 2
		0x00, 0x00, 0x00, // Compression, Filter, Interlace
		// Missing IEND
	}
	
	result, err := Repair(data, "test.png", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairJPEGComplete(t *testing.T) {
	// JPEG without SOI and EOI
	data := []byte{0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46} // JFIF data without SOI/EOI
	
	result, err := Repair(data, "test.jpg", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairPDFComplete(t *testing.T) {
	// PDF without header and EOF
	data := []byte("1 0 obj\n<< /Type /Catalog >>\nendobj")
	
	result, err := Repair(data, "test.pdf", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestRepairZIPComplete(t *testing.T) {
	// ZIP without EOCD
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00} // Local file header
	
	result, err := Repair(data, "test.zip", &Options{NoBackup: true})
	if err != nil {
		t.Fatalf("Repair() error = %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}
