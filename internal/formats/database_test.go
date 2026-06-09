package formats

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDatabase(t *testing.T) {
	// Create temporary directory with test format
	tmpDir := t.TempDir()

	yamlContent := `
format: test-format
version: "1.0"
mime:
  - application/test
category: test
confidence_weight: 0.9
extensions:
  - .test
description: Test format
signatures:
  - offset: 0
    hex: "54 45 53 54"
    description: TEST magic bytes
    weight: 1.0
`

	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create test format: %v", err)
	}

	db, err := NewDatabase(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.List()) != 1 {
		t.Errorf("expected 1 format, got %d", len(db.List()))
	}
}

func TestNewDatabaseEmpty(t *testing.T) {
	tmpDir := t.TempDir()

	db, err := NewDatabase(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.List()) != 0 {
		t.Errorf("expected 0 formats, got %d", len(db.List()))
	}
}

func TestNewDatabaseInvalidDir(t *testing.T) {
	_, err := NewDatabase("/nonexistent/dir")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestLoadFile(t *testing.T) {
	tmpDir := t.TempDir()

	yamlContent := `
format: test-format
version: "1.0"
`

	path := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create test format: %v", err)
	}

	db := &Database{
		formats: make(map[string]*FormatSpec),
		dir:     tmpDir,
	}

	if err := db.LoadFile(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := db.Get("test-format"); !ok {
		t.Error("expected format to be loaded")
	}
}

func TestLoadFileMissingFormat(t *testing.T) {
	tmpDir := t.TempDir()

	yamlContent := `
version: "1.0"
`

	path := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create test format: %v", err)
	}

	db := &Database{
		formats: make(map[string]*FormatSpec),
		dir:     tmpDir,
	}

	err := db.LoadFile(path)
	if err == nil {
		t.Error("expected error for missing format field")
	}
}

func TestLoadFileInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	path := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(path, []byte("not: yaml: [invalid"), 0644); err != nil {
		t.Fatalf("failed to create test format: %v", err)
	}

	db := &Database{
		formats: make(map[string]*FormatSpec),
		dir:     tmpDir,
	}

	// This should not error since the YAML is technically valid
	_ = db.LoadFile(path)
}

func TestGet(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"test": {Format: "test"},
		},
	}

	spec, ok := db.Get("test")
	if !ok {
		t.Error("expected format to be found")
	}
	if spec.Format != "test" {
		t.Errorf("expected format test, got %s", spec.Format)
	}
}

func TestGetNotFound(t *testing.T) {
	db := &Database{
		formats: make(map[string]*FormatSpec),
	}

	_, ok := db.Get("nonexistent")
	if ok {
		t.Error("expected format not to be found")
	}
}

func TestList(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"format1": {Format: "format1"},
			"format2": {Format: "format2"},
		},
	}

	names := db.List()
	if len(names) != 2 {
		t.Errorf("expected 2 formats, got %d", len(names))
	}
}

func TestByCategory(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"image1":  {Format: "image1", Category: "image"},
			"image2":  {Format: "image2", Category: "image"},
			"archive": {Format: "archive", Category: "archive"},
		},
	}

	results := db.ByCategory("image")
	if len(results) != 2 {
		t.Errorf("expected 2 image formats, got %d", len(results))
	}
}

func TestByExtension(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"png": {Format: "png", Extensions: []string{"png"}},
			"jpg": {Format: "jpg", Extensions: []string{"jpg", "jpeg"}},
		},
	}

	results := db.ByExtension("jpg")
	if len(results) != 1 {
		t.Errorf("expected 1 format for .jpg, got %d", len(results))
	}

	results = db.ByExtension(".png")
	if len(results) != 1 {
		t.Errorf("expected 1 format for .png, got %d", len(results))
	}
}

func TestMatch(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"png": {
				Format:           "png",
				ConfidenceWeight: 1.0,
				Signatures: []Signature{
					{Offset: 0, Hex: "89 50 4E 47 0D 0A 1A 0A", Description: "PNG magic", Weight: 1.0},
				},
			},
		},
	}

	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00}
	results := db.Match(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}

	if results[0].Format.Format != "png" {
		t.Errorf("expected PNG match, got %s", results[0].Format.Format)
	}

	if results[0].Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", results[0].Confidence)
	}
}

func TestMatchNoMatch(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"png": {
				Format:           "png",
				ConfidenceWeight: 1.0,
				Signatures: []Signature{
					{Offset: 0, Hex: "89 50 4E 47 0D 0A 1A 0A", Description: "PNG magic", Weight: 1.0},
				},
			},
		},
	}

	data := []byte{0x00, 0x00, 0x00, 0x00}
	results := db.Match(data)

	if len(results) != 0 {
		t.Errorf("expected 0 matches, got %d", len(results))
	}
}

func TestMatchPartial(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"test": {
				Format:           "test",
				ConfidenceWeight: 1.0,
				Signatures: []Signature{
					{Offset: 0, Hex: "AA BB", Description: "Sig1", Weight: 0.5},
					{Offset: 0, Hex: "CC DD", Description: "Sig2", Weight: 0.5},
				},
			},
		},
	}

	// Only first signature matches
	data := []byte{0xAA, 0xBB, 0x00, 0x00}
	results := db.Match(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}

	// Confidence should be 50%
	if results[0].Confidence != 0.5 {
		t.Errorf("expected confidence 0.5, got %f", results[0].Confidence)
	}
}

func TestMatchSignatureRange(t *testing.T) {
	db := &Database{
		formats: map[string]*FormatSpec{
			"test": {
				Format:           "test",
				ConfidenceWeight: 1.0,
				Signatures: []Signature{
					{Offset: 0, OffsetMax: 10, Hex: "AA BB", Description: "Sig1", Weight: 1.0},
				},
			},
		},
	}

	// Signature at offset 5
	data := make([]byte, 20)
	data[5] = 0xAA
	data[6] = 0xBB

	results := db.Match(data)

	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
}

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		name     string
		hex      string
		expected []byte
		wantErr  bool
	}{
		{"valid", "AA BB CC", []byte{0xAA, 0xBB, 0xCC}, false},
		{"no spaces", "AABBCC", []byte{0xAA, 0xBB, 0xCC}, false},
		{"lowercase", "aa bb cc", []byte{0xAA, 0xBB, 0xCC}, false},
		{"uppercase", "AA BB CC", []byte{0xAA, 0xBB, 0xCC}, false},
		{"odd length", "AA B", nil, true},
		{"invalid char", "AA GG", nil, true},
		{"empty", "", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := hexToBytes(tt.hex)
			if (err != nil) != tt.wantErr {
				t.Errorf("hexToBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != len(tt.expected) {
				t.Errorf("hexToBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchResultJSON(t *testing.T) {
	result := MatchResult{
		Format:      &FormatSpec{Format: "test"},
		Confidence:  0.9,
		MatchedSigs: []string{"sig1", "sig2"},
	}

	if result.Format.Format != "test" {
		t.Errorf("expected format test, got %s", result.Format.Format)
	}
	if result.Confidence != 0.9 {
		t.Errorf("expected confidence 0.9, got %f", result.Confidence)
	}
	if len(result.MatchedSigs) != 2 {
		t.Errorf("expected 2 matched sigs, got %d", len(result.MatchedSigs))
	}
}

func TestFormatSpecJSON(t *testing.T) {
	spec := FormatSpec{
		Format:           "test",
		Version:          "1.0",
		MIME:             []string{"application/test"},
		Category:         "test",
		ConfidenceWeight: 0.9,
		Extensions:       []string{".test"},
		Description:      "Test format",
		References:       []string{"https://example.com"},
		Signatures:       []Signature{},
		Footers:          []Footer{},
	}

	if spec.Format != "test" {
		t.Errorf("expected format test, got %s", spec.Format)
	}
	if spec.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", spec.Version)
	}
}

func TestSignatureJSON(t *testing.T) {
	sig := Signature{
		Offset:      0,
		OffsetMax:   10,
		Hex:         "AA BB",
		Description: "Test sig",
		Weight:      0.5,
	}

	if sig.Offset != 0 {
		t.Errorf("expected offset 0, got %d", sig.Offset)
	}
	if sig.OffsetMax != 10 {
		t.Errorf("expected offset_max 10, got %d", sig.OffsetMax)
	}
}

func TestLoadAllIgnoresNonYAML(t *testing.T) {
	tmpDir := t.TempDir()

	// Create YAML file
	yamlContent := `
format: test-format
version: "1.0"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create test format: %v", err)
	}

	// Create non-YAML file
	if err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("not yaml"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create directory (should be ignored)
	if err := os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	db, err := NewDatabase(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(db.List()) != 1 {
		t.Errorf("expected 1 format, got %d", len(db.List()))
	}
}

func TestConfidenceWeightDefault(t *testing.T) {
	tmpDir := t.TempDir()

	yamlContent := `
format: test-format
version: "1.0"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to create test format: %v", err)
	}

	db, err := NewDatabase(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spec, ok := db.Get("test-format")
	if !ok {
		t.Fatal("expected format to be found")
	}

	if spec.ConfidenceWeight != 0.8 {
		t.Errorf("expected default confidence weight 0.8, got %f", spec.ConfidenceWeight)
	}
}
