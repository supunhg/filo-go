package export

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNewExporter(t *testing.T) {
	tests := []struct {
		format Format
	}{
		{JSON},
		{SARIF},
		{CSV},
	}

	for _, tt := range tests {
		e := NewExporter(tt.format)
		if e == nil {
			t.Errorf("NewExporter(%s) returned nil", tt.format)
		}
	}
}

func TestExportJSON(t *testing.T) {
	e := NewExporter(JSON)
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	err := e.ExportResult(result, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportJSONToFile(t *testing.T) {
	e := NewExporter(JSON)
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	tmpFile := t.TempDir() + "/test.json"
	err := e.ExportResult(result, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestExportSARIF(t *testing.T) {
	e := NewExporter(SARIF)
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	err := e.ExportResult(result, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportSARIFToFile(t *testing.T) {
	e := NewExporter(SARIF)
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	tmpFile := t.TempDir() + "/test.sarif"
	err := e.ExportResult(result, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created and contains valid JSON
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}

	// Verify it's valid JSON
	var result2 interface{}
	if err := json.Unmarshal(data, &result2); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}
}

func TestExportSARIFBatch(t *testing.T) {
	e := NewExporter(SARIF)
	results := []*SARIFAnalysisResult{
		{
			FilePath:      "/test/file1.bin",
			FileName:      "file1.bin",
			PrimaryFormat: "unknown",
			Confidence:    0.5,
			Entropy:       5.0,
		},
		{
			FilePath:      "/test/file2.png",
			FileName:      "file2.png",
			PrimaryFormat: "png",
			Confidence:    0.9,
			Entropy:       4.0,
		},
	}

	tmpFile := t.TempDir() + "/batch.sarif"
	err := e.ExportBatch(results, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestExportCSV(t *testing.T) {
	e := NewExporter(CSV)
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	err := e.ExportResult(result, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportCSVToFile(t *testing.T) {
	e := NewExporter(CSV)
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	tmpFile := t.TempDir() + "/test.csv"
	err := e.ExportResult(result, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestExportCSVBatch(t *testing.T) {
	e := NewExporter(CSV)
	results := []*SARIFAnalysisResult{
		{
			FilePath:      "/test/file1.bin",
			FileName:      "file1.bin",
			PrimaryFormat: "unknown",
			Confidence:    0.5,
			Entropy:       5.0,
		},
		{
			FilePath:      "/test/file2.png",
			FileName:      "file2.png",
			PrimaryFormat: "png",
			Confidence:    0.9,
			Entropy:       4.0,
		},
	}

	tmpFile := t.TempDir() + "/batch.csv"
	err := e.ExportBatch(results, tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("output file is empty")
	}
}

func TestUnsupportedFormat(t *testing.T) {
	e := NewExporter("invalid")
	result := &SARIFAnalysisResult{
		FilePath:      "/test/file.bin",
		FileName:      "file.bin",
		PrimaryFormat: "unknown",
		Confidence:    0.5,
		Entropy:       5.0,
	}

	err := e.ExportResult(result, "")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestGetSARIFLevel(t *testing.T) {
	tests := []struct {
		name     string
		result   *SARIFAnalysisResult
		expected string
	}{
		{
			name: "no issues",
			result: &SARIFAnalysisResult{
				Contradictions: []string{},
			},
			expected: "none",
		},
		{
			name: "contradictions",
			result: &SARIFAnalysisResult{
				Contradictions: []string{"missing IEND"},
			},
			expected: "warning",
		},
		{
			name: "high entropy",
			result: &SARIFAnalysisResult{
				Entropy: 7.5,
			},
			expected: "note",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := getSARIFLevel(tt.result)
			if level != tt.expected {
				t.Errorf("getSARIFLevel() = %v, want %v", level, tt.expected)
			}
		})
	}
}

func TestJoinCSV(t *testing.T) {
	record := []string{"a", "b", "c"}
	result := joinCSV(record)
	if result != "a,b,c" {
		t.Errorf("joinCSV() = %v, want a,b,c", result)
	}
}
