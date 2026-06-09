package pcap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewNetworkExtractor(t *testing.T) {
	tmpDir := t.TempDir()
	extractor := NewNetworkExtractor(tmpDir)

	if extractor == nil {
		t.Fatal("Expected non-nil extractor")
	}

	if extractor.OutputDir != tmpDir {
		t.Errorf("Expected output dir %s, got %s", tmpDir, extractor.OutputDir)
	}
}

func TestExtractFiles_InvalidData(t *testing.T) {
	extractor := NewNetworkExtractor("")

	_, err := extractor.ExtractFiles([]byte("invalid"))
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

func TestExtractFiles_Empty(t *testing.T) {
	extractor := NewNetworkExtractor("")

	files, err := extractor.ExtractFiles([]byte{})
	if err == nil && len(files) > 0 {
		t.Error("Expected no files from empty data")
	}
}

func TestGuessFileName(t *testing.T) {
	extractor := NewNetworkExtractor("")

	// Test with Content-Disposition
	headers := map[string]string{
		"Content-Disposition": "attachment; filename=\"test.pdf\"",
	}
	body := []byte("%PDF-1.4")
	name := extractor.guessFileName(headers, body, "test123")
	if name != "test.pdf" {
		t.Errorf("Expected test.pdf, got %s", name)
	}

	// Test with content detection
	headers = map[string]string{}
	body = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	name = extractor.guessFileName(headers, body, "test456")
	if name != "file_test456.png" {
		t.Errorf("Expected file_test456.png, got %s", name)
	}
}

func TestDetectContentExtension(t *testing.T) {
	extractor := NewNetworkExtractor("")

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"png", []byte{0x89, 0x50, 0x4E, 0x47}, ".png"},
		{"jpg", []byte{0xFF, 0xD8, 0xFF}, ".jpg"},
		{"pdf", []byte{0x25, 0x50, 0x44, 0x46}, ".pdf"},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04}, ".zip"},
		{"empty", []byte{}, ""},
		{"unknown", []byte{0x00, 0x01, 0x02}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractor.detectContentExtension(tt.data)
			if got != tt.want {
				t.Errorf("detectContentExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatNetworkExtraction(t *testing.T) {
	// Test empty
	result := FormatNetworkExtraction(nil)
	if result != "No files extracted from network traffic" {
		t.Errorf("Expected 'No files extracted', got %s", result)
	}

	// Test with files
	files := []ExtractedFile{
		{
			Protocol: "HTTP",
			FileName: "test.pdf",
			Size:     1024,
			SavePath: "/tmp/test.pdf",
		},
	}
	result = FormatNetworkExtraction(files)
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		got := formatSize(tt.bytes)
		if got != tt.want {
			t.Errorf("formatSize(%d) = %v, want %v", tt.bytes, got, tt.want)
		}
	}
}

func TestExportNetworkReport(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	files := []ExtractedFile{
		{
			Protocol: "HTTP",
			FileName: "test.pdf",
			Size:     1024,
		},
	}

	err := ExportNetworkReport(files, outputPath)
	if err != nil {
		t.Fatalf("ExportNetworkReport() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Report file was not created")
	}
}

func TestGetStreamStats(t *testing.T) {
	extractor := NewNetworkExtractor("")

	stats := extractor.GetStreamStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	if stats["total_streams"] != 0 {
		t.Errorf("Expected 0 streams, got %v", stats["total_streams"])
	}
}
