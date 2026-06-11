package analyzer

import (
	"os"
	"testing"
)

func TestAnalyzeStream(t *testing.T) {
	// Create a test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeStream(testFile, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileSize != int64(len(data)) {
		t.Errorf("expected file size %d, got %d", len(data), result.FileSize)
	}

	if result.Entropy <= 0 {
		t.Error("expected positive entropy")
	}

	if result.TotalChunks != 1 {
		t.Errorf("expected 1 chunk for 1MB file, got %d", result.TotalChunks)
	}
}

func TestAnalyzeStreamPNG(t *testing.T) {
	// Create a test PNG file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.png"
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
		0x08, 0x06, 0x00, 0x00, 0x00,
	}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzeStream(testFile, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "png" {
		t.Errorf("expected format png, got %s", result.Format)
	}

	if result.MIME != "image/png" {
		t.Errorf("expected MIME image/png, got %s", result.MIME)
	}
}

func TestAnalyzeStreamLargeFile(t *testing.T) {
	// Create a larger test file (4MB)
	tmpDir := t.TempDir()
	testFile := tmpDir + "/large.bin"
	data := make([]byte, 4*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	opts := &StreamOptions{
		ChunkSize: 1024 * 1024, // 1MB chunks
	}

	result, err := AnalyzeStream(testFile, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalChunks != 4 {
		t.Errorf("expected 4 chunks for 4MB file, got %d", result.TotalChunks)
	}

	if result.ProcessedBytes != int64(len(data)) {
		t.Errorf("expected processed bytes %d, got %d", len(data), result.ProcessedBytes)
	}
}

func TestAnalyzeStreamNonexistent(t *testing.T) {
	_, err := AnalyzeStream("/nonexistent/file.bin", nil)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestAnalyzeStreamMaxSize(t *testing.T) {
	// Create a test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	data := make([]byte, 1024)
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Set max size smaller than file
	opts := &StreamOptions{
		MaxFileSize: 512,
	}

	_, err := AnalyzeStream(testFile, opts)
	if err == nil {
		t.Error("expected error for file exceeding max size")
	}
}

func TestDetectFormatStream(t *testing.T) {
	tests := []struct {
		name     string
		header   []byte
		expected string
	}{
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpeg"},
		{"PDF", []byte{0x25, 0x50, 0x44, 0x46, 0x2D}, "pdf"},
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04}, "zip"},
		{"ELF", []byte{0x7F, 0x45, 0x4C, 0x46, 0x02}, "elf"},
		{"PE", []byte{0x4D, 0x5A, 0x00, 0x00}, "pe"},
		{"Unknown", []byte{0x00, 0x00, 0x00, 0x00}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, _, _ := detectFormatStream(tt.header, "")
			if format != tt.expected {
				t.Errorf("expected format %s, got %s", tt.expected, format)
			}
		})
	}
}

func TestAnalyzeStreamWithFormatsDir(t *testing.T) {
	// Create a test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.pdf"
	data := []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Use formats directory if available
	formatsDir := "../../formats"
	if _, err := os.Stat(formatsDir); os.IsNotExist(err) {
		t.Skip("formats directory not found")
	}

	opts := &StreamOptions{
		FormatsDir: formatsDir,
	}

	result, err := AnalyzeStream(testFile, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "pdf" {
		t.Errorf("expected format pdf, got %s", result.Format)
	}
}

func TestStreamResultStructure(t *testing.T) {
	result := &StreamResult{
		FilePath:       "/test/file.bin",
		FileName:       "file.bin",
		FileSize:       1024,
		Format:         "binary",
		MIME:           "application/octet-stream",
		Confidence:     0.8,
		Entropy:        5.5,
		EntropyLabel:   "High",
		TotalChunks:    1,
		ProcessedBytes: 1024,
	}

	if result.FilePath != "/test/file.bin" {
		t.Errorf("expected path /test/file.bin, got %s", result.FilePath)
	}

	if result.TotalChunks != 1 {
		t.Errorf("expected 1 chunk, got %d", result.TotalChunks)
	}
}
