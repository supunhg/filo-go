package container

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestDetectContainerFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04}, "zip"},
		{"7z", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z"},
		{"RAR", []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "rar"},
		{"GZIP", []byte{0x1F, 0x8B}, "gzip"},
		{"Unknown", []byte{0x00, 0x00, 0x00, 0x00}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectContainerFormat(tt.data); got != tt.expected {
				t.Errorf("detectContainerFormat() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetectFileFormat(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		expected string
	}{
		{"JPEG", "photo.jpg", "jpeg"},
		{"JPEG uppercase", "photo.JPG", "jpeg"},
		{"PNG", "image.png", "png"},
		{"GIF", "animation.gif", "gif"},
		{"PDF", "document.pdf", "pdf"},
		{"DOCX", "report.docx", "docx"},
		{"XLSX", "spreadsheet.xlsx", "xlsx"},
		{"PPTX", "slides.pptx", "pptx"},
		{"ZIP", "archive.zip", "zip"},
		{"TAR", "backup.tar", "tar"},
		{"GZIP", "compressed.gz", "gzip"},
		{"7Z", "archive.7z", "7z"},
		{"RAR", "archive.rar", "rar"},
		{"EXE", "program.exe", "pe"},
		{"ELF", "binary.elf", "elf"},
		{"Python", "script.py", "python"},
		{"JavaScript", "code.js", "javascript"},
		{"HTML", "page.html", "html"},
		{"XML", "data.xml", "xml"},
		{"JSON", "config.json", "json"},
		{"CSV", "data.csv", "csv"},
		{"Text", "readme.txt", "text"},
		{"SQL", "schema.sql", "sql"},
		{"Shell", "script.sh", "shell"},
		{"YAML", "config.yaml", "yaml"},
		{"TOML", "config.toml", "toml"},
		{"Config", "settings.ini", "config"},
		{"Unknown", "file.xyz", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectFileFormat(tt.fileName); got != tt.expected {
				t.Errorf("detectFileFormat(%q) = %v, want %v", tt.fileName, got, tt.expected)
			}
		})
	}
}

func TestIsContainer(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		expected bool
	}{
		{"ZIP", "archive.zip", true},
		{"TAR", "backup.tar", true},
		{"GZIP", "file.gz", true},
		{"TGZ", "archive.tgz", true},
		{"7Z", "archive.7z", true},
		{"RAR", "archive.rar", true},
		{"BZ2", "file.bz2", true},
		{"XZ", "file.xz", true},
		{"ZST", "file.zst", true},
		{"Text", "readme.txt", false},
		{"PDF", "document.pdf", false},
		{"PNG", "image.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isContainer(tt.fileName); got != tt.expected {
				t.Errorf("isContainer(%q) = %v, want %v", tt.fileName, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeSmallData(t *testing.T) {
	result, err := Analyze([]byte{0x01, 0x02}, "tiny.bin", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Small data returns empty format (not a recognized container)
	if result.Format != "" && result.Format != "unknown" {
		t.Errorf("expected empty or unknown format, got %s", result.Format)
	}
}

func TestAnalyzeUnknownFormat(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := Analyze(data, "unknown.bin", 0)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestAnalyzeEmptyData(t *testing.T) {
	result, err := Analyze([]byte{}, "empty.bin", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty data returns empty format (not a recognized container)
	if result.Format != "" && result.Format != "unknown" {
		t.Errorf("expected empty or unknown format, got %s", result.Format)
	}
}

func TestAnalyze7z(t *testing.T) {
	// 7z header
	data := []byte{
		0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, // 7z signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Start header
	}

	result, err := Analyze(data, "archive.7z", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "7z" {
		t.Errorf("expected format 7z, got %s", result.Format)
	}
}

func TestAnalyzeRAR(t *testing.T) {
	// RAR header
	data := []byte{
		0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, // RAR signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	result, err := Analyze(data, "archive.rar", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "rar" {
		t.Errorf("expected format rar, got %s", result.Format)
	}
}

func TestAnalyzeGzip(t *testing.T) {
	// GZIP header - minimal valid gzip
	data := []byte{
		0x1F, 0x8B, // GZIP signature
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // Header
		0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extra fields
	}

	result, err := Analyze(data, "archive.gz", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "gzip" {
		t.Errorf("expected format gzip, got %s", result.Format)
	}
}

func TestAnalyzeTAR(t *testing.T) {
	// TAR format detection requires ustar at offset 257
	// The Analyze function returns an error for invalid tar headers
	data := make([]byte, 512)
	copy(data[257:], "ustar")

	_, err := Analyze(data, "archive.tar", 0)
	// We expect an error because the tar header is invalid
	if err == nil {
		t.Error("expected error for invalid tar header")
	}
}

func TestAnalyzeZIP(t *testing.T) {
	// Create a valid ZIP file in memory
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add a file
	fw, err := w.Create("test.txt")
	if err != nil {
		t.Fatalf("failed to create file in zip: %v", err)
	}
	if _, err := fw.Write([]byte("Hello, World!")); err != nil {
		t.Fatalf("failed to write to zip: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	data := buf.Bytes()

	result, err := Analyze(data, "test.zip", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "zip" {
		t.Errorf("expected format zip, got %s", result.Format)
	}

	if result.EntryCount != 1 {
		t.Errorf("expected 1 entry, got %d", result.EntryCount)
	}

	if result.TotalSize == 0 {
		t.Error("expected non-zero total size")
	}
}

func TestAnalyzeTARFromReader(t *testing.T) {
	// TAR format detection
	data := make([]byte, 1024)
	copy(data[257:], "ustar")

	_, err := Analyze(data, "archive.tar", 0)
	// We expect an error because the tar header is invalid
	if err == nil {
		t.Error("expected error for invalid tar header")
	}
}

func TestEntryJSON(t *testing.T) {
	entry := Entry{
		Path:   "/test/file.txt",
		Size:   1024,
		Format: "text",
		IsDir:  false,
		Offset: 0,
	}

	if entry.Path != "/test/file.txt" {
		t.Errorf("expected path /test/file.txt, got %s", entry.Path)
	}
	if entry.Size != 1024 {
		t.Errorf("expected size 1024, got %d", entry.Size)
	}
	if entry.Format != "text" {
		t.Errorf("expected format text, got %s", entry.Format)
	}
}

func TestNestedResultJSON(t *testing.T) {
	nested := NestedResult{
		Path:   "nested.zip",
		Format: "zip",
		Entries: []Entry{
			{Path: "file.txt", Size: 100},
		},
	}

	if nested.Path != "nested.zip" {
		t.Errorf("expected path nested.zip, got %s", nested.Path)
	}
	if len(nested.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(nested.Entries))
	}
}

func TestResultJSON(t *testing.T) {
	result := Result{
		FileName:   "test.zip",
		Format:     "zip",
		Entries:    []Entry{},
		TotalSize:  1024,
		EntryCount: 0,
		Nested:     []NestedResult{},
	}

	if result.FileName != "test.zip" {
		t.Errorf("expected filename test.zip, got %s", result.FileName)
	}
	if result.Format != "zip" {
		t.Errorf("expected format zip, got %s", result.Format)
	}
}
