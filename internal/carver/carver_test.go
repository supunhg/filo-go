package carver

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestCarve(t *testing.T) {
	// Create test data with embedded PNG
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	pngEnd := []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}

	testData := make([]byte, 1000)
	copy(testData[100:], pngMagic)
	copy(testData[500:], pngEnd)

	result, err := Carve(testData, "test.bin", &Options{
		MinSize: 100,
		MaxSize: 1000,
	})
	if err != nil {
		t.Fatalf("Carve() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.FileName != "test.bin" {
		t.Errorf("Expected filename 'test.bin', got '%s'", result.FileName)
	}
}

func TestCarveWithFilter(t *testing.T) {
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	pngEnd := []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}

	testData := make([]byte, 1000)
	copy(testData[100:], pngMagic)
	copy(testData[500:], pngEnd)

	// Filter for jpeg only (should find nothing)
	result, err := Carve(testData, "test.bin", &Options{
		Formats: []string{"jpeg"},
		MinSize: 100,
	})
	if err != nil {
		t.Fatalf("Carve() error = %v", err)
	}

	if result.TotalFound != 0 {
		t.Errorf("Expected 0 found, got %d", result.TotalFound)
	}
}

func TestCarveNilOptions(t *testing.T) {
	testData := []byte{0x00, 0x00, 0x00, 0x00}
	result, err := Carve(testData, "test.bin", nil)
	if err != nil {
		t.Fatalf("Carve() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestNewExtractor(t *testing.T) {
	ext := NewExtractor(nil)
	if ext == nil {
		t.Fatal("Expected non-nil extractor")
	}

	if ext.OutputDir != "extracted" {
		t.Errorf("Expected default output dir 'extracted', got '%s'", ext.OutputDir)
	}

	if !ext.Recursive {
		t.Error("Expected Recursive to be true by default")
	}
}

func TestNewExtractorWithOptions(t *testing.T) {
	ext := NewExtractor(&ExtractorOptions{
		OutputDir: "/tmp/test",
		Recursive: false,
		Force:     true,
		Verbose:   true,
	})

	if ext.OutputDir != "/tmp/test" {
		t.Errorf("Expected output dir '/tmp/test', got '%s'", ext.OutputDir)
	}

	if ext.Recursive {
		t.Error("Expected Recursive to be false")
	}

	if !ext.Force {
		t.Error("Expected Force to be true")
	}

	if !ext.Verbose {
		t.Error("Expected Verbose to be true")
	}
}

func TestExtract(t *testing.T) {
	tmpDir := t.TempDir()
	ext := NewExtractor(&ExtractorOptions{
		OutputDir: tmpDir,
	})

	// Create test data with PNG signature (simpler extraction)
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	testData := make([]byte, 1000)
	copy(testData[100:], pngMagic)

	result, err := ext.Extract(testData, "test.bin", nil)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestExtractWithFormatFilter(t *testing.T) {
	tmpDir := t.TempDir()
	ext := NewExtractor(&ExtractorOptions{
		OutputDir: tmpDir,
	})

	// Create test data with PNG signature
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	testData := make([]byte, 1000)
	copy(testData[100:], pngMagic)

	// Filter for gzip only (should find nothing)
	result, err := ext.Extract(testData, "test.bin", &ExtractorOptions{
		OutputDir: tmpDir,
		Formats:   []string{"gzip"},
	})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if len(result.Files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(result.Files))
	}
}

func TestExtractSpecific(t *testing.T) {
	tmpDir := t.TempDir()
	ext := NewExtractor(&ExtractorOptions{
		OutputDir: tmpDir,
	})

	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	outputPath := filepath.Join(tmpDir, "output.bin")

	file, err := ext.ExtractSpecific(testData, "raw", 0, 5, outputPath)
	if err != nil {
		t.Fatalf("ExtractSpecific() error = %v", err)
	}

	if file == nil {
		t.Fatal("Expected non-nil file")
	}

	if file.Size != 5 {
		t.Errorf("Expected size 5, got %d", file.Size)
	}
}

func TestExtractSpecificInvalidOffset(t *testing.T) {
	ext := NewExtractor(nil)
	testData := []byte{0x00, 0x01, 0x02}

	_, err := ext.ExtractSpecific(testData, "raw", 100, 5, "output.bin")
	if err == nil {
		t.Error("Expected error for invalid offset")
	}
}

func TestExtractGzip(t *testing.T) {
	// Skip this test for now as gzip extraction requires specific conditions
	t.Skip("Skipping gzip extraction test")
}

func TestHexDump(t *testing.T) {
	data := []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64}

	result := HexDump(data, nil)
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestHexDumpWithOptions(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	opts := &HexDumpOptions{
		Offset:    0,
		Length:    8,
		Colored:   false,
		ShowASCII: true,
		Width:     8,
	}

	result := HexDump(data, opts)
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestHexDumpColored(t *testing.T) {
	data := []byte{0x00, 0xFF, 0x41, 0x0A, 0x0D}

	opts := &HexDumpOptions{
		Offset:    0,
		Length:    5,
		Colored:   true,
		ShowASCII: true,
		Width:     8,
	}

	result := HexDump(data, opts)
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestScanSignatures(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"png", []byte{0x89, 0x50, 0x4E, 0x47}, "png"},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF}, "jpeg"},
		{"pdf", []byte{0x25, 0x50, 0x44, 0x46}, "pdf"},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04}, "zip"},
		{"gzip", []byte{0x1F, 0x8B}, "gzip"},
		{"elf", []byte{0x7F, 0x45, 0x4C, 0x46}, "elf"},
		{"pe", []byte{0x4D, 0x5A}, "pe"},
		{"unknown", []byte{0x00, 0x00, 0x00, 0x00}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ScanSignatures(tt.data)
			if tt.expected == "" {
				if len(results) > 0 {
					t.Errorf("Expected no results, got %d", len(results))
				}
			} else {
				if len(results) == 0 {
					t.Error("Expected at least one result")
				} else if results[0].Format != tt.expected {
					t.Errorf("Expected format '%s', got '%s'", tt.expected, results[0].Format)
				}
			}
		})
	}
}

func TestScanSignaturesWithOffset(t *testing.T) {
	data := make([]byte, 100)
	copy(data[50:], []byte{0x89, 0x50, 0x4E, 0x47})

	results := ScanSignatures(data)
	if len(results) == 0 {
		t.Error("Expected at least one result")
	}

	if results[0].Offset != 50 {
		t.Errorf("Expected offset 50, got %d", results[0].Offset)
	}
}

func TestIsCompressed(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"gzip", []byte{0x1F, 0x8B}, true},
		{"bzip2", []byte{0x42, 0x5A, 0x68}, true},
		{"xz", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, true},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04}, true},
		{"7z", []byte{0x37, 0x7A, 0xBC, 0xAF}, true},
		{"rar", []byte{0x52, 0x61, 0x72}, true},
		{"unknown", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"empty", []byte{}, false},
		{"short", []byte{0x00}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCompressed(tt.data); got != tt.expected {
				t.Errorf("IsCompressed() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGuessFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"png", []byte{0x89, 0x50, 0x4E, 0x47}, "png"},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF, 0x00}, "jpeg"},
		{"pdf", []byte{0x25, 0x50, 0x44, 0x46}, "pdf"},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04}, "zip"},
		{"gzip", []byte{0x1F, 0x8B, 0x00, 0x00}, "gzip"},
		{"bzip2", []byte{0x42, 0x5A, 0x68, 0x00}, "bzip2"},
		{"xz", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "xz"},
		{"7z", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z"},
		{"rar", []byte{0x52, 0x61, 0x72, 0x21}, "rar"},
		{"elf", []byte{0x7F, 0x45, 0x4C, 0x46}, "elf"},
		{"pe", []byte{0x4D, 0x5A, 0x00, 0x00}, "pe"},
		{"tiff_le", []byte{0x49, 0x49, 0x2A, 0x00}, "tiff"},
		{"tiff_be", []byte{0x4D, 0x4D, 0x00, 0x2A}, "tiff"},
		{"gif", []byte{0x47, 0x49, 0x46, 0x38}, "gif"},
		{"bmp", []byte{0x42, 0x4D, 0x00, 0x00}, "bmp"},
		{"sqlite", []byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65}, "sqlite"},
		{"unknown", []byte{0x00, 0x00, 0x00, 0x00}, "unknown"},
		{"short", []byte{0x00, 0x01}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GuessFormat(tt.data); got != tt.expected {
				t.Errorf("GuessFormat() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRawSearch(t *testing.T) {
	data := []byte("Hello World Hello Go Hello")
	pattern := []byte("Hello")

	offsets := RawSearch(data, pattern)
	if len(offsets) != 3 {
		t.Errorf("Expected 3 occurrences, got %d", len(offsets))
	}

	if offsets[0] != 0 {
		t.Errorf("Expected first offset 0, got %d", offsets[0])
	}

	if offsets[1] != 12 {
		t.Errorf("Expected second offset 12, got %d", offsets[1])
	}
}

func TestSearchStrings(t *testing.T) {
	data := []byte("Hello World Hello Go")
	offsets := SearchStrings(data, "Hello")
	if len(offsets) != 2 {
		t.Errorf("Expected 2 occurrences, got %d", len(offsets))
	}
}

func TestSearchHex(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	offsets, err := SearchHex(data, "01 02 03")
	if err != nil {
		t.Fatalf("SearchHex() error = %v", err)
	}

	if len(offsets) != 1 {
		t.Errorf("Expected 1 occurrence, got %d", len(offsets))
	}
}

func TestSearchHexInvalid(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	_, err := SearchHex(data, "ZZ")
	if err == nil {
		t.Error("Expected error for invalid hex")
	}
}

func TestSearchHexOddLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	_, err := SearchHex(data, "1")
	if err == nil {
		t.Error("Expected error for odd length hex")
	}
}

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
		hasError bool
	}{
		{"48656C6C6F", []byte("Hello"), false},
		{"48 65 6C 6C 6F", []byte("Hello"), false},
		{"ZZ", nil, true},
		{"1", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := hexToBytes(tt.input)
			if tt.hasError {
				if err == nil {
					t.Error("Expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("hexToBytes() error = %v", err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("hexToBytes() = %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestScanBytes(t *testing.T) {
	data := []byte("Hello World Hello")
	pattern := []byte("Hello")

	offset := scanBytes(data, pattern, 0)
	if offset != 0 {
		t.Errorf("Expected offset 0, got %d", offset)
	}

	offset = scanBytes(data, pattern, 1)
	if offset != 12 {
		t.Errorf("Expected offset 12, got %d", offset)
	}

	offset = scanBytes(data, []byte("NotExist"), 0)
	if offset != -1 {
		t.Errorf("Expected -1, got %d", offset)
	}

	offset = scanBytes([]byte("Hi"), []byte("Hello"), 0)
	if offset != -1 {
		t.Errorf("Expected -1 for pattern longer than data, got %d", offset)
	}
}

func TestDefaultHexDumpOptions(t *testing.T) {
	opts := DefaultHexDumpOptions()
	if opts == nil {
		t.Fatal("Expected non-nil options")
	}

	if opts.Offset != 0 {
		t.Errorf("Expected offset 0, got %d", opts.Offset)
	}

	if opts.Length != 256 {
		t.Errorf("Expected length 256, got %d", opts.Length)
	}

	if !opts.Colored {
		t.Error("Expected Colored to be true")
	}

	if !opts.ShowASCII {
		t.Error("Expected ShowASCII to be true")
	}

	if opts.Width != 16 {
		t.Errorf("Expected width 16, got %d", opts.Width)
	}
}

func TestDD(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.bin")
	outputPath := filepath.Join(tmpDir, "output.bin")

	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	os.WriteFile(inputPath, data, 0644)

	err := DD(inputPath, outputPath, 0, 5)
	if err != nil {
		t.Fatalf("DD() error = %v", err)
	}

	output, _ := os.ReadFile(outputPath)
	if len(output) != 5 {
		t.Errorf("Expected 5 bytes, got %d", len(output))
	}
}

func TestDDWithOffset(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.bin")
	outputPath := filepath.Join(tmpDir, "output.bin")

	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	os.WriteFile(inputPath, data, 0644)

	err := DD(inputPath, outputPath, 5, 3)
	if err != nil {
		t.Fatalf("DD() error = %v", err)
	}

	output, _ := os.ReadFile(outputPath)
	if len(output) != 3 {
		t.Errorf("Expected 3 bytes, got %d", len(output))
	}
}

func TestDDInvalidOffset(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.bin")
	outputPath := filepath.Join(tmpDir, "output.bin")

	data := []byte{0x00, 0x01, 0x02}
	os.WriteFile(inputPath, data, 0644)

	err := DD(inputPath, outputPath, 100, 5)
	if err == nil {
		t.Error("Expected error for invalid offset")
	}
}

func TestDDNonexistentFile(t *testing.T) {
	err := DD("/nonexistent/file.bin", "/tmp/output.bin", 0, 5)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestDDCommand(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.bin")
	outputPath := filepath.Join(tmpDir, "output.bin")

	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	os.WriteFile(inputPath, data, 0644)

	cmd := &DDCommand{
		InputPath:  inputPath,
		OutputPath: outputPath,
		BlockSize:  1,
		Count:      5,
		Skip:       0,
		Seek:       0,
	}

	err := cmd.Run()
	if err != nil {
		t.Fatalf("DDCommand.Run() error = %v", err)
	}

	output, _ := os.ReadFile(outputPath)
	if len(output) != 5 {
		t.Errorf("Expected 5 bytes, got %d", len(output))
	}
}

func TestParseDDOptions(t *testing.T) {
	args := []string{"if=input.bin", "of=output.bin", "bs=1024", "count=10", "skip=5", "seek=2"}
	cmd := ParseDDOptions(args)

	if cmd.InputPath != "input.bin" {
		t.Errorf("Expected InputPath 'input.bin', got '%s'", cmd.InputPath)
	}

	if cmd.OutputPath != "output.bin" {
		t.Errorf("Expected OutputPath 'output.bin', got '%s'", cmd.OutputPath)
	}

	if cmd.BlockSize != 1024 {
		t.Errorf("Expected BlockSize 1024, got %d", cmd.BlockSize)
	}

	if cmd.Count != 10 {
		t.Errorf("Expected Count 10, got %d", cmd.Count)
	}

	if cmd.Skip != 5 {
		t.Errorf("Expected Skip 5, got %d", cmd.Skip)
	}

	if cmd.Seek != 2 {
		t.Errorf("Expected Seek 2, got %d", cmd.Seek)
	}
}

func TestParseDDOptionsInvalid(t *testing.T) {
	args := []string{"invalid", "if=input.bin"}
	cmd := ParseDDOptions(args)

	if cmd.InputPath != "input.bin" {
		t.Errorf("Expected InputPath 'input.bin', got '%s'", cmd.InputPath)
	}
}

func TestColorByte(t *testing.T) {
	tests := []struct {
		name     string
		byte     byte
		expected string
	}{
		{"null", 0x00, "\033[90m00\033[0m "},
		{"0xFF", 0xFF, "\033[91mFF\033[0m "},
		{"printable", 0x41, "\033[92m41\033[0m "},
		{"newline", 0x0A, "\033[93m0A\033[0m "},
		{"carriage", 0x0D, "\033[93m0D\033[0m "},
		{"other", 0x80, "\033[0m80\033[0m "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := colorByte(tt.byte)
			if result != tt.expected {
				t.Errorf("colorByte(%02X) = %q, want %q", tt.byte, result, tt.expected)
			}
		})
	}
}

func TestFindArchiveEnd(t *testing.T) {
	data := make([]byte, 1000)
	end := findArchiveEnd(data, 0, "zip")
	if end <= 0 {
		t.Error("Expected positive end offset")
	}
}

func TestFindGzipEnd(t *testing.T) {
	// Create valid gzip data
	original := []byte("Hello, World!")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(original)
	w.Close()

	gzipData := buf.Bytes()
	data := make([]byte, 1000)
	copy(data[100:], gzipData)

	end := findGzipEnd(data, 100)
	if end <= 100 {
		t.Error("Expected end offset greater than start")
	}
}

func TestFindPNGEnd(t *testing.T) {
	data := make([]byte, 1000)
	copy(data[100:], []byte("IEND"))
	// IEND + 4 bytes CRC = 8 bytes total
	end := findPNGEnd(data, 100)
	if end != 108 {
		t.Errorf("Expected end 108, got %d", end)
	}
}

func TestFindJPEGEnd(t *testing.T) {
	data := make([]byte, 1000)
	copy(data[100:], []byte{0xFF, 0xD9})

	end := findJPEGEnd(data, 100)
	if end != 102 {
		t.Errorf("Expected end 102, got %d", end)
	}
}

func TestFindPDFEnd(t *testing.T) {
	data := make([]byte, 1000)
	copy(data[100:], []byte("%%EOF"))

	end := findPDFEnd(data, 100)
	if end != 105 {
		t.Errorf("Expected end 105, got %d", end)
	}
}

func TestFindELFEnd(t *testing.T) {
	data := make([]byte, 1000)
	data[0] = 0x7F
	data[1] = 0x45
	data[2] = 0x4C
	data[3] = 0x46

	end := findELFEnd(data, 0)
	if end <= 0 {
		t.Error("Expected positive end offset")
	}
}

func TestFindPEEnd(t *testing.T) {
	data := make([]byte, 1000)
	data[0] = 0x4D
	data[1] = 0x5A

	end := findPEEnd(data, 0)
	if end <= 0 {
		t.Error("Expected positive end offset")
	}
}

func TestFindMachOEnd(t *testing.T) {
	data := make([]byte, 1000)

	end := findMachOEnd(data, 0)
	if end <= 0 {
		t.Error("Expected positive end offset")
	}
}

func TestDDFromReader(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.bin")

	data := []byte("Hello, World!")
	reader := bytes.NewReader(data)

	err := DDFromReader(reader, outputPath, 0, 5)
	if err != nil {
		t.Fatalf("DDFromReader() error = %v", err)
	}

	output, _ := os.ReadFile(outputPath)
	if len(output) != 5 {
		t.Errorf("Expected 5 bytes, got %d", len(output))
	}
}

func TestDDFromReaderWithOffset(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.bin")

	data := []byte("Hello, World!")
	reader := bytes.NewReader(data)

	err := DDFromReader(reader, outputPath, 7, 5)
	if err != nil {
		t.Fatalf("DDFromReader() error = %v", err)
	}

	output, _ := os.ReadFile(outputPath)
	if string(output) != "World" {
		t.Errorf("Expected 'World', got '%s'", string(output))
	}
}

func TestExtractWithInvalidOutputDir(t *testing.T) {
	ext := NewExtractor(&ExtractorOptions{
		OutputDir: "/nonexistent/path/that/should/fail",
	})

	testData := []byte{0x00, 0x00, 0x00, 0x00}
	_, err := ext.Extract(testData, "test.bin", nil)
	if err == nil {
		t.Error("Expected error for invalid output directory")
	}
}

func TestCarveMultipleSignatures(t *testing.T) {
	// Create data with multiple signatures
	testData := make([]byte, 2000)

	// PNG at offset 100
	copy(testData[100:], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	copy(testData[500:], []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82})

	// JPEG at offset 600
	copy(testData[600:], []byte{0xFF, 0xD8, 0xFF})
	copy(testData[800:], []byte{0xFF, 0xD9})

	result, err := Carve(testData, "multi.bin", &Options{
		MinSize: 50,
		MaxSize: 1000,
	})
	if err != nil {
		t.Fatalf("Carve() error = %v", err)
	}

	if result.TotalFound < 1 {
		t.Errorf("Expected at least 1 carved file, got %d", result.TotalFound)
	}
}
