package sqlite

import (
	"testing"
)

func TestParseHeader(t *testing.T) {
	// Create a minimal SQLite header (100 bytes)
	data := make([]byte, 100)
	copy(data, Magic) // "SQLite format 3\0"
	data[16] = 0x10   // Page size high byte
	data[17] = 0x00   // Page size low byte (4096)
	data[18] = 0x01   // Write version
	data[19] = 0x01   // Read version
	data[20] = 0x00   // Reserved bytes
	data[56] = 0x01   // Encoding (UTF-8)

	header, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if header.Magic != "SQLite format 3" {
		t.Errorf("expected magic 'SQLite format 3', got %q", header.Magic)
	}

	if header.PageSize != 4096 {
		t.Errorf("expected page size 4096, got %d", header.PageSize)
	}

	if header.WriteVersion != 1 {
		t.Errorf("expected write version 1, got %d", header.WriteVersion)
	}

	if header.ReadVersion != 1 {
		t.Errorf("expected read version 1, got %d", header.ReadVersion)
	}

	if header.TextEncoding != "UTF-8" {
		t.Errorf("expected UTF-8 encoding, got %s", header.TextEncoding)
	}
}

func TestParseHeaderTooSmall(t *testing.T) {
	data := make([]byte, 50) // Too small
	_, err := ParseHeader(data)
	if err == nil {
		t.Error("expected error for small file")
	}
}

func TestParseHeaderInvalidMagic(t *testing.T) {
	data := make([]byte, 100)
	copy(data, "Not a SQLite file")
	_, err := ParseHeader(data)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected uint64
		bytes    int
	}{
		{
			name:     "single byte",
			data:     []byte{0x7F},
			offset:   0,
			expected: 127,
			bytes:    1,
		},
		{
			name:     "zero",
			data:     []byte{0x00},
			offset:   0,
			expected: 0,
			bytes:    1,
		},
		{
			name:     "one",
			data:     []byte{0x01},
			offset:   0,
			expected: 1,
			bytes:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, n := readVarint(tt.data, tt.offset)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
			if n != tt.bytes {
				t.Errorf("expected %d bytes, got %d", tt.bytes, n)
			}
		})
	}
}

func TestDetectWAL(t *testing.T) {
	// No WAL file
	info := DetectWAL("/nonexistent/path.db")
	if info.Present {
		t.Error("expected no WAL for nonexistent file")
	}
}

func TestParseRecord(t *testing.T) {
	// Minimal test with empty data
	page := make([]byte, 100)
	result := parseRecord(page, 0)
	if result != nil {
		t.Error("expected nil for minimal data")
	}
}

func TestCountTableRows(t *testing.T) {
	// Test with invalid data
	data := make([]byte, 100)
	header := &FileHeader{
		PageSize:      4096,
		DBSizeInPages: 1,
	}
	result := countTableRows(data, header, 1)
	if result != 0 {
		t.Errorf("expected 0 rows for minimal data, got %d", result)
	}
}

func TestScanDeletedRecords(t *testing.T) {
	// Test with minimal data
	data := make([]byte, 4096)
	header := &FileHeader{
		PageSize:      4096,
		DBSizeInPages: 1,
		FreelistTrunk: 0,
	}
	records := ScanDeletedRecords(data, header)
	if len(records) != 0 {
		t.Errorf("expected 0 deleted records for minimal data, got %d", len(records))
	}
}

func TestFloat64FromBits(t *testing.T) {
	// Test IEEE 754 conversion
	bits := uint64(0x3FF0000000000000) // 1.0
	result := float64frombits(bits)
	if result != 1.0 {
		t.Errorf("expected 1.0, got %f", result)
	}
}

func TestParseRecordEdgeCases(t *testing.T) {
	// Test with offset beyond data
	page := make([]byte, 10)
	result := parseRecord(page, 100)
	if result != nil {
		t.Error("expected nil for offset beyond data")
	}
}

func TestReadVarintEdgeCases(t *testing.T) {
	// Test with empty data
	result, n := readVarint([]byte{}, 0)
	if result != 0 || n != 0 {
		t.Errorf("expected 0,0 for empty data, got %d,%d", result, n)
	}

	// Test with offset beyond data
	result, n = readVarint([]byte{0x01}, 10)
	if result != 0 || n != 0 {
		t.Errorf("expected 0,0 for offset beyond data, got %d,%d", result, n)
	}
}

func TestFileHeader(t *testing.T) {
	// Test all page size values
	data := make([]byte, 100)
	copy(data, Magic)
	
	// Test page size 512
	data[16] = 0x02
	data[17] = 0x00
	header, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header.PageSize != 512 {
		t.Errorf("expected page size 512, got %d", header.PageSize)
	}

	// Test page size 1 (means 65536)
	data[16] = 0x00
	data[17] = 0x01
	header, err = ParseHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header.PageSize != 65536 {
		t.Errorf("expected page size 65536, got %d", header.PageSize)
	}
}
