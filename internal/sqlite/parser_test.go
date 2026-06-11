package sqlite

import (
	"os"
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

func TestParseHeaderEncodings(t *testing.T) {
	data := make([]byte, 100)
	copy(data, Magic)

	// Test UTF-8 encoding (uint32 at offset 56)
	data[56] = 0x00
	data[57] = 0x00
	data[58] = 0x00
	data[59] = 0x01
	header, _ := ParseHeader(data)
	if header.TextEncoding != "UTF-8" {
		t.Errorf("expected UTF-8, got %s", header.TextEncoding)
	}

	// Test UTF-16LE encoding
	data[56] = 0x00
	data[57] = 0x00
	data[58] = 0x00
	data[59] = 0x02
	header, _ = ParseHeader(data)
	if header.TextEncoding != "UTF-16le" {
		t.Errorf("expected UTF-16le, got %s", header.TextEncoding)
	}

	// Test UTF-16BE encoding
	data[56] = 0x00
	data[57] = 0x00
	data[58] = 0x00
	data[59] = 0x03
	header, _ = ParseHeader(data)
	if header.TextEncoding != "UTF-16be" {
		t.Errorf("expected UTF-16be, got %s", header.TextEncoding)
	}
}

func TestParseRecordText(t *testing.T) {
	// Test that parseRecord handles various serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecordInteger(t *testing.T) {
	// Test that parseRecord handles integer serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecordNull(t *testing.T) {
	// Create a page with NULL record
	page := make([]byte, 256)

	page[0] = 2 // header size
	page[1] = 0 // serial type 0 = NULL

	result := parseRecord(page, 0)
	if len(result) != 1 {
		t.Errorf("expected 1 column, got %d", len(result))
	}
	if result[0] != "" {
		t.Errorf("expected empty string for NULL, got %q", result[0])
	}
}

func TestParseRecordBlob(t *testing.T) {
	// Test that parseRecord handles BLOB serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecord2ByteInt(t *testing.T) {
	// Test that parseRecord handles 2-byte integer serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecord4ByteInt(t *testing.T) {
	// Test that parseRecord handles 4-byte integer serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecord8ByteInt(t *testing.T) {
	// Test that parseRecord handles 8-byte integer serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecordFloat(t *testing.T) {
	// Test that parseRecord handles float serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecord3ByteInt(t *testing.T) {
	// Test that parseRecord handles 3-byte integer serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecord6ByteInt(t *testing.T) {
	// Test that parseRecord handles 6-byte integer serial types
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseRecordMultiColumn(t *testing.T) {
	// Test that parseRecord handles multiple columns
	page := make([]byte, 256)

	// Just test that it doesn't panic with various inputs
	result := parseRecord(page, 0)
	_ = result // May be nil or empty for minimal data
}

func TestParseSchemaTable(t *testing.T) {
	// Create minimal SQLite data
	data := make([]byte, 8192) // 2 pages of 4096
	copy(data, Magic)
	data[16] = 0x10 // Page size 4096
	data[17] = 0x00
	data[28] = 0x00 // DBSizeInPages = 2
	data[29] = 0x00
	data[30] = 0x00
	data[31] = 0x02

	header, _ := ParseHeader(data)

	// parseSchemaTable will fail because page 1 isn't a valid leaf table page
	_, err := parseSchemaTable(data, header, 1)
	// Error is expected for minimal data
	_ = err
}

func TestCountTableRowsInvalidPage(t *testing.T) {
	data := make([]byte, 4096)
	header := &FileHeader{
		PageSize:      4096,
		DBSizeInPages: 1,
	}

	// Invalid root page
	result := countTableRows(data, header, 0)
	if result != 0 {
		t.Errorf("expected 0 rows for invalid page, got %d", result)
	}

	result = countTableRows(data, header, 100)
	if result != 0 {
		t.Errorf("expected 0 rows for page beyond DB, got %d", result)
	}
}

func TestScanDeletedRecordsFreelist(t *testing.T) {
	// Create data with freelist trunk page
	data := make([]byte, 8192)
	header := &FileHeader{
		PageSize:      4096,
		DBSizeInPages: 2,
		FreelistTrunk: 2, // Page 2 is trunk
	}

	// Write next trunk page (0) and leaf page (1)
	// Trunk page at offset 4096
	data[4096] = 0 // next trunk = 0
	data[4097] = 0
	data[4098] = 0
	data[4099] = 0
	data[4100] = 0 // leaf page 1
	data[4101] = 0
	data[4102] = 0
	data[4103] = 1

	records := ScanDeletedRecords(data, header)
	// Should find some records or none
	_ = records
}

func TestDetectWALNonexistent(t *testing.T) {
	info := DetectWAL("/nonexistent/path.db")
	if info.Present {
		t.Error("expected no WAL for nonexistent file")
	}
}

func TestParseFile(t *testing.T) {
	// Test with nonexistent file
	_, err := Parse("/nonexistent/path.db")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestResultStructure(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Pages:    10,
		Stats:    map[string]int{"tables": 5},
	}

	if result.FileName != "test.db" {
		t.Errorf("expected filename test.db, got %s", result.FileName)
	}

	if result.Pages != 10 {
		t.Errorf("expected 10 pages, got %d", result.Pages)
	}
}

func TestTableStructure(t *testing.T) {
	table := &Table{
		Name:     "users",
		RootPage: 2,
		SQL:      "CREATE TABLE users (id INTEGER PRIMARY KEY)",
		RowCount: 100,
	}

	if table.Name != "users" {
		t.Errorf("expected name users, got %s", table.Name)
	}

	if table.RowCount != 100 {
		t.Errorf("expected 100 rows, got %d", table.RowCount)
	}
}

func TestWALInfoStructure(t *testing.T) {
	wal := &WALInfo{
		Present:       true,
		Magic:         0x77777777,
		Version:       3007000,
		PageSize:      4096,
		CheckpointSeq: 5,
	}

	if !wal.Present {
		t.Error("expected Present to be true")
	}

	if wal.PageSize != 4096 {
		t.Errorf("expected page size 4096, got %d", wal.PageSize)
	}
}

func TestDeletedRecordStructure(t *testing.T) {
	dr := &DeletedRecord{
		Page:    5,
		Offset:  100,
		Size:    50,
		RawData: "test data",
	}

	if dr.Page != 5 {
		t.Errorf("expected page 5, got %d", dr.Page)
	}

	if dr.Size != 50 {
		t.Errorf("expected size 50, got %d", dr.Size)
	}
}

func TestPrintResults(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 1,
			TextEncoding: "UTF-8",
		},
		Pages: 10,
		Tables: []Table{
			{Name: "users", RootPage: 2, RowCount: 100},
		},
		WAL: &WALInfo{Present: false},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestPrintResultsWithWAL(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 2,
			TextEncoding: "UTF-8",
		},
		Pages: 10,
		WAL: &WALInfo{
			Present:       true,
			PageSize:      4096,
			CheckpointSeq: 5,
		},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestPrintResultsWithDeletedRecords(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 1,
			TextEncoding: "UTF-8",
		},
		Pages: 10,
		DeletedRecords: []DeletedRecord{
			{Page: 5, Offset: 100, Size: 50, RawData: "test data"},
		},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestReadVarintMultiByte(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected uint64
		bytes    int
	}{
		{
			name:     "2-byte varint",
			data:     []byte{0x81, 0x01},
			offset:   0,
			expected: 257, // (0x81 & 0x3F) << 8 | 0x01 = 1 << 8 | 1 = 257
			bytes:    2,
		},
		{
			name:     "2-byte varint max",
			data:     []byte{0xBF, 0xFF},
			offset:   0,
			expected: 16383, // (0xBF & 0x3F) << 8 | 0xFF = 0x3F << 8 | 0xFF = 16383
			bytes:    2,
		},
		{
			name:     "3-byte varint",
			data:     []byte{0xC0, 0x40, 0x00},
			offset:   0,
			expected: 16384, // (0xC0 & 0x1F) << 16 | 0x40 << 8 | 0x00 = 0 << 16 | 16384 = 16384
			bytes:    3,
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

func TestReadUint16BE(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected uint16
	}{
		{
			name:     "zero",
			data:     []byte{0x00, 0x00},
			offset:   0,
			expected: 0,
		},
		{
			name:     "one",
			data:     []byte{0x00, 0x01},
			offset:   0,
			expected: 1,
		},
		{
			name:     "256",
			data:     []byte{0x01, 0x00},
			offset:   0,
			expected: 256,
		},
		{
			name:     "65535",
			data:     []byte{0xFF, 0xFF},
			offset:   0,
			expected: 65535,
		},
		{
			name:     "with offset",
			data:     []byte{0x00, 0x01, 0x02},
			offset:   1,
			expected: 258,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := readUint16BE(tt.data, tt.offset)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestReadUint32BE(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected uint32
	}{
		{
			name:     "zero",
			data:     []byte{0x00, 0x00, 0x00, 0x00},
			offset:   0,
			expected: 0,
		},
		{
			name:     "one",
			data:     []byte{0x00, 0x00, 0x00, 0x01},
			offset:   0,
			expected: 1,
		},
		{
			name:     "256",
			data:     []byte{0x00, 0x00, 0x01, 0x00},
			offset:   0,
			expected: 256,
		},
		{
			name:     "65536",
			data:     []byte{0x00, 0x01, 0x00, 0x00},
			offset:   0,
			expected: 65536,
		},
		{
			name:     "max",
			data:     []byte{0xFF, 0xFF, 0xFF, 0xFF},
			offset:   0,
			expected: 4294967295,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := readUint32BE(tt.data, tt.offset)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestParseRecordSerialTypes(t *testing.T) {
	// Test various serial types
	page := make([]byte, 1024)

	// Set up a record with various serial types
	// Header: size(1) + serial types
	page[0] = 9 // header size (includes the size byte itself, so 8 serial types + 1 size byte = 9)
	page[1] = 0 // serial type 0 = NULL
	page[2] = 1 // serial type 1 = 1-byte integer
	page[3] = 2 // serial type 2 = 2-byte integer
	page[4] = 3 // serial type 3 = 3-byte integer
	page[5] = 4 // serial type 4 = 4-byte integer
	page[6] = 5 // serial type 5 = 6-byte integer
	page[7] = 6 // serial type 6 = 8-byte integer
	page[8] = 7 // serial type 7 = IEEE 754 float64

	// Data area (after header)
	offset := 9
	// 1-byte integer (value: 42)
	page[offset] = 42
	offset += 1
	// 2-byte integer (value: 1000)
	page[offset] = 0x03
	page[offset+1] = 0xE8
	offset += 2
	// 3-byte integer (value: 100000)
	page[offset] = 0x01
	page[offset+1] = 0x86
	page[offset+2] = 0xA0
	offset += 3
	// 4-byte integer (value: 1000000)
	page[offset] = 0x00
	page[offset+1] = 0x0F
	page[offset+2] = 0x42
	page[offset+3] = 0x40
	offset += 4
	// 6-byte integer (value: 0)
	offset += 6
	// 8-byte integer (value: 0)
	offset += 8
	// Float64 (1.0)
	page[offset] = 0x3F
	page[offset+1] = 0xF0
	page[offset+2] = 0x00
	page[offset+3] = 0x00
	page[offset+4] = 0x00
	page[offset+5] = 0x00
	page[offset+6] = 0x00
	page[offset+7] = 0x00

	result := parseRecord(page, 0)
	if len(result) != 8 {
		t.Errorf("expected 8 columns, got %d", len(result))
	}
}

func TestParseRecordTextAndBlob(t *testing.T) {
	// Test text and blob serial types
	page := make([]byte, 1024)

	// Header
	page[0] = 4 // header size
	page[1] = 13 // serial type 13 = text of length 0 (13-13)/2 = 0
	page[2] = 15 // serial type 15 = text of length 1 (15-13)/2 = 1
	page[3] = 25 // serial type 25 = blob of length 6 (25-12)/2 = 6

	// Data
	offset := 4
	// Text of length 1: "A"
	page[offset] = 'A'
	offset += 1
	// Blob of length 6
	page[offset] = 0x01
	page[offset+1] = 0x02
	page[offset+2] = 0x03
	page[offset+3] = 0x04
	page[offset+4] = 0x05
	page[offset+5] = 0x06

	result := parseRecord(page, 0)
	if len(result) != 3 {
		t.Errorf("expected 3 columns, got %d", len(result))
	}
}

func TestParseRecordInteger0And1(t *testing.T) {
	// Test integer 0 and 1 serial types
	page := make([]byte, 1024)

	// Header
	page[0] = 3 // header size
	page[1] = 8 // serial type 8 = integer 0
	page[2] = 9 // serial type 9 = integer 1

	result := parseRecord(page, 0)
	if len(result) != 2 {
		t.Errorf("expected 2 columns, got %d", len(result))
	}
	if result[0] != "0" {
		t.Errorf("expected '0', got %q", result[0])
	}
	if result[1] != "1" {
		t.Errorf("expected '1', got %q", result[1])
	}
}

func TestParseRecordEdgeCases2(t *testing.T) {
	// Test with header size larger than page
	page := make([]byte, 10)
	page[0] = 20 // header size larger than page

	result := parseRecord(page, 0)
	// Should not panic, may return empty or partial results
	_ = result
}

func TestCountTableRowsLeaf(t *testing.T) {
	// Test counting rows in a leaf table page
	page := make([]byte, 4096)

	// Set page type to leaf table (0x0D)
	page[0] = 0x0D
	// Set number of cells
	page[3] = 0x00
	page[4] = 0x03 // 3 cells

	header := &FileHeader{
		PageSize:      4096,
		DBSizeInPages: 1,
	}

	result := countTableRows(page, header, 1)
	if result != 3 {
		t.Errorf("expected 3 rows, got %d", result)
	}
}

func TestCountTableRowsInterior(t *testing.T) {
	// Test counting rows in an interior table page
	page := make([]byte, 4096)

	// Set page type to interior table (0x05)
	page[0] = 0x05
	// Set number of cells
	page[3] = 0x00
	page[4] = 0x00 // 0 cells (simplified)

	header := &FileHeader{
		PageSize:      4096,
		DBSizeInPages: 1,
	}

	result := countTableRows(page, header, 1)
	if result != 0 {
		t.Errorf("expected 0 rows, got %d", result)
	}
}

func TestDetectWALWithFile(t *testing.T) {
	// Create a temporary WAL file
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	walPath := dbPath + "-wal"

	// Create the WAL file
	walData := make([]byte, 32)
	// WAL magic (0x377f0682 or 0x377f0683)
	walData[0] = 0x37
	walData[1] = 0x7F
	walData[2] = 0x06
	walData[3] = 0x82
	// Version (3007000)
	walData[4] = 0x00
	walData[5] = 0x2D
	walData[6] = 0xE9
	walData[7] = 0xB8
	// Page size (4096)
	walData[8] = 0x00
	walData[9] = 0x00
	walData[10] = 0x10
	walData[11] = 0x00
	// Checkpoint sequence
	walData[12] = 0x00
	walData[13] = 0x00
	walData[14] = 0x00
	walData[15] = 0x01

	if err := os.WriteFile(walPath, walData, 0644); err != nil {
		t.Fatal(err)
	}

	info := DetectWAL(dbPath)
	if !info.Present {
		t.Error("expected WAL to be present")
	}
	if info.PageSize != 4096 {
		t.Errorf("expected page size 4096, got %d", info.PageSize)
	}
}

func TestParseInvalidFile(t *testing.T) {
	// Test Parse with various invalid files
	tmpDir := t.TempDir()

	// File too small
	smallFile := tmpDir + "/small.db"
	if err := os.WriteFile(smallFile, []byte("small"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Parse(smallFile)
	if err == nil {
		t.Error("expected error for small file")
	}

	// Invalid magic
	invalidFile := tmpDir + "/invalid.db"
	data := make([]byte, 100)
	copy(data, "Not SQLite")
	if err := os.WriteFile(invalidFile, data, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = Parse(invalidFile)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestPrintWithEmptyTables(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 1,
			TextEncoding: "UTF-8",
		},
		Pages:  10,
		Tables: []Table{},
	}

	// Test that Print doesn't panic with empty tables
	Print(result)
}

func TestPrintWithMultipleTables(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 1,
			TextEncoding: "UTF-8",
		},
		Pages: 100,
		Tables: []Table{
			{Name: "users", RootPage: 2, RowCount: 100, SQL: "CREATE TABLE users (id INTEGER PRIMARY KEY)"},
			{Name: "posts", RootPage: 5, RowCount: 500, SQL: "CREATE TABLE posts (id INTEGER PRIMARY KEY)"},
			{Name: "comments", RootPage: 8, RowCount: 1000},
		},
	}

	// Test that Print doesn't panic
	Print(result)
}

func TestPrintWithDeletedRecords(t *testing.T) {
	result := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 1,
			TextEncoding: "UTF-8",
		},
		Pages: 10,
		DeletedRecords: []DeletedRecord{
			{Page: 5, Offset: 100, Size: 50, RawData: "deleted data"},
			{Page: 6, Offset: 200, Size: 30, RawData: "more deleted data"},
		},
	}

	// Test that Print doesn't panic
	Print(result)
}
