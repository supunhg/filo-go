package sqlite

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseHeaderAllEncodings verifies all three supported text encodings.
func TestParseHeaderAllEncodings(t *testing.T) {
	cases := []struct {
		name string
		enc  uint32
		want string
	}{
		{"UTF-8", EncodingUTF8, "UTF-8"},
		{"UTF-16LE", EncodingUTF16LE, "UTF-16le"},
		{"UTF-16BE", EncodingUTF16BE, "UTF-16be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 100)
			copy(data, Magic)
			// Encoding is a big-endian uint32 at offset 56.
			data[56] = byte((tc.enc >> 24) & 0xFF)
			data[57] = byte((tc.enc >> 16) & 0xFF)
			data[58] = byte((tc.enc >> 8) & 0xFF)
			data[59] = byte(tc.enc & 0xFF)
			h, err := ParseHeader(data)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}
			if h.TextEncoding != tc.want {
				t.Errorf("TextEncoding = %q, want %q", h.TextEncoding, tc.want)
			}
		})
	}
}

// TestParseHeaderPageSize65536 verifies the "page size == 1 means 65536"
// behavior.
func TestParseHeaderPageSize65536(t *testing.T) {
	data := make([]byte, 100)
	copy(data, Magic)
	data[16] = 0x00
	data[17] = 0x01 // page size = 1
	h, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.PageSize != 65536 {
		t.Errorf("PageSize = %d, want 65536", h.PageSize)
	}
}

// TestParseHeaderFields verifies that all the parsed fields propagate
// from the raw bytes to the FileHeader struct.
func TestParseHeaderFields(t *testing.T) {
	data := make([]byte, 100)
	copy(data, Magic)
	data[16] = 0x10 // page size 4096
	data[17] = 0x00
	data[18] = 2    // write version
	data[19] = 2    // read version
	data[20] = 0x20 // reserved bytes
	// file change count at offset 24 (uint32 BE)
	data[24] = 0x00
	data[25] = 0x00
	data[26] = 0x00
	data[27] = 0x05
	// db size in pages at offset 28
	data[28] = 0x00
	data[29] = 0x00
	data[30] = 0x00
	data[31] = 0x0A // 10 pages
	// schema cookie at offset 40
	data[40] = 0x00
	data[41] = 0x00
	data[42] = 0x00
	data[43] = 0x07
	// user version at offset 48
	data[48] = 0x00
	data[49] = 0x00
	data[50] = 0x00
	data[51] = 0x01
	h, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.WriteVersion != 2 {
		t.Errorf("WriteVersion = %d, want 2", h.WriteVersion)
	}
	if h.ReadVersion != 2 {
		t.Errorf("ReadVersion = %d, want 2", h.ReadVersion)
	}
	if h.ReservedBytes != 0x20 {
		t.Errorf("ReservedBytes = %d, want 32", h.ReservedBytes)
	}
	if h.FileChangeCount != 5 {
		t.Errorf("FileChangeCount = %d, want 5", h.FileChangeCount)
	}
	if h.DBSizeInPages != 10 {
		t.Errorf("DBSizeInPages = %d, want 10", h.DBSizeInPages)
	}
	if h.SchemaCookie != 7 {
		t.Errorf("SchemaCookie = %d, want 7", h.SchemaCookie)
	}
	if h.UserVersion != 1 {
		t.Errorf("UserVersion = %d, want 1", h.UserVersion)
	}
}

// TestDetectWALWithTruncatedFile verifies that a WAL file shorter than 32
// bytes returns Present=false.
func TestDetectWALWithTruncatedFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	walPath := dbPath + "-wal"
	if err := os.WriteFile(walPath, []byte{0x01, 0x02, 0x03, 0x04}, 0644); err != nil {
		t.Fatalf("write wal: %v", err)
	}
	os.WriteFile(dbPath, []byte("fake"), 0644)

	info := DetectWAL(dbPath)
	if info.Present {
		t.Error("expected Present=false for truncated WAL")
	}
}

// TestPrintFullResult exercises the full Print code path, including WAL and
// deleted records.
func TestPrintFullResult(t *testing.T) {
	r := &Result{
		FileName: "test.db",
		Header: &FileHeader{
			Magic:        "SQLite format 3",
			PageSize:     4096,
			WriteVersion: 2,
			TextEncoding: "UTF-8",
		},
		Pages: 10,
		Tables: []Table{
			{Name: "users", RootPage: 2, RowCount: 100, SQL: "CREATE TABLE users (id INTEGER)"},
			{Name: "posts", RootPage: 3, RowCount: 250, SQL: "CREATE TABLE posts (id INTEGER)"},
		},
		WAL: &WALInfo{
			Present:       true,
			PageSize:      4096,
			CheckpointSeq: 5,
		},
		DeletedRecords: []DeletedRecord{
			{Page: 5, Offset: 100, Size: 50, RawData: "suspicious data string"},
		},
	}
	// Should not panic.
	Print(r)
}

// TestReadUint16BEAndUint32BE exercises both helpers.
func TestReadUint16BEAndUint32BE(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	if got := readUint16BE(data, 0); got != 0x1234 {
		t.Errorf("readUint16BE = 0x%X, want 0x1234", got)
	}
	if got := readUint32BE(data, 2); got != 0x56789ABC {
		t.Errorf("readUint32BE = 0x%X, want 0x56789ABC", got)
	}
}
