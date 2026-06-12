package sqlite

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
)

// Magic is the SQLite file signature.
const Magic = "SQLite format 3\x00"

// B-tree page type constants.
const (
	PageTypeInteriorIndex = 0x02
	PageTypeLeafIndex     = 0x0A
	PageTypeInteriorTable = 0x05
	PageTypeLeafTable     = 0x0D
)

// Text encoding constants.
const (
	EncodingUTF8    = 1
	EncodingUTF16LE = 2
	EncodingUTF16BE = 3
)

// FileHeader represents the 100-byte SQLite database file header.
type FileHeader struct {
	Magic           string `json:"magic"`
	PageSize        int    `json:"page_size"`
	WriteVersion    int    `json:"write_version"`
	ReadVersion     int    `json:"read_version"`
	ReservedBytes   int    `json:"reserved_bytes"`
	FileChangeCount uint32 `json:"file_change_count"`
	DBSizeInPages   uint32 `json:"db_size_in_pages"`
	FreelistTrunk   uint32 `json:"freelist_trunk_page"`
	FreelistPages   uint32 `json:"freelist_pages"`
	SchemaCookie    uint32 `json:"schema_cookie"`
	SchemaFormat    uint32 `json:"schema_format"`
	Encoding        int    `json:"encoding"`
	UserVersion     uint32 `json:"user_version"`
	AutoVacuum      uint32 `json:"auto_vacuum"`
	TextEncoding    string `json:"text_encoding"`
}

// Table represents an extracted SQLite table.
type Table struct {
	Name     string   `json:"name"`
	RootPage int      `json:"root_page"`
	SQL      string   `json:"sql"`
	Columns  []string `json:"columns,omitempty"`
	RowCount int      `json:"row_count"`
}

// WALInfo represents WAL journal metadata.
type WALInfo struct {
	Present       bool   `json:"present"`
	Magic         uint32 `json:"magic,omitempty"`
	Version       uint32 `json:"version,omitempty"`
	PageSize      int    `json:"page_size,omitempty"`
	CheckpointSeq uint32 `json:"checkpoint_sequence,omitempty"`
}

// DeletedRecord represents a recovered deleted record.
type DeletedRecord struct {
	Page    int    `json:"page"`
	Offset  int    `json:"offset"`
	Size    int    `json:"size"`
	RawData string `json:"raw_data,omitempty"`
}

// Result holds the complete SQLite analysis results.
type Result struct {
	FileName       string          `json:"file_name"`
	Header         *FileHeader     `json:"header"`
	Tables         []Table         `json:"tables"`
	WAL            *WALInfo        `json:"wal"`
	DeletedRecords []DeletedRecord `json:"deleted_records,omitempty"`
	Pages          int             `json:"total_pages"`
	Stats          map[string]int  `json:"stats"`
}

// readUint16BE reads a big-endian uint16.
func readUint16BE(data []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(data[offset : offset+2])
}

// readUint32BE reads a big-endian uint32.
func readUint32BE(data []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(data[offset : offset+4])
}

// readVarint reads a SQLite variable-length integer (1-9 bytes).
// SQLite varint encoding: first byte determines additional bytes needed.
// 0x00-0x7F: 1 byte, 0x80-0xBF: 2 bytes, 0xC0-0xDF: 3 bytes, etc.
func readVarint(data []byte, offset int) (uint64, int) {
	if offset >= len(data) {
		return 0, 0
	}
	first := data[offset]
	if first <= 0x7F {
		return uint64(first), 1
	}

	var numBytes int
	switch {
	case first >= 0x80 && first <= 0xBF:
		numBytes = 2
	case first >= 0xC0 && first <= 0xDF:
		numBytes = 3
	case first >= 0xE0 && first <= 0xEF:
		numBytes = 4
	case first >= 0xF0 && first <= 0xF7:
		numBytes = 5
	case first >= 0xF8 && first <= 0xFB:
		numBytes = 6
	case first >= 0xFC && first <= 0xFD:
		numBytes = 7
	case first == 0xFE:
		numBytes = 8
	case first == 0xFF:
		numBytes = 9
	}

	if offset+numBytes > len(data) {
		return 0, 0
	}

	// Strip the high bits that encode the length
	mask := byte(0x7F) >> uint(numBytes-1)
	result := uint64(first & mask)
	for i := 1; i < numBytes; i++ {
		result = (result << 8) | uint64(data[offset+i])
	}
	return result, numBytes
}

// ParseHeader reads the 100-byte SQLite file header.
func ParseHeader(data []byte) (*FileHeader, error) {
	if len(data) < 100 {
		return nil, fmt.Errorf("file too small for SQLite header (%d bytes)", len(data))
	}

	magic := string(data[:16])
	if magic != Magic {
		return nil, fmt.Errorf("not a valid SQLite file: invalid magic %q", magic)
	}

	pageSize := int(readUint16BE(data, 16))
	if pageSize == 1 {
		pageSize = 65536
	}

	encoding := int(readUint32BE(data, 56))
	encName := "UTF-8"
	switch encoding {
	case EncodingUTF16LE:
		encName = "UTF-16le"
	case EncodingUTF16BE:
		encName = "UTF-16be"
	}

	return &FileHeader{
		Magic:           strings.TrimRight(magic, "\x00"),
		PageSize:        pageSize,
		WriteVersion:    int(data[18]),
		ReadVersion:     int(data[19]),
		ReservedBytes:   int(data[20]),
		FileChangeCount: readUint32BE(data, 24),
		DBSizeInPages:   readUint32BE(data, 28),
		FreelistTrunk:   readUint32BE(data, 32),
		FreelistPages:   readUint32BE(data, 36),
		SchemaCookie:    readUint32BE(data, 40),
		SchemaFormat:    readUint32BE(data, 44),
		Encoding:        encoding,
		UserVersion:     readUint32BE(data, 48),
		AutoVacuum:      readUint32BE(data, 52),
		TextEncoding:    encName,
	}, nil
}

// parseSchemaTable extracts the sqlite_master table to find all tables.
func parseSchemaTable(data []byte, header *FileHeader, rootPage int) ([]Table, error) {
	pageSize := header.PageSize
	if rootPage < 1 || rootPage > int(header.DBSizeInPages) {
		return nil, fmt.Errorf("invalid root page %d", rootPage)
	}

	// Calculate the offset of the root page in the file.
	pageOffset := (rootPage - 1) * pageSize
	if pageOffset+pageSize > len(data) {
		return nil, fmt.Errorf("root page %d exceeds file size", rootPage)
	}

	page := data[pageOffset : pageOffset+pageSize]

	// Check page type.
	if len(page) < 8 {
		return nil, nil
	}
	pageType := page[0]
	if pageType != PageTypeLeafTable {
		return nil, fmt.Errorf("sqlite_master root is not a leaf table page (type 0x%02x)", pageType)
	}

	// Parse cells from the leaf page.
	numCells := int(readUint16BE(page, 3))
	tables := make([]Table, 0, numCells)

	for i := 0; i < numCells; i++ {
		cellOffset := 8 + i*2 // Cell pointer array starts at offset 8
		if cellOffset+2 > len(page) {
			break
		}
		cellPtr := int(readUint16BE(page, cellOffset))
		if cellPtr >= len(page) {
			continue
		}

		// For leaf table cells: varint(payload size), varint(rowid), record data
		_, n := readVarint(page, cellPtr)
		if n == 0 {
			continue
		}
		cellPtr += n

		_, n = readVarint(page, cellPtr)
		if n == 0 {
			continue
		}
		cellPtr += n

		// Parse the record to extract type, name, tbl_name, rootpage, sql
		cols := parseRecord(page, cellPtr)
		if len(cols) >= 5 {
			typeVal := cols[0]
			name := cols[1]
			tblName := cols[2]
			rootpage := cols[3]
			sql := cols[4]

			if typeVal == "table" && name == tblName {
				rp := 0
				_, _ = fmt.Sscanf(rootpage, "%d", &rp) // rootpage should be integer
				tables = append(tables, Table{
					Name:     name,
					RootPage: rp,
					SQL:      sql,
				})
			}
		}
	}

	return tables, nil
}

// parseRecord extracts column values from a SQLite record format.
// The record header contains serial types; we extract the text values.
func parseRecord(page []byte, offset int) []string {
	if offset >= len(page) {
		return nil
	}

	// Record header: varint(header size), then serial types
	headerSize, n := readVarint(page, offset)
	if n == 0 {
		return nil
	}
	offset += n
	_ = headerSize

	// Read serial types
	var serialTypes []uint64
	headerEnd := offset + int(headerSize) - n
	for offset < headerEnd && offset < len(page) {
		st, sn := readVarint(page, offset)
		if sn == 0 {
			break
		}
		offset += sn
		serialTypes = append(serialTypes, st)
	}

	// Read column values based on serial types
	var cols []string
	for _, st := range serialTypes {
		switch {
		case st == 0:
			// NULL
			cols = append(cols, "")
		case st == 1:
			// 1-byte integer
			if offset < len(page) {
				cols = append(cols, fmt.Sprintf("%d", int8(page[offset])))
				offset += 1
			}
		case st == 2:
			// 2-byte integer
			if offset+2 <= len(page) {
				cols = append(cols, fmt.Sprintf("%d", int16(readUint16BE(page, offset))))
				offset += 2
			}
		case st == 3:
			// 3-byte integer
			if offset+3 <= len(page) {
				v := uint32(page[offset])<<16 | uint32(page[offset+1])<<8 | uint32(page[offset+2])
				cols = append(cols, fmt.Sprintf("%d", v))
				offset += 3
			}
		case st == 4:
			// 4-byte integer
			if offset+4 <= len(page) {
				cols = append(cols, fmt.Sprintf("%d", readUint32BE(page, offset)))
				offset += 4
			}
		case st == 5:
			// 6-byte integer
			if offset+6 <= len(page) {
				v := uint64(readUint32BE(page, offset))<<16 | uint64(readUint16BE(page, offset+4))
				cols = append(cols, fmt.Sprintf("%d", v))
				offset += 6
			}
		case st == 6:
			// 8-byte integer
			if offset+8 <= len(page) {
				v := uint64(readUint32BE(page, offset))<<32 | uint64(readUint32BE(page, offset+4))
				cols = append(cols, fmt.Sprintf("%d", v))
				offset += 8
			}
		case st == 7:
			// IEEE 754 float64
			if offset+8 <= len(page) {
				bits := uint64(readUint32BE(page, offset))<<32 | uint64(readUint32BE(page, offset+4))
				cols = append(cols, fmt.Sprintf("%g", float64frombits(bits)))
				offset += 8
			}
		case st == 8:
			// Integer 0
			cols = append(cols, "0")
		case st == 9:
			// Integer 1
			cols = append(cols, "1")
		case st >= 12 && st%2 == 0:
			// BLOB of length (st-12)/2
			blobLen := int((st - 12) / 2)
			if offset+blobLen <= len(page) {
				cols = append(cols, fmt.Sprintf("[BLOB %d bytes]", blobLen))
				offset += blobLen
			}
		case st >= 13 && st%2 == 1:
			// Text of length (st-13)/2
			textLen := int((st - 13) / 2)
			if offset+textLen <= len(page) {
				cols = append(cols, string(page[offset:offset+textLen]))
				offset += textLen
			}
		default:
			// Unknown serial type, skip
			cols = append(cols, "")
		}
	}

	return cols
}

// float64frombits converts uint64 bits to float64.
func float64frombits(b uint64) float64 {
	return math.Float64frombits(b)
}

// countTableRows counts rows in a table by iterating its leaf pages.
func countTableRows(data []byte, header *FileHeader, rootPage int) int {
	if rootPage < 1 || rootPage > int(header.DBSizeInPages) {
		return 0
	}

	pageSize := header.PageSize
	pageOffset := (rootPage - 1) * pageSize
	if pageOffset+pageSize > len(data) {
		return 0
	}

	page := data[pageOffset : pageOffset+pageSize]
	if len(page) < 8 {
		return 0
	}

	pageType := page[0]

	switch pageType {
	case PageTypeLeafTable:
		return int(readUint16BE(page, 3))
	case PageTypeInteriorTable:
		// Sum up children
		numCells := int(readUint16BE(page, 3))
		total := 0
		for i := 0; i < numCells; i++ {
			cellOffset := 8 + i*2
			if cellOffset+2 > len(page) {
				break
			}
			// Interior table cells start with a 4-byte left-child page number
			leftChildPage := int(readUint32BE(page, int(readUint16BE(page, cellOffset))))
			total += countTableRows(data, header, leftChildPage)
		}
		return total
	}
	return 0
}

// DetectWAL checks for a companion WAL file and parses its header.
func DetectWAL(dbPath string) *WALInfo {
	walPath := dbPath + "-wal"
	info := &WALInfo{Present: false}

	f, err := os.Open(walPath)
	if err != nil {
		return info
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.Size() < 32 {
		return info
	}

	header := make([]byte, 32)
	if _, err := f.Read(header); err != nil {
		return info
	}

	info.Present = true
	info.Magic = readUint32BE(header, 0)
	info.Version = readUint32BE(header, 4)
	info.PageSize = int(readUint32BE(header, 8))
	if info.PageSize == 1 {
		info.PageSize = 65536
	}
	info.CheckpointSeq = readUint32BE(header, 12)

	return info
}

// ScanDeletedRecords scans for potential deleted records in freeblocks.
func ScanDeletedRecords(data []byte, header *FileHeader) []DeletedRecord {
	var records []DeletedRecord
	pageSize := header.PageSize
	totalPages := int(header.DBSizeInPages)

	// Scan freelist trunk pages for clues
	trunkPage := int(header.FreelistTrunk)
	freelistPages := make(map[int]bool)
	for trunkPage > 0 && trunkPage <= totalPages && len(records) < 1000 {
		freelistPages[trunkPage] = true
		offset := (trunkPage - 1) * pageSize
		if offset+pageSize > len(data) {
			break
		}
		// Trunk page: first 4 bytes = next trunk page, rest = leaf page numbers
		nextTrunk := int(readUint32BE(data, offset))
		for i := 4; i+4 <= pageSize && offset+i+4 <= len(data); i += 4 {
			leafPage := int(readUint32BE(data, offset+i))
			if leafPage > 0 && leafPage <= totalPages {
				freelistPages[leafPage] = true
			}
		}
		trunkPage = nextTrunk
	}

	// Sample freeblock content from freelist pages
	for page := range freelistPages {
		if len(records) >= 500 {
			break
		}
		pageOffset := (page - 1) * pageSize
		if pageOffset+pageSize > len(data) {
			continue
		}
		pageData := data[pageOffset : pageOffset+pageSize]

		// Look for recognizable patterns in freed pages
		for i := 0; i < pageSize-8; i++ {
			// Look for text-like content (potential deleted record data)
			textStart := i
			textLen := 0
			for j := i; j < pageSize && j < i+256; j++ {
				if pageData[j] >= 0x20 && pageData[j] < 0x7f {
					textLen++
				} else if pageData[j] == 0 && textLen > 4 {
					break
				} else {
					textLen = 0
					break
				}
			}
			if textLen > 8 {
				records = append(records, DeletedRecord{
					Page:    page,
					Offset:  textStart,
					Size:    textLen,
					RawData: string(pageData[textStart : textStart+textLen]),
				})
				i = textStart + textLen
				if len(records) >= 500 {
					break
				}
			}
		}
	}

	return records
}

// Parse analyzes a SQLite database file.
func Parse(filePath string) (*Result, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	header, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	result := &Result{
		FileName: filePath,
		Header:   header,
		Stats:    make(map[string]int),
	}

	// Total pages
	if header.DBSizeInPages > 0 {
		result.Pages = int(header.DBSizeInPages)
	} else {
		result.Pages = (len(data) + header.PageSize - 1) / header.PageSize
	}
	result.Stats["pages"] = result.Pages

	// Parse schema (sqlite_master is always at page 1, root page 1)
	tables, err := parseSchemaTable(data, header, 1)
	if err != nil {
		return nil, fmt.Errorf("parsing schema: %w", err)
	}

	// Count rows for each table
	for i := range tables {
		tables[i].RowCount = countTableRows(data, header, tables[i].RootPage)
		result.Stats["rows_"+tables[i].Name] = tables[i].RowCount
	}
	result.Tables = tables
	result.Stats["tables"] = len(tables)

	// Check for WAL
	result.WAL = DetectWAL(filePath)
	if result.WAL.Present {
		result.Stats["wal_pages"] = 1
	}

	// Scan for deleted records in freelist
	result.DeletedRecords = ScanDeletedRecords(data, header)
	result.Stats["deleted_records"] = len(result.DeletedRecords)

	return result, nil
}

// Print displays the SQLite analysis results.
func Print(r *Result) {
	h := r.Header
	fmt.Println()
	fmt.Printf("  SQLite Database: %s\n", r.FileName)
	fmt.Printf("  Format Version:  %s\n", h.Magic)
	fmt.Printf("  Page Size:       %d bytes\n", h.PageSize)
	fmt.Printf("  Total Pages:     %d\n", r.Pages)
	fmt.Printf("  DB Size:         %d pages\n", h.DBSizeInPages)
	fmt.Printf("  Text Encoding:   %s\n", h.TextEncoding)
	fmt.Printf("  Write Version:   %d", h.WriteVersion)
	if h.WriteVersion == 2 {
		fmt.Print(" (WAL)")
	}
	fmt.Println()
	fmt.Printf("  User Version:    %d\n", h.UserVersion)
	fmt.Printf("  Freelist Pages:  %d\n", h.FreelistPages)
	fmt.Println()

	// Tables
	if len(r.Tables) > 0 {
		fmt.Printf("  Tables (%d):\n", len(r.Tables))
		for _, t := range r.Tables {
			fmt.Printf("    - %s (root page %d, ~%d rows)\n", t.Name, t.RootPage, t.RowCount)
			if t.SQL != "" {
				fmt.Printf("      %s\n", t.SQL)
			}
		}
		fmt.Println()
	}

	// WAL
	if r.WAL != nil && r.WAL.Present {
		fmt.Println("  WAL Journal: present")
		fmt.Printf("    Page Size: %d, Checkpoint Seq: %d\n", r.WAL.PageSize, r.WAL.CheckpointSeq)
		fmt.Println()
	}

	// Deleted records
	if len(r.DeletedRecords) > 0 {
		fmt.Printf("  Potential Deleted Records: %d\n", len(r.DeletedRecords))
		for i, dr := range r.DeletedRecords {
			if i >= 20 {
				fmt.Printf("    ... and %d more\n", len(r.DeletedRecords)-20)
				break
			}
			if dr.RawData != "" {
				preview := dr.RawData
				if len(preview) > 60 {
					preview = preview[:60] + "..."
				}
				fmt.Printf("    Page %d, offset %d: %q\n", dr.Page, dr.Offset, preview)
			}
		}
		fmt.Println()
	}
}
