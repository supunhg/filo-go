package firmware

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeTemp writes data to a temp file and returns the path.
func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fw.bin")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return path
}

func TestDetectFirmwareUnknown(t *testing.T) {
	path := writeTemp(t, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	if got := DetectFirmware(path); got != "unknown" {
		t.Errorf("expected 'unknown', got %q", got)
	}
}

func TestDetectFirmwareNonexistent(t *testing.T) {
	if got := DetectFirmware("/nonexistent/file.bin"); got != "unknown" {
		t.Errorf("expected 'unknown' for missing file, got %q", got)
	}
}

func TestDetectFirmwareSquashFS(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], SquashFSMagic)
	path := writeTemp(t, data)
	if got := DetectFirmware(path); got != "squashfs" {
		t.Errorf("expected 'squashfs', got %q", got)
	}
}

func TestDetectFirmwareCramFS(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], CramFSMagic)
	path := writeTemp(t, data)
	if got := DetectFirmware(path); got != "cramfs" {
		t.Errorf("expected 'cramfs', got %q", got)
	}
}

func TestDetectFirmwareJFFS2(t *testing.T) {
	data := make([]byte, 280)
	binary.LittleEndian.PutUint16(data[0:2], JFFS2MagicLE)
	path := writeTemp(t, data)
	if got := DetectFirmware(path); got != "jffs2" {
		t.Errorf("expected 'jffs2', got %q", got)
	}
}

func TestDetectFirmwareJFFS2BE(t *testing.T) {
	data := make([]byte, 280)
	binary.LittleEndian.PutUint16(data[0:2], JFFS2MagicBE)
	path := writeTemp(t, data)
	if got := DetectFirmware(path); got != "jffs2" {
		t.Errorf("expected 'jffs2' for BE magic, got %q", got)
	}
}

func TestExtractFirmwareUnsupported(t *testing.T) {
	_, err := ExtractFirmware("/tmp/x", "/tmp/out", "yaffs")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

// --- CramFS tests ---

func TestDetectCramFSPositive(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], CramFSMagic)
	path := writeTemp(t, data)
	if !DetectCramFS(path) {
		t.Error("expected detection of CramFS")
	}
}

func TestDetectCramFSNegative(t *testing.T) {
	path := writeTemp(t, []byte{0x00, 0x00, 0x00, 0x00})
	if DetectCramFS(path) {
		t.Error("expected no detection for non-CramFS")
	}
}

func TestDetectCramFSNonexistent(t *testing.T) {
	if DetectCramFS("/nonexistent/file") {
		t.Error("expected false for missing file")
	}
}

func TestParseCramFS(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], CramFSMagic)
	binary.LittleEndian.PutUint32(data[4:8], 4096)   // Size
	binary.LittleEndian.PutUint32(data[8:12], 0x100) // Flags
	binary.LittleEndian.PutUint32(data[36:40], 5)    // Edition
	binary.LittleEndian.PutUint32(data[40:44], 100)  // Blocks
	binary.LittleEndian.PutUint32(data[44:48], 50)   // Files
	path := writeTemp(t, data)

	sb, err := ParseCramFS(path)
	if err != nil {
		t.Fatalf("ParseCramFS: %v", err)
	}
	if sb.Magic != CramFSMagic {
		t.Errorf("expected magic=0x%X, got 0x%X", CramFSMagic, sb.Magic)
	}
	if sb.Size != 4096 {
		t.Errorf("expected Size=4096, got %d", sb.Size)
	}
	if sb.Edition != 5 {
		t.Errorf("expected Edition=5, got %d", sb.Edition)
	}
	if sb.Files != 50 {
		t.Errorf("expected Files=50, got %d", sb.Files)
	}
}

func TestParseCramFSInvalidMagic(t *testing.T) {
	path := writeTemp(t, []byte{0x00, 0x00, 0x00, 0x00})
	_, err := ParseCramFS(path)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestParseCramFSNonexistent(t *testing.T) {
	_, err := ParseCramFS("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExtractCramFS(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], CramFSMagic)
	binary.LittleEndian.PutUint32(data[40:44], 100) // Blocks
	binary.LittleEndian.PutUint32(data[44:48], 50)  // Files
	srcPath := writeTemp(t, data)

	destDir := filepath.Join(t.TempDir(), "extracted")
	r, err := ExtractCramFS(srcPath, destDir)
	if err != nil {
		t.Fatalf("ExtractCramFS: %v", err)
	}
	if r.Format != "cramfs" {
		t.Errorf("expected format=cramfs, got %q", r.Format)
	}
	if r.SourceFile != srcPath {
		t.Errorf("expected SourceFile=%q, got %q", srcPath, r.SourceFile)
	}
	if len(r.Files) < 2 {
		t.Errorf("expected at least 2 files (superblock + info), got %d", len(r.Files))
	}
	// Verify the info file was actually written
	infoPath := filepath.Join(destDir, "cramfs-info.txt")
	if _, err := os.Stat(infoPath); err != nil {
		t.Errorf("expected info file at %s: %v", infoPath, err)
	}
}

func TestExtractCramFSNotCramFS(t *testing.T) {
	srcPath := writeTemp(t, []byte{0x00, 0x00, 0x00, 0x00})
	_, err := ExtractCramFS(srcPath, t.TempDir())
	if err == nil {
		t.Error("expected error for non-CramFS file")
	}
}

func TestFormatCramFSSuperblock(t *testing.T) {
	if got := FormatCramFSSuperblock(nil); got != "No CramFS superblock" {
		t.Errorf("expected 'No CramFS superblock' for nil, got %q", got)
	}
	sb := &CramFSSuperblock{
		Magic:   CramFSMagic,
		Size:    4096,
		Edition: 5,
	}
	out := FormatCramFSSuperblock(sb)
	if out == "" {
		t.Error("expected non-empty formatted output")
	}
}

// --- SquashFS tests ---

func TestDetectSquashFSPositive(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], SquashFSMagic)
	path := writeTemp(t, data)
	if !DetectSquashFS(path) {
		t.Error("expected detection of SquashFS")
	}
}

func TestDetectSquashFSNegative(t *testing.T) {
	path := writeTemp(t, []byte{0x00, 0x00, 0x00, 0x00})
	if DetectSquashFS(path) {
		t.Error("expected no detection for non-SquashFS")
	}
}

func TestDetectSquashFSNonexistent(t *testing.T) {
	if DetectSquashFS("/nonexistent/file") {
		t.Error("expected false for missing file")
	}
}

func TestParseSquashFS(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], SquashFSMagic)
	binary.LittleEndian.PutUint32(data[4:8], 100)   // Inodes
	binary.LittleEndian.PutUint32(data[12:16], 4096) // BlockSize
	binary.LittleEndian.PutUint16(data[20:22], 0)    // Compressor (gzip)
	binary.LittleEndian.PutUint16(data[32:34], 4)    // MajorVersion
	binary.LittleEndian.PutUint16(data[34:36], 0)    // MinorVersion
	path := writeTemp(t, data)

	sb, err := ParseSquashFS(path)
	if err != nil {
		t.Fatalf("ParseSquashFS: %v", err)
	}
	if sb.Magic != SquashFSMagic {
		t.Errorf("expected magic=0x%X, got 0x%X", SquashFSMagic, sb.Magic)
	}
	if sb.Inodes != 100 {
		t.Errorf("expected Inodes=100, got %d", sb.Inodes)
	}
	if sb.BlockSize != 4096 {
		t.Errorf("expected BlockSize=4096, got %d", sb.BlockSize)
	}
	if sb.Compressor != 0 {
		t.Errorf("expected Compressor=0 (gzip), got %d", sb.Compressor)
	}
}

func TestParseSquashFSInvalidMagic(t *testing.T) {
	path := writeTemp(t, []byte{0x00, 0x00, 0x00, 0x00})
	_, err := ParseSquashFS(path)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestParseSquashFSNonexistent(t *testing.T) {
	_, err := ParseSquashFS("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExtractSquashFS(t *testing.T) {
	data := make([]byte, 96)
	binary.LittleEndian.PutUint32(data[0:4], SquashFSMagic)
	binary.LittleEndian.PutUint32(data[12:16], 4096) // BlockSize
	binary.LittleEndian.PutUint16(data[20:22], 3)    // Compressor (xz)
	srcPath := writeTemp(t, data)

	destDir := filepath.Join(t.TempDir(), "extracted")
	r, err := ExtractSquashFS(srcPath, destDir)
	if err != nil {
		t.Fatalf("ExtractSquashFS: %v", err)
	}
	if r.Format != "squashfs" {
		t.Errorf("expected format=squashfs, got %q", r.Format)
	}
	if len(r.Files) < 2 {
		t.Errorf("expected at least 2 files, got %d", len(r.Files))
	}
	infoPath := filepath.Join(destDir, "squashfs-info.txt")
	if _, err := os.Stat(infoPath); err != nil {
		t.Errorf("expected info file: %v", err)
	}
}

func TestExtractSquashFSNotSquashFS(t *testing.T) {
	srcPath := writeTemp(t, []byte{0x00, 0x00, 0x00, 0x00})
	_, err := ExtractSquashFS(srcPath, t.TempDir())
	if err == nil {
		t.Error("expected error for non-SquashFS file")
	}
}

func TestFormatSquashFSSuperblock(t *testing.T) {
	if got := FormatSquashFSSuperblock(nil); got != "No SquashFS superblock" {
		t.Errorf("expected 'No SquashFS superblock' for nil, got %q", got)
	}
	sb := &SquashFSSuperblock{
		Magic:        SquashFSMagic,
		MajorVersion: 4,
		MinorVersion: 0,
		Compressor:   4, // lz4
	}
	out := FormatSquashFSSuperblock(sb)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatSquashFSUnknownCompressor(t *testing.T) {
	sb := &SquashFSSuperblock{
		Magic:      SquashFSMagic,
		Compressor: 99, // not in the map
	}
	out := FormatSquashFSSuperblock(sb)
	if out == "" {
		t.Error("expected non-empty output even for unknown compressor")
	}
}

// --- JFFS2 tests ---

func TestDetectJFFS2LE(t *testing.T) {
	data := make([]byte, 280)
	binary.LittleEndian.PutUint16(data[0:2], JFFS2MagicLE)
	path := writeTemp(t, data)
	if !DetectJFFS2(path) {
		t.Error("expected detection of JFFS2 LE")
	}
}

func TestDetectJFFS2BE(t *testing.T) {
	data := make([]byte, 280)
	binary.LittleEndian.PutUint16(data[0:2], JFFS2MagicBE)
	path := writeTemp(t, data)
	if !DetectJFFS2(path) {
		t.Error("expected detection of JFFS2 BE")
	}
}

func TestDetectJFFS2Negative(t *testing.T) {
	path := writeTemp(t, []byte{0x00, 0x00})
	if DetectJFFS2(path) {
		t.Error("expected no detection for non-JFFS2")
	}
}

func TestDetectJFFS2Nonexistent(t *testing.T) {
	if DetectJFFS2("/nonexistent/file") {
		t.Error("expected false for missing file")
	}
}

func TestParseJFFS2(t *testing.T) {
	data := make([]byte, 280)
	binary.LittleEndian.PutUint16(data[0:2], JFFS2MagicLE)
	path := writeTemp(t, data)

	sb, err := ParseJFFS2(path)
	if err != nil {
		t.Fatalf("ParseJFFS2: %v", err)
	}
	if sb.Magic != JFFS2MagicLE {
		t.Errorf("expected LE magic, got 0x%X", sb.Magic)
	}
}

func TestParseJFFS2InvalidMagic(t *testing.T) {
	path := writeTemp(t, []byte{0x00, 0x00})
	_, err := ParseJFFS2(path)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
}

func TestParseJFFS2Nonexistent(t *testing.T) {
	_, err := ParseJFFS2("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExtractJFFS2(t *testing.T) {
	data := make([]byte, 280)
	binary.LittleEndian.PutUint16(data[0:2], JFFS2MagicLE)
	srcPath := writeTemp(t, data)

	destDir := filepath.Join(t.TempDir(), "extracted")
	r, err := ExtractJFFS2(srcPath, destDir)
	if err != nil {
		t.Fatalf("ExtractJFFS2: %v", err)
	}
	if r.Format != "jffs2" {
		t.Errorf("expected format=jffs2, got %q", r.Format)
	}
	if len(r.Files) < 2 {
		t.Errorf("expected at least 2 files, got %d", len(r.Files))
	}
	infoPath := filepath.Join(destDir, "jffs2-info.txt")
	if _, err := os.Stat(infoPath); err != nil {
		t.Errorf("expected info file: %v", err)
	}
}

func TestExtractJFFS2NotJFFS2(t *testing.T) {
	srcPath := writeTemp(t, []byte{0x00, 0x00})
	_, err := ExtractJFFS2(srcPath, t.TempDir())
	if err == nil {
		t.Error("expected error for non-JFFS2 file")
	}
}

func TestFormatJFFS2Superblock(t *testing.T) {
	if got := FormatJFFS2Superblock(nil); got != "No JFFS2 superblock" {
		t.Errorf("expected 'No JFFS2 superblock' for nil, got %q", got)
	}
	sb := &JFFS2Superblock{Magic: JFFS2MagicLE}
	out := FormatJFFS2Superblock(sb)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestJFFS2NodeTypeStringAll(t *testing.T) {
	tests := []struct {
		nodType uint16
		want    string
	}{
		{JFFS2NodeAccurate, "Accurate"},
		{JFFS2NodeTypeDir, "Directory"},
		{JFFS2NodeTypeFile, "File"},
		{JFFS2NodeClean, "Clean"},
		{JFFS2NodeDirty, "Dirty"},
		{JFFS2NodeBitBucket, "BitBucket"},
		{0x9999, "Unknown"},
	}
	for _, tt := range tests {
		if got := JFFS2NodeTypeString(tt.nodType); got != tt.want {
			t.Errorf("JFFS2NodeTypeString(0x%X) = %q, want %q", tt.nodType, got, tt.want)
		}
	}
}

// --- FormatFirmwareInfo tests ---

func TestFormatFirmwareInfoUnknown(t *testing.T) {
	if got := FormatFirmwareInfo("yaffs", nil); got != "Unknown firmware format" {
		t.Errorf("expected 'Unknown firmware format', got %q", got)
	}
}

func TestFormatFirmwareInfoCramFS(t *testing.T) {
	sb := &CramFSSuperblock{Magic: CramFSMagic, Edition: 1}
	out := FormatFirmwareInfo("cramfs", sb)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatFirmwareInfoCramFSWrongType(t *testing.T) {
	// Passing wrong type should fall through to "Unknown firmware format"
	out := FormatFirmwareInfo("cramfs", "not a superblock")
	if out != "Unknown firmware format" {
		t.Errorf("expected 'Unknown firmware format' for wrong type, got %q", out)
	}
}

func TestFormatFirmwareInfoSquashFS(t *testing.T) {
	sb := &SquashFSSuperblock{Magic: SquashFSMagic, MajorVersion: 4}
	out := FormatFirmwareInfo("squashfs", sb)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatFirmwareInfoJFFS2(t *testing.T) {
	sb := &JFFS2Superblock{Magic: JFFS2MagicLE}
	out := FormatFirmwareInfo("jffs2", sb)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

// --- ReadAt test ---

func TestReadAt(t *testing.T) {
	data := []byte("Hello, World!")
	r := &byteReaderAt{data: data}
	buf := make([]byte, 5)
	if err := ReadAt(r, 7, buf); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(buf) != "World" {
		t.Errorf("expected 'World', got %q", string(buf))
	}
}

type byteReaderAt struct {
	data []byte
}

func (b *byteReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if offset >= int64(len(b.data)) {
		return 0, os.ErrInvalid
	}
	n := copy(p, b.data[offset:])
	return n, nil
}
