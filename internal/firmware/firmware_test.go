package firmware

import (
	"os"
	"testing"
)

func TestDetectFirmware(t *testing.T) {
	// Test with non-existent file
	format := DetectFirmware("/tmp/nonexistent")
	if format != "unknown" {
		t.Errorf("Expected 'unknown', got %s", format)
	}
}

func TestFormatFirmwareInfo(t *testing.T) {
	// Test with unknown format
	info := FormatFirmwareInfo("unknown", nil)
	if info != "Unknown firmware format" {
		t.Errorf("Expected 'Unknown firmware format', got %s", info)
	}

	// Test with SquashFS
	sb := &SquashFSSuperblock{
		Magic:     SquashFSMagic,
		Inodes:    100,
		BlockSize: 4096,
	}
	info = FormatFirmwareInfo("squashfs", sb)
	if info == "" {
		t.Error("Expected non-empty info")
	}

	// Test with CramFS
	sb2 := &CramFSSuperblock{
		Magic: CramFSMagic,
		Size:  1024,
	}
	info = FormatFirmwareInfo("cramfs", sb2)
	if info == "" {
		t.Error("Expected non-empty info")
	}

	// Test with JFFS2
	sb3 := &JFFS2Superblock{
		Magic: JFFS2MagicLE,
	}
	info = FormatFirmwareInfo("jffs2", sb3)
	if info == "" {
		t.Error("Expected non-empty info")
	}
}

func TestExtractFirmware(t *testing.T) {
	// Test with non-existent file
	_, err := ExtractFirmware("/tmp/nonexistent", "/tmp/output", "squashfs")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestDetectSquashFS(t *testing.T) {
	// Create test file
	tmpFile, err := os.CreateTemp("", "test-squashfs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write SquashFS magic
	data := []byte{0x68, 0x73, 0x71, 0x73} // little-endian
	tmpFile.Write(data)
	tmpFile.Close()

	// Test detection
	if !DetectSquashFS(tmpFile.Name()) {
		t.Error("Expected true for SquashFS file")
	}
}

func TestDetectCramFS(t *testing.T) {
	// Create test file
	tmpFile, err := os.CreateTemp("", "test-cramfs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write CramFS magic
	data := []byte{0x45, 0x3D, 0xCD, 0x28} // little-endian
	tmpFile.Write(data)
	tmpFile.Close()

	// Test detection
	if !DetectCramFS(tmpFile.Name()) {
		t.Error("Expected true for CramFS file")
	}
}

func TestDetectJFFS2(t *testing.T) {
	// Create test file
	tmpFile, err := os.CreateTemp("", "test-jffs2-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write JFFS2 magic
	data := []byte{0x19, 0x85} // little-endian
	tmpFile.Write(data)
	tmpFile.Close()

	// Test detection
	if !DetectJFFS2(tmpFile.Name()) {
		t.Error("Expected true for JFFS2 file")
	}
}

func TestJFFS2NodeTypeString(t *testing.T) {
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
		{0xFFFF, "Unknown"},
	}

	for _, tt := range tests {
		got := JFFS2NodeTypeString(tt.nodType)
		if got != tt.want {
			t.Errorf("JFFS2NodeTypeString(%d) = %s, want %s", tt.nodType, got, tt.want)
		}
	}
}

func TestDetectYAFFS(t *testing.T) {
	// Test with non-existent file
	if DetectYAFFS("/tmp/nonexistent") {
		t.Error("Expected false for non-existent file")
	}

	// Test with empty file
	tmpFile, err := os.CreateTemp("", "test-yaffs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if DetectYAFFS(tmpFile.Name()) {
		t.Error("Expected false for empty file")
	}
}

func TestFormatYAFFSSuperblock(t *testing.T) {
	// Test with nil
	info := FormatYAFFSSuperblock(nil)
	if info != "No YAFFS superblock" {
		t.Errorf("Expected 'No YAFFS superblock', got %s", info)
	}

	// Test with valid superblock
	sb := &YAFFSSuperblock{
		Magic:         YAFFS1Magic,
		Version:       1,
		ChunkSize:     512,
		SpareSize:     16,
		BlockSize:     32768,
		ChunksPerBlock: 64,
		TotalBlocks:   100,
		ObjectCount:   50,
	}
	info = FormatYAFFSSuperblock(sb)
	if info == "" {
		t.Error("Expected non-empty info")
	}

	// Test with YAFFS2
	sb2 := &YAFFSSuperblock{
		Magic:         YAFFS2Magic,
		Version:       2,
		ChunkSize:     2048,
		SpareSize:     64,
		BlockSize:     131072,
		ChunksPerBlock: 64,
		TotalBlocks:   200,
		ObjectCount:   100,
	}
	info = FormatYAFFSSuperblock(sb2)
	if info == "" {
		t.Error("Expected non-empty info")
	}
}

func TestYAFFSDetectionWithFile(t *testing.T) {
	// Create a test file with YAFFS-like patterns
	tmpFile, err := os.CreateTemp("", "test-yaffs-pattern-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write data that looks like YAFFS1 (512 bytes + 16 bytes spare)
	data := make([]byte, 1024)
	// First chunk: object header
	data[0] = 0x01 // type = file
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x00
	// Parent ID = 1
	data[4] = 0x01
	data[5] = 0x00
	data[6] = 0x00
	data[7] = 0x00
	// Name "test.txt" at offset 8
	copy(data[8:], "test.txt")

	// Spare area at offset 512
	data[512] = 0x01 // tag byte
	data[513] = 0x00 // chunk ID low
	data[514] = 0x00 // chunk ID high
	data[515] = 0x01 // object ID low
	data[516] = 0x00 // object ID high

	tmpFile.Write(data)
	tmpFile.Close()

	// Test detection (may or may not detect depending on heuristics)
	// This is a heuristic-based detection, so we just test it doesn't panic
	DetectYAFFS(tmpFile.Name())
}

func TestExtractYAFFS(t *testing.T) {
	// Test with non-existent file
	_, err := ExtractYAFFS("/tmp/nonexistent", "/tmp/output")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test with empty file
	tmpFile, err := os.CreateTemp("", "test-yaffs-extract-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	_, err = ExtractYAFFS(tmpFile.Name(), "/tmp/yaffs-output")
	if err == nil {
		t.Error("Expected error for empty file")
	}
}
