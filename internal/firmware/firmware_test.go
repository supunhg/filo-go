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
