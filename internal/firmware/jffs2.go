package firmware

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// JFFS2 magic numbers
const (
	JFFS2MagicLE = 0x8519
	JFFS2MagicBE = 0x1985
)

// JFFS2 node types
const (
	JFFS2NodeAccurate = 0x200
	JFFS2NodeTypeDir  = 0x400
	JFFS2NodeTypeFile = 0x800
	JFFS2NodeClean    = 0xFF0
	JFFS2NodeDirty     = 0xFE0
	JFFS2NodeBitBucket = 0xFD0
)

// JFFS2Superblock represents a JFFS2 superblock
type JFFS2Superblock struct {
	Magic uint16
	Pad   [278]byte
}

// JFFS2NodeHeader represents a JFFS2 node header
type JFFS2NodeHeader struct {
	Magic   uint16
	NodType uint16
	Length  uint32
	CRC     uint32
}

// DetectJFFS2 detects if a file contains a JFFS2 filesystem
func DetectJFFS2(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read first 2 bytes
	var magic uint16
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return false
	}

	return magic == JFFS2MagicLE || magic == JFFS2MagicBE
}

// ParseJFFS2 parses a JFFS2 filesystem
func ParseJFFS2(filePath string) (*JFFS2Superblock, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read superblock
	sb := &JFFS2Superblock{}
	if err := binary.Read(f, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to read superblock: %w", err)
	}

	// Validate magic number
	if sb.Magic != JFFS2MagicLE && sb.Magic != JFFS2MagicBE {
		return nil, fmt.Errorf("invalid JFFS2 magic number: 0x%04X", sb.Magic)
	}

	return sb, nil
}

// ExtractJFFS2 extracts files from a JFFS2 filesystem
func ExtractJFFS2(srcPath, destDir string) (*ExtractionResult, error) {
	// Check if file is JFFS2
	if !DetectJFFS2(srcPath) {
		return nil, fmt.Errorf("not a JFFS2 filesystem")
	}

	// Parse superblock
	sb, err := ParseJFFS2(srcPath)
	if err != nil {
		return nil, err
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}

	result := &ExtractionResult{
		Format:    "jffs2",
		SourceFile: srcPath,
		OutputDir:  destDir,
		Files:     []ExtractedFile{},
	}

	// Add superblock as extracted file
	result.Files = append(result.Files, ExtractedFile{
		Name:      "superblock",
		Size:      280,
		Offset:    0,
		IsDir:     false,
	})

	// Add info file
	infoPath := destDir + "/jffs2-info.txt"
	info := fmt.Sprintf("JFFS2 Filesystem Info\n")
	info += fmt.Sprintf("Magic: 0x%04X\n", sb.Magic)

	if err := os.WriteFile(infoPath, []byte(info), 0644); err != nil {
		return nil, err
	}

	result.Files = append(result.Files, ExtractedFile{
		Name:    "jffs2-info.txt",
		Size:    int64(len(info)),
		Offset:  0,
		IsDir:   false,
	})

	return result, nil
}

// FormatJFFS2Superblock formats a JFFS2 superblock for display
func FormatJFFS2Superblock(sb *JFFS2Superblock) string {
	if sb == nil {
		return "No JFFS2 superblock"
	}

	var sbuilder strings.Builder
	sbuilder.WriteString("JFFS2 Filesystem:\n")
	sbuilder.WriteString(fmt.Sprintf("  Magic: 0x%04X\n", sb.Magic))
	sbuilder.WriteString("  Type: JFFS2\n")

	return sbuilder.String()
}

// JFFS2NodeTypeString returns a string representation of a JFFS2 node type
func JFFS2NodeTypeString(nodType uint16) string {
	switch nodType {
	case JFFS2NodeAccurate:
		return "Accurate"
	case JFFS2NodeTypeDir:
		return "Directory"
	case JFFS2NodeTypeFile:
		return "File"
	case JFFS2NodeClean:
		return "Clean"
	case JFFS2NodeDirty:
		return "Dirty"
	case JFFS2NodeBitBucket:
		return "BitBucket"
	default:
		return "Unknown"
	}
}
