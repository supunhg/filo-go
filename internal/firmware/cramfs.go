package firmware

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// CramFS magic number
const CramFSMagic = 0x28CD3D45

// CramFSSuperblock represents a CramFS superblock
type CramFSSuperblock struct {
	Magic          uint32
	Size           uint32
	Flags          uint32
	Future         uint32
	Signature      [16]byte
	FsCrc          uint32
	Edition        uint32
	Blocks         uint32
	Files          uint32
	User           uint32
	Gid            uint32
	Name           [16]byte
}

// DetectCramFS detects if a file contains a CramFS filesystem
func DetectCramFS(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read first 4 bytes
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return false
	}

	return magic == CramFSMagic
}

// ParseCramFS parses a CramFS filesystem
func ParseCramFS(filePath string) (*CramFSSuperblock, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read superblock
	sb := &CramFSSuperblock{}
	if err := binary.Read(f, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to read superblock: %w", err)
	}

	// Validate magic number
	if sb.Magic != CramFSMagic {
		return nil, fmt.Errorf("invalid CramFS magic number: 0x%08X", sb.Magic)
	}

	return sb, nil
}

// ExtractCramFS extracts files from a CramFS filesystem
func ExtractCramFS(srcPath, destDir string) (*ExtractionResult, error) {
	// Check if file is CramFS
	if !DetectCramFS(srcPath) {
		return nil, fmt.Errorf("not a CramFS filesystem")
	}

	// Parse superblock
	sb, err := ParseCramFS(srcPath)
	if err != nil {
		return nil, err
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}

	result := &ExtractionResult{
		Format:    "cramfs",
		SourceFile: srcPath,
		OutputDir:  destDir,
		Files:     []ExtractedFile{},
	}

	// Add superblock as extracted file
	result.Files = append(result.Files, ExtractedFile{
		Name:      "superblock",
		Size:      96,
		Offset:    0,
		IsDir:     false,
	})

	// Add info file
	infoPath := destDir + "/cramfs-info.txt"
	info := fmt.Sprintf("CramFS Filesystem Info\n")
	info += fmt.Sprintf("Magic: 0x%08X\n", sb.Magic)
	info += fmt.Sprintf("Size: %d bytes\n", sb.Size)
	info += fmt.Sprintf("Flags: 0x%08X\n", sb.Flags)
	info += fmt.Sprintf("Edition: %d\n", sb.Edition)
	info += fmt.Sprintf("Blocks: %d\n", sb.Blocks)
	info += fmt.Sprintf("Files: %d\n", sb.Files)

	if err := os.WriteFile(infoPath, []byte(info), 0644); err != nil {
		return nil, err
	}

	result.Files = append(result.Files, ExtractedFile{
		Name:    "cramfs-info.txt",
		Size:    int64(len(info)),
		Offset:  0,
		IsDir:   false,
	})

	return result, nil
}

// FormatCramFSSuperblock formats a CramFS superblock for display
func FormatCramFSSuperblock(sb *CramFSSuperblock) string {
	if sb == nil {
		return "No CramFS superblock"
	}

	var sbuilder strings.Builder
	sbuilder.WriteString("CramFS Superblock:\n")
	sbuilder.WriteString(fmt.Sprintf("  Magic: 0x%08X\n", sb.Magic))
	sbuilder.WriteString(fmt.Sprintf("  Size: %d bytes\n", sb.Size))
	sbuilder.WriteString(fmt.Sprintf("  Flags: 0x%08X\n", sb.Flags))
	sbuilder.WriteString(fmt.Sprintf("  Edition: %d\n", sb.Edition))
	sbuilder.WriteString(fmt.Sprintf("  Blocks: %d\n", sb.Blocks))
	sbuilder.WriteString(fmt.Sprintf("  Files: %d\n", sb.Files))

	return sbuilder.String()
}
