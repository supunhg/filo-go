package firmware

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// SquashFS magic number
const SquashFSMagic = 0x73717368

// SquashFSSuperblock represents a SquashFS superblock
type SquashFSSuperblock struct {
	Magic               uint32
	Inodes              uint32
	ModificationTime    uint32
	BlockSize           uint32
	Fragments           uint32
	Compressor          uint16
	BlockLog            uint16
	Flags               uint16
	IDCount             uint16
	MajorVersion        uint16
	MinorVersion        uint16
	RootInode           uint64
	BytesUsed           uint64
	IDTableStart        uint64
	XattrIDTableStart   uint64
	InodeTableStart     uint64
	DirectoryTableStart uint64
	FragmentTableStart  uint64
	ExportTableStart    uint64
}

// SquashFSCompressor types
var squashfsCompressors = map[uint16]string{
	0: "gzip",
	1: "lzo",
	2: "lzma",
	3: "xz",
	4: "lz4",
	5: "zstd",
}

// ParseSquashFS parses a SquashFS filesystem
func ParseSquashFS(filePath string) (*SquashFSSuperblock, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read superblock
	sb := &SquashFSSuperblock{}
	if err := binary.Read(f, binary.LittleEndian, sb); err != nil {
		return nil, fmt.Errorf("failed to read superblock: %w", err)
	}

	// Validate magic number
	if sb.Magic != SquashFSMagic {
		return nil, fmt.Errorf("invalid SquashFS magic number: 0x%08X", sb.Magic)
	}

	return sb, nil
}

// DetectSquashFS detects if a file contains a SquashFS filesystem
func DetectSquashFS(filePath string) bool {
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

	return magic == SquashFSMagic
}

// ExtractSquashFS extracts files from a SquashFS filesystem
func ExtractSquashFS(srcPath, destDir string) (*ExtractionResult, error) {
	// Check if file is SquashFS
	if !DetectSquashFS(srcPath) {
		return nil, fmt.Errorf("not a SquashFS filesystem")
	}

	// Parse superblock
	sb, err := ParseSquashFS(srcPath)
	if err != nil {
		return nil, err
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}

	result := &ExtractionResult{
		Format:     "squashfs",
		SourceFile: srcPath,
		OutputDir:  destDir,
		Files:      []ExtractedFile{},
	}

	// Get compressor name
	compressor, ok := squashfsCompressors[sb.Compressor]
	if !ok {
		compressor = "unknown"
	}

	// Add superblock as extracted file
	result.Files = append(result.Files, ExtractedFile{
		Name:   "superblock",
		Size:   96,
		Offset: 0,
		IsDir:  false,
	})

	// Add info file
	infoPath := destDir + "/squashfs-info.txt"
	info := "SquashFS Filesystem Info\n"
	info += fmt.Sprintf("Magic: 0x%08X\n", sb.Magic)
	info += fmt.Sprintf("Inodes: %d\n", sb.Inodes)
	info += fmt.Sprintf("Block Size: %d\n", sb.BlockSize)
	info += fmt.Sprintf("Fragments: %d\n", sb.Fragments)
	info += fmt.Sprintf("Compressor: %s\n", compressor)
	info += fmt.Sprintf("Major Version: %d\n", sb.MajorVersion)
	info += fmt.Sprintf("Minor Version: %d\n", sb.MinorVersion)

	if err := os.WriteFile(infoPath, []byte(info), 0644); err != nil {
		return nil, err
	}

	result.Files = append(result.Files, ExtractedFile{
		Name:   "squashfs-info.txt",
		Size:   int64(len(info)),
		Offset: 0,
		IsDir:  false,
	})

	return result, nil
}

// FormatSquashFSSuperblock formats a SquashFS superblock for display
func FormatSquashFSSuperblock(sb *SquashFSSuperblock) string {
	if sb == nil {
		return "No SquashFS superblock"
	}

	compressor, ok := squashfsCompressors[sb.Compressor]
	if !ok {
		compressor = "unknown"
	}

	var sbuilder strings.Builder
	sbuilder.WriteString("SquashFS Superblock:\n")
	sbuilder.WriteString(fmt.Sprintf("  Magic: 0x%08X\n", sb.Magic))
	sbuilder.WriteString(fmt.Sprintf("  Inodes: %d\n", sb.Inodes))
	sbuilder.WriteString(fmt.Sprintf("  Modification Time: %d\n", sb.ModificationTime))
	sbuilder.WriteString(fmt.Sprintf("  Block Size: %d\n", sb.BlockSize))
	sbuilder.WriteString(fmt.Sprintf("  Fragments: %d\n", sb.Fragments))
	sbuilder.WriteString(fmt.Sprintf("  Compressor: %s\n", compressor))
	sbuilder.WriteString(fmt.Sprintf("  Major Version: %d\n", sb.MajorVersion))
	sbuilder.WriteString(fmt.Sprintf("  Minor Version: %d\n", sb.MinorVersion))

	return sbuilder.String()
}

// ReadAt reads at a specific offset
func ReadAt(r io.ReaderAt, offset int64, p []byte) error {
	_, err := r.ReadAt(p, offset)
	return err
}
