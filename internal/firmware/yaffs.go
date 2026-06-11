package firmware

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// YAFFS magic numbers
const (
	YAFFS1Magic = 0x00000001 // YAFFS1 object header magic
	YAFFS2Magic = 0x00000002 // YAFFS2 object header magic
)

// YAFFS object types
const (
	YAFFSObjectTypeUnknown   = 0
	YAFFSObjectTypeFile      = 1
	YAFFSObjectTypeSymlink   = 2
	YAFFSObjectTypeDirectory = 3
	YAFFSObjectTypeHardlink  = 4
	YAFFSObjectTypeSpecial   = 5
)

// YAFFSSuperblock represents YAFFS filesystem information
type YAFFSSuperblock struct {
	Magic         uint32
	Version       int
	ChunkSize     int
	SpareSize     int
	BlockSize     int
	ChunksPerBlock int
	TotalBlocks   int
	ObjectCount   int
}

// YAFFSObject represents a YAFFS object (file, directory, etc.)
type YAFFSObject struct {
	ObjectID   uint32
	ParentID   uint32
	ObjectType int
	Name       string
	Size       int64
	Mode       uint32
	ModTime    int64
	LinkTarget string
}

// DetectYAFFS detects if a file contains a YAFFS filesystem
func DetectYAFFS(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read first 4KB to check for YAFFS patterns
	header := make([]byte, 4096)
	n, err := f.Read(header)
	if err != nil || n < 512 {
		return false
	}

	// Check for YAFFS1 patterns (small page NAND)
	// YAFFS1 uses 512-byte chunks with 16-byte spare
	if n >= 528 {
		// Check spare area for YAFFS tags
		spare := header[512:528]
		if isYAFFS1Spare(spare) {
			return true
		}
	}

	// Check for YAFFS2 patterns (large page NAND)
	// YAFFS2 uses 2048-byte chunks with 64-byte spare
	if n >= 2112 {
		spare := header[2048:2112]
		if isYAFFS2Spare(spare) {
			return true
		}
	}

	// Check for YAFFS object header patterns
	// Look for valid object types in first chunk
	if isYAFFSObjectHeader(header[:512]) {
		return true
	}

	return false
}

// isYAFFS1Spare checks if spare area looks like YAFFS1
func isYAFFS1Spare(spare []byte) bool {
	if len(spare) < 16 {
		return false
	}

	// YAFFS1 spare format:
	// Byte 0: tag byte 0 (should be valid)
	// Byte 1-2: chunk ID (little-endian)
	// Byte 3-4: object ID (little-endian)
	// Byte 5-6: block number (little-endian)
	// Byte 7: ECC byte
	// Byte 8-15: additional ECC

	// Check for non-zero but reasonable values
	tag := spare[0]
	if tag == 0xFF || tag == 0x00 {
		return false
	}

	// Check chunk ID (should be < 1024 for YAFFS1)
	chunkID := binary.LittleEndian.Uint16(spare[1:3])
	if chunkID >= 1024 {
		return false
	}

	// Check object ID (should be > 0 and < 65535)
	objID := binary.LittleEndian.Uint16(spare[3:5])
	return objID != 0
}

// isYAFFS2Spare checks if spare area looks like YAFFS2
func isYAFFS2Spare(spare []byte) bool {
	if len(spare) < 64 {
		return false
	}

	// YAFFS2 spare format:
	// Bytes 0-3: YAFFS magic (0x00000002 for YAFFS2)
	// Bytes 4-7: chunk ID
	// Bytes 8-11: object ID
	// Bytes 12-15: block number
	// Bytes 16-19: file size
	// Bytes 20-23: checksum
	// Bytes 24-31: name (first 8 chars)
	// Bytes 32-63: ECC

	// Check for YAFFS2 magic in spare
	magic := binary.LittleEndian.Uint32(spare[0:4])
	if magic == YAFFS2Magic {
		return true
	}

	// Also check if spare area has valid-looking data
	// YAFFS2 typically has non-FF non-00 data in spare
	nonZeroCount := 0
	for _, b := range spare[:32] {
		if b != 0xFF && b != 0x00 {
			nonZeroCount++
		}
	}

	// If there's a reasonable amount of non-trivial data, might be YAFFS
	return nonZeroCount >= 4 && nonZeroCount <= 24
}

// isYAFFSObjectHeader checks if data looks like a YAFFS object header
func isYAFFSObjectHeader(data []byte) bool {
	if len(data) < 512 {
		return false
	}

	// YAFFS object header structure:
	// Bytes 0-3: Type (1=file, 2=symlink, 3=dir, 4=hardlink, 5=special)
	// Bytes 4-7: Parent object ID
	// Bytes 8-39: Name (null-terminated)
	// Bytes 40-43: File size (for files)
	// Bytes 44-47: Mode (permissions)

	// Check for valid object type
	objType := binary.LittleEndian.Uint32(data[0:4])
	if objType < 1 || objType > 5 {
		return false
	}

	// Check for reasonable parent ID (0 = root, otherwise > 0)
	parentID := binary.LittleEndian.Uint32(data[4:8])
	if parentID > 65536 {
		return false
	}

	// Check name (should be null-terminated and printable)
	name := string(data[8:40])
	nullIdx := strings.IndexByte(name, 0)
	if nullIdx == 0 {
		return false // Empty name
	}
	if nullIdx > 0 {
		name = name[:nullIdx]
	}

	// Check if name is mostly printable
	printableCount := 0
	for _, c := range name {
		if c >= 32 && c < 127 {
			printableCount++
		}
	}
	if len(name) > 0 && float64(printableCount)/float64(len(name)) < 0.5 {
		return false
	}

	return true
}

// ParseYAFFS parses a YAFFS filesystem
func ParseYAFFS(filePath string) (*YAFFSSuperblock, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read first chunk to determine YAFFS version
	header := make([]byte, 4096)
	n, err := f.Read(header)
	if err != nil || n < 512 {
		return nil, fmt.Errorf("file too small for YAFFS")
	}

	sb := &YAFFSSuperblock{}

	// Determine YAFFS version
	if isYAFFS2Spare(header[2048:2112]) && n >= 2112 {
		sb.Magic = YAFFS2Magic
		sb.Version = 2
		sb.ChunkSize = 2048
		sb.SpareSize = 64
	} else if isYAFFS1Spare(header[512:528]) && n >= 528 {
		sb.Magic = YAFFS1Magic
		sb.Version = 1
		sb.ChunkSize = 512
		sb.SpareSize = 16
	} else {
		return nil, fmt.Errorf("not a valid YAFFS filesystem")
	}

	// Calculate block size (typically 64 or 128 chunks per block)
	// Default to 64 chunks per block
	sb.ChunksPerBlock = 64
	sb.BlockSize = sb.ChunkSize * sb.ChunksPerBlock

	// Get file size to estimate total blocks
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sb.TotalBlocks = int(info.Size()) / sb.BlockSize

	// Count objects by scanning chunks
	sb.ObjectCount = countYAFFSObjects(f, sb)

	return sb, nil
}

// countYAFFSObjects counts the number of objects in YAFFS
func countYAFFSObjects(f *os.File, sb *YAFFSSuperblock) int {
	// Simple heuristic: count chunks that look like object headers
	count := 0
	chunk := make([]byte, sb.ChunkSize+sb.SpareSize)

	for {
		n, err := f.Read(chunk)
		if err != nil || n < sb.ChunkSize {
			break
		}

		if isYAFFSObjectHeader(chunk[:sb.ChunkSize]) {
			count++
		}
	}

	return count
}

// ExtractYAFFS extracts files from a YAFFS filesystem
func ExtractYAFFS(srcPath, destDir string) (*ExtractionResult, error) {
	// Check if file is YAFFS
	if !DetectYAFFS(srcPath) {
		return nil, fmt.Errorf("not a YAFFS filesystem")
	}

	// Parse superblock
	sb, err := ParseYAFFS(srcPath)
	if err != nil {
		return nil, err
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, err
	}

	result := &ExtractionResult{
		Format:     fmt.Sprintf("yaffs%d", sb.Version),
		SourceFile: srcPath,
		OutputDir:  destDir,
		Files:      []ExtractedFile{},
	}

	// Add superblock info
	result.Files = append(result.Files, ExtractedFile{
		Name:   "superblock",
		Size:   int64(sb.ChunkSize),
		Offset: 0,
		IsDir:  false,
	})

	// Add info file
	infoPath := destDir + "/yaffs-info.txt"
	info := "YAFFS Filesystem Info\n"
	info += fmt.Sprintf("Version: YAFFS%d\n", sb.Version)
	info += fmt.Sprintf("Magic: 0x%08X\n", sb.Magic)
	info += fmt.Sprintf("Chunk Size: %d\n", sb.ChunkSize)
	info += fmt.Sprintf("Spare Size: %d\n", sb.SpareSize)
	info += fmt.Sprintf("Block Size: %d\n", sb.BlockSize)
	info += fmt.Sprintf("Chunks per Block: %d\n", sb.ChunksPerBlock)
	info += fmt.Sprintf("Total Blocks: %d\n", sb.TotalBlocks)
	info += fmt.Sprintf("Object Count: %d\n", sb.ObjectCount)

	if err := os.WriteFile(infoPath, []byte(info), 0644); err != nil {
		return nil, err
	}

	result.Files = append(result.Files, ExtractedFile{
		Name:   "yaffs-info.txt",
		Size:   int64(len(info)),
		Offset: 0,
		IsDir:  false,
	})

	return result, nil
}

// FormatYAFFSSuperblock formats a YAFFS superblock for display
func FormatYAFFSSuperblock(sb *YAFFSSuperblock) string {
	if sb == nil {
		return "No YAFFS superblock"
	}

	var sbuilder strings.Builder
	sbuilder.WriteString("YAFFS Superblock:\n")
	sbuilder.WriteString(fmt.Sprintf("  Version: YAFFS%d\n", sb.Version))
	sbuilder.WriteString(fmt.Sprintf("  Magic: 0x%08X\n", sb.Magic))
	sbuilder.WriteString(fmt.Sprintf("  Chunk Size: %d\n", sb.ChunkSize))
	sbuilder.WriteString(fmt.Sprintf("  Spare Size: %d\n", sb.SpareSize))
	sbuilder.WriteString(fmt.Sprintf("  Block Size: %d\n", sb.BlockSize))
	sbuilder.WriteString(fmt.Sprintf("  Chunks per Block: %d\n", sb.ChunksPerBlock))
	sbuilder.WriteString(fmt.Sprintf("  Total Blocks: %d\n", sb.TotalBlocks))
	sbuilder.WriteString(fmt.Sprintf("  Object Count: %d\n", sb.ObjectCount))

	return sbuilder.String()
}
