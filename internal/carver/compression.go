package carver

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// CompressionType represents the type of compression
type CompressionType int

const (
	CompressionNone CompressionType = iota
	CompressionGzip
	CompressionBzip2
	CompressionXZ
	CompressionLZMA
	CompressionZstd
	CompressionLZ4
	CompressionSnappy
)

// String returns the string representation of CompressionType
func (c CompressionType) String() string {
	switch c {
	case CompressionGzip:
		return "gzip"
	case CompressionBzip2:
		return "bzip2"
	case CompressionXZ:
		return "xz"
	case CompressionLZMA:
		return "lzma"
	case CompressionZstd:
		return "zstd"
	case CompressionLZ4:
		return "lz4"
	case CompressionSnappy:
		return "snappy"
	default:
		return "none"
	}
}

// DetectCompression detects the compression type of data
func DetectCompression(data []byte) CompressionType {
	if len(data) < 2 {
		return CompressionNone
	}

	// Gzip: 1f 8b
	if data[0] == 0x1F && data[1] == 0x8B {
		return CompressionGzip
	}

	// Bzip2: 42 5a 68
	if len(data) >= 3 && data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68 {
		return CompressionBzip2
	}

	// XZ: fd 37 7a 58 5a 00
	if len(data) >= 6 && data[0] == 0xFD && data[1] == 0x37 && data[2] == 0x7A &&
		data[3] == 0x58 && data[4] == 0x5A && data[5] == 0x00 {
		return CompressionXZ
	}

	// LZMA: 5d 00 00
	if data[0] == 0x5D && data[1] == 0x00 && data[2] == 0x00 {
		return CompressionLZMA
	}

	// Zstd: 28 b5 2f fd
	if len(data) >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
		return CompressionZstd
	}

	// LZ4: 04 22 4d 18
	if len(data) >= 4 && data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4D && data[3] == 0x18 {
		return CompressionLZ4
	}

	// Snappy: (varies, but often starts with specific frames)
	// Not implementing Snappy detection as it's less common

	return CompressionNone
}

// Decompress decompresses data using the specified compression type
func Decompress(data []byte, compType CompressionType) ([]byte, error) {
	switch compType {
	case CompressionGzip:
		return decompressGzip(data)
	case CompressionXZ, CompressionLZMA:
		return decompressXZ(data)
	case CompressionBzip2:
		return decompressBzip2(data)
	default:
		return nil, fmt.Errorf("unsupported compression type: %s", compType)
	}
}

// decompressGzip decompresses gzip data
func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// decompressXZ decompresses XZ/LZMA data
func decompressXZ(data []byte) ([]byte, error) {
	reader, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create xz reader: %w", err)
	}

	return io.ReadAll(reader)
}

// decompressBzip2 decompresses bzip2 data (placeholder)
func decompressBzip2(data []byte) ([]byte, error) {
	// bzip2 decompression would require a bzip2 library
	// For now, return an error
	return nil, fmt.Errorf("bzip2 decompression not implemented")
}

// DecompressFile decompresses a file and writes the output
func DecompressFile(srcPath, dstPath string, compType CompressionType) error {
	// Read source file
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Detect compression if not specified
	if compType == CompressionNone {
		compType = DetectCompression(data)
		if compType == CompressionNone {
			return fmt.Errorf("no compression detected")
		}
	}

	// Decompress
	decompressed, err := Decompress(data, compType)
	if err != nil {
		return err
	}

	// Create destination directory
	dir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write output
	return os.WriteFile(dstPath, decompressed, 0644)
}

// FindCompressedFiles finds compressed files in a directory
func FindCompressedFiles(dir string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		if DetectCompression(data) != CompressionNone {
			files = append(files, path)
		}
	}

	return files, nil
}

// CompressionInfo holds information about compressed data
type CompressionInfo struct {
	Type            CompressionType
	OriginalSize    int
	CompressedSize  int
	Ratio           float64
	NeedsDecompress bool
}

// AnalyzeCompression analyzes compression in data
func AnalyzeCompression(data []byte) *CompressionInfo {
	compType := DetectCompression(data)
	if compType == CompressionNone {
		return &CompressionInfo{
			Type:            CompressionNone,
			CompressedSize:  len(data),
			NeedsDecompress: false,
		}
	}

	// Try to decompress to get original size
	decompressed, err := Decompress(data, compType)
	if err != nil {
		return &CompressionInfo{
			Type:            compType,
			CompressedSize:  len(data),
			NeedsDecompress: true,
		}
	}

	ratio := float64(len(decompressed)) / float64(len(data))

	return &CompressionInfo{
		Type:            compType,
		OriginalSize:    len(decompressed),
		CompressedSize:  len(data),
		Ratio:           ratio,
		NeedsDecompress: true,
	}
}

// FormatCompressionInfo formats compression info for display
func FormatCompressionInfo(info *CompressionInfo) string {
	if info == nil || info.Type == CompressionNone {
		return "No compression detected"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Compression: %s\n", info.Type))
	sb.WriteString(fmt.Sprintf("  Compressed size: %d bytes\n", info.CompressedSize))

	if info.OriginalSize > 0 {
		sb.WriteString(fmt.Sprintf("  Original size: %d bytes\n", info.OriginalSize))
		sb.WriteString(fmt.Sprintf("  Compression ratio: %.2f:1\n", info.Ratio))
	}

	return sb.String()
}

// SearchForCompression searches data for compressed regions
func SearchForCompression(data []byte, minSize int) []CompressionRegion {
	var regions []CompressionRegion

	// Search for common compression signatures
	signatures := []struct {
		compType CompressionType
		header   []byte
	}{
		{CompressionGzip, []byte{0x1F, 0x8B}},
		{CompressionXZ, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}},
		{CompressionLZMA, []byte{0x5D, 0x00, 0x00}},
		{CompressionZstd, []byte{0x28, 0xB5, 0x2F, 0xFD}},
		{CompressionLZ4, []byte{0x04, 0x22, 0x4D, 0x18}},
	}

	for i := 0; i <= len(data)-minSize; i++ {
		for _, sig := range signatures {
			if i+len(sig.header) <= len(data) && bytes.Equal(data[i:i+len(sig.header)], sig.header) {
				// Found a compression signature
				regions = append(regions, CompressionRegion{
					Offset:      i,
					Compression: sig.compType,
				})
				break
			}
		}
	}

	return regions
}

// CompressionRegion represents a compressed region in data
type CompressionRegion struct {
	Offset      int
	Compression CompressionType
	Size        int
}
