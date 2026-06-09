package firmware

import (
	"fmt"
)

// ExtractionResult represents the result of a file extraction
type ExtractionResult struct {
	Format     string
	SourceFile string
	OutputDir  string
	Files      []ExtractedFile
	Errors     []error
}

// ExtractedFile represents an extracted file
type ExtractedFile struct {
	Name     string
	Path     string
	Size     int64
	Offset   int64
	IsDir    bool
	Mode     uint32
	ModTime  int64
	LinkPath string
}

// DetectFirmware detects the firmware format of a file
func DetectFirmware(filePath string) string {
	if DetectSquashFS(filePath) {
		return "squashfs"
	}
	if DetectCramFS(filePath) {
		return "cramfs"
	}
	if DetectJFFS2(filePath) {
		return "jffs2"
	}
	return "unknown"
}

// ExtractFirmware extracts firmware based on detected format
func ExtractFirmware(srcPath, destDir, format string) (*ExtractionResult, error) {
	switch format {
	case "squashfs":
		return ExtractSquashFS(srcPath, destDir)
	case "cramfs":
		return ExtractCramFS(srcPath, destDir)
	case "jffs2":
		return ExtractJFFS2(srcPath, destDir)
	default:
		return nil, fmt.Errorf("unsupported firmware format: %s", format)
	}
}

// FormatFirmwareInfo formats firmware info for display
func FormatFirmwareInfo(format string, data interface{}) string {
	switch format {
	case "squashfs":
		if sb, ok := data.(*SquashFSSuperblock); ok {
			return FormatSquashFSSuperblock(sb)
		}
	case "cramfs":
		if sb, ok := data.(*CramFSSuperblock); ok {
			return FormatCramFSSuperblock(sb)
		}
	case "jffs2":
		if sb, ok := data.(*JFFS2Superblock); ok {
			return FormatJFFS2Superblock(sb)
		}
	}
	return "Unknown firmware format"
}
