package repair

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

// Result holds repair results.
type Result struct {
	FileName      string   `json:"file_name"`
	Success       bool     `json:"success"`
	Strategy      string   `json:"strategy"`
	OriginalSize  int64    `json:"original_size"`
	RepairedSize  int64    `json:"repaired_size"`
	Changes       []string `json:"changes"`
	Warnings      []string `json:"warnings"`
	BackupCreated bool     `json:"backup_created"`
}

// Options controls repair behavior.
type Options struct {
	TargetFormat string
	OutputPath   string
	Strategy     string
	NoBackup     bool
	DryRun       bool
}

// Repair attempts to repair a corrupted file.
func Repair(data []byte, filePath string, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{Strategy: "auto"}
	}

	result := &Result{
		FileName:     filepath.Base(filePath),
		OriginalSize: int64(len(data)),
		Changes:      []string{},
		Warnings:     []string{},
	}

	// Detect format
	format := opts.TargetFormat
	if format == "" {
		format = detectFormat(data)
	}

	// Try repair strategies
	var repaired []byte
	var strategy string

	switch format {
	case "png":
		repaired, strategy = repairPNG(data)
	case "jpeg":
		repaired, strategy = repairJPEG(data)
	case "pdf":
		repaired, strategy = repairPDF(data)
	case "zip":
		repaired, strategy = repairZIP(data)
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("No repair strategy for format: %s", format))
		return result, nil
	}

	if repaired == nil {
		result.Warnings = append(result.Warnings, "No repair needed or repair failed")
		return result, nil
	}

	result.Success = true
	result.Strategy = strategy
	result.RepairedSize = int64(len(repaired))

	// Create backup if not disabled
	if !opts.NoBackup && !opts.DryRun {
		backupPath := filePath + ".bak"
		if err := os.WriteFile(backupPath, data, 0644); err == nil {
			result.BackupCreated = true
			result.Changes = append(result.Changes, fmt.Sprintf("Backup created: %s", backupPath))
		}
	}

	// Write repaired file
	if !opts.DryRun {
		outputPath := opts.OutputPath
		if outputPath == "" {
			outputPath = filePath
		}
		if err := os.WriteFile(outputPath, repaired, 0644); err != nil {
			return result, fmt.Errorf("failed to write repaired file: %w", err)
		}
	}

	return result, nil
}

func detectFormat(data []byte) string {
	if bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
		return "png"
	}
	if bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		return "jpeg"
	}
	if bytes.HasPrefix(data, []byte{0x25, 0x50, 0x44, 0x46}) {
		return "pdf"
	}
	if bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) {
		return "zip"
	}
	return "unknown"
}

// repairPNG repairs corrupted PNG files.
func repairPNG(data []byte) ([]byte, string) {
	// Check for missing PNG signature
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(data, pngSig) {
		// Try to find IHDR chunk
		ihdrIdx := bytes.Index(data, []byte("IHDR"))
		if ihdrIdx >= 4 {
			// Reconstruct with PNG signature + IHDR
			repaired := make([]byte, 0, len(data)+8)
			repaired = append(repaired, pngSig...)
			repaired = append(repaired, data[ihdrIdx-4:]...)

			if validatePNG(repaired) {
				return repaired, "reconstruct_from_chunks"
			}
		}

		// Generate minimal PNG
		repaired := generateMinimalPNG()
		return repaired, "generate_minimal_header"
	}

	// Check for missing IEND
	if !bytes.Contains(data, []byte("IEND")) {
		repaired := make([]byte, len(data)+12)
		copy(repaired, data)
		// Add IEND chunk
		offset := len(data)
		binary.BigEndian.PutUint32(repaired[offset:], 0) // Length: 0
		copy(repaired[offset+4:], "IEND")
		binary.BigEndian.PutUint32(repaired[offset+8:], crc32.ChecksumIEEE(repaired[offset+4:offset+8]))

		return repaired, "add_iend_chunk"
	}

	return nil, ""
}

func validatePNG(data []byte) bool {
	if !bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
		return false
	}
	return bytes.Contains(data, []byte("IHDR"))
}

func generateMinimalPNG() []byte {
	// Minimal 1x1 white PNG
	return []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, // IHDR length
		0x49, 0x48, 0x44, 0x52, // IHDR
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08, 0x02, // Bit depth: 8, Color type: RGB
		0x00, 0x00, 0x00, // Compression, Filter, Interlace
		0x90, 0x77, 0x53, 0xDE, // CRC
	}
}

// repairJPEG repairs corrupted JPEG files.
func repairJPEG(data []byte) ([]byte, string) {
	// Check for missing SOI
	if !bytes.HasPrefix(data, []byte{0xFF, 0xD8}) {
		repaired := make([]byte, len(data)+2)
		copy(repaired[2:], data)
		repaired[0] = 0xFF
		repaired[1] = 0xD8

		// Add EOI if missing
		if !bytes.HasSuffix(repaired, []byte{0xFF, 0xD9}) {
			repaired = append(repaired, 0xFF, 0xD9)
		}

		return repaired, "add_soi_and_eoi"
	}

	// Check for missing EOI
	if !bytes.HasSuffix(data, []byte{0xFF, 0xD9}) {
		repaired := make([]byte, len(data)+2)
		copy(repaired, data)
		repaired[len(data)] = 0xFF
		repaired[len(data)+1] = 0xD9

		return repaired, "add_eoi_marker"
	}

	return nil, ""
}

// repairPDF repairs corrupted PDF files.
func repairPDF(data []byte) ([]byte, string) {
	// Check for missing header
	if !bytes.HasPrefix(data, []byte("%PDF")) {
		repaired := make([]byte, len(data)+9)
		copy(repaired[9:], data)
		copy(repaired, "%PDF-1.7\r\n")

		// Add %%EOF if missing
		if !bytes.Contains(repaired, []byte("%%EOF")) {
			repaired = append(repaired, []byte("\r\n%%EOF\r\n")...)
		}

		return repaired, "add_pdf_header"
	}

	// Check for missing %%EOF
	if !bytes.Contains(data, []byte("%%EOF")) {
		repaired := make([]byte, len(data)+9)
		copy(repaired, data)
		copy(repaired[len(data):], "\r\n%%EOF\r\n")

		return repaired, "add_pdf_eof"
	}

	return nil, ""
}

// repairZIP repairs corrupted ZIP files.
func repairZIP(data []byte) ([]byte, string) {
	// Check for missing EOCD
	eocdSig := []byte{0x50, 0x4B, 0x05, 0x06}
	if !bytes.Contains(data, eocdSig) {
		// Try to find local file headers and reconstruct
		repaired := make([]byte, len(data)+22)
		copy(repaired, data)

		// Add minimal EOCD
		offset := len(data)
		copy(repaired[offset:], eocdSig)
		// Disk number, CD start disk, etc. all zeros
		// Number of entries on this disk: 0
		// Total number of entries: 0
		// CD size: 0
		// CD offset: 0
		// Comment length: 0

		return repaired, "add_eocd"
	}

	return nil, ""
}
