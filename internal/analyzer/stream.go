package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/supunhg/filo-go/internal/entropy"
	"github.com/supunhg/filo-go/internal/formats"
)

// StreamOptions controls streaming analysis behavior.
type StreamOptions struct {
	ChunkSize   int    // Size of chunks to process (default 1MB)
	MaxFileSize int64  // Maximum file size to process (0 = unlimited)
	FormatsDir  string // Path to format definitions
}

// StreamResult holds streaming analysis results.
type StreamResult struct {
	FilePath       string  `json:"file_path"`
	FileName       string  `json:"file_name"`
	FileSize       int64   `json:"file_size"`
	Format         string  `json:"format"`
	MIME           string  `json:"mime"`
	Confidence     float64 `json:"confidence"`
	Entropy        float64 `json:"entropy"`
	EntropyLabel   string  `json:"entropy_label"`
	TotalChunks    int     `json:"total_chunks"`
	ProcessedBytes int64   `json:"processed_bytes"`
}

// AnalyzeStream performs streaming analysis on a file without loading it entirely into memory.
// This is suitable for files >100MB.
func AnalyzeStream(filePath string, opts *StreamOptions) (*StreamResult, error) {
	if opts == nil {
		opts = &StreamOptions{
			ChunkSize: 1024 * 1024, // 1MB default
		}
	}

	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat file: %w", err)
	}

	// Check max file size
	if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
		return nil, fmt.Errorf("file size %d exceeds maximum %d", info.Size(), opts.MaxFileSize)
	}

	// Open file for streaming
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	result := &StreamResult{
		FilePath: filePath,
		FileName: filepath.Base(filePath),
		FileSize: info.Size(),
	}

	// Read first chunk for format detection
	headerSize := 8192 // 8KB for format detection
	header := make([]byte, headerSize)
	n, err := io.ReadAtLeast(file, header, 4)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("cannot read header: %w", err)
	}
	header = header[:n]

	// Detect format from header
	format, mime, confidence := detectFormatStream(header, opts.FormatsDir)
	result.Format = format
	result.MIME = mime
	result.Confidence = confidence

	// Calculate entropy in chunks
	file.Seek(0, io.SeekStart)
	chunkSize := opts.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 1024 * 1024
	}

	var totalEntropy float64
	var totalBytes int64
	chunkCount := 0

	buf := make([]byte, chunkSize)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			chunkEntropy := entropy.Calculate(buf[:n])
			totalEntropy += chunkEntropy * float64(n)
			totalBytes += int64(n)
			chunkCount++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
	}

	// Calculate weighted average entropy
	if totalBytes > 0 {
		result.Entropy = totalEntropy / float64(totalBytes)
	}
	result.EntropyLabel = entropy.Interpret(result.Entropy)
	result.TotalChunks = chunkCount
	result.ProcessedBytes = totalBytes

	return result, nil
}

// detectFormatStream detects format from header bytes.
func detectFormatStream(header []byte, formatsDir string) (string, string, float64) {
	// Try YAML format database first
	if formatsDir != "" {
		if db, err := formats.NewDatabase(formatsDir); err == nil {
			results := db.Match(header)
			if len(results) > 0 {
				best := results[0]
				mime := ""
				if len(best.Format.MIME) > 0 {
					mime = best.Format.MIME[0]
				}
				return best.Format.Format, mime, best.Confidence
			}
		}
	}

	// Fallback to magic byte detection
	if len(header) < 4 {
		return "unknown", "application/octet-stream", 0
	}

	// Common format signatures
	signatures := []struct {
		magic    []byte
		format   string
		mime     string
		conf     float64
	}{
		{[]byte{0x89, 0x50, 0x4E, 0x47}, "png", "image/png", 0.95},
		{[]byte{0xFF, 0xD8, 0xFF}, "jpeg", "image/jpeg", 0.95},
		{[]byte{0x47, 0x49, 0x46, 0x38}, "gif", "image/gif", 0.95},
		{[]byte{0x25, 0x50, 0x44, 0x46}, "pdf", "application/pdf", 0.95},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip", "application/zip", 0.90},
		{[]byte{0x1F, 0x8B}, "gzip", "application/gzip", 0.90},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, "elf", "application/x-executable", 0.95},
		{[]byte{0x4D, 0x5A}, "pe", "application/x-dosexec", 0.90},
		{[]byte{0x52, 0x61, 0x72, 0x21}, "rar", "application/x-rar", 0.90},
		{[]byte{0x37, 0x7A, 0xBC, 0xAF}, "7z", "application/x-7z", 0.90},
	}

	for _, sig := range signatures {
		if len(header) >= len(sig.magic) {
			match := true
			for i, b := range sig.magic {
				if header[i] != b {
					match = false
					break
				}
			}
			if match {
				return sig.format, sig.mime, sig.conf
			}
		}
	}

	return "unknown", "application/octet-stream", 0
}
