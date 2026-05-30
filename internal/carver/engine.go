package carver

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Result holds carving results.
type Result struct {
	FileName   string        `json:"file_name"`
	Carved     []CarvedFile  `json:"carved"`
	TotalFound int           `json:"total_found"`
}

// CarvedFile represents a carved file.
type CarvedFile struct {
	Offset   int64  `json:"offset"`
	Size     int64  `json:"size"`
	Format   string `json:"format"`
	FilePath string `json:"file_path,omitempty"`
}

// Options controls carving behavior.
type Options struct {
	Formats   []string
	OutputDir string
	MinSize   int
	MaxSize   int
}

// Signature represents a file signature for carving.
type Signature struct {
	Magic  []byte
	Format string
	Footer []byte
}

var signatures = []Signature{
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png", []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}},
	{[]byte{0xFF, 0xD8, 0xFF}, "jpeg", []byte{0xFF, 0xD9}},
	{[]byte{0x47, 0x49, 0x46, 0x38}, "gif", []byte{0x00, 0x3B}},
	{[]byte{0x25, 0x50, 0x44, 0x46}, "pdf", []byte{0x25, 0x25, 0x45, 0x4F, 0x46}},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip", nil},
	{[]byte{0x1F, 0x8B}, "gzip", nil},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, "elf", nil},
	{[]byte{0x4D, 0x5A}, "pe", nil},
}

// Carve extracts embedded files from binary data.
func Carve(data []byte, filePath string, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{MinSize: 512}
	}

	result := &Result{
		FileName: filepath.Base(filePath),
		Carved:   []CarvedFile{},
	}

	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = "carved"
	}

	for _, sig := range signatures {
		// Check if format filter is active
		if len(opts.Formats) > 0 {
			found := false
			for _, f := range opts.Formats {
				if f == sig.Format {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		offset := 0
		for {
			idx := bytes.Index(data[offset:], sig.Magic)
			if idx < 0 {
				break
			}
			start := offset + idx
			end := start + len(sig.Magic)

			// Try to find footer for size estimation
			if sig.Footer != nil {
				footerIdx := bytes.Index(data[end:], sig.Footer)
				if footerIdx >= 0 {
					end = end + footerIdx + len(sig.Footer)
				} else {
					// No footer found, estimate size
					end = min(start+opts.MaxSize, len(data))
					if opts.MaxSize == 0 {
						end = min(start+10*1024*1024, len(data)) // 10MB default
					}
				}
			} else {
				end = min(start+opts.MaxSize, len(data))
				if opts.MaxSize == 0 {
					end = min(start+10*1024*1024, len(data))
				}
			}

			size := int64(end - start)
			if size >= int64(opts.MinSize) {
				carved := CarvedFile{
					Offset: int64(start),
					Size:   size,
					Format: sig.Format,
				}

				// Save to file if output directory specified
				if outputDir != "" {
					os.MkdirAll(outputDir, 0755)
					outPath := filepath.Join(outputDir, fmt.Sprintf("%s_%d.%s", sig.Format, start, sig.Format))
					if err := os.WriteFile(outPath, data[start:end], 0644); err == nil {
						carved.FilePath = outPath
					}
				}

				result.Carved = append(result.Carved, carved)
			}

			offset = end
		}
	}

	result.TotalFound = len(result.Carved)
	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
