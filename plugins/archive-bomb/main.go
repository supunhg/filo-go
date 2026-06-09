// Package main implements an archive bomb detection plugin for filo-go.
//
// Archive bombs (zip bombs) are compressed files designed to consume
// excessive resources when extracted. Common examples:
// - 42.zip: 42KB compressed → 4.5PB extracted
// - Zip of Death: 10KB → several GB
//
// This plugin detects potential archive bombs by analyzing compression
// ratios and nested archive structures.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/supunhg/filo-go/internal/plugins"
)

func init() {
	plugins.Register(&plugins.Plugin{
		Name:        "archive-bomb",
		Version:     "1.0.0",
		Description: "Detects archive bombs (zip bombs, compression bombs)",
		Author:      "filo-go",
		Analyzer:    analyzeArchiveBomb,
	})
}

// CompressionRatio thresholds
const (
	// HighRatio flags files with compression ratio > 100:1
	HighRatio = 100.0
	// ExtremeRatio flags files with compression ratio > 1000:1
	ExtremeRatio = 1000.0
	// MaxNesting is the maximum nesting level to check
	MaxNesting = 5
)

func analyzeArchiveBomb(ctx *plugins.Context) (*plugins.Result, error) {
	result := &plugins.Result{
		Details: map[string]interface{}{},
	}

	// Check if this is a known archive format
	if !isArchive(ctx.Data) {
		return nil, nil
	}

	// Analyze compression ratio
	ratio, err := analyzeCompressionRatio(ctx.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze compression: %w", err)
	}

	result.Details["compression_ratio"] = ratio

	// Flag based on ratio
	if ratio >= ExtremeRatio {
		result.Format = "archive-bomb"
		result.Confidence = 0.95
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("EXTREME compression ratio detected: %.0f:1", ratio),
			"This file is likely an archive bomb designed to exhaust resources",
		)
		result.Artifacts = append(result.Artifacts, plugins.Artifact{
			Name: "bomb-indicator",
			Type: "flagged",
		})
	} else if ratio >= HighRatio {
		result.Format = "suspicious-archive"
		result.Confidence = 0.7
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("High compression ratio detected: %.0f:1", ratio),
			"This file may be an archive bomb",
		)
	} else {
		// Normal archive, low confidence
		result.Format = "archive"
		result.Confidence = 0.3
	}

	// Check for nested archives (potential recursion bomb)
	nesting := detectNesting(ctx.Data, 0)
	result.Details["nesting_depth"] = nesting

	if nesting >= MaxNesting {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Deep nesting detected: %d levels", nesting),
			"Recursive extraction could cause resource exhaustion",
		)
		if result.Confidence < 0.8 {
			result.Confidence = 0.8
		}
	}

	// Check for ZIP64 (large file support, often used in bombs)
	if isZIP64(ctx.Data) {
		result.Details["zip64"] = true
		result.Warnings = append(result.Warnings,
			"ZIP64 format detected - supports files > 4GB",
		)
	}

	return result, nil
}

// isArchive checks if data starts with known archive signatures.
func isArchive(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// ZIP: PK\x03\x04
	if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
		return true
	}

	// GZIP: \x1f\x8b
	if data[0] == 0x1F && data[1] == 0x8B {
		return true
	}

	// 7z: 7z\xBC\xAF\x27\x1C
	if len(data) >= 6 && data[0] == 0x37 && data[1] == 0x7A && data[2] == 0xBC {
		return true
	}

	// RAR: Rar!\x1a\x07
	if len(data) >= 6 && data[0] == 0x52 && data[1] == 0x61 && data[2] == 0x72 {
		return true
	}

	// BZ2: BZ
	if len(data) >= 3 && data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68 {
		return true
	}

	// XZ: \xfd7zXZ
	if len(data) >= 6 && data[0] == 0xFD && data[1] == 0x37 && data[2] == 0x7A {
		return true
	}

	return false
}

// analyzeCompressionRatio estimates compression ratio.
func analyzeCompressionRatio(data []byte) (float64, error) {
	if len(data) == 0 {
		return 0, nil
	}

	// For ZIP files, read the central directory to get uncompressed size
	if data[0] == 0x50 && data[1] == 0x4B {
		return analyzeZIPRatio(data)
	}

	// For GZIP, try to decompress and compare
	if data[0] == 0x1F && data[1] == 0x8B {
		return analyzeGZIPRatio(data)
	}

	// For other formats, estimate based on entropy
	// Low entropy + small file = likely high compression potential
	entropy := estimateEntropy(data)
	if entropy < 3.0 && len(data) < 1024*1024 {
		return 50.0, nil // Estimate
	}

	return 1.0, nil
}

// analyzeZIPRatio reads ZIP central directory for compression stats.
func analyzeZIPRatio(data []byte) (float64, error) {
	// Find End of Central Directory (EOCD)
	eocdOffset := findEOCD(data)
	if eocdOffset < 0 {
		return 0, fmt.Errorf("EOCD not found")
	}

	// Parse EOCD
	if eocdOffset+22 > len(data) {
		return 0, fmt.Errorf("invalid EOCD")
	}

	totalEntries := int(binary.LittleEndian.Uint16(data[eocdOffset+10 : eocdOffset+12]))
	centralDirSize := int(binary.LittleEndian.Uint32(data[eocdOffset+12 : eocdOffset+16]))

	if totalEntries == 0 || centralDirSize == 0 {
		return 1.0, nil
	}

	// Calculate average entry size
	avgEntrySize := float64(centralDirSize) / float64(totalEntries)

	// Very rough estimation based on file size vs entry count
	compressedSize := float64(len(data))
	uncompressedEstimate := avgEntrySize * float64(totalEntries) * 10 // Rough multiplier

	if compressedSize == 0 {
		return 1.0, nil
	}

	return uncompressedEstimate / compressedSize, nil
}

// analyzeGZIPRatio estimates GZIP compression ratio.
func analyzeGZIPRatio(data []byte) (float64, error) {
	// Try to decompress to get actual size
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer gr.Close()

	// Read up to 1MB to estimate ratio
	buf := make([]byte, 1024*1024)
	totalRead := 0
	for {
		n, err := gr.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if totalRead >= len(buf) {
			break
		}
	}

	if totalRead == 0 {
		return 1.0, nil
	}

	return float64(totalRead) / float64(len(data)), nil
}

// findEOCD finds the End of Central Directory record.
func findEOCD(data []byte) int {
	// EOCD signature: PK\x05\x06
	for i := len(data) - 22; i >= 0; i-- {
		if i+4 > len(data) {
			continue
		}
		if data[i] == 0x50 && data[i+1] == 0x4B && data[i+2] == 0x05 && data[i+3] == 0x06 {
			return i
		}
	}
	return -1
}

// isZIP64 checks if the archive uses ZIP64 extensions.
func isZIP64(data []byte) bool {
	// Look for ZIP64 Extended Information Extra Field signature
	// PK\x01\x04 followed by tag 0x0001
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x50 && data[i+1] == 0x4B && data[i+2] == 0x01 && data[i+3] == 0x04 {
			// Check for ZIP64 extra field
			if i+30 < len(data) {
				extraLen := int(binary.LittleEndian.Uint16(data[i+28 : i+30]))
				if extraLen > 0 && i+30+extraLen <= len(data) {
					for j := i + 30; j < i+30+extraLen-4; j++ {
						if data[j] == 0x01 && data[j+1] == 0x00 {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// detectNesting checks for nested archives.
func detectNesting(data []byte, depth int) int {
	if depth >= MaxNesting {
		return depth
	}

	if !isArchive(data) {
		return depth
	}

	// Simple heuristic: check if file contains archive signatures
	// within the first 1KB (common for zip bombs)
	checkSize := 1024
	if checkSize > len(data) {
		checkSize = len(data)
	}

	nestedCount := 0
	for i := 0; i < checkSize-4; i++ {
		// Check for ZIP signature
		if data[i] == 0x50 && data[i+1] == 0x4B && data[i+2] == 0x03 && data[i+3] == 0x04 {
			nestedCount++
		}
	}

	if nestedCount > 1 {
		return depth + nestedCount
	}

	return depth
}

// estimateEntropy calculates approximate Shannon entropy.
func estimateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	size := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / size
			entropy -= p * log2(p)
		}
	}
	return entropy
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Simple log2 implementation
	ln := 0.0
	for x > 2 {
		x /= 2
		ln++
	}
	return ln
}

func main() {
	// Plugin is registered via init()
}
