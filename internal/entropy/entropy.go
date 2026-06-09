package entropy

import (
	"fmt"
	"math"
)

// Calculate computes Shannon entropy of data (0.0 - 8.0 bits/byte).
func Calculate(data []byte) float64 {
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
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// Interpret returns a human-readable label for an entropy value.
func Interpret(e float64) string {
	switch {
	case e < 1.0:
		return "Very low - likely structured/predictable data"
	case e < 3.0:
		return "Low - simple text or basic compression"
	case e < 5.0:
		return "Medium - compressed data or weak encryption"
	case e < 7.0:
		return "High - compressed or encrypted data"
	default:
		return "Very high - strong encryption or random data"
	}
}

// Chunks splits data into fixed-size chunks and returns per-chunk entropy.
func Chunks(data []byte, chunkSize int) []Chunk {
	var chunks []Chunk
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, Chunk{
			Offset:  int64(i),
			Entropy: Calculate(data[i:end]),
		})
	}
	return chunks
}

// Chunk holds entropy for a segment of data.
type Chunk struct {
	Offset  int64   `json:"offset"`
	Entropy float64 `json:"entropy"`
}

// Bar returns a single-line entropy bar with ANSI colors.
func Bar(entropy float64, width int) string {
	if width <= 0 {
		width = 40
	}

	scaled := entropy / 8.0
	barLen := int(scaled * float64(width))
	if barLen > width {
		barLen = width
	}

	color := Color(entropy)
	empty := width - barLen

	// Build bar: colored blocks + empty blocks + reset + value
	result := color
	for i := 0; i < barLen; i++ {
		result += "\xe2\x96\x88" // █
	}
	result += "\033[0m"
	for i := 0; i < empty; i++ {
		result += "\xe2\x96\x91" // ░
	}
	result += " " + fmt.Sprintf("%.2f", entropy)
	return result
}

// Color returns ANSI color code based on entropy level.
func Color(e float64) string {
	switch {
	case e < 2.0:
		return "\033[32m" // Green - low entropy
	case e < 4.0:
		return "\033[36m" // Cyan - medium-low
	case e < 6.0:
		return "\033[33m" // Yellow - medium
	case e < 7.0:
		return "\033[35m" // Magenta - high
	default:
		return "\033[31m" // Red - very high
	}
}
