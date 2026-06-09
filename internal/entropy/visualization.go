package entropy

import (
	"fmt"
	"strings"
)

// VizOptions controls visualization output.
type VizOptions struct {
	Width     int
	Height    int
	Color     bool
	ExportPNG bool
}

// DefaultVizOptions returns default visualization options.
func DefaultVizOptions() *VizOptions {
	return &VizOptions{
		Width:  80,
		Height: 20,
		Color:  true,
	}
}

// Visualize creates an ASCII entropy graph similar to binwalk -E.
func Visualize(data []byte, opts *VizOptions) string {
	if opts == nil {
		opts = DefaultVizOptions()
	}

	chunks := Chunks(data, opts.Width)
	if len(chunks) == 0 {
		return "No data to visualize"
	}

	var sb strings.Builder

	// Title
	sb.WriteString(fmt.Sprintf("Entropy Analysis (%d bytes)\n", len(data)))
	sb.WriteString(strings.Repeat("─", opts.Width+10) + "\n")

	// Y-axis labels and bars
	for row := opts.Height; row > 0; row-- {
		threshold := float64(row) / float64(opts.Height) * 8.0

		// Y-axis label
		if row == opts.Height {
			sb.WriteString(fmt.Sprintf(" 8.0 │"))
		} else if row == opts.Height/2 {
			sb.WriteString(fmt.Sprintf(" 4.0 │"))
		} else if row == 1 {
			sb.WriteString(fmt.Sprintf(" 0.0 │"))
		} else {
			sb.WriteString("     │")
		}

		// Bar segments
		for _, chunk := range chunks {
			if chunk.Entropy >= threshold {
				sb.WriteString(entropyBarChar(chunk.Entropy, opts.Color))
			} else {
				sb.WriteString(" ")
			}
		}
		sb.WriteString("\n")
	}

	// X-axis
	sb.WriteString("     └" + strings.Repeat("─", opts.Width) + "\n")
	sb.WriteString("      0%" + strings.Repeat(" ", opts.Width-10) + "100%\n")

	// Legend
	if opts.Color {
		sb.WriteString("\n  Legend: ")
		sb.WriteString("\033[32m██\033[0m Low  ")
		sb.WriteString("\033[33m██\033[0m Med  ")
		sb.WriteString("\033[31m██\033[0m High ")
		sb.WriteString("\033[35m██\033[0m Random\n")
	}

	return sb.String()
}

// entropyBarChar returns a colored block character based on entropy.
func entropyBarChar(ent float64, color bool) string {
	if !color {
		if ent < 2.0 {
			return "░"
		} else if ent < 4.0 {
			return "▒"
		} else if ent < 6.0 {
			return "▓"
		}
		return "█"
	}

	// ANSI color codes
	if ent < 2.0 {
		return "\033[32m█\033[0m" // Green - low entropy
	} else if ent < 4.0 {
		return "\033[33m█\033[0m" // Yellow - medium entropy
	} else if ent < 6.0 {
		return "\033[31m█\033[0m" // Red - high entropy
	}
	return "\033[35m█\033[0m" // Magenta - random/encrypted
}

// MiniViz creates a compact single-line entropy indicator.
func MiniViz(data []byte, width int) string {
	if width <= 0 {
		width = 40
	}

	chunks := Chunks(data, width)
	var sb strings.Builder

	for _, chunk := range chunks {
		sb.WriteString(entropyBarChar(chunk.Entropy, true))
	}

	return sb.String()
}

// EntropyProfile creates a detailed entropy profile.
type EntropyProfile struct {
	Min     float64
	Max     float64
	Average float64
	Chunks  []ChunkInfo
}

// ChunkInfo holds information about a single chunk.
type ChunkInfo struct {
	Offset  int64
	Size    int
	Entropy float64
}

// Profile analyzes entropy distribution.
func Profile(data []byte, chunkSize int) *EntropyProfile {
	if chunkSize <= 0 {
		chunkSize = 1024
	}

	profile := &EntropyProfile{
		Min: 8.0,
		Max: 0.0,
	}

	var totalEnt float64
	var count int

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[i:end]
		ent := Calculate(chunk)

		profile.Chunks = append(profile.Chunks, ChunkInfo{
			Offset:  int64(i),
			Size:    len(chunk),
			Entropy: ent,
		})

		if ent < profile.Min {
			profile.Min = ent
		}
		if ent > profile.Max {
			profile.Max = ent
		}

		totalEnt += ent
		count++
	}

	if count > 0 {
		profile.Average = totalEnt / float64(count)
	}

	return profile
}

// InterpretEntropy returns a human-readable description of entropy level.
func InterpretEntropy(ent float64) string {
	switch {
	case ent < 1.0:
		return "Very low entropy (highly compressible, structured data)"
	case ent < 2.0:
		return "Low entropy (text, code, configuration)"
	case ent < 3.5:
		return "Medium-low entropy (mixed content)"
	case ent < 5.0:
		return "Medium entropy (compressed data, binaries)"
	case ent < 6.5:
		return "High entropy (compressed/encrypted data)"
	case ent < 7.5:
		return "Very high entropy (likely encrypted)"
	default:
		return "Maximum entropy (random data, strong encryption)"
	}
}
