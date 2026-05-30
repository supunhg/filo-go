package analyzer

import (
	"fmt"
	"strings"
)

// EntropyViz creates a visual entropy bar chart.
func EntropyViz(chunks []EntropyChunk, width int) string {
	if len(chunks) == 0 {
		return ""
	}

	if width <= 0 {
		width = 64
	}

	var sb strings.Builder
	sb.WriteString("\n  Entropy Visualization\n\n")

	// Find min/max for scaling
	minE, maxE := chunks[0].Entropy, chunks[0].Entropy
	for _, c := range chunks {
		if c.Entropy < minE {
			minE = c.Entropy
		}
		if c.Entropy > maxE {
			maxE = c.Entropy
		}
	}

	// Scale chunks to display width
	chunkWidth := len(chunks) / width
	if chunkWidth < 1 {
		chunkWidth = 1
	}

	for i := 0; i < len(chunks); i += chunkWidth {
		end := i + chunkWidth
		if end > len(chunks) {
			end = len(chunks)
		}

		// Average entropy for this display chunk
		avg := 0.0
		for j := i; j < end; j++ {
			avg += chunks[j].Entropy
		}
		avg /= float64(end - i)

		// Scale to bar width (0-8 scale)
		scaled := avg / 8.0
		barLen := int(scaled * float64(width))
		if barLen > width {
			barLen = width
		}

		// Choose color based on entropy level
		color := entropyColor(avg)
		bar := strings.Repeat("█", barLen)
		sb.WriteString(fmt.Sprintf("  %s%s\033[0m\n", color, bar))
	}

	sb.WriteString("\n  Scale: 0.0 ")
	sb.WriteString(strings.Repeat("─", width-10))
	sb.WriteString(" 8.0\n")

	return sb.String()
}

func entropyColor(e float64) string {
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

// EntropyBar returns a single-line entropy bar.
func EntropyBar(entropy float64, width int) string {
	if width <= 0 {
		width = 40
	}

	scaled := entropy / 8.0
	barLen := int(scaled * float64(width))
	if barLen > width {
		barLen = width
	}

	color := entropyColor(entropy)
	bar := strings.Repeat("█", barLen)
	empty := strings.Repeat("░", width-barLen)

	return fmt.Sprintf("%s%s\033[0m%s %.2f", color, bar, empty, entropy)
}
