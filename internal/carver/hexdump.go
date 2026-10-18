package carver

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/supunhg/filo-go/internal/signature"

	"github.com/supunhg/filo-go/internal/term"
)

// HexDumpOptions controls hex dump output.
type HexDumpOptions struct {
	Offset    int64
	Length    int
	Colored   bool
	ShowASCII bool
	Width     int
}

// DefaultHexDumpOptions returns default options.
func DefaultHexDumpOptions() *HexDumpOptions {
	return &HexDumpOptions{
		Offset:    0,
		Length:    256,
		Colored:   true,
		ShowASCII: true,
		Width:     16,
	}
}

// HexDump generates a hex dump similar to xxd or hexdump -C.
func HexDump(data []byte, opts *HexDumpOptions) string {
	if opts == nil {
		opts = DefaultHexDumpOptions()
	}

	if opts.Length <= 0 || opts.Length > len(data) {
		opts.Length = len(data)
	}

	if opts.Width <= 0 {
		opts.Width = 16
	}

	var sb strings.Builder

	// Header
	sb.WriteString("  Offset      ")
	for i := 0; i < opts.Width; i++ {
		sb.WriteString(fmt.Sprintf("%02X ", i))
	}
	if opts.ShowASCII {
		sb.WriteString(" |ASCII")
	}
	sb.WriteString("\n")
	sb.WriteString("  " + strings.Repeat("-", 75) + "\n")

	// Data
	offset := opts.Offset
	end := opts.Offset + int64(opts.Length)

	for pos := opts.Offset; pos < end; pos += int64(opts.Width) {
		// Offset column
		sb.WriteString(fmt.Sprintf("  %08X  ", pos))

		// Hex column
		var asciiLine strings.Builder
		for i := 0; i < opts.Width; i++ {
			idx := pos + int64(i)
			if idx >= int64(len(data)) {
				sb.WriteString("   ")
				asciiLine.WriteString(" ")
				continue
			}

			b := data[idx]
			if opts.Colored {
				sb.WriteString(colorByte(b))
			} else {
				sb.WriteString(fmt.Sprintf("%02X ", b))
			}

			// ASCII representation
			if b >= 32 && b <= 126 {
				asciiLine.WriteString(string(b))
			} else {
				asciiLine.WriteString(".")
			}
		}

		// ASCII column
		if opts.ShowASCII {
			sb.WriteString(" |")
			sb.WriteString(asciiLine.String())
		}
		sb.WriteString("\n")
		_ = offset
	}

	return sb.String()
}

// colorByte returns a colored hex string based on byte value.
func colorByte(b byte) string {
	var color string
	switch {
	case b == 0:
		color = term.C(term.Gray) // Gray for null bytes
	case b == 0xFF:
		color = term.C(term.BrRed) // Red for 0xFF
	case b >= 0x20 && b <= 0x7E:
		color = term.C(term.BrGreen) // Green for printable ASCII
	case b == 0x0A || b == 0x0D:
		color = term.C(term.BrYel) // Yellow for newlines
	default:
		color = term.C(term.Reset) // Default
	}

	return fmt.Sprintf("%s%02X"+term.C(term.Reset)+" ", color, b)
}

// SignatureScan is one embedded file found by ScanSignatures.
type SignatureScan struct {
	Offset      int64  `json:"offset"`
	Size        int64  `json:"size,omitempty"`
	Format      string `json:"format"`
	MIME        string `json:"mime,omitempty"`
	Description string `json:"description"`
}

// ScanSignatures finds embedded files in data using the validated signature
// table in the signature package.
func ScanSignatures(data []byte) []SignatureScan {
	matches := signature.Scan(data, signature.Options{})
	out := make([]SignatureScan, len(matches))
	for i, m := range matches {
		out[i] = SignatureScan{Offset: m.Offset, Size: m.Size, Format: m.Format, MIME: m.MIME, Description: m.Description}
	}
	return out
}

// scanBytes finds the first occurrence of pattern in data.
func scanBytes(data, pattern []byte, startOffset int) int {
	if startOffset < 0 {
		startOffset = 0
	}

	if len(pattern) > len(data) {
		return -1
	}

	for i := startOffset; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}

	return -1
}

// RawSearch searches for a pattern in data.
func RawSearch(data []byte, pattern []byte) []int64 {
	var offsets []int64
	offset := 0

	if len(pattern) == 0 {
		return nil
	}
	for offset <= len(data) {
		idx := bytes.Index(data[offset:], pattern)
		if idx < 0 {
			break
		}
		offsets = append(offsets, int64(offset+idx))
		offset += idx + 1
	}

	return offsets
}

// SearchStrings searches for text strings in data.
func SearchStrings(data []byte, search string) []int64 {
	return RawSearch(data, []byte(search))
}

// SearchHex searches for hex pattern in data.
func SearchHex(data []byte, hexPattern string) ([]int64, error) {
	pattern, err := hexToBytes(hexPattern)
	if err != nil {
		return nil, err
	}
	return RawSearch(data, pattern), nil
}

func hexToBytes(hex string) ([]byte, error) {
	// Remove spaces and convert
	hex = strings.ReplaceAll(hex, " ", "")
	if len(hex)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}

	result := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := hex[i+j]
			switch {
			case c >= '0' && c <= '9':
				b = b*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				b = b*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				b = b*16 + (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i/2] = b
	}
	return result, nil
}
