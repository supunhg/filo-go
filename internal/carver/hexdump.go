package carver

import (
	"fmt"
	"strings"
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
		color = "\033[90m" // Gray for null bytes
	case b == 0xFF:
		color = "\033[91m" // Red for 0xFF
	case b >= 0x20 && b <= 0x7E:
		color = "\033[92m" // Green for printable ASCII
	case b == 0x0A || b == 0x0D:
		color = "\033[93m" // Yellow for newlines
	default:
		color = "\033[0m" // Default
	}

	return fmt.Sprintf("%s%02X\033[0m ", color, b)
}

// SignatureScan scans data for known file signatures.
type SignatureScan struct {
	Offset    int64  `json:"offset"`
	Signature string `json:"signature"`
	Format    string `json:"format"`
	MIME      string `json:"mime,omitempty"`
}

// ScanSignatures scans data for file signatures.
func ScanSignatures(data []byte) []SignatureScan {
	var results []SignatureScan

	signatures := []struct {
		Magic  []byte
		Format string
		MIME   string
		Offset int
	}{
		{[]byte{0x89, 0x50, 0x4E, 0x47}, "png", "image/png", 0},
		{[]byte{0xFF, 0xD8, 0xFF}, "jpeg", "image/jpeg", 0},
		{[]byte{0x47, 0x49, 0x46, 0x38}, "gif", "image/gif", 0},
		{[]byte{0x25, 0x50, 0x44, 0x46}, "pdf", "application/pdf", 0},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip", "application/zip", 0},
		{[]byte{0x1F, 0x8B}, "gzip", "application/gzip", 0},
		{[]byte{0x42, 0x5A, 0x68}, "bzip2", "application/x-bzip2", 0},
		{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "xz", "application/x-xz", 0},
		{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z", "application/x-7z-compressed", 0},
		{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "rar", "application/x-rar-compressed", 0},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, "elf", "application/x-executable", 0},
		{[]byte{0x4D, 0x5A}, "pe", "application/x-dosexec", 0},
		{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png", "image/png", 0},
		{[]byte{0x00, 0x00, 0x01, 0x00}, "ico", "image/x-icon", 0},
		{[]byte{0x42, 0x4D}, "bmp", "image/bmp", 0},
		{[]byte{0x49, 0x49, 0x2A, 0x00}, "tiff", "image/tiff", 0},
		{[]byte{0x4D, 0x4D, 0x00, 0x2A}, "tiff", "image/tiff", 0},
		{[]byte{0x52, 0x49, 0x46, 0x46}, "wav", "audio/wav", 0},
		{[]byte{0x66, 0x4C, 0x61, 0x43}, "flac", "audio/flac", 0},
		{[]byte{0x1A, 0x45, 0xDF, 0xA3}, "mkv", "video/x-matroska", 0},
		{[]byte{0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70}, "mp4", "video/mp4", 0},
		{[]byte{0x49, 0x44, 0x33}, "mp3", "audio/mpeg", 0},
		{[]byte{0xFF, 0xFB}, "mp3", "audio/mpeg", 0},
		{[]byte{0x6F, 0x67, 0x67, 0x53}, "ogg", "audio/ogg", 0},
		{[]byte{0x4F, 0x67, 0x67, 0x53}, "ogg", "audio/ogg", 0},
		{[]byte{0x76, 0x2F, 0x31, 0x01}, "av1", "video/av1", 0},
		// SQLite
		{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00}, "sqlite", "application/x-sqlite3", 0},
		// Executables
		{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, "macho", "application/x-mach-binary", 0},
		{[]byte{0xFE, 0xED, 0xFA, 0xCE}, "macho", "application/x-mach-binary", 0},
		{[]byte{0xFE, 0xED, 0xFA, 0xCF}, "macho", "application/x-mach-binary", 0},
		// Java
		{[]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02}, "java_class", "application/java-vm", 0},
		// Web
		{[]byte{0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45}, "html", "text/html", 0},
		{[]byte{0x3C, 0x68, 0x74, 0x6D, 0x6C}, "html", "text/html", 0},
		// Scripts
		{[]byte{0x23, 0x21}, "shell", "text/x-shellscript", 0},
		// Documents
		{[]byte{0x7B, 0x5C, 0x72, 0x74, 0x66}, "rtf", "application/rtf", 0},
		{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "ole2", "application/vnd.ms-office", 0},
		// Archives with offset
		{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip", "application/zip", 0},
		// LUKS
		{[]byte{0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE}, "luks", "application/x-luks", 0},
		// Filesystem images
		{[]byte{0x53, 0x71, 0x75, 0x61, 0x73, 0x68, 0x66, 0x73}, "squashfs", "application/x-squashfs", 0},
		{[]byte{0x68, 0x37, 0x31, 0x38, 0x37}, "cramfs", "application/x-cramfs", 0},
		{[]byte{0x19, 0x35}, "jffs2", "application/x-jffs2", 0},
		// Android
		{[]byte{0x3A, 0x42, 0x49, 0x4E, 0x41, 0x52, 0x59}, "android_img", "application/x-android-binary", 0},
		// Docker
		{[]byte{0x3A, 0x44, 0x4F, 0x43, 0x4B, 0x45, 0x52}, "dockerfile", "text/plain", 0},
	}

	for _, sig := range signatures {
		offset := scanBytes(data, sig.Magic, sig.Offset)
		if offset >= 0 {
			results = append(results, SignatureScan{
				Offset:    int64(offset),
				Signature: fmt.Sprintf("%X", sig.Magic),
				Format:    sig.Format,
				MIME:      sig.MIME,
			})
		}
	}

	return results
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

	for {
		idx := scanBytes(data, pattern, offset)
		if idx < 0 {
			break
		}
		offsets = append(offsets, int64(idx))
		offset = idx + 1
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
