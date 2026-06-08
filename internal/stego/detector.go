package stego

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"regexp"
	"strings"
)

// Result holds steganography analysis results.
type Result struct {
	FileName string          `json:"file_name"`
	Format   string          `json:"format"`
	Methods  []MethodResult  `json:"methods"`
	Flags    []string        `json:"flags,omitempty"`
}

// MethodResult holds results from a single detection method.
type MethodResult struct {
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
	Data       string  `json:"data,omitempty"`
	HasFlag    bool    `json:"has_flag"`
	Preview    string  `json:"preview,omitempty"`
}

// Detect performs steganography analysis on a file.
func Detect(data []byte, fileName string) (*Result, error) {
	result := &Result{
		FileName: fileName,
		Methods:  []MethodResult{},
		Flags:    []string{},
	}

	if len(data) < 8 {
		return result, nil
	}

	// Detect format
	format := detectFormat(data)
	result.Format = format

	switch format {
	case "png":
		detectPNGStego(data, result)
	case "jpeg":
		detectJPEGTrailing(data, result)
	case "pdf":
		detectPDFMetadata(data, result)
	case "gif":
		detectGIFStego(data, result)
	}

	// Trailing data detection (works for all formats)
	detectTrailingData(data, result)

	return result, nil
}

func detectFormat(data []byte) string {
	if bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		return "png"
	}
	if bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		return "jpeg"
	}
	if bytes.HasPrefix(data, []byte{0x25, 0x50, 0x44, 0x46}) {
		return "pdf"
	}
	if bytes.HasPrefix(data, []byte{0x47, 0x49, 0x46, 0x38}) {
		return "gif"
	}
	return "unknown"
}

// detectPNGStego performs LSB steganography detection on PNG files.
func detectPNGStego(data []byte, r *Result) {
	img, err := decodeImage(data)
	if err != nil {
		return
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Method 1: LSB extraction (b1,rgba,lsb,xy)
	lsbData := extractLSB(img, width, height, 1, "rgba", "lsb", "xy")
	if len(lsbData) > 0 {
		preview := string(lsbData[:min(100, len(lsbData))])
		hasFlag := detectFlagPattern(lsbData)
		confidence := 0.3
		if hasFlag {
			confidence = 0.95
		} else if isPrintable(lsbData) {
			confidence = 0.6
		}
		r.Methods = append(r.Methods, MethodResult{
			Name:       "b1,rgba,lsb,xy",
			Confidence: confidence,
			Data:       string(lsbData),
			HasFlag:    hasFlag,
			Preview:    preview,
		})
		if hasFlag {
			r.Flags = append(r.Flags, extractFlag(lsbData))
		}
	}

	// Method 2: LSB extraction (b1,rgb,lsb,xy)
	lsbData = extractLSB(img, width, height, 1, "rgb", "lsb", "xy")
	if len(lsbData) > 0 {
		preview := string(lsbData[:min(100, len(lsbData))])
		hasFlag := detectFlagPattern(lsbData)
		confidence := 0.3
		if hasFlag {
			confidence = 0.95
		} else if isPrintable(lsbData) {
			confidence = 0.5
		}
		r.Methods = append(r.Methods, MethodResult{
			Name:       "b1,rgb,lsb,xy",
			Confidence: confidence,
			Data:       string(lsbData),
			HasFlag:    hasFlag,
			Preview:    preview,
		})
		if hasFlag {
			r.Flags = append(r.Flags, extractFlag(lsbData))
		}
	}

	// Method 3: LSB extraction single channel (b1,r,lsb,xy)
	for _, ch := range []string{"r", "g", "b", "a"} {
		lsbData = extractLSB(img, width, height, 1, ch, "lsb", "xy")
		if len(lsbData) > 0 {
			hasFlag := detectFlagPattern(lsbData)
			if hasFlag {
				r.Methods = append(r.Methods, MethodResult{
					Name:       fmt.Sprintf("b1,%s,lsb,xy", ch),
					Confidence: 0.95,
					Data:       string(lsbData),
					HasFlag:    true,
					Preview:    string(lsbData[:min(100, len(lsbData))]),
				})
				r.Flags = append(r.Flags, extractFlag(lsbData))
			}
		}
	}

	// Method 4: MSB extraction (b1,rgba,msb,xy)
	msbData := extractLSB(img, width, height, 1, "rgba", "msb", "xy")
	if len(msbData) > 0 {
		hasFlag := detectFlagPattern(msbData)
		if hasFlag {
			r.Methods = append(r.Methods, MethodResult{
				Name:       "b1,rgba,msb,xy",
				Confidence: 0.95,
				Data:       string(msbData),
				HasFlag:    true,
				Preview:    string(msbData[:min(100, len(msbData))]),
			})
			r.Flags = append(r.Flags, extractFlag(msbData))
		}
	}

	// Method 5: PNG metadata chunks
	detectPNGMetadata(data, r)
}

// extractLSB extracts data from image using LSB/MSB technique.
func extractLSB(img image.Image, width, height, bits int, channel, order, layout string) []byte {
	var result []byte
	bitBuffer := byte(0)
	bitCount := 0

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			// Normalize to 8-bit
			r8 := uint8(r >> 8)
			g8 := uint8(g >> 8)
			b8 := uint8(b >> 8)
			a8 := uint8(a >> 8)

			var channels []uint8
			switch channel {
			case "rgba":
				channels = []uint8{r8, g8, b8, a8}
			case "rgb":
				channels = []uint8{r8, g8, b8}
			case "r":
				channels = []uint8{r8}
			case "g":
				channels = []uint8{g8}
			case "b":
				channels = []uint8{b8}
			case "a":
				channels = []uint8{a8}
			}

			for _, ch := range channels {
				var bit byte
				if order == "lsb" {
					bit = ch & 1
				} else {
					bit = (ch >> 7) & 1
				}

				bitBuffer = (bitBuffer << 1) | bit
				bitCount++

				if bitCount == 8 {
					if bitBuffer != 0 {
						result = append(result, bitBuffer)
					}
					bitBuffer = 0
					bitCount = 0
				}
			}
		}
	}

	// Trim null bytes
	for len(result) > 0 && result[len(result)-1] == 0 {
		result = result[:len(result)-1]
	}

	return result
}

// detectPNGMetadata checks PNG chunks for hidden data.
func detectPNGMetadata(data []byte, r *Result) {
	if len(data) < 8 {
		return
	}

	offset := 8 // Skip PNG signature
	for offset+8 <= len(data) {
		chunkLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		chunkType := string(data[offset+4 : offset+8])

		if chunkType == "tEXt" || chunkType == "iTXt" || chunkType == "zTXt" {
			if offset+12+chunkLen <= len(data) {
				chunkData := data[offset+8 : offset+8+chunkLen]
				text := string(chunkData)
				if len(text) > 0 {
					hasFlag := detectFlagPattern([]byte(text))
					r.Methods = append(r.Methods, MethodResult{
						Name:       fmt.Sprintf("png_%s", chunkType),
						Confidence: 0.4,
						Data:       text,
						HasFlag:    hasFlag,
						Preview:    text[:min(100, len(text))],
					})
					if hasFlag {
						r.Flags = append(r.Flags, extractFlag([]byte(text)))
					}
				}
			}
		}

		offset += 12 + chunkLen
		if chunkType == "IEND" {
			break
		}
	}
}

// detectJPEGTrailing detects data after JPEG EOI marker.
func detectJPEGTrailing(data []byte, r *Result) {
	eoiIdx := bytes.LastIndex(data, []byte{0xFF, 0xD9})
	if eoiIdx < 0 || eoiIdx+2 >= len(data) {
		return
	}

	trailing := data[eoiIdx+2:]
	if len(trailing) < 4 {
		return
	}

	hasFlag := detectFlagPattern(trailing)
	preview := string(trailing[:min(200, len(trailing))])
	confidence := 0.5
	if hasFlag {
		confidence = 0.9
	}

	r.Methods = append(r.Methods, MethodResult{
		Name:       "jpeg_trailing",
		Confidence: confidence,
		Data:       string(trailing),
		HasFlag:    hasFlag,
		Preview:    preview,
	})
	if hasFlag {
		r.Flags = append(r.Flags, extractFlag(trailing))
	}
}

// detectPDFMetadata checks PDF for hidden metadata.
func detectPDFMetadata(data []byte, r *Result) {
	text := string(data)
	suspiciousFields := []string{
		"/Author", "/Title", "/Subject", "/Keywords",
		"/Creator", "/Producer", "/JS", "/JavaScript",
	}

	for _, field := range suspiciousFields {
		idx := strings.Index(text, field)
		if idx >= 0 {
			// Extract value
			start := idx + len(field)
			if start < len(text) {
				rest := text[start:]
				if len(rest) > 100 {
					rest = rest[:100]
				}
				hasFlag := detectFlagPattern([]byte(rest))
				r.Methods = append(r.Methods, MethodResult{
					Name:       fmt.Sprintf("pdf_%s", strings.TrimPrefix(field, "/")),
					Confidence: 0.3,
					HasFlag:    hasFlag,
					Preview:    rest,
				})
			}
		}
	}
}

// detectGIFStego detects hidden data in GIF files.
func detectGIFStego(data []byte, r *Result) {
	// Check for data after GIF trailer (0x3B)
	trailerIdx := bytes.LastIndex(data, []byte{0x3B})
	if trailerIdx >= 0 && trailerIdx+1 < len(data) {
		trailing := data[trailerIdx+1:]
		if len(trailing) > 0 {
			hasFlag := detectFlagPattern(trailing)
			r.Methods = append(r.Methods, MethodResult{
				Name:       "gif_trailing",
				Confidence: 0.5,
				Data:       string(trailing),
				HasFlag:    hasFlag,
				Preview:    string(trailing[:min(100, len(trailing))]),
			})
			if hasFlag {
				r.Flags = append(r.Flags, extractFlag(trailing))
			}
		}
	}
}

// detectTrailingData detects data appended after file end markers.
func detectTrailingData(data []byte, r *Result) {
	if r.Format == "jpeg" {
		return // Already handled
	}

	// PNG IEND
	if r.Format == "png" {
		iendIdx := bytes.Index(data, []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82})
		if iendIdx >= 0 && iendIdx+8 < len(data) {
			trailing := data[iendIdx+8:]
			if len(trailing) > 0 {
				hasFlag := detectFlagPattern(trailing)
				r.Methods = append(r.Methods, MethodResult{
					Name:       "png_trailing",
					Confidence: 0.5,
					Data:       string(trailing),
					HasFlag:    hasFlag,
					Preview:    string(trailing[:min(100, len(trailing))]),
				})
				if hasFlag {
					r.Flags = append(r.Flags, extractFlag(trailing))
				}
			}
		}
	}

	// PDF %%EOF
	if r.Format == "pdf" {
		eofIdx := bytes.LastIndex(data, []byte("%%EOF"))
		if eofIdx >= 0 && eofIdx+5 < len(data) {
			trailing := data[eofIdx+5:]
			if len(trailing) > 0 {
				hasFlag := detectFlagPattern(trailing)
				r.Methods = append(r.Methods, MethodResult{
					Name:       "pdf_trailing",
					Confidence: 0.5,
					Data:       string(trailing),
					HasFlag:    hasFlag,
					Preview:    string(trailing[:min(100, len(trailing))]),
				})
				if hasFlag {
					r.Flags = append(r.Flags, extractFlag(trailing))
				}
			}
		}
	}
}

// detectFlagPattern looks for CTF flag patterns.
func detectFlagPattern(data []byte) bool {
	patterns := []string{
		"picoCTF{", "flag{", "FLAG{", "HTB{", "CTF{",
		"FLAG}", "picoCTF}", "HTB}",
	}
	text := string(data)
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

// extractFlag extracts the full flag from data.
func extractFlag(data []byte) string {
	text := string(data)
	patterns := []string{
		`picoCTF\{[^}]+\}`,
		`flag\{[^}]+\}`,
		`FLAG\{[^}]+\}`,
		`HTB\{[^}]+\}`,
		`CTF\{[^}]+\}`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if match := re.FindString(text); match != "" {
			return match
		}
	}
	return ""
}

// isPrintable checks if data is mostly printable ASCII.
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E || b == 0x09 || b == 0x0A || b == 0x0D {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.7
}

func decodeImage(data []byte) (image.Image, error) {
	reader := bytes.NewReader(data)
	img, _, err := image.Decode(reader)
	return img, err
}


