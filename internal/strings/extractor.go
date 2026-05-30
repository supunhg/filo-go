package strings

import (
	"fmt"
	"math"
	"regexp"
	"unicode"
)

// Result holds string extraction results.
type Result struct {
	FileName string        `json:"file_name"`
	Strings  []StringEntry `json:"strings"`
	Total    int           `json:"total"`
}

// StringEntry represents a single extracted string.
type StringEntry struct {
	Offset  int64   `json:"offset"`
	Value   string  `json:"value"`
	Type    string  `json:"type"`
	Entropy float64 `json:"entropy"`
}

// Options controls string extraction behavior.
type Options struct {
	MinLength    int
	MinEntropy   float64
	MaxCount     int
	Type         string // "ascii", "unicode", "all"
	Regex        string
	EncodeDetect bool
}

// Extract pulls strings from binary data.
func Extract(data []byte, fileName string, opts *Options) (*Result, error) {
	if opts == nil {
		opts = &Options{MinLength: 4, Type: "all"}
	}

	result := &Result{
		FileName: fileName,
		Strings:  []StringEntry{},
	}

	var re *regexp.Regexp
	if opts.Regex != "" {
		var err error
		re, err = regexp.Compile(opts.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
	}

	// Extract ASCII strings
	if opts.Type == "ascii" || opts.Type == "all" {
		extractASCII(data, opts, re, result)
	}

	// Extract Unicode strings
	if opts.Type == "unicode" || opts.Type == "all" {
		extractUnicode(data, opts, re, result)
	}

	// Filter by entropy if specified
	if opts.MinEntropy > 0 {
		var filtered []StringEntry
		for _, s := range result.Strings {
			if s.Entropy >= opts.MinEntropy {
				filtered = append(filtered, s)
			}
		}
		result.Strings = filtered
	}

	// Limit count if specified
	if opts.MaxCount > 0 && len(result.Strings) > opts.MaxCount {
		result.Strings = result.Strings[:opts.MaxCount]
	}

	result.Total = len(result.Strings)
	return result, nil
}

func extractASCII(data []byte, opts *Options, re *regexp.Regexp, result *Result) {
	var current []byte
	var startOffset int64

	for i, b := range data {
		if b >= 0x20 && b <= 0x7E || b == 0x09 || b == 0x0A || b == 0x0D {
			if len(current) == 0 {
				startOffset = int64(i)
			}
			current = append(current, b)
		} else {
			if len(current) >= opts.MinLength {
				str := string(current)
				if re != nil && !re.MatchString(str) {
					current = nil
					continue
				}
				entropy := calculateEntropy(current)
				result.Strings = append(result.Strings, StringEntry{
					Offset:  startOffset,
					Value:   str,
					Type:    "ascii",
					Entropy: entropy,
				})
			}
			current = nil
		}
	}

	// Handle string at end of data
	if len(current) >= opts.MinLength {
		str := string(current)
		if re == nil || re.MatchString(str) {
			entropy := calculateEntropy(current)
			result.Strings = append(result.Strings, StringEntry{
				Offset:  startOffset,
				Value:   str,
				Type:    "ascii",
				Entropy: entropy,
			})
		}
	}
}

func extractUnicode(data []byte, opts *Options, re *regexp.Regexp, result *Result) {
	if len(data) < 2 {
		return
	}

	var current []byte
	var startOffset int64

	for i := 0; i < len(data)-1; i += 2 {
		// Check for UTF-16LE
		lo := data[i]
		hi := data[i+1]

		if hi == 0 && lo >= 0x20 && lo <= 0x7E {
			if len(current) == 0 {
				startOffset = int64(i)
			}
			current = append(current, lo)
		} else {
			if len(current) >= opts.MinLength {
				str := string(current)
				if re != nil && !re.MatchString(str) {
					current = nil
					continue
				}
				entropy := calculateEntropy(current)
				result.Strings = append(result.Strings, StringEntry{
					Offset:  startOffset,
					Value:   str,
					Type:    "unicode",
					Entropy: entropy,
				})
			}
			current = nil
		}
	}

	if len(current) >= opts.MinLength {
		str := string(current)
		if re == nil || re.MatchString(str) {
			entropy := calculateEntropy(current)
			result.Strings = append(result.Strings, StringEntry{
				Offset:  startOffset,
				Value:   str,
				Type:    "unicode",
				Entropy: entropy,
			})
		}
	}
}

func calculateEntropy(data []byte) float64 {
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

// DetectEncoding detects the encoding of a string.
func DetectEncoding(data []byte) string {
	if len(data) == 0 {
		return "unknown"
	}

	// Check for UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return "utf-8-bom"
	}

	// Check for UTF-16 LE BOM
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return "utf-16le"
	}

	// Check for UTF-16 BE BOM
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return "utf-16be"
	}

	// Check if valid UTF-8
	if isValidUTF8(data) {
		return "utf-8"
	}

	// Check if ASCII
	isASCII := true
	for _, b := range data {
		if b > 127 {
			isASCII = false
			break
		}
	}
	if isASCII {
		return "ascii"
	}

	return "binary"
}

func isValidUTF8(data []byte) bool {
	i := 0
	for i < len(data) {
		b := data[i]
		switch {
		case b <= 0x7F:
			i++
		case b <= 0xBF:
			return false
		case b <= 0xDF:
			if i+1 >= len(data) || data[i+1]&0xC0 != 0x80 {
				return false
			}
			i += 2
		case b <= 0xEF:
			if i+2 >= len(data) || data[i+1]&0xC0 != 0x80 || data[i+2]&0xC0 != 0x80 {
				return false
			}
			i += 3
		case b <= 0xF7:
			if i+3 >= len(data) || data[i+1]&0xC0 != 0x80 || data[i+2]&0xC0 != 0x80 || data[i+3]&0xC0 != 0x80 {
				return false
			}
			i += 4
		default:
			return false
		}
	}
	return true
}

// IsPrintableRatio returns the ratio of printable characters.
func IsPrintableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	printable := 0
	for _, b := range data {
		if unicode.IsPrint(rune(b)) || b == '\t' || b == '\n' || b == '\r' {
			printable++
		}
	}
	return float64(printable) / float64(len(data))
}
