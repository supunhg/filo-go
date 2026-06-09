package metadata

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Result holds metadata extraction results.
type Result struct {
	FileName   string                 `json:"file_name"`
	Format     string                 `json:"format"`
	Metadata   map[string]interface{} `json:"metadata"`
	Suspicious []string               `json:"suspicious,omitempty"`
}

// Extract pulls metadata from image files.
func Extract(data []byte, fileName string) (*Result, error) {
	result := &Result{
		FileName:   fileName,
		Metadata:   make(map[string]interface{}),
		Suspicious: []string{},
	}

	if len(data) < 8 {
		return result, nil
	}

	// Detect format
	format := detectFormat(data)
	result.Format = format

	switch format {
	case "jpeg":
		extractJPEGMetadata(data, result)
	case "png":
		extractPNGMetadata(data, result)
	case "pdf":
		extractPDFMetadata(data, result)
	}

	return result, nil
}

func detectFormat(data []byte) string {
	if bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		return "jpeg"
	}
	if bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
		return "png"
	}
	if bytes.HasPrefix(data, []byte{0x25, 0x50, 0x44, 0x46}) {
		return "pdf"
	}
	return "unknown"
}

// extractJPEGMetadata extracts EXIF and other JPEG metadata.
func extractJPEGMetadata(data []byte, r *Result) {
	offset := 2 // Skip SOI

	for offset+4 <= len(data) {
		// Find APP markers
		if data[offset] != 0xFF {
			offset++
			continue
		}

		marker := data[offset+1]
		if marker == 0xD9 { // EOI
			break
		}

		if marker == 0xE0 { // APP0 (JFIF)
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			if offset+2+length <= len(data) {
				appData := data[offset+4 : offset+2+length]
				if len(appData) >= 5 && string(appData[:5]) == "JFIF\x00" {
					r.Metadata["format"] = "JFIF"
					if len(appData) >= 7 {
						r.Metadata["version"] = fmt.Sprintf("%d.%02d", appData[5], appData[6])
					}
				}
			}
			offset += 2 + length
		} else if marker == 0xE1 { // APP1 (EXIF)
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			if offset+2+length <= len(data) {
				appData := data[offset+4 : offset+2+length]
				if len(appData) >= 6 && string(appData[:6]) == "Exif\x00\x00" {
					parseEXIF(appData[6:], r)
				}
			}
			offset += 2 + length
		} else if marker == 0xFE { // COM (Comment)
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			if offset+2+length <= len(data) {
				comment := string(data[offset+4 : offset+2+length])
				r.Metadata["comment"] = comment
				if containsSuspicious(comment) {
					r.Suspicious = append(r.Suspicious, fmt.Sprintf("JPEG comment: %s", comment[:min(100, len(comment))]))
				}
			}
			offset += 2 + length
		} else {
			// Skip unknown marker
			length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			offset += 2 + length
		}
	}
}

func parseEXIF(data []byte, r *Result) {
	if len(data) < 8 {
		return
	}

	// Check byte order
	byteOrder := string(data[:2])
	littleEndian := byteOrder == "II"
	_ = littleEndian

	// Read IFD
	r.Metadata["has_exif"] = true

	// Extract basic EXIF tags
	for i := 0; i < len(data)-12; i += 12 {
		tag := binary.BigEndian.Uint16(data[i : i+2])
		if tag == 0 {
			break
		}

		switch tag {
		case 0x010F: // Make
			r.Metadata["camera_make"] = extractEXIFString(data, i+8)
		case 0x0110: // Model
			r.Metadata["camera_model"] = extractEXIFString(data, i+8)
		case 0x0112: // Orientation
			orient := binary.BigEndian.Uint16(data[i+8 : i+10])
			r.Metadata["orientation"] = orient
		case 0x0131: // Software
			r.Metadata["software"] = extractEXIFString(data, i+8)
		case 0x9003: // DateTimeOriginal
			r.Metadata["date_original"] = extractEXIFString(data, i+8)
		case 0x927C: // MakerNote
			r.Metadata["has_maker_note"] = true
		}
	}
}

func extractEXIFString(data []byte, offset int) string {
	if offset+4 > len(data) {
		return ""
	}
	// Simple extraction - may need refinement for actual EXIF
	if offset < len(data) {
		end := offset + 32
		if end > len(data) {
			end = len(data)
		}
		return string(data[offset:end])
	}
	return ""
}

// extractPNGMetadata extracts PNG chunk metadata.
func extractPNGMetadata(data []byte, r *Result) {
	offset := 8 // Skip PNG signature

	for offset+8 <= len(data) {
		chunkLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		chunkType := string(data[offset+4 : offset+8])

		if offset+8+chunkLen > len(data) {
			break
		}

		chunkData := data[offset+8 : offset+8+chunkLen]

		switch chunkType {
		case "IHDR":
			if len(chunkData) >= 13 {
				r.Metadata["width"] = binary.BigEndian.Uint32(chunkData[0:4])
				r.Metadata["height"] = binary.BigEndian.Uint32(chunkData[4:8])
				r.Metadata["bit_depth"] = chunkData[8]
				r.Metadata["color_type"] = chunkData[9]
				r.Metadata["compression"] = chunkData[10]
				r.Metadata["filter"] = chunkData[11]
				r.Metadata["interlace"] = chunkData[12]
			}
		case "tEXt":
			parts := bytes.SplitN(chunkData, []byte{0}, 2)
			if len(parts) == 2 {
				key := string(parts[0])
				value := string(parts[1])
				r.Metadata["text_"+key] = value
				if containsSuspicious(value) {
					r.Suspicious = append(r.Suspicious, fmt.Sprintf("PNG tEXt '%s': %s", key, value[:min(100, len(value))]))
				}
			}
		case "zTXt":
			parts := bytes.SplitN(chunkData, []byte{0}, 2)
			if len(parts) == 2 {
				key := string(parts[0])
				r.Metadata["text_"+key] = "(compressed)"
			}
		case "iTXt":
			parts := bytes.SplitN(chunkData, []byte{0}, 3)
			if len(parts) >= 2 {
				key := string(parts[0])
				r.Metadata["text_"+key] = string(parts[1])
			}
		case "tIME":
			if len(chunkData) >= 7 {
				year := binary.BigEndian.Uint16(chunkData[0:2])
				month := chunkData[2]
				day := chunkData[3]
				hour := chunkData[4]
				minute := chunkData[5]
				second := chunkData[6]
				r.Metadata["modification_time"] = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
			}
		}

		offset += 12 + chunkLen
		if chunkType == "IEND" {
			break
		}
	}
}

// extractPDFMetadata extracts PDF metadata.
func extractPDFMetadata(data []byte, r *Result) {
	text := string(data)

	// Extract PDF version
	if len(text) >= 8 && text[:5] == "%PDF-" {
		r.Metadata["pdf_version"] = text[5:8]
	}

	// Extract metadata fields
	fields := map[string]string{
		"/Author":       "author",
		"/Title":        "title",
		"/Subject":      "subject",
		"/Creator":      "creator",
		"/Producer":     "producer",
		"/Keywords":     "keywords",
		"/CreationDate": "creation_date",
		"/ModDate":      "modification_date",
	}

	for pdfField, metaKey := range fields {
		idx := strings.Index(text, pdfField)
		if idx >= 0 {
			// Find value after field
			start := idx + len(pdfField)
			if start < len(text) {
				// Skip whitespace
				for start < len(text) && (text[start] == ' ' || text[start] == '\t') {
					start++
				}
				// Extract value
				end := start
				for end < len(text) && text[end] != '\n' && text[end] != '\r' {
					end++
				}
				if end > start {
					value := text[start:end]
					// Remove parentheses if present
					if len(value) >= 2 && value[0] == '(' && value[len(value)-1] == ')' {
						value = value[1 : len(value)-1]
					}
					r.Metadata[metaKey] = value
				}
			}
		}
	}

	// Check for JavaScript
	if strings.Contains(text, "/JavaScript") || strings.Contains(text, "/JS") {
		r.Suspicious = append(r.Suspicious, "PDF contains JavaScript")
	}
	if strings.Contains(text, "/OpenAction") {
		r.Suspicious = append(r.Suspicious, "PDF contains OpenAction (auto-execute)")
	}
	if strings.Contains(text, "/AA") {
		r.Suspicious = append(r.Suspicious, "PDF contains Additional Actions")
	}
}

func containsSuspicious(s string) bool {
	suspicious := []string{
		"picoCTF{", "flag{", "FLAG{", "HTB{",
		"<?php", "<script", "eval(", "exec(",
		"base64_decode", "shell_exec", "system(",
	}
	lower := strings.ToLower(s)
	for _, pattern := range suspicious {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// Print displays metadata results.
func Print(r *Result) {
	fmt.Println()
	fmt.Printf("  Metadata: %s\n", r.FileName)
	fmt.Printf("  Format: %s\n", r.Format)
	fmt.Println()

	if len(r.Metadata) == 0 {
		fmt.Println("  No metadata found")
	} else {
		fmt.Println("  Metadata:")
		for k, v := range r.Metadata {
			fmt.Printf("    %-20s %v\n", k, v)
		}
	}

	if len(r.Suspicious) > 0 {
		fmt.Println()
		fmt.Println("  ⚠  Suspicious:")
		for _, s := range r.Suspicious {
			fmt.Printf("    %s\n", s)
		}
	}

	fmt.Println()
}
