package metadata

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

// XMPData represents XMP metadata
type XMPData struct {
	XMLName     xml.Name        `xml:"xmpmeta"`
	Description []XMPDescription `xml:"RDF>Description"`
}

// XMPDescription represents an XMP description
type XMPDescription struct {
	About           string `xml:"about,attr"`
	CameraMake      string `xml:"Make"`
	CameraModel     string `xml:"Model"`
	Software        string `xml:"Software"`
	DateOriginal    string `xml:"DateOriginal"`
	DateDigitized   string `xml:"DateDigitized"`
	Orientation     string `xml:"Orientation"`
	LensMake        string `xml:"LensMake"`
	LensModel       string `xml:"LensModel"`
	ExposureTime    string `xml:"ExposureTime"`
	FNumber         string `xml:"FNumber"`
	ISOSpeedRatings string `xml:"ISOSpeedRatings"`
	FocalLength     string `xml:"FocalLength"`
	GPSLatitude     string `xml:"GPSLatitude"`
	GPSLongitude    string `xml:"GPSLongitude"`
	GPSAltitude     string `xml:"GPSAltitude"`
	GPSTimeStamp    string `xml:"GPSTimeStamp"`
	GPSDateStamp    string `xml:"GPSDateStamp"`
}

// ExtractXMP extracts XMP metadata from a file
func ExtractXMP(filePath string) (*XMPData, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read file content
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Look for XMP data between markers
	xmpStart := []byte("<x:xmpmeta")
	xmpEnd := []byte("</x:xmpmeta>")

	startIdx := indexOf(content, xmpStart)
	if startIdx == -1 {
		return nil, fmt.Errorf("no XMP data found")
	}

	endIdx := indexOf(content[startIdx:], xmpEnd)
	if endIdx == -1 {
		return nil, fmt.Errorf("XMP data incomplete")
	}

	xmpData := content[startIdx : startIdx+endIdx+len(xmpEnd)]

	// Parse XML
	var xmp XMPData
	if err := xml.Unmarshal(xmpData, &xmp); err != nil {
		return nil, fmt.Errorf("failed to parse XMP: %w", err)
	}

	return &xmp, nil
}

// ExtractXMPFromBuffer extracts XMP from a byte buffer
func ExtractXMPFromBuffer(data []byte) (*XMPData, error) {
	xmpStart := []byte("<x:xmpmeta")
	xmpEnd := []byte("</x:xmpmeta>")

	startIdx := indexOf(data, xmpStart)
	if startIdx == -1 {
		return nil, fmt.Errorf("no XMP data found")
	}

	endIdx := indexOf(data[startIdx:], xmpEnd)
	if endIdx == -1 {
		return nil, fmt.Errorf("XMP data incomplete")
	}

	xmpData := data[startIdx : startIdx+endIdx+len(xmpEnd)]

	var xmp XMPData
	if err := xml.Unmarshal(xmpData, &xmp); err != nil {
		return nil, fmt.Errorf("failed to parse XMP: %w", err)
	}

	return &xmp, nil
}

// FormatXMPData formats XMP data for display
func FormatXMPData(xmp *XMPData) string {
	if xmp == nil || len(xmp.Description) == 0 {
		return "No XMP data found"
	}

	var sb strings.Builder
	sb.WriteString("XMP Metadata:\n")

	for _, desc := range xmp.Description {
		if desc.CameraMake != "" {
			sb.WriteString(fmt.Sprintf("  Camera Make: %s\n", desc.CameraMake))
		}
		if desc.CameraModel != "" {
			sb.WriteString(fmt.Sprintf("  Camera Model: %s\n", desc.CameraModel))
		}
		if desc.Software != "" {
			sb.WriteString(fmt.Sprintf("  Software: %s\n", desc.Software))
		}
		if desc.DateOriginal != "" {
			sb.WriteString(fmt.Sprintf("  Date Original: %s\n", desc.DateOriginal))
		}
		if desc.DateDigitized != "" {
			sb.WriteString(fmt.Sprintf("  Date Digitized: %s\n", desc.DateDigitized))
		}
		if desc.Orientation != "" {
			sb.WriteString(fmt.Sprintf("  Orientation: %s\n", desc.Orientation))
		}
		if desc.LensMake != "" {
			sb.WriteString(fmt.Sprintf("  Lens Make: %s\n", desc.LensMake))
		}
		if desc.LensModel != "" {
			sb.WriteString(fmt.Sprintf("  Lens Model: %s\n", desc.LensModel))
		}
		if desc.ExposureTime != "" {
			sb.WriteString(fmt.Sprintf("  Exposure Time: %s\n", desc.ExposureTime))
		}
		if desc.FNumber != "" {
			sb.WriteString(fmt.Sprintf("  F-Number: %s\n", desc.FNumber))
		}
		if desc.ISOSpeedRatings != "" {
			sb.WriteString(fmt.Sprintf("  ISO: %s\n", desc.ISOSpeedRatings))
		}
		if desc.FocalLength != "" {
			sb.WriteString(fmt.Sprintf("  Focal Length: %s\n", desc.FocalLength))
		}
		if desc.GPSLatitude != "" {
			sb.WriteString(fmt.Sprintf("  GPS Latitude: %s\n", desc.GPSLatitude))
		}
		if desc.GPSLongitude != "" {
			sb.WriteString(fmt.Sprintf("  GPS Longitude: %s\n", desc.GPSLongitude))
		}
		if desc.GPSAltitude != "" {
			sb.WriteString(fmt.Sprintf("  GPS Altitude: %s\n", desc.GPSAltitude))
		}
	}

	return sb.String()
}

// indexOf returns the index of the first occurrence of pattern in s
func indexOf(s, pattern []byte) int {
	for i := 0; i <= len(s)-len(pattern); i++ {
		if equal(s[i:i+len(pattern)], pattern) {
			return i
		}
	}
	return -1
}

// equal returns true if two byte slices are equal
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
