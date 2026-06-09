package metadata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractEXIF(t *testing.T) {
	// Test with non-JPEG file
	_, err := ExtractEXIF("/tmp/nonexistent.jpg")
	if err == nil {
		t.Error("Expected error for non-JPEG file")
	}
}

func TestExtractEXIFNonJPEG(t *testing.T) {
	// Create a non-JPEG file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	os.WriteFile(testFile, []byte("not a jpeg"), 0644)
	
	_, err := ExtractEXIF(testFile)
	if err == nil {
		t.Error("Expected error for non-JPEG file")
	}
}

func TestExtractEXIFNoEXIF(t *testing.T) {
	// Create a minimal JPEG without EXIF
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.jpg")
	
	// Minimal JPEG: SOI + EOI
	data := []byte{0xFF, 0xD8, 0xFF, 0xD9}
	os.WriteFile(testFile, data, 0644)
	
	_, err := ExtractEXIF(testFile)
	if err == nil {
		t.Error("Expected error for JPEG without EXIF")
	}
}

func TestFormatEXIFResult(t *testing.T) {
	// Test with nil result
	result := FormatEXIFResult(nil)
	if result != "No EXIF data found" {
		t.Errorf("Expected 'No EXIF data found', got %s", result)
	}

	// Test with empty tags
	result = FormatEXIFResult(&EXIFResult{
		Tags: make(map[string]interface{}),
	})
	if result != "No EXIF data found" {
		t.Errorf("Expected 'No EXIF data found', got %s", result)
	}
}

func TestFormatEXIFResultWithData(t *testing.T) {
	result := &EXIFResult{
		Tags: map[string]interface{}{
			"Make":           "Canon",
			"Model":          "EOS 5D",
			"Software":       "1.0",
			"PixelXDimension": 4000,
			"PixelYDimension": 3000,
			"ExposureTime":   0.01,
			"FNumber":        2.8,
			"ISOSpeedRatings": 100,
			"FocalLength":    50.0,
			"DateTime":       "2024:01:01 12:00:00",
			"DateTimeOriginal": "2024:01:01 12:00:00",
			"GPSLatitude":    37.7749,
			"GPSLatitudeRef": "N",
			"GPSLongitude":   -122.4194,
			"GPSLongitudeRef": "W",
			"GPSAltitude":    100.0,
		},
	}
	
	formatted := FormatEXIFResult(result)
	if formatted == "" {
		t.Error("Expected non-empty result")
	}
}

func TestExtractXMP(t *testing.T) {
	// Test with non-existent file
	_, err := ExtractXMP("/tmp/nonexistent.jpg")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestExtractXMPNonexistent(t *testing.T) {
	_, err := ExtractXMP("/nonexistent/path/file.jpg")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestFormatXMPData(t *testing.T) {
	// Test with nil
	result := FormatXMPData(nil)
	if result != "No XMP data found" {
		t.Errorf("Expected 'No XMP data found', got %s", result)
	}
}

func TestFormatXMPDataWithData(t *testing.T) {
	data := &XMPData{
		Description: []XMPDescription{{
			About:       "test",
			CameraMake:  "Canon",
			CameraModel: "EOS 5D",
			Software:    "1.0",
			DateOriginal: "2024-01-01T12:00:00Z",
			LensMake:    "Canon",
			LensModel:   "EF 50mm f/1.4",
		}},
	}
	
	formatted := FormatXMPData(data)
	if formatted == "" {
		t.Error("Expected non-empty result")
	}
}

func TestExtractIPTC(t *testing.T) {
	// Test with non-existent file
	_, err := ExtractIPTC("/tmp/nonexistent.jpg")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestExtractIPTCNonexistent(t *testing.T) {
	_, err := ExtractIPTC("/nonexistent/path/file.jpg")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestFormatIPTCData(t *testing.T) {
	// Test with nil
	result := FormatIPTCData(nil)
	if result != "No IPTC data found" {
		t.Errorf("Expected 'No IPTC data found', got %s", result)
	}
}

func TestFormatIPTCDataWithData(t *testing.T) {
	// Test with empty data
	data := map[string]string{}
	
	formatted := FormatIPTCData(data)
	if formatted != "No IPTC data found" {
		t.Error("Expected 'No IPTC data found' for empty data")
	}
}

func TestEXIFTags(t *testing.T) {
	// Test that common tags exist
	commonTags := []uint16{
		0x010F, // Make
		0x0110, // Model
		0x0131, // Software
		0x9003, // DateTimeOriginal
		0x829A, // ExposureTime
		0x829D, // FNumber
		0x8827, // ISOSpeedRatings
		0x920A, // FocalLength
	}
	
	for _, tag := range commonTags {
		if _, ok := exifTags[tag]; !ok {
			t.Errorf("Expected tag 0x%04X to be defined", tag)
		}
	}
}

func TestEXIFDataTypes(t *testing.T) {
	// Test that data types are defined
	if exifTypeByte != 1 {
		t.Error("Expected exifTypeByte to be 1")
	}
	if exifTypeAscii != 2 {
		t.Error("Expected exifTypeAscii to be 2")
	}
	if exifTypeShort != 3 {
		t.Error("Expected exifTypeShort to be 3")
	}
	if exifTypeLong != 4 {
		t.Error("Expected exifTypeLong to be 4")
	}
	if exifTypeRational != 5 {
		t.Error("Expected exifTypeRational to be 5")
	}
}

func TestParseIFDEmpty(t *testing.T) {
	// Test with empty data
	tags, err := parseIFD([]byte{}, nil, nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(tags) != 0 {
		t.Errorf("Expected empty tags, got %d", len(tags))
	}
}

func TestParseEXIFValueUnsupported(t *testing.T) {
	// Test unsupported data type
	_, err := parseEXIFValue(99, 1, 0, []byte{}, nil, nil)
	if err == nil {
		t.Error("Expected error for unsupported data type")
	}
}
