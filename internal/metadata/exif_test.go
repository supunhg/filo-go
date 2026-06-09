package metadata

import (
	"testing"
)

func TestExtractEXIF(t *testing.T) {
	// Test with non-JPEG file
	_, err := ExtractEXIF("/tmp/nonexistent.jpg")
	if err == nil {
		t.Error("Expected error for non-JPEG file")
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

func TestExtractXMP(t *testing.T) {
	// Test with non-existent file
	_, err := ExtractXMP("/tmp/nonexistent.jpg")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestFormatXMPData(t *testing.T) {
	// Test with nil
	result := FormatXMPData(nil)
	if result != "No XMP data found" {
		t.Errorf("Expected 'No XMP data found', got %s", result)
	}
}

func TestExtractIPTC(t *testing.T) {
	// Test with non-existent file
	_, err := ExtractIPTC("/tmp/nonexistent.jpg")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestFormatIPTCData(t *testing.T) {
	// Test with nil
	result := FormatIPTCData(nil)
	if result != "No IPTC data found" {
		t.Errorf("Expected 'No IPTC data found', got %s", result)
	}
}
