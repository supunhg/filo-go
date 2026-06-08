package strings

import (
	"testing"
)

func TestExtractDefaultOptions(t *testing.T) {
	data := []byte("Hello, World! This is a test string.")
	result, err := Extract(data, "test.bin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FileName != "test.bin" {
		t.Errorf("expected filename test.bin, got %s", result.FileName)
	}

	if result.Total == 0 {
		t.Error("expected at least one string")
	}
}

func TestExtractMinLength(t *testing.T) {
	data := []byte("Hi test string")

	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not include "Hi" (length 2)
	for _, s := range result.Strings {
		if s.Value == "Hi" {
			t.Error("should not include strings shorter than MinLength")
		}
	}
}

func TestExtractASCIIOnly(t *testing.T) {
	data := []byte("Hello, World!")
	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, s := range result.Strings {
		if s.Type != "ascii" {
			t.Errorf("expected type ascii, got %s", s.Type)
		}
	}
}

func TestExtractUnicodeOnly(t *testing.T) {
	// Create UTF-16LE encoded string "Hello"
	data := []byte{
		'H', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00,
	}

	opts := &Options{
		MinLength: 2,
		Type:      "unicode",
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Strings) == 0 {
		t.Error("expected at least one unicode string")
	}

	for _, s := range result.Strings {
		if s.Type != "unicode" {
			t.Errorf("expected type unicode, got %s", s.Type)
		}
	}
}

func TestExtractMaxCount(t *testing.T) {
	data := []byte("String1 String2 String3 String4 String5")
	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
		MaxCount:  2,
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Strings) > 2 {
		t.Errorf("expected at most 2 strings, got %d", len(result.Strings))
	}
}

func TestExtractWithRegex(t *testing.T) {
	data := []byte("Hello World 123 Test 456")
	opts := &Options{
		MinLength: 1,
		Type:      "ascii",
		Regex:     `^\d+$`,
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, s := range result.Strings {
		if s.Value != "123" && s.Value != "456" {
			t.Errorf("expected only numeric strings, got %s", s.Value)
		}
	}
}

func TestExtractInvalidRegex(t *testing.T) {
	data := []byte("test data")
	opts := &Options{
		MinLength: 1,
		Type:      "ascii",
		Regex:     `[invalid`,
	}

	_, err := Extract(data, "test.bin", opts)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestExtractEntropy(t *testing.T) {
	// High entropy data (random bytes)
	data := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	opts := &Options{
		MinLength: 1,
		Type:      "ascii",
		MinEntropy: 3.0,
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should include high entropy strings
	if len(result.Strings) == 0 {
		t.Error("expected at least one high entropy string")
	}

	for _, s := range result.Strings {
		if s.Entropy < 3.0 {
			t.Errorf("expected entropy >= 3.0, got %f", s.Entropy)
		}
	}
}

func TestExtractEmptyData(t *testing.T) {
	result, err := Extract([]byte{}, "empty.bin", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Total != 0 {
		t.Errorf("expected 0 strings, got %d", result.Total)
	}
}

func TestExtractBinaryData(t *testing.T) {
	// Binary data with embedded strings
	data := []byte{
		0x00, 0x00, 'H', 'e', 'l', 'l', 'o', 0x00, 0x00, 'W', 'o', 'r', 'l', 'd',
	}

	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
	}

	result, err := Extract(data, "binary.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Strings) < 2 {
		t.Errorf("expected at least 2 strings, got %d", len(result.Strings))
	}
}

func TestExtractStringAtEnd(t *testing.T) {
	data := []byte("Hello World")
	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should capture string at end of data
	found := false
	for _, s := range result.Strings {
		if s.Value == "Hello World" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find 'Hello World' at end of data")
	}
}

func TestDetectEncodingEmpty(t *testing.T) {
	encoding := DetectEncoding([]byte{})
	if encoding != "unknown" {
		t.Errorf("expected unknown, got %s", encoding)
	}
}

func TestDetectEncodingUTF8(t *testing.T) {
	data := []byte("Hello, World!")
	encoding := DetectEncoding(data)
	// Both ascii and utf-8 are valid for this data
	if encoding != "ascii" && encoding != "utf-8" {
		t.Errorf("expected ascii or utf-8, got %s", encoding)
	}
}

func TestDetectEncodingUTF8BOM(t *testing.T) {
	data := []byte{0xEF, 0xBB, 0xBF, 'H', 'e', 'l', 'l', 'o'}
	encoding := DetectEncoding(data)
	if encoding != "utf-8-bom" {
		t.Errorf("expected utf-8-bom, got %s", encoding)
	}
}

func TestDetectEncodingUTF16LE(t *testing.T) {
	data := []byte{0xFF, 0xFE, 'H', 0x00}
	encoding := DetectEncoding(data)
	if encoding != "utf-16le" {
		t.Errorf("expected utf-16le, got %s", encoding)
	}
}

func TestDetectEncodingUTF16BE(t *testing.T) {
	data := []byte{0xFE, 0xFF, 0x00, 'H'}
	encoding := DetectEncoding(data)
	if encoding != "utf-16be" {
		t.Errorf("expected utf-16be, got %s", encoding)
	}
}

func TestDetectEncodingBinary(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x80, 0xFF}
	encoding := DetectEncoding(data)
	if encoding != "binary" {
		t.Errorf("expected binary, got %s", encoding)
	}
}

func TestIsPrintableRatioEmpty(t *testing.T) {
	ratio := IsPrintableRatio([]byte{})
	if ratio != 0 {
		t.Errorf("expected 0, got %f", ratio)
	}
}

func TestIsPrintableRatioAllPrintable(t *testing.T) {
	data := []byte("Hello, World!")
	ratio := IsPrintableRatio(data)
	if ratio != 1.0 {
		t.Errorf("expected 1.0, got %f", ratio)
	}
}

func TestIsPrintableRatioAllNonPrintable(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03}
	ratio := IsPrintableRatio(data)
	if ratio != 0 {
		t.Errorf("expected 0, got %f", ratio)
	}
}

func TestIsPrintableRatioMixed(t *testing.T) {
	data := []byte("Hello\x00\x01\x02")
	ratio := IsPrintableRatio(data)
	if ratio < 0.5 || ratio > 0.8 {
		t.Errorf("expected ratio between 0.5 and 0.8, got %f", ratio)
	}
}

func TestStringEntryJSON(t *testing.T) {
	entry := StringEntry{
		Offset:  1024,
		Value:   "test string",
		Type:    "ascii",
		Entropy: 3.5,
	}

	if entry.Offset != 1024 {
		t.Errorf("expected offset 1024, got %d", entry.Offset)
	}
	if entry.Value != "test string" {
		t.Errorf("expected value 'test string', got %s", entry.Value)
	}
	if entry.Type != "ascii" {
		t.Errorf("expected type ascii, got %s", entry.Type)
	}
	if entry.Entropy != 3.5 {
		t.Errorf("expected entropy 3.5, got %f", entry.Entropy)
	}
}

func TestResultJSON(t *testing.T) {
	result := Result{
		FileName: "test.bin",
		Strings: []StringEntry{
			{Offset: 0, Value: "hello", Type: "ascii", Entropy: 2.0},
		},
		Total: 1,
	}

	if result.FileName != "test.bin" {
		t.Errorf("expected filename test.bin, got %s", result.FileName)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
}

func TestExtractSpecialCharacters(t *testing.T) {
	data := []byte("Hello\tWorld\nTest\rString")
	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should capture strings with tabs and newlines
	if len(result.Strings) == 0 {
		t.Error("expected at least one string with special characters")
	}
}

func TestExtractMultipleStrings(t *testing.T) {
	data := []byte("First string\x00Second string\x00Third string")
	opts := &Options{
		MinLength: 4,
		Type:      "ascii",
	}

	result, err := Extract(data, "test.bin", opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Strings) < 3 {
		t.Errorf("expected at least 3 strings, got %d", len(result.Strings))
	}
}
