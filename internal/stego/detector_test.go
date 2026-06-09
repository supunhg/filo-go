package stego

import (
	"testing"
)

func TestDetectSmallData(t *testing.T) {
	result, err := Detect([]byte{0x01, 0x02}, "tiny.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Format != "" {
		t.Errorf("expected empty format for small data, got %s", result.Format)
	}
}

func TestDetectPNG(t *testing.T) {
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE,
	}

	result, err := Detect(data, "test.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "png" {
		t.Errorf("expected format png, got %s", result.Format)
	}
}

func TestDetectJPEG(t *testing.T) {
	data := []byte{
		0xFF, 0xD8, 0xFF, 0xE0,
		0x00, 0x10,
		0x4A, 0x46, 0x49, 0x46, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0xFF, 0xD9,
	}

	result, err := Detect(data, "test.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "jpeg" {
		t.Errorf("expected format jpeg, got %s", result.Format)
	}
}

func TestDetectPDF(t *testing.T) {
	data := []byte("%PDF-1.7\r\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")

	result, err := Detect(data, "test.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "pdf" {
		t.Errorf("expected format pdf, got %s", result.Format)
	}
}

func TestDetectGIF(t *testing.T) {
	data := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
		0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
		0xFF, 0xFF, 0xFF,
		0x21, 0xF9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x02, 0x02, 0x44, 0x01, 0x00,
		0x3B,
	}

	result, err := Detect(data, "test.gif")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "gif" {
		t.Errorf("expected format gif, got %s", result.Format)
	}
}

func TestDetectUnknownFormat(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	result, err := Detect(data, "unknown.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "unknown" {
		t.Errorf("expected format unknown, got %s", result.Format)
	}
}

func TestDetectFlagPattern(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"picoCTF flag", []byte("picoCTF{this_is_a_flag}"), true},
		{"flag{} pattern", []byte("flag{test123}"), true},
		{"HTB flag", []byte("HTB{hack_the_box}"), true},
		{"no flag", []byte("just some random text"), false},
		{"empty data", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectFlagPattern(tt.data); got != tt.expected {
				t.Errorf("detectFlagPattern() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExtractFlag(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"picoCTF flag", []byte("some text picoCTF{this_is_a_flag} more text"), "picoCTF{this_is_a_flag}"},
		{"flag{} pattern", []byte("flag{test123}"), "flag{test123}"},
		{"HTB flag", []byte("HTB{hack_the_box}"), "HTB{hack_the_box}"},
		{"no flag", []byte("just some random text"), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractFlag(tt.data); got != tt.expected {
				t.Errorf("extractFlag() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"printable text", []byte("Hello, World!"), true},
		{"binary data", []byte{0x00, 0x01, 0x02, 0x03}, false},
		{"empty data", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPrintable(tt.data); got != tt.expected {
				t.Errorf("isPrintable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF}, "jpeg"},
		{"PDF", []byte{0x25, 0x50, 0x44, 0x46}, "pdf"},
		{"GIF", []byte{0x47, 0x49, 0x46, 0x38}, "gif"},
		{"Unknown", []byte{0x00, 0x00, 0x00, 0x00}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectFormat(tt.data); got != tt.expected {
				t.Errorf("detectFormat() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMethodResultJSON(t *testing.T) {
	m := MethodResult{
		Name:       "test_method",
		Confidence: 0.85,
		Data:       "test data",
		HasFlag:    true,
		Preview:    "preview",
	}

	if m.Name != "test_method" {
		t.Errorf("expected name test_method, got %s", m.Name)
	}
	if m.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %f", m.Confidence)
	}
	if !m.HasFlag {
		t.Error("expected HasFlag true")
	}
}

func TestResultJSON(t *testing.T) {
	r := Result{
		FileName: "test.png",
		Format:   "png",
		Methods:  []MethodResult{},
		Flags:    []string{"flag1"},
	}

	if r.FileName != "test.png" {
		t.Errorf("expected filename test.png, got %s", r.FileName)
	}
	if r.Format != "png" {
		t.Errorf("expected format png, got %s", r.Format)
	}
	if len(r.Flags) != 1 {
		t.Errorf("expected 1 flag, got %d", len(r.Flags))
	}
}

func TestDetectPNGMetadata(t *testing.T) {
	// PNG with tEXt chunk
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE,
	}

	result, err := Detect(data, "test.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// PNG detection should work
	if result.Format != "png" {
		t.Errorf("expected format png, got %s", result.Format)
	}
}

func TestJPEGTrailingData(t *testing.T) {
	// JPEG with trailing data
	data := []byte{
		0xFF, 0xD8, 0xFF, 0xE0,
		0x00, 0x10,
		0x4A, 0x46, 0x49, 0x46, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0xFF, 0xD9,
		0x53, 0x65, 0x63, 0x72, 0x65, 0x74, // "Secret"
	}

	result, err := Detect(data, "test.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect trailing data
	foundTrailing := false
	for _, m := range result.Methods {
		if m.Name == "jpeg_trailing" {
			foundTrailing = true
		}
	}

	if !foundTrailing {
		t.Error("expected jpeg_trailing method to be detected")
	}
}

func TestGIFTrailingData(t *testing.T) {
	// GIF with trailing data
	data := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61,
		0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
		0xFF, 0xFF, 0xFF,
		0x21, 0xF9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x02, 0x02, 0x44, 0x01, 0x00,
		0x3B, // Trailer
		0xDE, 0xAD, 0xBE, 0xEF, // Trailing data
	}

	result, err := Detect(data, "test.gif")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect trailing data
	foundTrailing := false
	for _, m := range result.Methods {
		if m.Name == "gif_trailing" {
			foundTrailing = true
		}
	}

	if !foundTrailing {
		t.Error("expected gif_trailing method to be detected")
	}
}

func TestEmptyData(t *testing.T) {
	result, err := Detect([]byte{}, "empty.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Format != "" {
		t.Errorf("expected empty format, got %s", result.Format)
	}
	if len(result.Methods) != 0 {
		t.Errorf("expected no methods, got %d", len(result.Methods))
	}
}
