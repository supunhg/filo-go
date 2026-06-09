package carver

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestDetectCompression(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want CompressionType
	}{
		{"gzip", []byte{0x1F, 0x8B, 0x08}, CompressionGzip},
		{"xz", []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, CompressionXZ},
		{"lzma", []byte{0x5D, 0x00, 0x00}, CompressionLZMA},
		{"zstd", []byte{0x28, 0xB5, 0x2F, 0xFD}, CompressionZstd},
		{"none", []byte{0x00, 0x00, 0x00}, CompressionNone},
		{"empty", []byte{}, CompressionNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectCompression(tt.data)
			if got != tt.want {
				t.Errorf("DetectCompression() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompressionTypeString(t *testing.T) {
	tests := []struct {
		compType CompressionType
		want     string
	}{
		{CompressionGzip, "gzip"},
		{CompressionXZ, "xz"},
		{CompressionLZMA, "lzma"},
		{CompressionNone, "none"},
	}

	for _, tt := range tests {
		if got := tt.compType.String(); got != tt.want {
			t.Errorf("CompressionType.String() = %v, want %v", got, tt.want)
		}
	}
}

func TestDecompressGzip(t *testing.T) {
	original := []byte("Hello, World! This is test data for gzip compression.")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(original)
	w.Close()

	decompressed, err := Decompress(buf.Bytes(), CompressionGzip)
	if err != nil {
		t.Fatalf("Decompress() error = %v", err)
	}

	if !bytes.Equal(decompressed, original) {
		t.Errorf("Decompress() = %v, want %v", decompressed, original)
	}
}

func TestDecompressInvalidData(t *testing.T) {
	_, err := Decompress([]byte("invalid data"), CompressionGzip)
	if err == nil {
		t.Error("Expected error for invalid gzip data")
	}
}

func TestAnalyzeCompression(t *testing.T) {
	original := []byte("Hello, World! This is test data for compression analysis.")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(original)
	w.Close()

	info := AnalyzeCompression(buf.Bytes())
	if info == nil {
		t.Fatal("Expected non-nil info")
	}

	if info.Type != CompressionGzip {
		t.Errorf("Expected gzip, got %v", info.Type)
	}

	if info.OriginalSize != len(original) {
		t.Errorf("Expected original size %d, got %d", len(original), info.OriginalSize)
	}
}

func TestFormatCompressionInfo(t *testing.T) {
	result := FormatCompressionInfo(nil)
	if result != "No compression detected" {
		t.Errorf("Expected 'No compression detected', got %s", result)
	}

	info := &CompressionInfo{
		Type:            CompressionGzip,
		CompressedSize:  100,
		OriginalSize:    200,
		Ratio:           2.0,
		NeedsDecompress: true,
	}
	result = FormatCompressionInfo(info)
	if result == "" {
		t.Error("Expected non-empty result")
	}
}
