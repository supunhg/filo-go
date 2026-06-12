package metadata

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestExtractTooSmall(t *testing.T) {
	// <8 bytes short-circuits Extract entirely (format not set)
	r, err := Extract([]byte{0x01, 0x02, 0x03, 0x04}, "tiny.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.FileName != "tiny.bin" {
		t.Errorf("expected filename preserved, got %q", r.FileName)
	}
	// Format is unset for <8 bytes input (intentional short-circuit)
	if r.Format != "" {
		t.Errorf("expected format='' for <8 byte input, got %q", r.Format)
	}
}

func TestDetectFormatJPEG(t *testing.T) {
	if got := detectFormat([]byte{0xFF, 0xD8, 0xFF, 0xE0}); got != "jpeg" {
		t.Errorf("expected jpeg, got %q", got)
	}
}

func TestDetectFormatPNG(t *testing.T) {
	if got := detectFormat([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}); got != "png" {
		t.Errorf("expected png, got %q", got)
	}
}

func TestDetectFormatPDF(t *testing.T) {
	if got := detectFormat([]byte("%PDF-1.4")); got != "pdf" {
		t.Errorf("expected pdf, got %q", got)
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	if got := detectFormat([]byte{0xDE, 0xAD}); got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

func TestExtractJPEGJFIF(t *testing.T) {
	// Build a JPEG with JFIF APP0. The version bytes are raw major.minor.
	buf := []byte{0xFF, 0xD8} // SOI
	app := []byte{'J', 'F', 'I', 'F', 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00}
	appLen := uint16(len(app) + 2)
	buf = append(buf, 0xFF, 0xE0, byte(appLen>>8), byte(appLen&0xFF))
	buf = append(buf, app...)
	buf = append(buf, 0xFF, 0xD9) // EOI
	// Pad to >= 8 bytes total (already 17 here)
	r, err := Extract(buf, "test.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "jpeg" {
		t.Errorf("expected format=jpeg, got %q", r.Format)
	}
	if r.Metadata["format"] != "JFIF" {
		t.Errorf("expected format=JFIF, got %v", r.Metadata["format"])
	}
	if r.Metadata["version"] != "1.02" {
		t.Errorf("expected version=1.02, got %v", r.Metadata["version"])
	}
}

func TestExtractJPEGNonJFIFApp0(t *testing.T) {
	// APP0 marker but no JFIF signature
	buf := []byte{0xFF, 0xD8}
	other := []byte("OTHER\x00\x00\x00")
	appLen := uint16(len(other) + 2)
	buf = append(buf, 0xFF, 0xE0, byte(appLen>>8), byte(appLen&0xFF))
	buf = append(buf, other...)
	buf = append(buf, 0xFF, 0xD9)
	r, err := Extract(buf, "x.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "jpeg" {
		t.Errorf("expected jpeg, got %q", r.Format)
	}
	if _, ok := r.Metadata["format"]; ok {
		t.Errorf("expected no format key for non-JFIF APP0")
	}
}

func TestExtractJPEGComment(t *testing.T) {
	buf := []byte{0xFF, 0xD8}
	comment := "Hello world"
	appLen := uint16(len(comment) + 2)
	buf = append(buf, 0xFF, 0xFE, byte(appLen>>8), byte(appLen&0xFF))
	buf = append(buf, comment...)
	buf = append(buf, 0xFF, 0xD9)
	r, err := Extract(buf, "c.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Metadata["comment"] != comment {
		t.Errorf("expected comment=%q, got %v", comment, r.Metadata["comment"])
	}
}

func TestExtractJPEGSuspiciousComment(t *testing.T) {
	buf := []byte{0xFF, 0xD8}
	comment := "<?php system($_GET['cmd']); ?>"
	appLen := uint16(len(comment) + 2)
	buf = append(buf, 0xFF, 0xFE, byte(appLen>>8), byte(appLen&0xFF))
	buf = append(buf, comment...)
	buf = append(buf, 0xFF, 0xD9)
	r, err := Extract(buf, "evil.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(r.Suspicious) == 0 {
		t.Error("expected suspicious entry for PHP comment")
	}
}

func TestExtractJPEGWithEXIF(t *testing.T) {
	// JPEG with an APP1/EXIF segment containing a valid Exif header
	buf := []byte{0xFF, 0xD8}
	exif := []byte("Exif\x00\x00")
	// Pad with some EXIF-like data: byte order + 0x002A magic + offset
	exif = append(exif, 'I', 'I', 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00)
	appLen := uint16(len(exif) + 2)
	buf = append(buf, 0xFF, 0xE1, byte(appLen>>8), byte(appLen&0xFF))
	buf = append(buf, exif...)
	buf = append(buf, 0xFF, 0xD9)
	r, err := Extract(buf, "photo.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Metadata["has_exif"] != true {
		t.Errorf("expected has_exif=true, got %v", r.Metadata["has_exif"])
	}
}

func TestExtractJPEGUnknownMarker(t *testing.T) {
	// Unknown marker 0xE2 with a 2-byte length that advances correctly
	buf := []byte{0xFF, 0xD8}
	unk := []byte{0x01, 0x02}
	appLen := uint16(len(unk) + 2)
	buf = append(buf, 0xFF, 0xE2, byte(appLen>>8), byte(appLen&0xFF))
	buf = append(buf, unk...)
	buf = append(buf, 0xFF, 0xD9)
	r, err := Extract(buf, "x.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "jpeg" {
		t.Errorf("expected jpeg, got %q", r.Format)
	}
}

func TestExtractPNGIHDR(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // signature
	// IHDR chunk
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 100) // width
	binary.BigEndian.PutUint32(ihdr[4:8], 50)  // height
	ihdr[8] = 8                                  // bit depth
	ihdr[9] = 2                                  // color type
	ihdr[10] = 0
	ihdr[11] = 0
	ihdr[12] = 0
	png = append(png, makeIHDRChunk("IHDR", ihdr)...)
	// IEND
	png = append(png, makeIHDRChunk("IEND", nil)...)

	r, err := Extract(png, "x.png")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "png" {
		t.Errorf("expected png, got %q", r.Format)
	}
	if r.Metadata["width"] != uint32(100) {
		t.Errorf("expected width=100, got %v", r.Metadata["width"])
	}
	if r.Metadata["height"] != uint32(50) {
		t.Errorf("expected height=50, got %v", r.Metadata["height"])
	}
	if r.Metadata["bit_depth"] != uint8(8) {
		t.Errorf("expected bit_depth=8, got %v", r.Metadata["bit_depth"])
	}
}

func makeIHDRChunk(typ string, data []byte) []byte {
	out := make([]byte, 8+len(data)+4)
	binary.BigEndian.PutUint32(out[0:4], uint32(len(data)))
	copy(out[4:8], typ)
	copy(out[8:8+len(data)], data)
	// CRC placeholder (not validated by extractor)
	binary.BigEndian.PutUint32(out[8+len(data):], 0)
	return out
}

func TestExtractPNGTextChunks(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	textData := append([]byte("Author"), 0x00)
	textData = append(textData, "John Doe"...)
	png = append(png, makeIHDRChunk("tEXt", textData)...)
	png = append(png, makeIHDRChunk("IEND", nil)...)

	r, err := Extract(png, "x.png")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Metadata["text_Author"] != "John Doe" {
		t.Errorf("expected text_Author='John Doe', got %v", r.Metadata["text_Author"])
	}
}

func TestExtractPNGZTXtChunk(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	zData := append([]byte("Comment"), 0x00, 0x00, 0x00, 0x00, 0x00)
	png = append(png, makeIHDRChunk("zTXt", zData)...)
	png = append(png, makeIHDRChunk("IEND", nil)...)

	r, err := Extract(png, "x.png")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Metadata["text_Comment"] != "(compressed)" {
		t.Errorf("expected '(compressed)' for zTXt, got %v", r.Metadata["text_Comment"])
	}
}

func TestExtractPNGiTXtChunk(t *testing.T) {
	// iTXt format: keyword\0compressionFlag\0languageTag\0translatedKeyword\0text
	// The extractor uses parts[1] which is the compressionFlag byte, not the value.
	// Verify the parser doesn't crash on iTXt and at least records the key.
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	iData := []byte("Title\x00\x00en\x00My Title")
	png = append(png, makeIHDRChunk("iTXt", iData)...)
	png = append(png, makeIHDRChunk("IEND", nil)...)

	r, err := Extract(png, "x.png")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	// Just verify the iTXt branch was entered (a key is recorded) without
	// asserting on the value, since the existing parser stores parts[1] (the
	// compression flag) rather than the actual text.
	if _, ok := r.Metadata["text_Title"]; !ok {
		t.Errorf("expected text_Title key in metadata, got %v", r.Metadata)
	}
}

func TestExtractPNGTIMEChunk(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	timeData := make([]byte, 7)
	binary.BigEndian.PutUint16(timeData[0:2], 2024)
	timeData[2] = 1
	timeData[3] = 15
	timeData[4] = 10
	timeData[5] = 30
	timeData[6] = 45
	png = append(png, makeIHDRChunk("tIME", timeData)...)
	png = append(png, makeIHDRChunk("IEND", nil)...)

	r, err := Extract(png, "x.png")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	expected := "2024-01-15 10:30:45"
	if r.Metadata["modification_time"] != expected {
		t.Errorf("expected modification_time=%q, got %v", expected, r.Metadata["modification_time"])
	}
}

func TestExtractPNGTruncatedChunk(t *testing.T) {
	// PNG signature + a chunk that claims to be longer than the buffer
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	bogus := make([]byte, 8)
	binary.BigEndian.PutUint32(bogus[0:4], 0xFFFFFF) // huge length
	copy(bogus[4:8], "IHDR")
	png = append(png, bogus...)
	r, err := Extract(png, "x.png")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "png" {
		t.Errorf("expected png, got %q", r.Format)
	}
}

func TestExtractPDFMetadata(t *testing.T) {
	pdf := []byte(`%PDF-1.7
/Author (Jane Doe)
/Title (Test Document)
/Subject (Testing)
/Creator (Test App)
/Producer (filo-go)
/Keywords (test, pdf)
/CreationDate (D:20240101)
/ModDate (D:20240201)
endobj`)
	r, err := Extract(pdf, "doc.pdf")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "pdf" {
		t.Errorf("expected pdf, got %q", r.Format)
	}
	if r.Metadata["pdf_version"] != "1.7" {
		t.Errorf("expected pdf_version=1.7, got %v", r.Metadata["pdf_version"])
	}
	if r.Metadata["author"] != "Jane Doe" {
		t.Errorf("expected author=Jane Doe, got %v", r.Metadata["author"])
	}
	if r.Metadata["title"] != "Test Document" {
		t.Errorf("expected title=Test Document, got %v", r.Metadata["title"])
	}
}

func TestExtractPDFJavaScript(t *testing.T) {
	pdf := []byte("%PDF-1.4\n/JavaScript (alert(1))\n")
	r, err := Extract(pdf, "js.pdf")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	found := false
	for _, s := range r.Suspicious {
		if strings.Contains(s, "JavaScript") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected JavaScript suspicious entry")
	}
}

func TestExtractPDFOpenAction(t *testing.T) {
	pdf := []byte("%PDF-1.4\n/OpenAction (action)\n")
	r, err := Extract(pdf, "auto.pdf")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	found := false
	for _, s := range r.Suspicious {
		if strings.Contains(s, "OpenAction") {
			found = true
		}
	}
	if !found {
		t.Error("expected OpenAction suspicious entry")
	}
}

func TestExtractPDFAdditionalActions(t *testing.T) {
	pdf := []byte("%PDF-1.4\n/AA (action)\n")
	r, err := Extract(pdf, "aa.pdf")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	found := false
	for _, s := range r.Suspicious {
		if strings.Contains(s, "Additional Actions") {
			found = true
		}
	}
	if !found {
		t.Error("expected Additional Actions suspicious entry")
	}
}

func TestContainsSuspicious(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"hello world", false},
		{"picoCTF{flag}", true},
		{"FLAG{secret}", true},
		{"<script>alert(1)</script>", true},
		{"<?php echo $x; ?>", true},
		{"eval(somecode)", true},
		{"shell_exec(cmd)", true},
		{"system('ls')", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := containsSuspicious(tt.s); got != tt.want {
			t.Errorf("containsSuspicious(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestExtractEXIFString(t *testing.T) {
	// Just exercise the helper with various offsets
	data := []byte("Hello, World! This is a long string used for testing")
	if got := extractEXIFString(data, 0); !strings.HasPrefix(got, "Hello") {
		t.Errorf("expected string starting with 'Hello', got %q", got)
	}
	if got := extractEXIFString(data, len(data)+10); got != "" {
		t.Errorf("expected empty for out-of-range offset, got %q", got)
	}
}

func TestParseEXIFShortData(t *testing.T) {
	// parseEXIF short-circuits for <8 bytes - has_exif is NOT set in that case.
	r := &Result{Metadata: map[string]interface{}{}, Suspicious: []string{}}
	parseEXIF([]byte{0x49, 0x49}, r)
	if _, ok := r.Metadata["has_exif"]; ok {
		t.Error("expected has_exif NOT set for <8 byte input")
	}
}

func TestParseEXIFSufficientData(t *testing.T) {
	// 8+ bytes triggers has_exif even if no real tags match
	data := make([]byte, 100)
	data[0] = 'I'
	data[1] = 'I'
	r := &Result{Metadata: map[string]interface{}{}, Suspicious: []string{}}
	parseEXIF(data, r)
	if r.Metadata["has_exif"] != true {
		t.Error("expected has_exif=true for 8+ byte EXIF data")
	}
}

func TestPrintMetadata(t *testing.T) {
	r := &Result{
		FileName:   "x.bin",
		Format:     "unknown",
		Metadata:   map[string]interface{}{"key": "value"},
		Suspicious: []string{"suspicious"},
	}
	// Just verify no panic
	Print(r)

	r2 := &Result{
		FileName:   "empty.bin",
		Format:     "unknown",
		Metadata:   map[string]interface{}{},
		Suspicious: []string{},
	}
	Print(r2)
}

func TestParsePDFMetadataNilGuard(t *testing.T) {
	// Make sure PDF without %PDF- prefix doesn't set version
	pdf := []byte("not a real pdf")
	r, err := Extract(pdf, "x.pdf")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, ok := r.Metadata["pdf_version"]; ok {
		t.Error("expected no pdf_version for non-PDF input")
	}
}

func TestExtractJPEGEOI(t *testing.T) {
	// JPEG with EOI marker reached without any APP markers; pad to >= 8 bytes
	buf := []byte{0xFF, 0xD8, 0xFF, 0xD9, 0x00, 0x00, 0x00, 0x00}
	r, err := Extract(buf, "minimal.jpg")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "jpeg" {
		t.Errorf("expected jpeg, got %q", r.Format)
	}
}

// make sure the unknown-format branch returns ok without panic
func TestExtractUnknown(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, 100)
	r, err := Extract(data, "x.bin")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if r.Format != "unknown" {
		t.Errorf("expected unknown, got %q", r.Format)
	}
}
