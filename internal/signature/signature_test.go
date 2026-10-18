package signature

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math/rand"
	"strings"
	"testing"
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 7, 5))
	img.Set(1, 1, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func jpegBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 9))
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gifBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewPaletted(image.Rect(0, 0, 3, 4), color.Palette{color.Black, color.White})
	var b bytes.Buffer
	if err := gif.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipBytes(t *testing.T, entries int) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i := 0; i < entries; i++ {
		f, err := w.Create("dir/file" + string(rune('a'+i%26)) + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		f.Write(bytes.Repeat([]byte("hello "), 50))
	}
	w.Close()
	return b.Bytes()
}

func gzipBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Name = "notes.txt"
	w.Write([]byte("some text"))
	w.Close()
	return b.Bytes()
}

func tarBytes(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	body := []byte("tar body")
	w.WriteHeader(&tar.Header{Name: "etc/passwd", Mode: 0o644, Size: int64(len(body)), Format: tar.FormatUSTAR})
	w.Write(body)
	w.Close()
	return b.Bytes()
}

func elf64() []byte {
	d := make([]byte, 64)
	copy(d, "\x7fELF")
	d[4], d[5], d[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(d[16:], 2)    // executable
	binary.LittleEndian.PutUint16(d[18:], 0x3E) // x86-64
	return d
}

func pe32plus() []byte {
	d := make([]byte, 0x200)
	copy(d, "MZ")
	binary.LittleEndian.PutUint32(d[60:], 0x80)
	copy(d[0x80:], "PE\x00\x00")
	coff := d[0x84:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], 1)    // one section
	binary.LittleEndian.PutUint16(coff[16:], 240) // optional header size
	opt := d[0x98:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)
	binary.LittleEndian.PutUint16(opt[68:], 3) // console
	sec := d[0x98+240:]
	binary.LittleEndian.PutUint32(sec[16:], 0x20)  // raw size
	binary.LittleEndian.PutUint32(sec[20:], 0x1E0) // raw offset
	return d
}

func xzHeader() []byte {
	d := []byte{0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x04, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(d[8:], crc32.ChecksumIEEE(d[6:8]))
	return d
}

func TestIdentify(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		format string
		desc   string
		size   bool
	}{
		{"png", pngBytes(t), "png", "PNG image, 7 x 5", true},
		{"jpeg", jpegBytes(t), "jpeg", "16 x 9", true},
		{"gif", gifBytes(t), "gif", "GIF image, version 89a, 3 x 4", true},
		{"zip", zipBytes(t, 3), "zip", "3 entries", true},
		{"gzip", gzipBytes(t), "gzip", `original name "notes.txt"`, false},
		{"tar", tarBytes(t), "tar", `"etc/passwd"`, false},
		{"elf", elf64(), "elf", "ELF 64-bit LSB executable, x86-64", false},
		{"pe", pe32plus(), "pe", "PE32+ executable, x86-64, console", true},
		{"xz", xzHeader(), "xz", "XZ compressed data", false},
		{"pdf", []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n%%EOF\n"), "pdf", "version 1.7", true},
		{"sqlite", append([]byte("SQLite format 3\x00\x10\x00"), make([]byte, 100)...), "sqlite", "page size 4096", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := Identify(c.data)
			if !ok {
				t.Fatalf("not identified")
			}
			if m.Format != c.format {
				t.Errorf("format = %q, want %q", m.Format, c.format)
			}
			if !strings.Contains(m.Description, c.desc) {
				t.Errorf("description %q does not contain %q", m.Description, c.desc)
			}
			if c.size && m.Size != int64(len(c.data)) {
				t.Errorf("size = %d, want %d", m.Size, len(c.data))
			}
		})
	}
}

func TestScanFindsEmbeddedFilesInOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	noise := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		return b
	}
	p, z, j := pngBytes(t), zipBytes(t, 40), jpegBytes(t)
	var blob []byte
	blob = append(blob, noise(1000)...)
	pngOff := len(blob)
	blob = append(blob, p...)
	blob = append(blob, noise(777)...)
	zipOff := len(blob)
	blob = append(blob, z...)
	blob = append(blob, noise(333)...)
	jpgOff := len(blob)
	blob = append(blob, j...)
	blob = append(blob, noise(100)...)

	got := Scan(blob, Options{})
	want := []struct {
		off    int
		format string
		size   int
	}{{pngOff, "png", len(p)}, {zipOff, "zip", len(z)}, {jpgOff, "jpeg", len(j)}}
	if len(got) != len(want) {
		t.Fatalf("got %d matches, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Offset != int64(w.off) || got[i].Format != w.format || got[i].Size != int64(w.size) {
			t.Errorf("match %d = %+v, want offset %d format %s size %d", i, got[i], w.off, w.format, w.size)
		}
	}
}

func TestScanSuppressesNestedMatchesByDefault(t *testing.T) {
	z := zipBytes(t, 40)
	if got := Scan(z, Options{}); len(got) != 1 {
		t.Fatalf("default scan: got %d matches, want 1", len(got))
	}
	if got := Scan(z, Options{IncludeNested: true}); len(got) != 40 {
		t.Fatalf("nested scan: got %d matches, want 40 local headers", len(got))
	}
}

func TestScanRandomDataHasNoFalsePositives(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	data := make([]byte, 8<<20)
	rng.Read(data)
	got := Scan(data, Options{})
	if len(got) > 0 {
		t.Errorf("found %d false positives in 8 MiB of random data, first: %+v", len(got), got[0])
	}
}

func TestScanFormatFilterAndLimit(t *testing.T) {
	blob := append(pngBytes(t), gzipBytes(t)...)
	if got := Scan(blob, Options{Formats: []string{"gzip"}}); len(got) != 1 || got[0].Format != "gzip" {
		t.Errorf("format filter: %+v", got)
	}
	if got := Scan(blob, Options{Limit: 1}); len(got) != 1 {
		t.Errorf("limit: got %d matches", len(got))
	}
}

func TestTruncatedPNGIsFlagged(t *testing.T) {
	p := pngBytes(t)
	m, ok := Identify(p[:len(p)-12])
	if !ok || m.Size != 0 || !strings.Contains(m.Description, "truncated") {
		t.Errorf("truncated PNG: %+v %v", m, ok)
	}
}

func TestFormatsIsSortedAndUnique(t *testing.T) {
	f := Formats()
	for i := 1; i < len(f); i++ {
		if f[i-1] >= f[i] {
			t.Fatalf("Formats() not sorted/unique at %q, %q", f[i-1], f[i])
		}
	}
}

func BenchmarkScanRandom(b *testing.B) {
	data := make([]byte, 16<<20)
	rand.New(rand.NewSource(7)).Read(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Scan(data, Options{})
	}
}
