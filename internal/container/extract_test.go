package container

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractZIPRejectsPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range []string{"ok.txt", "../../escaped.txt"} {
		f, _ := w.Create(name)
		f.Write([]byte("payload"))
	}
	w.Close()

	base := t.TempDir()
	dest := filepath.Join(base, "out")
	if err := ExtractTo(buf.Bytes(), "zip", dest); err == nil {
		t.Fatal("ExtractTo accepted a zip-slip entry")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped.txt")); err == nil {
		t.Fatal("zip-slip entry was written outside the destination")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(base), "escaped.txt")); err == nil {
		t.Fatal("zip-slip entry was written outside the destination")
	}
}

func TestExtractTarSkipsLinksAndRejectsTraversal(t *testing.T) {
	build := func(hdrs ...*tar.Header) []byte {
		var raw bytes.Buffer
		gz := gzip.NewWriter(&raw)
		tw := tar.NewWriter(gz)
		for _, h := range hdrs {
			tw.WriteHeader(h)
			if h.Typeflag == tar.TypeReg {
				tw.Write(make([]byte, h.Size))
			}
		}
		tw.Close()
		gz.Close()
		return raw.Bytes()
	}

	dest := filepath.Join(t.TempDir(), "out")
	data := build(
		&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "dir/file.bin", Typeflag: tar.TypeReg, Size: 4, Mode: 0o644},
		&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	)
	if err := ExtractTo(data, "tar.gz", dest); err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "dir", "file.bin")); err != nil {
		t.Errorf("regular file missing: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		t.Error("symlink from archive was created")
	}

	evil := build(&tar.Header{Name: "../evil.bin", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644})
	if err := ExtractTo(evil, "tar.gz", filepath.Join(t.TempDir(), "out")); err == nil {
		t.Error("ExtractTo accepted a traversal entry in a tar")
	}
}
