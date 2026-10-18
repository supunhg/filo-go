package safeio

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestJoin(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out")
	ok := map[string]string{
		"a.txt":          filepath.Join(dest, "a.txt"),
		"dir/b.txt":      filepath.Join(dest, "dir", "b.txt"),
		"dir/../c.txt":   filepath.Join(dest, "c.txt"),
		"./d.txt":        filepath.Join(dest, "d.txt"),
		`win\style.txt`:  filepath.Join(dest, "win", "style.txt"),
		"..hidden/e.txt": filepath.Join(dest, "..hidden", "e.txt"),
	}
	for name, want := range ok {
		got, err := Join(dest, name)
		if err != nil || got != want {
			t.Errorf("Join(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	bad := []string{"", "../evil", "a/../../evil", "/etc/passwd", `..\evil`, `C:\Windows\x`, "dir/../../.."}
	for _, name := range bad {
		if got, err := Join(dest, name); err == nil {
			t.Errorf("Join(%q) = %q, want error", name, got)
		}
	}
}

func TestCopyLimit(t *testing.T) {
	var out bytes.Buffer
	n, err := Copy(&out, strings.NewReader("12345"), 5)
	if err != nil || n != 5 {
		t.Errorf("exact limit: %d %v", n, err)
	}
	out.Reset()
	if _, err := Copy(&out, strings.NewReader("123456"), 5); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over limit: %v, want ErrTooLarge", err)
	}
	if out.Len() > 6 {
		t.Errorf("wrote %d bytes past the limit", out.Len())
	}
}
