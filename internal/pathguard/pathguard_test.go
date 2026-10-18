package pathguard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func setup(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "data")
	outside = filepath.Join(base, "data-secret") // shares the root's prefix
	for _, d := range []string{root, filepath.Join(root, "sub"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(root, "a.bin"), filepath.Join(root, "sub", "b.bin"), filepath.Join(outside, "key.pem")} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, outside
}

func TestRestrictedGuard(t *testing.T) {
	root, outside := setup(t)
	g, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	allowed := []string{"a.bin", "sub/b.bin", filepath.Join(root, "a.bin"), "sub/../a.bin"}
	for _, p := range allowed {
		if _, err := g.File(p); err != nil {
			t.Errorf("File(%q) = %v, want allowed", p, err)
		}
	}
	if _, err := g.Dir("sub"); err != nil {
		t.Errorf("Dir(sub) = %v", err)
	}

	denied := []string{
		"../data-secret/key.pem",
		filepath.Join(outside, "key.pem"), // the old HasPrefix check allowed this
		"../../../../etc/passwd",
		"sub/../../data-secret/key.pem",
	}
	for _, p := range denied {
		if _, err := g.File(p); !errors.Is(err, ErrOutsideRoot) {
			t.Errorf("File(%q) = %v, want ErrOutsideRoot", p, err)
		}
	}
}

func TestMissingFilesDoNotLeakExistence(t *testing.T) {
	root, _ := setup(t)
	g, _ := New(root)
	if _, err := g.File("nope.bin"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file inside root: %v", err)
	}
	if _, err := g.File("../definitely-missing"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("missing file outside root: %v, want ErrOutsideRoot", err)
	}
}

func TestSymlinkEscape(t *testing.T) {
	root, outside := setup(t)
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	g, _ := New(root)
	if _, err := g.File("escape/key.pem"); !errors.Is(err, ErrOutsideRoot) {
		t.Errorf("symlink escape: %v, want ErrOutsideRoot", err)
	}
}

func TestTypeChecks(t *testing.T) {
	root, _ := setup(t)
	g, _ := New(root)
	if _, err := g.File("sub"); err == nil {
		t.Error("File accepted a directory")
	}
	if _, err := g.Dir("a.bin"); err == nil {
		t.Error("Dir accepted a file")
	}
	if _, err := g.File(""); err == nil {
		t.Error("File accepted an empty path")
	}
	if _, err := g.File("a\x00.bin"); err == nil {
		t.Error("File accepted a NUL byte")
	}
}

func TestUnrestricted(t *testing.T) {
	root, outside := setup(t)
	g, err := New("")
	if err != nil || g.Restricted() {
		t.Fatalf("New(\"\") = %v, restricted=%v", err, g.Restricted())
	}
	if _, err := g.File(filepath.Join(outside, "key.pem")); err != nil {
		t.Errorf("unrestricted guard denied access: %v", err)
	}
	_ = root
}

func TestNewRejectsBadRoots(t *testing.T) {
	root, _ := setup(t)
	if _, err := New(filepath.Join(root, "a.bin")); err == nil {
		t.Error("New accepted a file as root")
	}
	if _, err := New(filepath.Join(root, "missing")); err == nil {
		t.Error("New accepted a missing root")
	}
}
