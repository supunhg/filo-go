// Package pathguard confines file access to a directory tree.
//
// It is used by the REST API and the MCP server, which accept file paths from
// clients that may not be fully trusted (remote callers, or an AI agent
// steered by a malicious document). Paths are resolved through symlinks
// before the containment check, so neither "../" sequences nor links that
// point outside the root can escape it.
package pathguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrOutsideRoot is returned for paths that resolve outside the root.
var ErrOutsideRoot = errors.New("path is outside the allowed root")

// Guard resolves client-supplied paths. The zero value, and a Guard created
// with an empty root, allow any path.
type Guard struct {
	root string
}

// New returns a Guard confined to root. An empty root means unrestricted.
func New(root string) (*Guard, error) {
	if root == "" {
		return &Guard{}, nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("root %s: %w", root, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("root %s: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root %s is not a directory", root)
	}
	return &Guard{root: resolved}, nil
}

// Restricted reports whether the guard confines access to a root.
func (g *Guard) Restricted() bool { return g != nil && g.root != "" }

// Root returns the resolved root directory, or "" when unrestricted.
func (g *Guard) Root() string {
	if g == nil {
		return ""
	}
	return g.root
}

// File resolves p and requires it to be a regular file.
func (g *Guard) File(p string) (string, error) {
	resolved, info, err := g.resolve(p)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", p)
	}
	return resolved, nil
}

// Dir resolves p and requires it to be a directory.
func (g *Guard) Dir(p string) (string, error) {
	resolved, info, err := g.resolve(p)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s: not a directory", p)
	}
	return resolved, nil
}

// resolve turns p into an absolute, symlink-free path inside the root.
// Relative paths are taken relative to the root when one is set.
func (g *Guard) resolve(p string) (string, fs.FileInfo, error) {
	if p == "" {
		return "", nil, errors.New("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return "", nil, errors.New("path contains a NUL byte")
	}
	if g.Restricted() && !filepath.IsAbs(p) {
		p = filepath.Join(g.root, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Do not reveal whether files outside the root exist.
			if g.Restricted() && !within(g.root, abs) {
				return "", nil, ErrOutsideRoot
			}
			return "", nil, fs.ErrNotExist
		}
		return "", nil, err
	}
	if g.Restricted() && !within(g.root, resolved) {
		return "", nil, ErrOutsideRoot
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, err
	}
	return resolved, info, nil
}

// within reports whether path is root or lies below it. Both must be clean
// absolute paths.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
