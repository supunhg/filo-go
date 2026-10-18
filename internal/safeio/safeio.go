// Package safeio contains helpers for writing data derived from untrusted
// input: archive entry names that must stay inside a destination directory,
// and decompression that must not exhaust the disk.
package safeio

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// DefaultMaxExtract is the default limit on bytes written per extracted file.
const DefaultMaxExtract int64 = 4 << 30

// ErrTooLarge is returned when a copy exceeds its byte limit.
var ErrTooLarge = errors.New("output exceeds size limit (possible decompression bomb)")

// Join returns dest joined with an archive entry name, rejecting names that
// would escape dest ("zip slip"): absolute paths, drive letters and ".."
// components.
func Join(dest, name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	// Colons are rejected on every platform: on Windows they introduce drive
	// letters and alternate data streams.
	if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, ":") || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	cleaned := filepath.Clean(filepath.FromSlash(n))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("unsafe archive entry name %q", name)
	}
	return filepath.Join(dest, cleaned), nil
}

// DefaultMaxMemory is the default limit for data decompressed into memory.
const DefaultMaxMemory int64 = 256 << 20

// ReadAll reads src into memory, failing with ErrTooLarge after limit bytes.
// A limit of 0 or less means DefaultMaxMemory.
func ReadAll(src io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultMaxMemory
	}
	b, err := io.ReadAll(io.LimitReader(src, limit+1))
	if err != nil {
		return b, err
	}
	if int64(len(b)) > limit {
		return b[:limit], ErrTooLarge
	}
	return b, nil
}

// Copy copies from src to dst, failing with ErrTooLarge once more than limit
// bytes would be written. A limit of 0 or less means DefaultMaxExtract.
func Copy(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if limit <= 0 {
		limit = DefaultMaxExtract
	}
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return n, err
	}
	if n > limit {
		return limit, ErrTooLarge
	}
	return n, nil
}
