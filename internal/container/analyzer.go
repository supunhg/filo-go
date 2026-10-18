package container

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/supunhg/filo-go/internal/safeio"
)

// Result holds container analysis results.
type Result struct {
	FileName   string         `json:"file_name"`
	Format     string         `json:"format"`
	Entries    []Entry        `json:"entries"`
	TotalSize  int64          `json:"total_size"`
	EntryCount int            `json:"entry_count"`
	Nested     []NestedResult `json:"nested,omitempty"`
}

// Entry represents a single file in a container.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Format string `json:"format"`
	IsDir  bool   `json:"is_dir"`
	Offset int64  `json:"offset,omitempty"`
}

// NestedResult holds results from nested container analysis.
type NestedResult struct {
	Path    string  `json:"path"`
	Format  string  `json:"format"`
	Entries []Entry `json:"entries"`
}

// Analyze examines a container file and lists its contents.
func Analyze(data []byte, fileName string, maxDepth int) (*Result, error) {
	result := &Result{
		FileName: fileName,
		Entries:  []Entry{},
		Nested:   []NestedResult{},
	}

	if len(data) < 4 {
		return result, nil
	}

	// Detect container format
	format := detectContainerFormat(data)
	result.Format = format

	switch format {
	case "zip":
		return analyzeZIP(data, result, maxDepth, 0)
	case "tar.gz", "tgz":
		return analyzeTarGz(data, result, maxDepth, 0)
	case "tar":
		return analyzeTar(data, result, maxDepth, 0)
	case "gzip":
		return analyzeGzip(data, result, maxDepth)
	case "7z":
		result.Entries = append(result.Entries, Entry{
			Path:   "[7-Zip archive - extraction required]",
			Format: "7z",
		})
	case "rar":
		result.Entries = append(result.Entries, Entry{
			Path:   "[RAR archive - extraction required]",
			Format: "rar",
		})
	default:
		return result, fmt.Errorf("unsupported container format: %s", format)
	}

	return result, nil
}

func detectContainerFormat(data []byte) string {
	if bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) {
		return "zip"
	}
	if bytes.HasPrefix(data, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) {
		return "7z"
	}
	if bytes.HasPrefix(data, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}) {
		return "rar"
	}
	if bytes.HasPrefix(data, []byte{0x1F, 0x8B}) {
		// Check if it's a tar.gz
		if len(data) > 2 {
			reader, err := gzip.NewReader(bytes.NewReader(data))
			if err == nil && reader != nil {
				header := make([]byte, 262)
				n, _ := io.ReadAtLeast(reader, header, 262)
				if n >= 262 && bytes.HasPrefix(header[257:], []byte("ustar")) {
					_ = reader.Close()
					return "tar.gz"
				}
				_ = reader.Close()
			}
		}
		return "gzip"
	}
	if len(data) >= 262 && bytes.HasPrefix(data[257:], []byte("ustar")) {
		return "tar"
	}
	return "unknown"
}

func analyzeZIP(data []byte, result *Result, maxDepth, currentDepth int) (*Result, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return result, err
	}

	for _, file := range reader.File {
		entry := Entry{
			Path:  file.Name,
			Size:  int64(file.UncompressedSize64),
			IsDir: file.FileInfo().IsDir(),
		}

		if !file.FileInfo().IsDir() {
			entry.Format = detectFileFormat(file.Name)
		}

		result.Entries = append(result.Entries, entry)
		result.TotalSize += int64(file.UncompressedSize64)

		// Recursive nested container analysis
		if !file.FileInfo().IsDir() && currentDepth < maxDepth {
			if isContainer(file.Name) {
				rc, err := file.Open()
				if err != nil {
					continue
				}
				nestedData, err := safeio.ReadAll(rc, 0)
				_ = rc.Close()
				if err != nil {
					continue
				}

				nestedResult, err := Analyze(nestedData, file.Name, maxDepth)
				if err == nil && len(nestedResult.Entries) > 0 {
					result.Nested = append(result.Nested, NestedResult{
						Path:    file.Name,
						Format:  nestedResult.Format,
						Entries: nestedResult.Entries,
					})
				}
			}
		}
	}

	result.EntryCount = len(result.Entries)
	return result, nil
}

func analyzeTarGz(data []byte, result *Result, maxDepth, currentDepth int) (*Result, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	defer func() { _ = reader.Close() }()

	return analyzeTarFromReader(reader, result, maxDepth, currentDepth)
}

func analyzeTar(data []byte, result *Result, maxDepth, currentDepth int) (*Result, error) {
	return analyzeTarFromReader(bytes.NewReader(data), result, maxDepth, currentDepth)
}

func analyzeTarFromReader(reader io.Reader, result *Result, maxDepth, currentDepth int) (*Result, error) {
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, err
		}

		entry := Entry{
			Path:  header.Name,
			Size:  header.Size,
			IsDir: header.Typeflag == tar.TypeDir,
		}

		if header.Typeflag != tar.TypeDir {
			entry.Format = detectFileFormat(header.Name)
		}

		result.Entries = append(result.Entries, entry)
		result.TotalSize += header.Size
	}

	result.EntryCount = len(result.Entries)
	return result, nil
}

func analyzeGzip(data []byte, result *Result, maxDepth int) (*Result, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	defer func() { _ = reader.Close() }()

	// Read first few bytes to detect inner format
	peek := make([]byte, 512)
	n, _ := io.ReadAtLeast(reader, peek, 4)

	if n >= 4 {
		innerFormat := detectContainerFormat(peek[:n])
		result.Entries = append(result.Entries, Entry{
			Path:   fmt.Sprintf("[gzip -> %s]", innerFormat),
			Format: innerFormat,
		})
	}

	return result, nil
}

func detectFileFormat(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".jpg", ".jpeg":
		return "jpeg"
	case ".png":
		return "png"
	case ".gif":
		return "gif"
	case ".pdf":
		return "pdf"
	case ".doc", ".docx":
		return "docx"
	case ".xls", ".xlsx":
		return "xlsx"
	case ".ppt", ".pptx":
		return "pptx"
	case ".zip":
		return "zip"
	case ".tar":
		return "tar"
	case ".gz", ".gzip":
		return "gzip"
	case ".7z":
		return "7z"
	case ".rar":
		return "rar"
	case ".exe", ".dll":
		return "pe"
	case ".elf", ".so", ".bin":
		return "elf"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".html", ".htm":
		return "html"
	case ".xml":
		return "xml"
	case ".json":
		return "json"
	case ".csv":
		return "csv"
	case ".txt", ".md", ".log":
		return "text"
	case ".sql":
		return "sql"
	case ".sh", ".bash":
		return "shell"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".ini", ".cfg", ".conf":
		return "config"
	default:
		return "unknown"
	}
}

func isContainer(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".zip" || ext == ".tar" || ext == ".gz" ||
		ext == ".tgz" || ext == ".7z" || ext == ".rar" ||
		ext == ".bz2" || ext == ".xz" || ext == ".zst"
}

// ExtractTo extracts a container to a directory.
func ExtractTo(data []byte, format, destDir string) error {
	switch format {
	case "zip":
		return extractZIP(data, destDir)
	case "tar", "tar.gz", "tgz":
		return extractTarGz(data, destDir)
	default:
		return fmt.Errorf("extraction not supported for format: %s", format)
	}
}

func extractZIP(data []byte, destDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	for _, file := range reader.File {
		// safeio.Join also rejects these; the inline check keeps the guard
		// visible to static analysis (CodeQL go/zipslip).
		if strings.Contains(file.Name, "..") {
			return fmt.Errorf("unsafe archive entry name %q", file.Name)
		}
		path, err := safeio.Join(destDir, file.Name)
		if err != nil {
			return err
		}
		mode := file.FileInfo().Mode()
		if mode.IsDir() {
			if err := os.MkdirAll(path, 0o750); err != nil {
				return err
			}
			continue
		}
		if !mode.IsRegular() {
			continue // never materialise symlinks or devices from an archive
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = writeFile(path, rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// writeFile creates path exclusively and fills it from r, bounded by
// safeio.DefaultMaxExtract.
func writeFile(path string, r io.Reader) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = safeio.Copy(out, r, 0)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

func extractTarGz(data []byte, destDir string) error {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if strings.Contains(header.Name, "..") {
			return fmt.Errorf("unsafe archive entry name %q", header.Name)
		}
		path, err := safeio.Join(destDir, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
			if err := writeFile(path, tarReader); err != nil {
				return err
			}
		}
		// Symlinks, hard links and device nodes are skipped on purpose.
	}

	return nil
}
