package carver

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// Extractor handles file extraction.
type Extractor struct {
	OutputDir string
	Recursive bool
	Force     bool
	Verbose   bool
}

// ExtractorOptions controls extraction behavior.
type ExtractorOptions struct {
	OutputDir string
	Recursive bool
	Force     bool
	Verbose   bool
	MaxDepth  int
	Formats   []string
	Offset    int64
	Length    int64
}

// NewExtractor creates a new file extractor.
func NewExtractor(opts *ExtractorOptions) *Extractor {
	if opts == nil {
		opts = &ExtractorOptions{
			OutputDir: "extracted",
			Recursive: true,
		}
	}
	return &Extractor{
		OutputDir: opts.OutputDir,
		Recursive: opts.Recursive,
		Force:     opts.Force,
		Verbose:   opts.Verbose,
	}
}

// ExtractResult holds extraction results.
type ExtractResult struct {
	Files     []ExtractedFile `json:"files"`
	Errors    []string        `json:"errors,omitempty"`
	TotalSize int64           `json:"total_size"`
}

// ExtractedFile represents an extracted file.
type ExtractedFile struct {
	Source     string `json:"source"`
	OutputPath string `json:"output_path"`
	Format     string `json:"format"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset"`
}

// Extract extracts embedded files from data.
func (e *Extractor) Extract(data []byte, filePath string, opts *ExtractorOptions) (*ExtractResult, error) {
	if opts == nil {
		opts = &ExtractorOptions{
			OutputDir: e.OutputDir,
			Recursive: e.Recursive,
		}
	}

	result := &ExtractResult{
		Files: []ExtractedFile{},
	}

	// Create output directory
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Scan for signatures
	signatures := ScanSignatures(data)

	for _, sig := range signatures {
		// Filter by format if specified
		if len(opts.Formats) > 0 {
			found := false
			for _, f := range opts.Formats {
				if f == sig.Format {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Extract based on format
		extracted, err := e.extractByFormat(data, sig, opts)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s at 0x%X: %v", sig.Format, sig.Offset, err))
			continue
		}

		if extracted != nil {
			result.Files = append(result.Files, *extracted)
			result.TotalSize += extracted.Size
		}
	}

	return result, nil
}

// ExtractSpecific extracts a specific format at an offset.
func (e *Extractor) ExtractSpecific(data []byte, format string, offset, length int64, outputPath string) (*ExtractedFile, error) {
	if offset < 0 || offset >= int64(len(data)) {
		return nil, fmt.Errorf("invalid offset: %d", offset)
	}

	var end int64
	if length <= 0 {
		end = int64(len(data))
	} else {
		end = offset + length
	}
	if end > int64(len(data)) {
		end = int64(len(data))
	}

	chunk := data[offset:end]

	// Create output file
	if outputPath == "" {
		outputPath = filepath.Join(e.OutputDir, fmt.Sprintf("%s_%d.%s", format, offset, format))
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return nil, err
	}

	if err := os.WriteFile(outputPath, chunk, 0644); err != nil {
		return nil, err
	}

	return &ExtractedFile{
		Source:     "direct",
		OutputPath: outputPath,
		Format:     format,
		Size:       int64(len(chunk)),
		Offset:     offset,
	}, nil
}

func (e *Extractor) extractByFormat(data []byte, sig SignatureScan, opts *ExtractorOptions) (*ExtractedFile, error) {
	offset := sig.Offset

	// Determine extraction boundaries
	var end int64
	switch sig.Format {
	case "zip", "rar", "7z":
		end = findArchiveEnd(data, offset, sig.Format)
	case "gzip":
		end = findGzipEnd(data, offset)
	case "bzip2":
		end = findBzip2End(data, offset)
	case "xz":
		end = findXZEnd(data, offset)
	case "png":
		end = findPNGEnd(data, offset)
	case "jpeg":
		end = findJPEGEnd(data, offset)
	case "pdf":
		end = findPDFEnd(data, offset)
	case "elf", "pe", "macho":
		end = findExecutableEnd(data, offset, sig.Format)
	default:
		end = offset + 1024*1024 // Default 1MB
		if end > int64(len(data)) {
			end = int64(len(data))
		}
	}

	if end <= offset {
		return nil, fmt.Errorf("could not determine end of %s", sig.Format)
	}

	chunk := data[offset:end]

	// Try to decompress
	outputPath := filepath.Join(opts.OutputDir, fmt.Sprintf("%s_%d", sig.Format, offset))

	switch sig.Format {
	case "gzip":
		return e.extractGzip(chunk, offset, outputPath)
	case "bzip2":
		return e.extractBzip2(chunk, offset, outputPath)
	case "xz":
		return e.extractXZ(chunk, offset, outputPath)
	default:
		return e.extractRaw(chunk, sig.Format, offset, outputPath)
	}
}

func (e *Extractor) extractGzip(data []byte, offset int64, outputPath string) (*ExtractedFile, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	outputPath += ".gz"
	out, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	written, err := io.Copy(out, gr)
	if err != nil {
		return nil, err
	}

	return &ExtractedFile{
		Source:     "gzip",
		OutputPath: outputPath,
		Format:     "gzip",
		Size:       written,
		Offset:     offset,
	}, nil
}

func (e *Extractor) extractBzip2(data []byte, offset int64, outputPath string) (*ExtractedFile, error) {
	br := bzip2.NewReader(bytes.NewReader(data))

	outputPath += ".bz2"
	out, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	written, err := io.Copy(out, br)
	if err != nil {
		return nil, err
	}

	return &ExtractedFile{
		Source:     "bzip2",
		OutputPath: outputPath,
		Format:     "bzip2",
		Size:       written,
		Offset:     offset,
	}, nil
}

func (e *Extractor) extractXZ(data []byte, offset int64, outputPath string) (*ExtractedFile, error) {
	xr, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	outputPath += ".xz"
	out, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	written, err := io.Copy(out, xr)
	if err != nil {
		return nil, err
	}

	return &ExtractedFile{
		Source:     "xz",
		OutputPath: outputPath,
		Format:     "xz",
		Size:       written,
		Offset:     offset,
	}, nil
}

func (e *Extractor) extractRaw(data []byte, format string, offset int64, outputPath string) (*ExtractedFile, error) {
	outputPath += "." + format
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return nil, err
	}

	return &ExtractedFile{
		Source:     "raw",
		OutputPath: outputPath,
		Format:     format,
		Size:       int64(len(data)),
		Offset:     offset,
	}, nil
}

// findArchiveEnd finds the end of an archive.
func findArchiveEnd(data []byte, offset int64, format string) int64 {
	switch format {
	case "zip":
		return findZIPEnd(data, offset)
	case "rar":
		return findGenericArchiveEnd(data, offset)
	case "7z":
		return findGenericArchiveEnd(data, offset)
	default:
		return offset + 1024*1024
	}
}

func findGenericArchiveEnd(data []byte, offset int64) int64 {
	// For archives without clear end markers, search for next signature
	nextSigs := []byte{0x50, 0x4B, 0x03, 0x04} // ZIP
	for i := int(offset) + 100; i < len(data)-4; i++ {
		if bytes.Equal(data[i:i+4], nextSigs) {
			return int64(i)
		}
	}
	return offset + 1024*1024
}

func findZIPEnd(data []byte, offset int64) int64 {
	// Look for End of Central Directory
	eocdSig := []byte{0x50, 0x4B, 0x05, 0x06}
	for i := len(data) - 22; i >= int(offset); i-- {
		if i+4 > len(data) {
			continue
		}
		if bytes.Equal(data[i:i+4], eocdSig) {
			commentLen := int(data[i+20]) | int(data[i+21])<<8
			return int64(i + 22 + commentLen)
		}
	}
	return offset + 1024*1024
}

func findGzipEnd(data []byte, offset int64) int64 {
	// GZIP doesn't have a clear end marker in the header
	// We'll try to decompress to find the actual size
	gr, err := gzip.NewReader(bytes.NewReader(data[offset:]))
	if err != nil {
		return offset + 1024
	}
	defer gr.Close()

	// Read all to find end
	buf := make([]byte, 1024*1024)
	totalRead := int64(0)
	for {
		n, err := gr.Read(buf)
		totalRead += int64(n)
		if err != nil {
			break
		}
	}

	// Approximate end position
	return offset + totalRead/10 + 100 // Rough estimate
}

func findBzip2End(data []byte, offset int64) int64 {
	// BZIP2 ends with 6 bytes of zero padding
	for i := int(offset); i < len(data)-6; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 && data[i+2] == 0x00 &&
			data[i+3] == 0x00 && data[i+4] == 0x00 && data[i+5] == 0x00 {
			return int64(i + 6)
		}
	}
	return offset + 1024*1024
}

func findXZEnd(data []byte, offset int64) int64 {
	// XZ ends with magic bytes: 59 5A
	for i := int(offset); i < len(data)-6; i++ {
		if data[i] == 0x59 && data[i+1] == 0x5A &&
			data[i+2] == 0x00 && data[i+3] == 0x00 {
			return int64(i + 6)
		}
	}
	return offset + 1024*1024
}

func findPNGEnd(data []byte, offset int64) int64 {
	// PNG ends with IEND chunk
	iendSig := []byte("IEND")
	for i := int(offset); i < len(data)-8; i++ {
		if bytes.Equal(data[i:i+4], iendSig) {
			return int64(i + 8) // IEND + 4 bytes CRC
		}
	}
	return offset + 10*1024*1024 // 10MB max for PNG
}

func findJPEGEnd(data []byte, offset int64) int64 {
	// JPEG ends with FFD9
	eoiSig := []byte{0xFF, 0xD9}
	for i := int(offset); i < len(data)-2; i++ {
		if bytes.Equal(data[i:i+2], eoiSig) {
			return int64(i + 2)
		}
	}
	return offset + 10*1024*1024
}

func findPDFEnd(data []byte, offset int64) int64 {
	// PDF ends with %%EOF
	eofSig := []byte("%%EOF")
	for i := int(offset); i < len(data)-5; i++ {
		if bytes.Equal(data[i:i+5], eofSig) {
			return int64(i + 5)
		}
	}
	return offset + 100*1024*1024 // 100MB max for PDF
}

func findExecutableEnd(data []byte, offset int64, format string) int64 {
	switch format {
	case "elf":
		return findELFEnd(data, offset)
	case "pe":
		return findPEEnd(data, offset)
	case "macho":
		return findMachOEnd(data, offset)
	default:
		return offset + 10*1024*1024
	}
}

func findELFEnd(data []byte, offset int64) int64 {
	if offset+64 > int64(len(data)) {
		return offset + 1024
	}

	// Parse ELF header to find program headers
	phoff := int64(data[offset+28]) | int64(data[offset+29])<<8 |
		int64(data[offset+30])<<16 | int64(data[offset+31])<<24
	phnum := int(data[offset+44]) | int(data[offset+45])<<8
	phentsize := int(data[offset+42]) | int(data[offset+43])<<8

	// Find highest load address
	maxEnd := offset + 1024
	for i := 0; i < phnum; i++ {
		phOffset := phoff + int64(i*phentsize)
		if phOffset+32 > int64(len(data)) {
			break
		}

		// p_offset, p_vaddr, p_filesz, p_memsz
		pOffset := int64(data[phOffset+4]) | int64(data[phOffset+5])<<8 |
			int64(data[phOffset+6])<<16 | int64(data[phOffset+7])<<24
		pFilesz := int64(data[phOffset+16]) | int64(data[phOffset+17])<<8 |
			int64(data[phOffset+18])<<16 | int64(data[phOffset+19])<<24

		end := pOffset + pFilesz
		if end > maxEnd {
			maxEnd = end
		}
	}

	return maxEnd
}

func findPEEnd(data []byte, offset int64) int64 {
	if offset+64 > int64(len(data)) {
		return offset + 1024
	}

	// PE signature offset
	peOffset := int64(data[offset+60]) | int64(data[offset+61])<<8 |
		int64(data[offset+62])<<16 | int64(data[offset+63])<<24

	// Bounds check
	if offset+peOffset+24 > int64(len(data)) {
		return offset + 1024
	}

	// Number of sections
	numSections := int(data[offset+peOffset+6]) | int(data[offset+peOffset+7])<<8

	// Size of optional header
	optHeaderSize := int64(data[offset+peOffset+20]) | int64(data[offset+peOffset+21])<<8

	// Calculate end
	end := offset + peOffset + 24 + optHeaderSize + int64(numSections*40)
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return end
}

func findMachOEnd(data []byte, offset int64) int64 {
	if offset+32 > int64(len(data)) {
		return offset + 1024
	}

	// Number of commands (not used but parsed for validation)
	_ = int64(data[offset+16]) | int64(data[offset+17])<<8 |
		int64(data[offset+18])<<16 | int64(data[offset+19])<<24

	// Size of commands
	sizeofcmds := int64(data[offset+20]) | int64(data[offset+21])<<8 |
		int64(data[offset+22])<<16 | int64(data[offset+23])<<24

	return offset + 32 + sizeofcmds
}

// DD extracts raw bytes from a file (like dd command).
func DD(inputPath, outputPath string, offset, count int64) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", inputPath, err)
	}

	if offset >= int64(len(data)) {
		return fmt.Errorf("offset %d exceeds file size %d", offset, len(data))
	}

	var end int64
	if count <= 0 {
		end = int64(len(data))
	} else {
		end = offset + count
	}
	if end > int64(len(data)) {
		end = int64(len(data))
	}

	chunk := data[offset:end]

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}

	return os.WriteFile(outputPath, chunk, 0644)
}

// DDFromReader extracts bytes from a reader.
func DDFromReader(reader io.Reader, outputPath string, offset, count int64) error {
	if offset > 0 {
		if _, err := io.CopyN(io.Discard, reader, offset); err != nil {
			return err
		}
	}

	var reader2 io.Reader = reader
	if count > 0 {
		reader2 = io.LimitReader(reader, count)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader2)
	return err
}

// IsCompressed checks if data appears to be compressed.
func IsCompressed(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// Check for common compression signatures
	sigs := [][]byte{
		{0x1F, 0x8B},                         // GZIP
		{0x42, 0x5A, 0x68},                   // BZIP2
		{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, // XZ
		{0x50, 0x4B, 0x03, 0x04},             // ZIP
		{0x37, 0x7A, 0xBC, 0xAF},             // 7z
		{0x52, 0x61, 0x72},                   // RAR
		{0x1F, 0x9D},                         // TAR
		{0x1F, 0xA0},                         // TAR
	}

	for _, sig := range sigs {
		if bytes.HasPrefix(data, sig) {
			return true
		}
	}

	return false
}

// GuessFormat guesses the format of data.
func GuessFormat(data []byte) string {
	if len(data) < 4 {
		return "unknown"
	}

	sigs := []struct {
		Magic  []byte
		Format string
	}{
		{[]byte{0x89, 0x50, 0x4E, 0x47}, "png"},
		{[]byte{0xFF, 0xD8, 0xFF}, "jpeg"},
		{[]byte{0x25, 0x50, 0x44, 0x46}, "pdf"},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, "zip"},
		{[]byte{0x1F, 0x8B}, "gzip"},
		{[]byte{0x42, 0x5A, 0x68}, "bzip2"},
		{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "xz"},
		{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z"},
		{[]byte{0x52, 0x61, 0x72, 0x21}, "rar"},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, "elf"},
		{[]byte{0x4D, 0x5A}, "pe"},
		{[]byte{0x49, 0x49, 0x2A, 0x00}, "tiff"},
		{[]byte{0x4D, 0x4D, 0x00, 0x2A}, "tiff"},
		{[]byte{0x47, 0x49, 0x46, 0x38}, "gif"},
		{[]byte{0x42, 0x4D}, "bmp"},
		{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65}, "sqlite"},
	}

	for _, sig := range sigs {
		if bytes.HasPrefix(data, sig.Magic) {
			return sig.Format
		}
	}

	return "unknown"
}

// DDCommand implements the dd-like extraction.
type DDCommand struct {
	InputPath  string
	OutputPath string
	BlockSize  int64
	Count      int64
	Skip       int64
	Seek       int64
}

// Run executes the dd command.
func (d *DDCommand) Run() error {
	data, err := os.ReadFile(d.InputPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", d.InputPath, err)
	}

	offset := d.Skip * d.BlockSize
	count := d.Count * d.BlockSize

	if offset >= int64(len(data)) {
		return fmt.Errorf("skip offset exceeds file size")
	}

	var end int64
	if count <= 0 {
		end = int64(len(data))
	} else {
		end = offset + count
	}
	if end > int64(len(data)) {
		end = int64(len(data))
	}

	chunk := data[offset:end]

	if err := os.MkdirAll(filepath.Dir(d.OutputPath), 0755); err != nil {
		return err
	}

	return os.WriteFile(d.OutputPath, chunk, 0644)
}

// ParseDDOptions parses dd-style options.
func ParseDDOptions(args []string) *DDCommand {
	cmd := &DDCommand{
		BlockSize: 512,
	}

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := parts[1]

		switch key {
		case "if":
			cmd.InputPath = value
		case "of":
			cmd.OutputPath = value
		case "bs":
			fmt.Sscanf(value, "%d", &cmd.BlockSize)
		case "count":
			fmt.Sscanf(value, "%d", &cmd.Count)
		case "skip":
			fmt.Sscanf(value, "%d", &cmd.Skip)
		case "seek":
			fmt.Sscanf(value, "%d", &cmd.Seek)
		}
	}

	return cmd
}
