package pcap

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractedFile represents a file extracted from network traffic.
type ExtractedFile struct {
	Source   string            `json:"source"`
	Protocol string            `json:"protocol"`
	FileName string            `json:"file_name"`
	Size     int               `json:"size"`
	MimeType string            `json:"mime_type"`
	Headers  map[string]string `json:"headers,omitempty"`
	SavePath string            `json:"save_path,omitempty"`
}

// NetworkExtractor extracts files from network traffic.
type NetworkExtractor struct {
	ExtractedFiles []ExtractedFile
	Streams        map[StreamID]*TCPStream
	OutputDir      string
	Reassembler    *Reassembler
}

// NewNetworkExtractor creates a new network file extractor.
func NewNetworkExtractor(outputDir string) *NetworkExtractor {
	return &NetworkExtractor{
		Streams:     make(map[StreamID]*TCPStream),
		OutputDir:   outputDir,
		Reassembler: NewReassembler(),
	}
}

// ExtractFiles extracts files from PCAP data.
func (e *NetworkExtractor) ExtractFiles(data []byte) ([]ExtractedFile, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("file too small for PCAP")
	}

	// Parse PCAP global header
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
		return nil, fmt.Errorf("not a valid PCAP file")
	}

	littleEndian := magic == 0xa1b2c3d4

	// First pass: Reassemble TCP streams using the reassembler
	offset := 24
	for offset+16 <= len(data) {
		var tsSec, tsLen uint32
		if littleEndian {
			tsSec = binary.LittleEndian.Uint32(data[offset : offset+4])
			tsLen = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		} else {
			tsSec = binary.BigEndian.Uint32(data[offset : offset+4])
			tsLen = binary.BigEndian.Uint32(data[offset+12 : offset+16])
		}

		offset += 16

		if offset+int(tsLen) > len(data) {
			break
		}

		e.Reassembler.ProcessPacket(data[offset:offset+int(tsLen)], offset, tsSec)
		offset += int(tsLen)
	}

	// Assemble streams
	streams := e.Reassembler.Assemble()
	for _, stream := range streams {
		e.Streams[stream.ID] = stream
	}

	// Second pass: Extract files from streams
	e.extractFromStreams()

	// Third pass: Carve files from all packets
	e.carveFiles(data, littleEndian)

	return e.ExtractedFiles, nil
}

// extractFromStreams extracts files from reassembled TCP streams.
func (e *NetworkExtractor) extractFromStreams() {
	for _, stream := range e.Streams {
		if len(stream.Data) == 0 {
			continue
		}

		// Try HTTP extraction
		if stream.Protocol == "HTTP" {
			e.extractHTTP(stream)
		}

		// Try FTP extraction
		if stream.Protocol == "FTP" {
			e.extractFTP(stream)
		}
	}
}

// extractHTTP extracts files from HTTP responses.
func (e *NetworkExtractor) extractHTTP(stream *TCPStream) {
	data := stream.Data

	// Find HTTP response
	if !bytes.HasPrefix(data, []byte("HTTP/")) {
		// Try HTTP request
		if bytes.Contains(data, []byte("HTTP/")) {
			return // Skip requests, focus on responses
		}
		return
	}

	// Parse response
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return
	}

	headerData := data[:headerEnd]
	body := data[headerEnd+4:]

	// Parse headers
	headers := make(map[string]string)
	headerLines := strings.Split(string(headerData), "\r\n")

	for _, line := range headerLines[1:] {
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	// Check if response contains file data
	contentType := headers["Content-Type"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Handle chunked encoding
	if headers["Transfer-Encoding"] == "chunked" {
		body = e.dechunkBody(body)
	}

	// Handle gzip
	if headers["Content-Encoding"] == "gzip" {
		if decompressed, err := e.decompressGzip(body); err == nil {
			body = decompressed
		}
	}

	if len(body) == 0 {
		return
	}

	// Determine filename
	streamID := fmt.Sprintf("%x", stream.ID.SrcIP)
	fileName := e.guessFileName(headers, body, streamID)

	file := ExtractedFile{
		Source:   fmt.Sprintf("HTTP %d.%d.%d.%d:%d", byte(stream.ID.SrcIP>>24), byte(stream.ID.SrcIP>>16), byte(stream.ID.SrcIP>>8), byte(stream.ID.SrcIP), stream.ID.SrcPort),
		Protocol: "HTTP",
		FileName: fileName,
		Size:     len(body),
		MimeType: contentType,
		Headers:  headers,
	}

	// Save file if output dir specified
	if e.OutputDir != "" {
		savePath := filepath.Join(e.OutputDir, fileName)
		if err := os.WriteFile(savePath, body, 0644); err == nil {
			file.SavePath = savePath
		}
	}

	e.ExtractedFiles = append(e.ExtractedFiles, file)
}

// extractFTP extracts files from FTP data connections.
func (e *NetworkExtractor) extractFTP(stream *TCPStream) {
	data := stream.Data
	if len(data) < 10 {
		return
	}

	fileName := fmt.Sprintf("ftp_transfer_%x.bin", stream.ID.SrcIP)
	file := ExtractedFile{
		Source:   fmt.Sprintf("FTP %d.%d.%d.%d:%d", byte(stream.ID.SrcIP>>24), byte(stream.ID.SrcIP>>16), byte(stream.ID.SrcIP>>8), byte(stream.ID.SrcIP), stream.ID.SrcPort),
		Protocol: "FTP",
		FileName: fileName,
		Size:     len(data),
		MimeType: "application/octet-stream",
	}

	if e.OutputDir != "" {
		savePath := filepath.Join(e.OutputDir, fileName)
		if err := os.WriteFile(savePath, data, 0644); err == nil {
			file.SavePath = savePath
		}
	}

	e.ExtractedFiles = append(e.ExtractedFiles, file)
}

// carveFiles carves files directly from packet payloads.
func (e *NetworkExtractor) carveFiles(data []byte, littleEndian bool) {
	// File signatures to carve
	signatures := []struct {
		magic []byte
		ext   string
		name  string
	}{
		{[]byte{0x1F, 0x8B, 0x08}, ".gz", "archive"},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, ".zip", "archive"},
		{[]byte{0x42, 0x5A, 0x68}, ".bz2", "archive"},
		{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, ".xz", "archive"},
		{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, ".png", "image"},
		{[]byte{0xFF, 0xD8, 0xFF}, ".jpg", "image"},
		{[]byte{0x25, 0x50, 0x44, 0x46}, ".pdf", "document"},
		{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, ".doc", "document"},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, ".elf", "executable"},
		{[]byte{0x4D, 0x5A}, ".exe", "executable"},
		{[]byte{0x75, 0x73, 0x74, 0x61, 0x72}, ".tar", "archive"},
		{[]byte{0x04, 0x22, 0x4D, 0x18}, ".lz4", "archive"},
	}

	offset := 24
	packetNum := 0

	for offset+16 <= len(data) {
		var tsLen uint32
		if littleEndian {
			tsLen = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		} else {
			tsLen = binary.BigEndian.Uint32(data[offset+12 : offset+16])
		}

		offset += 16

		if offset+int(tsLen) > len(data) {
			break
		}

		packet := data[offset : offset+int(tsLen)]
		offset += int(tsLen)
		packetNum++

		// Search for file signatures in payload
		for _, sig := range signatures {
			idx := bytes.Index(packet, sig.magic)
			if idx >= 0 {
				// Check if we already have this file
				alreadyFound := false
				for _, f := range e.ExtractedFiles {
					if f.Protocol == "carved" && f.Size == len(packet[idx:]) {
						alreadyFound = true
						break
					}
				}

				if !alreadyFound {
					fileName := fmt.Sprintf("carved_%d_packet_%d%s", packetNum, packetNum, sig.ext)
					file := ExtractedFile{
						Source:   "Packet carving",
						Protocol: "carved",
						FileName: fileName,
						Size:     len(packet[idx:]),
						MimeType: sig.name,
					}

					if e.OutputDir != "" {
						savePath := filepath.Join(e.OutputDir, fileName)
						if err := os.WriteFile(savePath, packet[idx:], 0644); err == nil {
							file.SavePath = savePath
						}
					}

					e.ExtractedFiles = append(e.ExtractedFiles, file)
				}
			}
		}
	}
}

// dechunkBody handles HTTP chunked transfer encoding.
func (e *NetworkExtractor) dechunkBody(data []byte) []byte {
	var result []byte
	offset := 0

	for offset < len(data) {
		// Find chunk size
		end := bytes.IndexByte(data[offset:], '\n')
		if end < 0 {
			break
		}

		chunkSizeStr := strings.TrimSpace(string(data[offset : offset+end]))
		offset += end + 1

		// Parse hex chunk size
		var chunkSize int
		fmt.Sscanf(chunkSizeStr, "%x", &chunkSize)

		if chunkSize == 0 {
			break
		}

		// Read chunk data
		if offset+chunkSize > len(data) {
			break
		}

		result = append(result, data[offset:offset+chunkSize]...)
		offset += chunkSize + 2 // Skip \r\n after chunk
	}

	return result
}

// decompressGzip decompresses gzip data.
func (e *NetworkExtractor) decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// guessFileName determines the filename from headers or content.
func (e *NetworkExtractor) guessFileName(headers map[string]string, body []byte, streamID string) string {
	// Try Content-Disposition
	if cd, ok := headers["Content-Disposition"]; ok {
		if idx := strings.Index(cd, "filename="); idx >= 0 {
			name := cd[idx+9:]
			name = strings.Trim(name, "\"' ")
			if name != "" {
				return name
			}
		}
	}

	// Try URL path from Host header
	if host, ok := headers["Host"]; ok {
		parts := strings.Split(host, "/")
		if len(parts) > 0 {
			last := parts[len(parts)-1]
			if strings.Contains(last, ".") {
				return last
			}
		}
	}

	// Try to detect from content
	ext := e.detectContentExtension(body)
	if ext != "" {
		return fmt.Sprintf("file_%s%s", streamID, ext)
	}

	return fmt.Sprintf("file_%s.bin", streamID)
}

// detectContentExtension detects file extension from content.
func (e *NetworkExtractor) detectContentExtension(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	signatures := []struct {
		magic []byte
		ext   string
	}{
		{[]byte{0x89, 0x50, 0x4E, 0x47}, ".png"},
		{[]byte{0xFF, 0xD8, 0xFF}, ".jpg"},
		{[]byte{0x47, 0x49, 0x46, 0x38}, ".gif"},
		{[]byte{0x25, 0x50, 0x44, 0x46}, ".pdf"},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, ".zip"},
		{[]byte{0x1F, 0x8B}, ".gz"},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, ".elf"},
		{[]byte{0x4D, 0x5A}, ".exe"},
	}

	for _, sig := range signatures {
		if bytes.HasPrefix(data, sig.magic) {
			return sig.ext
		}
	}

	return ""
}

// GetStreamStats returns statistics about TCP streams.
func (e *NetworkExtractor) GetStreamStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_streams":   len(e.Streams),
		"extracted_files": len(e.ExtractedFiles),
		"streams":         make([]map[string]interface{}, 0, len(e.Streams)),
	}

	for key, stream := range e.Streams {
		streamInfo := map[string]interface{}{
			"key":          fmt.Sprintf("%x", key),
			"src_ip":       fmt.Sprintf("%d.%d.%d.%d", byte(key.SrcIP>>24), byte(key.SrcIP>>16), byte(key.SrcIP>>8), byte(key.SrcIP)),
			"dst_ip":       fmt.Sprintf("%d.%d.%d.%d", byte(key.DstIP>>24), byte(key.DstIP>>16), byte(key.DstIP>>8), byte(key.DstIP)),
			"src_port":     key.SrcPort,
			"dst_port":     key.DstPort,
			"packet_count": stream.Metadata.PacketCount,
			"total_bytes":  stream.Metadata.TotalBytes,
			"protocol":     stream.Protocol,
		}

		stats["streams"] = append(stats["streams"].([]map[string]interface{}), streamInfo)
	}

	return stats
}

// SaveExtractedFiles saves all extracted files to the output directory.
func (e *NetworkExtractor) SaveExtractedFiles() ([]string, error) {
	if e.OutputDir == "" {
		return nil, fmt.Errorf("no output directory specified")
	}

	var saved []string
	for _, file := range e.ExtractedFiles {
		if file.SavePath == "" {
			continue
		}
		saved = append(saved, file.SavePath)
	}
	return saved, nil
}

// FormatNetworkExtraction formats network extraction results for display.
func FormatNetworkExtraction(files []ExtractedFile) string {
	if len(files) == 0 {
		return "No files extracted from network traffic"
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("Extracted %d files from network traffic:\n\n", len(files)))

	// Group by protocol
	byProtocol := make(map[string][]ExtractedFile)
	for _, f := range files {
		byProtocol[f.Protocol] = append(byProtocol[f.Protocol], f)
	}

	for protocol, protocolFiles := range byProtocol {
		result.WriteString(fmt.Sprintf("  [%s] %d files\n", protocol, len(protocolFiles)))
		for _, f := range protocolFiles {
			sizeStr := formatSize(int64(f.Size))
			if f.SavePath != "" {
				result.WriteString(fmt.Sprintf("    - %s (%s) -> %s\n", f.FileName, sizeStr, f.SavePath))
			} else {
				result.WriteString(fmt.Sprintf("    - %s (%s)\n", f.FileName, sizeStr))
			}
		}
		result.WriteString("\n")
	}

	return result.String()
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// ExportNetworkReport exports network extraction report as JSON.
func ExportNetworkReport(files []ExtractedFile, outputPath string) error {
	report := map[string]interface{}{
		"total_files": len(files),
		"files":       files,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
