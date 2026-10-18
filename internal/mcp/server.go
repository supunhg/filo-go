// Package mcp implements a Model Context Protocol server over stdio, exposing
// filo's analyzers as tools for AI agents.
//
// Messages are newline-delimited JSON-RPC 2.0. Anything written to stdout
// other than protocol messages corrupts the stream, so diagnostics go to
// stderr.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/batch"
	"github.com/supunhg/filo-go/internal/container"
	"github.com/supunhg/filo-go/internal/crypto"
	"github.com/supunhg/filo-go/internal/hashing"
	"github.com/supunhg/filo-go/internal/metadata"
	"github.com/supunhg/filo-go/internal/pathguard"
	"github.com/supunhg/filo-go/internal/signature"
	"github.com/supunhg/filo-go/internal/sqlite"
	"github.com/supunhg/filo-go/internal/stego"
	filostrings "github.com/supunhg/filo-go/internal/strings"
	"github.com/supunhg/filo-go/internal/version"
)

// JSON-RPC error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// supportedVersions lists the MCP protocol revisions this server speaks,
// newest first.
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// maxMessageSize bounds a single JSON-RPC message.
const maxMessageSize = 16 << 20

// Server implements a JSON-RPC MCP server.
type Server struct {
	reader io.Reader
	writer io.Writer
	guard  *pathguard.Guard
	mu     sync.Mutex
}

// NewServer creates a server on stdin/stdout with unrestricted file access.
func NewServer() *Server {
	return &Server{reader: os.Stdin, writer: os.Stdout, guard: &pathguard.Guard{}}
}

// NewServerWithRoot creates a server whose tools can only read files under
// root. An empty root means unrestricted.
func NewServerWithRoot(root string) (*Server, error) {
	g, err := pathguard.New(root)
	if err != nil {
		return nil, err
	}
	s := NewServer()
	s.guard = g
	return s, nil
}

// Request represents a JSON-RPC request.
type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

// Response represents a JSON-RPC response.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// Error represents a JSON-RPC error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool represents an MCP tool.
type Tool struct {
	Name        string      `json:"name"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
	Annotations *Annotation `json:"annotations,omitempty"`
}

// Annotation carries MCP tool hints. Every filo tool only reads files.
type Annotation struct {
	ReadOnlyHint  bool `json:"readOnlyHint"`
	OpenWorldHint bool `json:"openWorldHint"`
}

var readOnly = &Annotation{ReadOnlyHint: true, OpenWorldHint: false}

// envelope is used to tell requests (which carry an id) from notifications.
type envelope struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params"`
}

// Run serves requests until the input is closed.
func (s *Server) Run() error {
	rd := bufio.NewReaderSize(s.reader, 64<<10)
	for {
		line, err := readLine(rd)
		if len(bytes.TrimSpace(line)) > 0 {
			s.handleLine(line)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func readLine(rd *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := rd.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxMessageSize {
			// Discard the rest of an oversized message.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = rd.ReadSlice('\n')
			}
			return []byte("\x00oversized"), err
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return buf, err
		}
	}
}

func (s *Server) handleLine(line []byte) {
	if bytes.HasPrefix(line, []byte("\x00oversized")) {
		s.write(&Response{JSONRPC: "2.0", Error: &Error{Code: codeInvalidRequest, Message: "message too large"}})
		return
	}
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		s.write(&Response{JSONRPC: "2.0", Error: &Error{Code: codeParseError, Message: "parse error: " + err.Error()}})
		return
	}
	if env.ID == nil {
		// Notifications (initialized, cancelled, ...) never get a reply.
		return
	}
	var id interface{}
	_ = json.Unmarshal(*env.ID, &id)
	if env.JSONRPC != "2.0" || env.Method == "" {
		s.write(&Response{JSONRPC: "2.0", Error: &Error{Code: codeInvalidRequest, Message: "invalid JSON-RPC 2.0 request"}, ID: id})
		return
	}
	var params interface{}
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &params); err != nil {
			s.write(&Response{JSONRPC: "2.0", Error: &Error{Code: codeInvalidParams, Message: "invalid params"}, ID: id})
			return
		}
	}
	s.write(s.handleRequest(Request{JSONRPC: env.JSONRPC, Method: env.Method, Params: params, ID: id}))
}

func (s *Server) write(resp *Response) {
	if resp == nil {
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		data, _ = json.Marshal(&Response{JSONRPC: "2.0", Error: &Error{Code: -32603, Message: "internal error"}, ID: resp.ID})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.writer.Write(append(data, '\n'))
}

func (s *Server) handleRequest(req Request) *Response {
	switch req.Method {
	case "initialize":
		return &Response{
			JSONRPC: "2.0",
			Result: map[string]interface{}{
				"protocolVersion": negotiateVersion(req.Params),
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{"listChanged": false},
				},
				"serverInfo": map[string]interface{}{
					"name":    "filo",
					"title":   "filo file forensics",
					"version": version.Version,
				},
				"instructions": "filo analyzes files on the local machine: identify formats, find embedded files, hash, extract strings and metadata, and assess encryption. Start with the analyze tool, then use scan for embedded content. All tools are read-only.",
			},
			ID: req.ID,
		}

	case "ping":
		return &Response{JSONRPC: "2.0", Result: map[string]interface{}{}, ID: req.ID}

	case "tools/list":
		return &Response{
			JSONRPC: "2.0",
			Result: map[string]interface{}{
				"tools": s.getTools(),
			},
			ID: req.ID,
		}

	case "tools/call":
		return s.handleToolCall(req)

	default:
		return &Response{
			JSONRPC: "2.0",
			Error: &Error{
				Code:    codeMethodNotFound,
				Message: "Method not found: " + req.Method,
			},
			ID: req.ID,
		}
	}
}

// negotiateVersion returns the client's requested protocol version when it
// is supported, and otherwise the newest version this server speaks.
func negotiateVersion(params interface{}) string {
	if m, ok := params.(map[string]interface{}); ok {
		if v, ok := m["protocolVersion"].(string); ok {
			for _, sv := range supportedVersions {
				if v == sv {
					return v
				}
			}
		}
	}
	return supportedVersions[0]
}

// readFile reads a file through the server's path guard.
func (s *Server) readFile(path string) ([]byte, error) {
	resolved, err := s.resolveFile(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

func (s *Server) resolveFile(path string) (string, error) {
	resolved, err := s.guard.File(path)
	return resolved, describePathError(path, err)
}

func describePathError(path string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pathguard.ErrOutsideRoot):
		return fmt.Errorf("%s: access denied (outside the directory this server may read)", path)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: no such file or directory", path)
	}
	return err
}

func (s *Server) getTools() []Tool {
	return []Tool{
		{
			Name:        "analyze",
			Title:       "Analyze file",
			Annotations: readOnly,
			Description: "Analyze a file to detect its format, entropy, embedded objects, and security indicators. Use this as the primary tool for initial file analysis.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "scan",
			Title:       "Find embedded files",
			Annotations: readOnly,
			Description: "Find files embedded anywhere inside a file (like binwalk): images, archives, executables, filesystems, compressed streams. Each match is validated against the format's header and includes its offset, size and a description. Use on firmware, disk images, memory dumps and suspicious documents.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file",
					},
					"formats": map[string]interface{}{
						"type":        "array",
						"description": "Only report these formats (default: all)",
						"items":       map[string]interface{}{"type": "string", "enum": signature.Formats()},
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of matches to return",
						"default":     200,
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "hash",
			Title:       "Hash file",
			Annotations: readOnly,
			Description: "Compute cryptographic hashes (MD5, SHA1, SHA256, SHA512, SHA3) of a file. Use for file identification and integrity verification.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the file to hash",
					},
					"algorithms": map[string]interface{}{
						"type":        "array",
						"description": "Hash algorithms to compute",
						"items": map[string]interface{}{
							"type": "string",
							"enum": []string{"md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512"},
						},
						"default": []string{"md5", "sha1", "sha256"},
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "strings",
			Title:       "Extract strings",
			Annotations: readOnly,
			Description: "Extract printable strings from a binary file. Use for finding URLs, file paths, IP addresses, and other human-readable content.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the file",
					},
					"min_length": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum string length",
						"default":     4,
					},
					"max_count": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of strings",
						"default":     1000,
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "crypto",
			Title:       "Assess encryption",
			Annotations: readOnly,
			Description: "Assess whether a file is encrypted: identifies encryption containers (OpenSSL, OpenPGP, age, LUKS, BitLocker, KeePass, ...) and runs a chi-square randomness test that separates encrypted or random data from compressed data. Ciphers cannot be identified from ciphertext alone.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "stego",
			Title:       "Detect steganography",
			Annotations: readOnly,
			Description: "Detect steganography in image files (PNG, BMP, GIF, JPEG). Use to find hidden data in media files.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the image file",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "metadata",
			Title:       "Extract metadata",
			Annotations: readOnly,
			Description: "Extract metadata from image files (EXIF, XMP, IPTC). Use to find camera info, GPS coordinates, timestamps.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the image file",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "container",
			Title:       "List archive contents",
			Annotations: readOnly,
			Description: "Analyze archive/container files (ZIP, TAR, 7z, RAR, GZIP). Inspect contents without extraction.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the archive file",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "sqlite",
			Title:       "Inspect SQLite database",
			Annotations: readOnly,
			Description: "Analyze SQLite database files. Extracts tables, schema, and metadata. Use for browser histories, app data.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the SQLite database",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "batch",
			Title:       "Analyze directory",
			Annotations: readOnly,
			Description: "Batch analyze all files in a directory. Use for quick triage of forensic images or malware samples.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"directory": map[string]interface{}{
						"type":        "string",
						"description": "Directory to analyze",
					},
					"workers": map[string]interface{}{
						"type":        "integer",
						"description": "Number of parallel workers",
						"default":     4,
					},
				},
				"required": []string{"directory"},
			},
		},
	}
}

func (s *Server) handleToolCall(req Request) *Response {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		return &Response{
			JSONRPC: "2.0",
			Error: &Error{
				Code:    codeInvalidParams,
				Message: "Invalid params: expected an object with \"name\" and \"arguments\"",
			},
			ID: req.ID,
		}
	}

	toolName, _ := params["name"].(string)
	arguments, _ := params["arguments"].(map[string]interface{})
	if arguments == nil {
		arguments = map[string]interface{}{}
	}

	var result interface{}
	var err error

	switch toolName {
	case "analyze":
		path, _ := arguments["path"].(string)
		result, err = s.toolAnalyze(path)

	case "scan":
		path, _ := arguments["path"].(string)
		result, err = s.toolScan(path, toStringSlice(arguments["formats"]), toInt(arguments["limit"], 200))

	case "hash":
		path, _ := arguments["path"].(string)
		algs := toStringSlice(arguments["algorithms"])
		result, err = s.toolHash(path, algs)

	case "strings":
		path, _ := arguments["path"].(string)
		minLen := toInt(arguments["min_length"], 4)
		maxCount := toInt(arguments["max_count"], 1000)
		result, err = s.toolStrings(path, minLen, maxCount)

	case "crypto":
		path, _ := arguments["path"].(string)
		result, err = s.toolCrypto(path)

	case "stego":
		path, _ := arguments["path"].(string)
		result, err = s.toolStego(path)

	case "metadata":
		path, _ := arguments["path"].(string)
		result, err = s.toolMetadata(path)

	case "container":
		path, _ := arguments["path"].(string)
		result, err = s.toolContainer(path)

	case "sqlite":
		path, _ := arguments["path"].(string)
		result, err = s.toolSQLite(path)

	case "batch":
		directory, _ := arguments["directory"].(string)
		workers := toInt(arguments["workers"], 4)
		result, err = s.toolBatch(directory, workers)

	default:
		return &Response{
			JSONRPC: "2.0",
			Error: &Error{
				Code:    codeInvalidParams,
				Message: "Unknown tool: " + toolName,
			},
			ID: req.ID,
		}
	}

	if err != nil {
		// Tool failures are reported in the result so the model can see and
		// react to them, as the MCP specification requires.
		return &Response{
			JSONRPC: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{{"type": "text", "text": err.Error()}},
				"isError": true,
			},
			ID: req.ID,
		}
	}

	return &Response{
		JSONRPC: "2.0",
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": formatResult(result),
				},
			},
		},
		ID: req.ID,
	}
}

func (s *Server) toolAnalyze(path string) (interface{}, error) {
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}

	result, err := analyzer.Analyze(data, path, nil)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	return map[string]interface{}{
		"file": map[string]interface{}{
			"name":   filepath.Base(path),
			"path":   path,
			"size":   result.FileSize,
			"sha256": result.SHA256,
		},
		"detection": map[string]interface{}{
			"format":      result.PrimaryFormat,
			"mime":        result.PrimaryMIME,
			"description": result.Description,
			"confidence":  result.Confidence,
		},
		"analysis": map[string]interface{}{
			"entropy":           result.Entropy,
			"architecture":      result.Architecture,
			"embedded":          result.EmbeddedObjects,
			"structural_issues": result.Contradictions,
			"encryption":        result.CryptoIndicators,
		},
	}, nil
}

func (s *Server) toolScan(path string, formats []string, limit int) (interface{}, error) {
	known := map[string]bool{}
	for _, f := range signature.Formats() {
		known[f] = true
	}
	for _, f := range formats {
		if !known[f] {
			return nil, fmt.Errorf("unknown format %q", f)
		}
	}
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 10000 {
		limit = 200
	}
	matches := signature.Scan(data, signature.Options{Formats: formats, Limit: limit + 1})
	truncated := len(matches) > limit
	if truncated {
		matches = matches[:limit]
	}
	if matches == nil {
		matches = []signature.Match{}
	}
	return map[string]interface{}{
		"path":      path,
		"size":      len(data),
		"matches":   matches,
		"truncated": truncated,
	}, nil
}

func (s *Server) toolHash(path string, algorithms []string) (interface{}, error) {
	var algos []hashing.Algorithm
	for _, a := range algorithms {
		alg, err := hashing.ParseAlgorithm(a)
		if err != nil {
			return nil, err
		}
		algos = append(algos, alg)
	}

	resolved, err := s.resolveFile(path)
	if err != nil {
		return nil, err
	}
	result, err := hashing.ComputeFile(resolved, algos)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"path":   path,
		"size":   result.FileSize,
		"hashes": result.Algorithms,
	}, nil
}

func (s *Server) toolStrings(path string, minLen int, maxCount int) (interface{}, error) {
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}

	opts := &filostrings.Options{
		MinLength: minLen,
		MaxCount:  maxCount,
		Type:      "all",
	}

	result, err := filostrings.Extract(data, filepath.Base(path), opts)
	if err != nil {
		return nil, fmt.Errorf("string extraction failed: %w", err)
	}

	var extracted []map[string]interface{}
	for _, s := range result.Strings {
		extracted = append(extracted, map[string]interface{}{
			"offset":  s.Offset,
			"value":   s.Value,
			"type":    s.Type,
			"entropy": fmt.Sprintf("%.2f", s.Entropy),
		})
	}

	return map[string]interface{}{
		"path":    path,
		"count":   result.Total,
		"strings": extracted,
	}, nil
}

func (s *Server) toolCrypto(path string) (interface{}, error) {
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}

	result := crypto.Analyze(data)

	return struct {
		Path string `json:"path"`
		*crypto.Result
	}{path, result}, nil
}

func (s *Server) toolStego(path string) (interface{}, error) {
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}

	result, err := stego.Detect(data, filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("stego detection failed: %w", err)
	}

	var methods []map[string]interface{}
	for _, m := range result.Methods {
		methods = append(methods, map[string]interface{}{
			"name":       m.Name,
			"confidence": fmt.Sprintf("%.1f%%", m.Confidence*100),
			"has_flag":   m.HasFlag,
		})
	}

	return map[string]interface{}{
		"path":    path,
		"format":  result.Format,
		"methods": methods,
		"flags":   result.Flags,
	}, nil
}

func (s *Server) toolMetadata(path string) (interface{}, error) {
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}

	result, err := metadata.Extract(data, filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("metadata extraction failed: %w", err)
	}

	return map[string]interface{}{
		"path":       path,
		"format":     result.Format,
		"metadata":   result.Metadata,
		"suspicious": result.Suspicious,
	}, nil
}

func (s *Server) toolContainer(path string) (interface{}, error) {
	data, err := s.readFile(path)
	if err != nil {
		return nil, err
	}

	result, err := container.Analyze(data, filepath.Base(path), 1)
	if err != nil {
		return nil, fmt.Errorf("container analysis failed: %w", err)
	}

	var entries []map[string]interface{}
	for _, e := range result.Entries {
		entries = append(entries, map[string]interface{}{
			"path":   e.Path,
			"size":   e.Size,
			"format": e.Format,
		})
	}

	return map[string]interface{}{
		"path":       path,
		"format":     result.Format,
		"entries":    entries,
		"total_size": result.TotalSize,
	}, nil
}

func (s *Server) toolSQLite(path string) (interface{}, error) {
	resolved, err := s.resolveFile(path)
	if err != nil {
		return nil, err
	}
	result, err := sqlite.Parse(resolved)
	if err != nil {
		return nil, fmt.Errorf("SQLite analysis failed: %w", err)
	}

	var tables []map[string]interface{}
	for _, t := range result.Tables {
		tables = append(tables, map[string]interface{}{
			"name":     t.Name,
			"rootpage": t.RootPage,
			"sql":      t.SQL,
		})
	}

	return map[string]interface{}{
		"path":    path,
		"tables":  tables,
		"pages":   result.Pages,
		"has_wal": result.WAL != nil,
	}, nil
}

func (s *Server) toolBatch(directory string, workers int) (interface{}, error) {
	if workers <= 0 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}
	dir, err := s.guard.Dir(directory)
	if err != nil {
		return nil, describePathError(directory, err)
	}

	result, err := batch.Process(dir, &batch.Options{
		Workers: workers,
	})
	if err != nil {
		return nil, fmt.Errorf("batch processing failed: %w", err)
	}

	return map[string]interface{}{
		"directory":     result.Directory,
		"total_files":   result.TotalFiles,
		"analyzed":      result.Analyzed,
		"failed":        result.Failed,
		"duration":      result.Duration.String(),
		"files_per_sec": result.FilesPerSec,
	}, nil
}

func formatResult(result interface{}) string {
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data)
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func toInt(v interface{}, defaultVal int) int {
	if v == nil {
		return defaultVal
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return defaultVal
	}
}
