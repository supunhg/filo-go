package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/batch"
	"github.com/supunhg/filo-go/internal/container"
	"github.com/supunhg/filo-go/internal/crypto"
	"github.com/supunhg/filo-go/internal/hashing"
	"github.com/supunhg/filo-go/internal/metadata"
	"github.com/supunhg/filo-go/internal/sqlite"
	"github.com/supunhg/filo-go/internal/stego"
	filostrings "github.com/supunhg/filo-go/internal/strings"
)

// Server implements a JSON-RPC MCP server.
type Server struct {
	reader io.Reader
	writer io.Writer
}

// NewServer creates a new MCP server.
func NewServer() *Server {
	return &Server{
		reader: os.Stdin,
		writer: os.Stdout,
	}
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
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// Run starts the MCP server.
func (s *Server) Run() error {
	decoder := json.NewDecoder(s.reader)
	encoder := json.NewEncoder(s.writer)

	for {
		var req Request
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		resp := s.handleRequest(req)
		if resp != nil {
			encoder.Encode(resp)
		}
	}

	return nil
}

func (s *Server) handleRequest(req Request) *Response {
	switch req.Method {
	case "initialize":
		return &Response{
			JSONRPC: "2.0",
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":        "filo-go",
					"version":     "0.2.0",
					"description": "AI-powered forensic analysis toolkit",
				},
			},
			ID: req.ID,
		}

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
				Code:    -32601,
				Message: "Method not found",
			},
			ID: req.ID,
		}
	}
}

func (s *Server) getTools() []Tool {
	return []Tool{
		{
			Name:        "analyze",
			Description: "Analyze a file to detect its format, entropy, embedded objects, and security indicators. Use this as the primary tool for initial file analysis.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the file to analyze",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "hash",
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
			Description: "Analyze a file for encryption indicators including ECB patterns, PKCS padding, OpenSSL/PGP headers.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the file to analyze",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "stego",
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
				Code:    -32602,
				Message: "Invalid params",
			},
			ID: req.ID,
		}
	}

	toolName, _ := params["name"].(string)
	arguments, _ := params["arguments"].(map[string]interface{})

	var result interface{}
	var err error

	switch toolName {
	case "analyze":
		path, _ := arguments["path"].(string)
		result, err = s.toolAnalyze(path)

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
				Code:    -32601,
				Message: "Tool not found: " + toolName,
			},
			ID: req.ID,
		}
	}

	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			Error: &Error{
				Code:    -32000,
				Message: err.Error(),
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
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
			"format":     result.PrimaryFormat,
			"mime":       result.PrimaryMIME,
			"confidence": fmt.Sprintf("%.1f%%", result.Confidence*100),
		},
		"analysis": map[string]interface{}{
			"entropy":        fmt.Sprintf("%.2f", result.Entropy),
			"architecture":   result.Architecture,
			"embedded":       result.EmbeddedObjects,
			"contradictions": result.Contradictions,
			"crypto_hints":   result.CryptoIndicators,
		},
	}, nil
}

func (s *Server) toolHash(path string, algorithms []string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var algos []hashing.Algorithm
	for _, a := range algorithms {
		algos = append(algos, hashing.Algorithm(a))
	}

	result := hashing.Compute(data, algos)

	return map[string]interface{}{
		"path":   path,
		"size":   result.FileSize,
		"hashes": result.Algorithms,
	}, nil
}

func (s *Server) toolStrings(path string, minLen int, maxCount int) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	result := crypto.Analyze(data)

	return map[string]interface{}{
		"path":       path,
		"detected":   result.Detected,
		"confidence": fmt.Sprintf("%.1f%%", result.Confidence*100),
		"entropy":    fmt.Sprintf("%.2f", result.Entropy),
		"block_size": result.BlockSize,
		"ecb":        result.ECBDetected,
		"hints":      result.CipherHints,
		"padding":    result.Padding,
	}, nil
}

func (s *Server) toolStego(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
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
		"path":     path,
		"format":   result.Format,
		"methods":  methods,
		"flags":    result.Flags,
	}, nil
}

func (s *Server) toolMetadata(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
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
	result, err := sqlite.Parse(path)
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
		"path":      path,
		"tables":    tables,
		"pages":     result.Pages,
		"has_wal":   result.WAL != nil,
	}, nil
}

func (s *Server) toolBatch(directory string, workers int) (interface{}, error) {
	if workers <= 0 {
		workers = 4
	}

	result, err := batch.Process(directory, &batch.Options{
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
