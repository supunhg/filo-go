package mcp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/batch"
	"github.com/supunhg/filo-go/internal/crypto"
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
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  interface{}   `json:"params,omitempty"`
	ID      interface{}   `json:"id"`
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
					"name":    "filo-go",
					"version": "0.1.0",
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
			Description: "Analyze a file to detect its format, entropy, and security indicators",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file to analyze",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "hash",
			Description: "Compute SHA-256 hash of a file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file to hash",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "batch",
			Description: "Batch analyze all files in a directory",
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
		{
			Name:        "crypto",
			Description: "Analyze file for encryption indicators",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file to analyze",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "strings",
			Description: "Extract printable strings from a file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file",
					},
					"min_length": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum string length",
						"default":     4,
					},
				},
				"required": []string{"path"},
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
		result, err = s.toolHash(path)

	case "batch":
		directory, _ := arguments["directory"].(string)
		workers, _ := arguments["workers"].(float64)
		result, err = s.toolBatch(directory, int(workers))

	case "crypto":
		path, _ := arguments["path"].(string)
		result, err = s.toolCrypto(path)

	case "strings":
		path, _ := arguments["path"].(string)
		minLen, _ := arguments["min_length"].(float64)
		result, err = s.toolStrings(path, int(minLen))

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
		return nil, err
	}

	result, err := analyzer.Analyze(data, path, nil)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"format":   result.PrimaryFormat,
		"mime":     result.PrimaryMIME,
		"confidence": result.Confidence,
		"size":     result.FileSize,
		"entropy":  result.Entropy,
		"sha256":   result.SHA256,
	}, nil
}

func (s *Server) toolHash(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(data)
	return map[string]interface{}{
		"path":  path,
		"size":  len(data),
		"sha256": fmt.Sprintf("%x", h),
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
		return nil, err
	}

	return map[string]interface{}{
		"directory":    result.Directory,
		"total_files":  result.TotalFiles,
		"analyzed":     result.Analyzed,
		"failed":       result.Failed,
		"duration":     result.Duration.String(),
		"files_per_sec": result.FilesPerSec,
	}, nil
}

func (s *Server) toolCrypto(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result := crypto.Analyze(data)
	return map[string]interface{}{
		"detected":    result.Detected,
		"confidence":  result.Confidence,
		"entropy":     result.Entropy,
		"block_size":  result.BlockSize,
		"cipher_hints": result.CipherHints,
		"ecb_detected": result.ECBDetected,
	}, nil
}

func (s *Server) toolStrings(path string, minLen int) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var strings []string
	var current []byte

	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				strings = append(strings, string(current))
			}
			current = nil
		}
	}

	return map[string]interface{}{
		"path":    path,
		"strings": strings,
		"count":   len(strings),
	}, nil
}

func formatResult(result interface{}) string {
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data)
}


