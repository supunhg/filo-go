package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/batch"
	"github.com/supunhg/filo-go/internal/crypto"
	"github.com/supunhg/filo-go/internal/hashing"
	"github.com/supunhg/filo-go/internal/metadata"
	"github.com/supunhg/filo-go/internal/stego"
	filostrings "github.com/supunhg/filo-go/internal/strings"
)

// Server represents the REST API server.
type Server struct {
	addr    string
	tmpDir  string
	version string
}

// NewServer creates a new API server.
func NewServer(addr string) *Server {
	return &Server{
		addr:    addr,
		tmpDir:  os.TempDir(),
		version: "0.4.0",
	}
}

// APIResponse represents a standard API response.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// Meta contains response metadata.
type Meta struct {
	Version   string  `json:"version"`
	Timestamp string  `json:"timestamp"`
	Duration  string  `json:"duration,omitempty"`
}

// AnalyzeRequest represents an analysis request.
type AnalyzeRequest struct {
	Path     string `json:"path"`
	DeepScan bool   `json:"deep_scan,omitempty"`
}

// HashRequest represents a hash request.
type HashRequest struct {
	Path       string   `json:"path"`
	Algorithms []string `json:"algorithms,omitempty"`
}

// StringsRequest represents a string extraction request.
type StringsRequest struct {
	Path      string `json:"path"`
	MinLength int    `json:"min_length,omitempty"`
	MaxCount  int    `json:"max_count,omitempty"`
}

// BatchRequest represents a batch analysis request.
type BatchRequest struct {
	Directory string `json:"directory"`
	Workers   int    `json:"workers,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

// Run starts the API server.
func (s *Server) Run() error {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/version", s.handleVersion)

	// Analysis endpoints
	mux.HandleFunc("POST /api/analyze", s.handleAnalyze)
	mux.HandleFunc("POST /api/hash", s.handleHash)
	mux.HandleFunc("POST /api/strings", s.handleStrings)
	mux.HandleFunc("POST /api/crypto", s.handleCrypto)
	mux.HandleFunc("POST /api/stego", s.handleStego)
	mux.HandleFunc("POST /api/metadata", s.handleMetadata)
	mux.HandleFunc("POST /api/batch", s.handleBatch)

	// File upload endpoint
	mux.HandleFunc("POST /api/upload", s.handleUpload)

	fmt.Printf("filo-go API server v%s\n", s.version)
	fmt.Printf("Listening on %s\n", s.addr)
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  GET  /api/health    - Health check\n")
	fmt.Printf("  GET  /api/version   - Version info\n")
	fmt.Printf("  POST /api/analyze   - Analyze file\n")
	fmt.Printf("  POST /api/hash      - Compute hashes\n")
	fmt.Printf("  POST /api/strings   - Extract strings\n")
	fmt.Printf("  POST /api/crypto    - Detect encryption\n")
	fmt.Printf("  POST /api/stego     - Detect steganography\n")
	fmt.Printf("  POST /api/metadata  - Extract metadata\n")
	fmt.Printf("  POST /api/batch     - Batch analysis\n")
	fmt.Printf("  POST /api/upload    - Upload and analyze\n")

	return http.ListenAndServe(s.addr, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]string{
			"status": "healthy",
		},
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
		},
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]string{
			"version": s.version,
			"tool":    "filo-go",
		},
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
		},
	})
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Path == "" {
		s.jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	data, err := os.ReadFile(req.Path)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "cannot read file: "+err.Error())
		return
	}

	result, err := analyzer.Analyze(data, req.Path, &analyzer.Options{
		DeepScan: req.DeepScan,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "analysis failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleHash(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req HashRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Path == "" {
		s.jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	if len(req.Algorithms) == 0 {
		req.Algorithms = []string{"md5", "sha1", "sha256"}
	}

	var algos []hashing.Algorithm
	for _, a := range req.Algorithms {
		algos = append(algos, hashing.Algorithm(a))
	}

	result, err := hashing.ComputeFile(req.Path, algos)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "hashing failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleStrings(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req StringsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Path == "" {
		s.jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	data, err := os.ReadFile(req.Path)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "cannot read file: "+err.Error())
		return
	}

	if req.MinLength == 0 {
		req.MinLength = 4
	}

	result, err := filostrings.Extract(data, filepath.Base(req.Path), &filostrings.Options{
		MinLength: req.MinLength,
		MaxCount:  req.MaxCount,
		Type:      "all",
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "string extraction failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleCrypto(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Path == "" {
		s.jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	data, err := os.ReadFile(req.Path)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "cannot read file: "+err.Error())
		return
	}

	result := crypto.Analyze(data)

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleStego(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Path == "" {
		s.jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	data, err := os.ReadFile(req.Path)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "cannot read file: "+err.Error())
		return
	}

	result, err := stego.Detect(data, filepath.Base(req.Path))
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "stego detection failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Path == "" {
		s.jsonError(w, http.StatusBadRequest, "path is required")
		return
	}

	data, err := os.ReadFile(req.Path)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "cannot read file: "+err.Error())
		return
	}

	result, err := metadata.Extract(data, filepath.Base(req.Path))
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "metadata extraction failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	if req.Directory == "" {
		s.jsonError(w, http.StatusBadRequest, "directory is required")
		return
	}

	if req.Workers == 0 {
		req.Workers = 4
	}

	result, err := batch.Process(req.Directory, &batch.Options{
		Workers:   req.Workers,
		Recursive: req.Recursive,
	})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "batch processing failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Parse multipart form
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max
		s.jsonError(w, http.StatusBadRequest, "failed to parse form: "+err.Error())
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "failed to get file: "+err.Error())
		return
	}
	defer file.Close()

	// Save to temp file
	tmpPath := filepath.Join(s.tmpDir, fmt.Sprintf("filo-upload-%d%s", time.Now().UnixNano(), filepath.Ext(header.Filename)))
	out, err := os.Create(tmpPath)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to create temp file: "+err.Error())
		return
	}
	defer out.Close()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(out, file); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to save file: "+err.Error())
		return
	}

	// Analyze the uploaded file
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to read file: "+err.Error())
		return
	}

	result, err := analyzer.Analyze(data, header.Filename, nil)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "analysis failed: "+err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"filename": header.Filename,
			"size":     header.Size,
			"analysis": result,
		},
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
			Duration:  time.Since(start).String(),
		},
	})
}

func (s *Server) jsonResponse(w http.ResponseWriter, status int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, msg string) {
	s.jsonResponse(w, status, APIResponse{
		Success: false,
		Error:   msg,
		Meta: &Meta{
			Version:   s.version,
			Timestamp: time.Now().Format(time.RFC3339),
		},
	})
}
