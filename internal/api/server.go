// Package api implements filo's REST API.
//
// The server is safe by default: it listens on localhost, refuses to listen
// on other interfaces without a bearer token, and serves file-path endpoints
// only for files under an explicitly configured root directory. Uploaded
// files can always be analyzed.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/batch"
	"github.com/supunhg/filo-go/internal/crypto"
	"github.com/supunhg/filo-go/internal/hashing"
	"github.com/supunhg/filo-go/internal/metadata"
	"github.com/supunhg/filo-go/internal/pathguard"
	"github.com/supunhg/filo-go/internal/signature"
	"github.com/supunhg/filo-go/internal/stego"
	filostrings "github.com/supunhg/filo-go/internal/strings"
)

const (
	// DefaultAddr is the listen address used when none is configured.
	DefaultAddr = "127.0.0.1:8080"
	// DefaultMaxUpload is the default upload size limit in bytes.
	DefaultMaxUpload = 64 << 20

	maxRequestBodySize = 1 << 20 // JSON bodies are small
	maxHeaderBytes     = 1 << 20
	maxBatchWorkers    = 64
)

// Config configures a Server.
type Config struct {
	// Addr is the TCP listen address. Defaults to DefaultAddr.
	Addr string
	// Version is reported by /api/version and in response metadata.
	Version string
	// Root enables the file-path endpoints for files under this directory.
	// When empty, only /api/upload can analyze files.
	Root string
	// Token, when set, is required as "Authorization: Bearer <token>" on
	// every endpoint except /api/health.
	Token string
	// AllowRemoteNoAuth permits listening on a non-loopback address without
	// a token. Only use it behind an authenticating reverse proxy.
	AllowRemoteNoAuth bool
	// MaxUpload limits upload size in bytes. Defaults to DefaultMaxUpload.
	MaxUpload int64
}

// Server represents the REST API server.
type Server struct {
	cfg   Config
	guard *pathguard.Guard
}

// NewServer validates cfg and returns a server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	if cfg.MaxUpload <= 0 {
		cfg.MaxUpload = DefaultMaxUpload
	}
	if cfg.Token == "" && !cfg.AllowRemoteNoAuth && !IsLoopback(cfg.Addr) {
		return nil, fmt.Errorf("refusing to listen on %s without authentication: set a token (--token or FILO_API_TOKEN) or listen on 127.0.0.1", cfg.Addr)
	}
	guard, err := pathguard.New(cfg.Root)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, guard: guard}, nil
}

// IsLoopback reports whether addr ("host:port") only accepts local
// connections. An empty host means all interfaces.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
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
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Duration  string `json:"duration,omitempty"`
}

// PathRequest is the body of the single-file endpoints.
type PathRequest struct {
	// Path is relative to the server root, or absolute inside it.
	Path string `json:"path"`
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

// ScanRequest represents an embedded-file scan request.
type ScanRequest struct {
	Path    string   `json:"path"`
	Formats []string `json:"formats,omitempty"`
	Nested  bool     `json:"nested,omitempty"`
}

// BatchRequest represents a batch analysis request.
type BatchRequest struct {
	Directory string `json:"directory"`
	Workers   int    `json:"workers,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

// Handler returns the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/version", s.handleVersion)

	mux.HandleFunc("POST /api/analyze", s.fileEndpoint(func(path string, data []byte, _ json.RawMessage) (any, error) {
		return analyzer.Analyze(data, path, nil)
	}))
	mux.HandleFunc("POST /api/scan", s.fileEndpoint(func(_ string, data []byte, body json.RawMessage) (any, error) {
		var req ScanRequest
		_ = json.Unmarshal(body, &req)
		m := signature.Scan(data, signature.Options{Formats: req.Formats, IncludeNested: req.Nested})
		if m == nil {
			m = []signature.Match{}
		}
		return m, nil
	}))
	mux.HandleFunc("POST /api/strings", s.fileEndpoint(func(path string, data []byte, body json.RawMessage) (any, error) {
		var req StringsRequest
		_ = json.Unmarshal(body, &req)
		if req.MinLength <= 0 {
			req.MinLength = 4
		}
		return filostrings.Extract(data, filepath.Base(path), &filostrings.Options{MinLength: req.MinLength, MaxCount: req.MaxCount, Type: "all"})
	}))
	mux.HandleFunc("POST /api/crypto", s.fileEndpoint(func(_ string, data []byte, _ json.RawMessage) (any, error) {
		return crypto.Analyze(data), nil
	}))
	mux.HandleFunc("POST /api/stego", s.fileEndpoint(func(path string, data []byte, _ json.RawMessage) (any, error) {
		return stego.Detect(data, filepath.Base(path))
	}))
	mux.HandleFunc("POST /api/metadata", s.fileEndpoint(func(path string, data []byte, _ json.RawMessage) (any, error) {
		return metadata.Extract(data, filepath.Base(path))
	}))
	mux.HandleFunc("POST /api/hash", s.handleHash)
	mux.HandleFunc("POST /api/batch", s.handleBatch)
	mux.HandleFunc("POST /api/upload", s.handleUpload)

	return s.withAuth(securityHeaders(mux))
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // uploads can be large
		WriteTimeout:      5 * time.Minute, // batch analysis can be slow
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.cfg.Addr }

// Root returns the resolved root directory, or "" when file-path endpoints
// are disabled.
func (s *Server) Root() string { return s.guard.Root() }

// AuthRequired reports whether requests need a bearer token.
func (s *Server) AuthRequired() bool { return s.cfg.Token != "" }

func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.cfg.Token == "" {
		return next
	}
	want := []byte("Bearer " + s.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			got := []byte(r.Header.Get("Authorization"))
			if subtle.ConstantTimeCompare(got, want) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="filo"`)
				s.jsonError(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// fileEndpoint builds a handler for endpoints that take {"path": ...},
// read the file and return fn's result.
func (s *Server) fileEndpoint(fn func(path string, data []byte, body json.RawMessage) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		body, ok := s.readBody(w, r)
		if !ok {
			return
		}
		var req PathRequest
		if err := json.Unmarshal(body, &req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
			return
		}
		path, ok := s.resolve(w, req.Path, false)
		if !ok {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "cannot read file")
			return
		}
		result, err := fn(req.Path, data, body)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.ok(w, start, result)
	}
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodySize))
	if err != nil {
		s.jsonError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	return body, true
}

// resolve maps a client path to a file (or directory) inside the root and
// writes an error response when that is not possible.
func (s *Server) resolve(w http.ResponseWriter, p string, dir bool) (string, bool) {
	if !s.guard.Restricted() {
		s.jsonError(w, http.StatusForbidden, "file-path endpoints are disabled; start the server with --root DIR, or use /api/upload")
		return "", false
	}
	if p == "" {
		field := "path"
		if dir {
			field = "directory"
		}
		s.jsonError(w, http.StatusBadRequest, field+" is required")
		return "", false
	}
	var resolved string
	var err error
	if dir {
		resolved, err = s.guard.Dir(p)
	} else {
		resolved, err = s.guard.File(p)
	}
	switch {
	case err == nil:
		return resolved, true
	case errors.Is(err, pathguard.ErrOutsideRoot):
		s.jsonError(w, http.StatusForbidden, "access denied: path is outside the server root")
	case errors.Is(err, fs.ErrNotExist):
		s.jsonError(w, http.StatusNotFound, "not found: "+p)
	default:
		s.jsonError(w, http.StatusBadRequest, err.Error())
	}
	return "", false
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: map[string]string{"status": "healthy"}, Meta: s.meta(time.Time{})})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: map[string]string{"version": s.cfg.Version, "tool": "filo"}, Meta: s.meta(time.Time{})})
}

func (s *Server) handleHash(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var req HashRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	var algos []hashing.Algorithm
	for _, a := range req.Algorithms {
		alg, err := hashing.ParseAlgorithm(a)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		algos = append(algos, alg)
	}
	path, ok := s.resolve(w, req.Path, false)
	if !ok {
		return
	}
	result, err := hashing.ComputeFile(path, algos)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "hashing failed")
		return
	}
	s.ok(w, start, result)
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var req BatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	dir, ok := s.resolve(w, req.Directory, true)
	if !ok {
		return
	}
	if req.Workers <= 0 {
		req.Workers = 4
	}
	if req.Workers > maxBatchWorkers {
		req.Workers = maxBatchWorkers
	}
	result, err := batch.Process(dir, &batch.Options{Workers: req.Workers, Recursive: req.Recursive})
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "batch processing failed: "+err.Error())
		return
	}
	s.ok(w, start, result)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload+1<<20) // allow for multipart framing
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.jsonError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("upload exceeds %d bytes", s.cfg.MaxUpload))
			return
		}
		s.jsonError(w, http.StatusBadRequest, "invalid multipart form: "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, `missing form field "file"`)
		return
	}
	defer func() { _ = file.Close() }()
	if header.Size > s.cfg.MaxUpload {
		s.jsonError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("upload exceeds %d bytes", s.cfg.MaxUpload))
		return
	}
	data, err := io.ReadAll(file)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to read upload")
		return
	}
	name := filepath.Base(header.Filename)
	result, err := analyzer.Analyze(data, name, nil)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "analysis failed: "+err.Error())
		return
	}
	s.ok(w, start, map[string]interface{}{"filename": name, "size": len(data), "analysis": result})
}

func (s *Server) meta(start time.Time) *Meta {
	m := &Meta{Version: s.cfg.Version, Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if !start.IsZero() {
		m.Duration = time.Since(start).String()
	}
	return m
}

func (s *Server) ok(w http.ResponseWriter, start time.Time, data any) {
	s.jsonResponse(w, http.StatusOK, APIResponse{Success: true, Data: data, Meta: s.meta(start)})
}

func (s *Server) jsonResponse(w http.ResponseWriter, status int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, msg string) {
	s.jsonResponse(w, status, APIResponse{Success: false, Error: msg, Meta: s.meta(time.Time{})})
}
