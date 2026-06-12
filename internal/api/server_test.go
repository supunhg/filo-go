package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	srv := NewServer(":0", "test")
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestVersionEndpoint(t *testing.T) {
	srv := NewServer(":0", "test")
	req := httptest.NewRequest("GET", "/api/version", nil)
	w := httptest.NewRecorder()

	srv.handleVersion(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestAnalyzeEndpoint(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data for analysis"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(":0", "test")

	body, _ := json.Marshal(AnalyzeRequest{Path: testFile})
	req := httptest.NewRequest("POST", "/api/analyze", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleAnalyze(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestAnalyzeEndpointMissingPath(t *testing.T) {
	srv := NewServer(":0", "test")

	body, _ := json.Marshal(AnalyzeRequest{})
	req := httptest.NewRequest("POST", "/api/analyze", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleAnalyze(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHashEndpoint(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data for hashing"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(":0", "test")

	body, _ := json.Marshal(HashRequest{Path: testFile})
	req := httptest.NewRequest("POST", "/api/hash", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleHash(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestStringsEndpoint(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("Hello World\x00Test String"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(":0", "test")

	body, _ := json.Marshal(StringsRequest{Path: testFile, MinLength: 4})
	req := httptest.NewRequest("POST", "/api/strings", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleStrings(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestCryptoEndpoint(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(":0", "test")

	body, _ := json.Marshal(map[string]string{"path": testFile})
	req := httptest.NewRequest("POST", "/api/crypto", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCrypto(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestMetadataEndpoint(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.bin"
	if err := os.WriteFile(testFile, []byte("test data"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(":0", "test")

	body, _ := json.Marshal(map[string]string{"path": testFile})
	req := httptest.NewRequest("POST", "/api/metadata", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestBatchEndpoint(t *testing.T) {
	// Create test directory with files
	tmpDir := t.TempDir()
	if err := os.WriteFile(tmpDir+"/test1.bin", []byte("test1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpDir+"/test2.bin", []byte("test2"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(":0", "test")

	body, _ := json.Marshal(BatchRequest{Directory: tmpDir, Workers: 1})
	req := httptest.NewRequest("POST", "/api/batch", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleBatch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}
}

func TestBatchEndpointMissingDirectory(t *testing.T) {
	srv := NewServer(":0", "test")

	body, _ := json.Marshal(BatchRequest{})
	req := httptest.NewRequest("POST", "/api/batch", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleBatch(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestJSONResponse(t *testing.T) {
	srv := NewServer(":0", "test")
	w := httptest.NewRecorder()

	srv.jsonResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    "test",
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}
}

func TestJSONError(t *testing.T) {
	srv := NewServer(":0", "test")
	w := httptest.NewRecorder()

	srv.jsonError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}

	var resp APIResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Error("expected success to be false")
	}

	if resp.Error != "test error" {
		t.Errorf("expected error 'test error', got %s", resp.Error)
	}
}

func TestServerStruct(t *testing.T) {
	srv := NewServer(":8080", "test")

	if srv.addr != ":8080" {
		t.Errorf("expected addr :8080, got %s", srv.addr)
	}

	if srv.version != "test" {
		t.Errorf("expected version test, got %s", srv.version)
	}
}
