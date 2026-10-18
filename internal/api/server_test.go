package api

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture creates <tmp>/data with a PNG and a text file, plus a sibling
// <tmp>/data-secret directory whose name shares the root's prefix.
func fixture(t *testing.T) (root, secret string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "data")
	secret = filepath.Join(base, "data-secret")
	for _, d := range []string{filepath.Join(root, "sub"), secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewGray(image.Rect(0, 0, 3, 2)))
	write := func(p string, b []byte) {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "img.png"), buf.Bytes())
	write(filepath.Join(root, "sub", "notes.txt"), []byte("hello http://example.com world"))
	write(filepath.Join(secret, "key.pem"), []byte("-----BEGIN PRIVATE KEY-----"))
	return root, secret
}

func newTestServer(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	if cfg.Version == "" {
		cfg.Version = "test"
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func do(t *testing.T, h http.Handler, method, path string, body any, header ...string) (*httptest.ResponseRecorder, APIResponse) {
	t.Helper()
	var rdr *bytes.Reader
	if s, ok := body.(string); ok {
		rdr = bytes.NewReader([]byte(s))
	} else {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp APIResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func TestHealthAndVersion(t *testing.T) {
	h := newTestServer(t, Config{})
	for _, p := range []string{"/api/health", "/api/version"} {
		w, resp := do(t, h, "GET", p, nil)
		if w.Code != http.StatusOK || !resp.Success || resp.Meta == nil || resp.Meta.Version != "test" {
			t.Errorf("%s: %d %+v", p, w.Code, resp)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing security headers", p)
		}
	}
}

func TestPathEndpointsDisabledWithoutRoot(t *testing.T) {
	root, _ := fixture(t)
	h := newTestServer(t, Config{})
	w, resp := do(t, h, "POST", "/api/analyze", PathRequest{Path: filepath.Join(root, "img.png")})
	if w.Code != http.StatusForbidden || !strings.Contains(resp.Error, "--root") {
		t.Errorf("got %d %q, want 403 mentioning --root", w.Code, resp.Error)
	}
}

func TestFileEndpointsInsideRoot(t *testing.T) {
	root, _ := fixture(t)
	h := newTestServer(t, Config{Root: root})

	cases := []struct {
		endpoint string
		body     any
		want     string
	}{
		{"/api/analyze", PathRequest{Path: "img.png"}, `"primary_format":"png"`},
		{"/api/analyze", PathRequest{Path: filepath.Join(root, "img.png")}, `"primary_format":"png"`},
		{"/api/scan", ScanRequest{Path: "img.png"}, `"format":"png"`},
		{"/api/hash", HashRequest{Path: "img.png", Algorithms: []string{"sha256"}}, `"sha256"`},
		{"/api/strings", StringsRequest{Path: "sub/notes.txt"}, "example.com"},
		{"/api/crypto", PathRequest{Path: "img.png"}, `"verdict"`},
		{"/api/metadata", PathRequest{Path: "img.png"}, `"width"`},
		{"/api/stego", PathRequest{Path: "img.png"}, `"success":true`},
		{"/api/batch", BatchRequest{Directory: ".", Recursive: true}, `"success":true`},
	}
	for _, c := range cases {
		w, resp := do(t, h, "POST", c.endpoint, c.body)
		if w.Code != http.StatusOK || !resp.Success {
			t.Errorf("%s: %d %s", c.endpoint, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: body does not contain %s: %s", c.endpoint, c.want, w.Body.String())
		}
	}
}

func TestRootConfinement(t *testing.T) {
	root, secret := fixture(t)
	h := newTestServer(t, Config{Root: root})

	escapes := []string{
		"../data-secret/key.pem",
		filepath.Join(secret, "key.pem"), // shares the root's prefix: the old check allowed it
		"sub/../../data-secret/key.pem",
	}
	for _, p := range escapes {
		for _, ep := range []string{"/api/analyze", "/api/strings", "/api/hash"} {
			w, resp := do(t, h, "POST", ep, PathRequest{Path: p})
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %q: got %d %q, want 403", ep, p, w.Code, resp.Error)
			}
		}
	}
	// Batch used to skip path validation entirely.
	if w, _ := do(t, h, "POST", "/api/batch", BatchRequest{Directory: secret}); w.Code != http.StatusForbidden {
		t.Errorf("batch outside root: got %d, want 403", w.Code)
	}
}

func TestRequestErrors(t *testing.T) {
	root, _ := fixture(t)
	h := newTestServer(t, Config{Root: root})
	cases := []struct {
		endpoint string
		body     any
		code     int
	}{
		{"/api/analyze", PathRequest{}, http.StatusBadRequest},
		{"/api/analyze", "{not json", http.StatusBadRequest},
		{"/api/analyze", PathRequest{Path: "missing.bin"}, http.StatusNotFound},
		{"/api/analyze", PathRequest{Path: "sub"}, http.StatusBadRequest},
		{"/api/hash", HashRequest{Path: "img.png", Algorithms: []string{"crc99"}}, http.StatusBadRequest},
		{"/api/batch", BatchRequest{}, http.StatusBadRequest},
		{"/api/batch", BatchRequest{Directory: "img.png"}, http.StatusBadRequest},
		{"/api/analyze", strings.Repeat("x", maxRequestBodySize+1), http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		if w, resp := do(t, h, "POST", c.endpoint, c.body); w.Code != c.code || resp.Success {
			t.Errorf("%s %v: got %d %+v, want %d", c.endpoint, c.body, w.Code, resp, c.code)
		}
	}
	if w, _ := do(t, h, "GET", "/api/analyze", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/analyze: got %d, want 405", w.Code)
	}
}

func TestTokenAuth(t *testing.T) {
	root, _ := fixture(t)
	h := newTestServer(t, Config{Root: root, Token: "s3cret"})

	if w, _ := do(t, h, "GET", "/api/health", nil); w.Code != http.StatusOK {
		t.Errorf("health must not require auth: %d", w.Code)
	}
	for _, hdr := range [][]string{nil, {"Authorization", "Bearer wrong"}, {"Authorization", "s3cret"}} {
		w, _ := do(t, h, "POST", "/api/analyze", PathRequest{Path: "img.png"}, hdr...)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("header %v: got %d, want 401", hdr, w.Code)
		}
	}
	if w, _ := do(t, h, "POST", "/api/analyze", PathRequest{Path: "img.png"}, "Authorization", "Bearer s3cret"); w.Code != http.StatusOK {
		t.Errorf("valid token: got %d", w.Code)
	}
}

func TestRemoteListenRequiresAuth(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.168.1.5:80"} {
		if _, err := NewServer(Config{Addr: addr}); err == nil {
			t.Errorf("NewServer(%q) without token succeeded", addr)
		}
		if _, err := NewServer(Config{Addr: addr, Token: "t"}); err != nil {
			t.Errorf("NewServer(%q) with token: %v", addr, err)
		}
		if _, err := NewServer(Config{Addr: addr, AllowRemoteNoAuth: true}); err != nil {
			t.Errorf("NewServer(%q) with AllowRemoteNoAuth: %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "localhost:9000", "[::1]:8080", ""} {
		if _, err := NewServer(Config{Addr: addr}); err != nil {
			t.Errorf("NewServer(%q): %v", addr, err)
		}
	}
	if _, err := NewServer(Config{Root: "/definitely/not/here"}); err == nil {
		t.Error("NewServer accepted a missing root")
	}
}

func upload(t *testing.T, h http.Handler, name string, content []byte) (*httptest.ResponseRecorder, APIResponse) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(content)
	mw.Close()
	req := httptest.NewRequest("POST", "/api/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp APIResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func TestUpload(t *testing.T) {
	root, _ := fixture(t)
	img, _ := os.ReadFile(filepath.Join(root, "img.png"))
	h := newTestServer(t, Config{MaxUpload: 1 << 10}) // works without --root

	w, resp := upload(t, h, "../../evil/../img.png", img)
	if w.Code != http.StatusOK || !resp.Success {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	data := resp.Data.(map[string]any)
	if data["filename"] != "img.png" {
		t.Errorf("filename not sanitised: %v", data["filename"])
	}
	if !strings.Contains(w.Body.String(), `"primary_format":"png"`) {
		t.Errorf("upload not analyzed: %s", w.Body.String())
	}

	if w, _ := upload(t, h, "big.bin", make([]byte, 4<<20)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized upload: got %d, want 413", w.Code)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:1": true, "localhost:1": true, "[::1]:1": true, "127.1.2.3:1": true,
		":1": false, "0.0.0.0:1": false, "10.0.0.1:1": false, "example.com:1": false,
	} {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
