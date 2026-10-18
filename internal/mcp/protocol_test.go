package mcp

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// session runs the server over the given newline-delimited messages and
// returns every response it wrote.
func session(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	s.reader = strings.NewReader(strings.Join(lines, "\n") + "\n")
	s.writer = &out
	if err := s.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var resps []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("server wrote a non-JSON line %q: %v", l, err)
		}
		resps = append(resps, m)
	}
	return resps
}

func TestNotificationsGetNoResponse(t *testing.T) {
	resps := session(t, NewServer(),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`,
	)
	if len(resps) != 1 || resps[0]["id"] != float64(7) {
		t.Fatalf("want exactly one response (to ping), got %v", resps)
	}
}

func TestMalformedInputDoesNotStopTheServer(t *testing.T) {
	// The old decoder looped forever on the first malformed message.
	resps := session(t, NewServer(),
		`{not json`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	if len(resps) != 2 {
		t.Fatalf("got %d responses, want 2: %v", len(resps), resps)
	}
	if e, _ := resps[0]["error"].(map[string]any); e == nil || e["code"] != float64(codeParseError) {
		t.Errorf("first response should be a parse error: %v", resps[0])
	}
	if resps[1]["result"] == nil {
		t.Errorf("server did not recover: %v", resps[1])
	}
}

func TestInvalidRequests(t *testing.T) {
	resps := session(t, NewServer(),
		`{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2}`,
		`{"jsonrpc":"2.0","id":"abc","method":"no/such/method"}`,
	)
	want := []float64{codeInvalidRequest, codeInvalidRequest, codeMethodNotFound}
	for i, code := range want {
		e, _ := resps[i]["error"].(map[string]any)
		if e == nil || e["code"] != code {
			t.Errorf("response %d: want error %v, got %v", i, code, resps[i])
		}
	}
	if resps[2]["id"] != "abc" {
		t.Errorf("string ids must be echoed: %v", resps[2]["id"])
	}
}

func TestVersionNegotiation(t *testing.T) {
	for requested, want := range map[string]string{
		"2024-11-05": "2024-11-05",
		"2025-03-26": "2025-03-26",
		"2099-01-01": supportedVersions[0],
	} {
		resps := session(t, NewServer(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+requested+`","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
		res := resps[0]["result"].(map[string]any)
		if res["protocolVersion"] != want {
			t.Errorf("requested %s: got %v, want %s", requested, res["protocolVersion"], want)
		}
	}
}

func TestToolsAreAnnotatedReadOnly(t *testing.T) {
	for _, tool := range NewServer().getTools() {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Title == "" {
			t.Errorf("tool %s: missing title or read-only annotation", tool.Name)
		}
	}
}

func writePNG(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewGray(image.Rect(0, 0, 2, 2)))
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func callTool(t *testing.T, s *Server, name string, args map[string]any) (text string, isError bool) {
	t.Helper()
	resp := s.handleToolCall(Request{JSONRPC: "2.0", Method: "tools/call", ID: 1, Params: map[string]any{"name": name, "arguments": args}})
	if resp.Error != nil {
		t.Fatalf("%s: protocol error %+v", name, resp.Error)
	}
	res := resp.Result.(map[string]interface{})
	content := res["content"].([]map[string]interface{})
	return content[0]["text"].(string), res["isError"] == true
}

func TestScanTool(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "x.png")
	writePNG(t, img)
	pngBytes, _ := os.ReadFile(img)
	blob := append(append(make([]byte, 100), pngBytes...), make([]byte, 100)...)
	blobPath := filepath.Join(dir, "blob.bin")
	_ = os.WriteFile(blobPath, blob, 0o644)

	text, isErr := callTool(t, NewServer(), "scan", map[string]any{"path": blobPath})
	if isErr || !strings.Contains(text, `"format": "png"`) || !strings.Contains(text, `"offset": 100`) {
		t.Errorf("scan result: %s", text)
	}
	if _, isErr := callTool(t, NewServer(), "scan", map[string]any{"path": blobPath, "formats": []any{"nope"}}); !isErr {
		t.Error("unknown format should be a tool error")
	}
}

func TestRootConfinement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "evidence")
	secret := filepath.Join(base, "evidence-private")
	_ = os.MkdirAll(root, 0o755)
	_ = os.MkdirAll(secret, 0o755)
	writePNG(t, filepath.Join(root, "ok.png"))
	writePNG(t, filepath.Join(secret, "no.png"))

	s, err := NewServerWithRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if text, isErr := callTool(t, s, "analyze", map[string]any{"path": "ok.png"}); isErr {
		t.Errorf("relative path inside root: %s", text)
	}
	for _, tool := range []string{"analyze", "hash", "strings", "scan", "sqlite"} {
		text, isErr := callTool(t, s, tool, map[string]any{"path": filepath.Join(secret, "no.png")})
		if !isErr || !strings.Contains(text, "access denied") {
			t.Errorf("%s outside root: isError=%v %s", tool, isErr, text)
		}
	}
	if text, isErr := callTool(t, s, "batch", map[string]any{"directory": secret}); !isErr {
		t.Errorf("batch outside root allowed: %s", text)
	}
}
