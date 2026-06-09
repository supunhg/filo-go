package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("Expected non-nil server")
	}
}

func TestHandleRequest_Initialize(t *testing.T) {
	server := NewServer()
	server.reader = &bytes.Buffer{}
	server.writer = &bytes.Buffer{}

	req := Request{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      1,
	}

	resp := server.handleRequest(req)
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected result to be a map")
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("Expected protocol version 2024-11-05, got %v", result["protocolVersion"])
	}
}

func TestHandleRequest_ToolsList(t *testing.T) {
	server := NewServer()

	req := Request{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      1,
	}

	resp := server.handleRequest(req)
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected result to be a map")
	}

	tools, ok := result["tools"].([]Tool)
	if !ok {
		t.Fatal("Expected tools to be a slice of Tool")
	}

	if len(tools) != 9 {
		t.Errorf("Expected 9 tools, got %d", len(tools))
	}

	// Check that all expected tools exist
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	expectedTools := []string{"analyze", "hash", "strings", "crypto", "stego", "metadata", "container", "sqlite", "batch"}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Expected tool %s not found", name)
		}
	}
}

func TestHandleRequest_MethodNotFound(t *testing.T) {
	server := NewServer()

	req := Request{
		JSONRPC: "2.0",
		Method:  "nonexistent",
		ID:      1,
	}

	resp := server.handleRequest(req)
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	if resp.Error == nil {
		t.Error("Expected error for unknown method")
	}

	if resp.Error.Code != -32601 {
		t.Errorf("Expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestHandleToolCall_InvalidParams(t *testing.T) {
	server := NewServer()

	req := Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  "invalid",
		ID:      1,
	}

	resp := server.handleToolCall(req)
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	if resp.Error == nil {
		t.Error("Expected error for invalid params")
	}
}

func TestHandleToolCall_ToolNotFound(t *testing.T) {
	server := NewServer()

	req := Request{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "nonexistent",
			"arguments": map[string]interface{}{},
		},
		ID:      1,
	}

	resp := server.handleToolCall(req)
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	if resp.Error == nil {
		t.Error("Expected error for unknown tool")
	}
}

func TestGetTools(t *testing.T) {
	server := NewServer()
	tools := server.getTools()

	if len(tools) != 9 {
		t.Errorf("Expected 9 tools, got %d", len(tools))
	}

	// Check tool properties
	for _, tool := range tools {
		if tool.Name == "" {
			t.Error("Tool has empty name")
		}
		if tool.Description == "" {
			t.Errorf("Tool %s has empty description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("Tool %s has nil input schema", tool.Name)
		}
	}
}

func TestFormatResult(t *testing.T) {
	data := map[string]interface{}{
		"key": "value",
		"num": 42,
	}

	result := formatResult(data)
	if result == "" {
		t.Error("Expected non-empty result")
	}

	// Verify it's valid JSON
	var parsed interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{"nil", nil, nil},
		{"string slice", []interface{}{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"mixed", []interface{}{"a", 1, "b"}, []string{"a", "b"}},
		{"not slice", "invalid", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toStringSlice(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("toStringSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToInt(t *testing.T) {
	tests := []struct {
		name       string
		input      interface{}
		defaultVal int
		want       int
	}{
		{"nil", nil, 10, 10},
		{"float64", float64(42), 10, 42},
		{"int", 42, 10, 42},
		{"string", "42", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toInt(tt.input, tt.defaultVal)
			if got != tt.want {
				t.Errorf("toInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequestJSON(t *testing.T) {
	req := Request{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      1,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	var parsed Request
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal request: %v", err)
	}

	if parsed.Method != "initialize" {
		t.Errorf("Expected method 'initialize', got %s", parsed.Method)
	}
}

func TestResponseJSON(t *testing.T) {
	resp := Response{
		JSONRPC: "2.0",
		Result:  map[string]interface{}{"key": "value"},
		ID:      1,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var parsed Response
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if parsed.Error != nil {
		t.Errorf("Expected no error, got %v", parsed.Error)
	}
}

func TestErrorResponseJSON(t *testing.T) {
	resp := Response{
		JSONRPC: "2.0",
		Error: &Error{
			Code:    -32600,
			Message: "Invalid Request",
		},
		ID: 1,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal error response: %v", err)
	}

	var parsed Response
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}

	if parsed.Error == nil {
		t.Error("Expected error in response")
	}

	if parsed.Error.Code != -32600 {
		t.Errorf("Expected error code -32600, got %d", parsed.Error.Code)
	}
}

func TestToolSchema(t *testing.T) {
	server := NewServer()
	tools := server.getTools()

	for _, tool := range tools {
		schema, ok := tool.InputSchema.(map[string]interface{})
		if !ok {
			t.Errorf("Tool %s has invalid schema type", tool.Name)
			continue
		}

		if _, ok := schema["type"]; !ok {
			t.Errorf("Tool %s schema missing 'type'", tool.Name)
		}

		if _, ok := schema["properties"]; !ok {
			t.Errorf("Tool %s schema missing 'properties'", tool.Name)
		}
	}
}
