package plugins

import (
	"fmt"
	"testing"
)

// mockLogger is a test logger.
type mockLogger struct {
	infoLogs  []string
	warnLogs  []string
	errorLogs []string
	debugLogs []string
}

func (l *mockLogger) Info(msg string, args ...interface{})  { l.infoLogs = append(l.infoLogs, msg) }
func (l *mockLogger) Warn(msg string, args ...interface{})  { l.warnLogs = append(l.warnLogs, msg) }
func (l *mockLogger) Error(msg string, args ...interface{}) { l.errorLogs = append(l.errorLogs, msg) }
func (l *mockLogger) Debug(msg string, args ...interface{}) { l.debugLogs = append(l.debugLogs, msg) }

// testPlugin is a simple test plugin.
func testPlugin() *Plugin {
	return &Plugin{
		Name:        "test-plugin",
		Version:     "1.0.0",
		Description: "Test plugin",
		Analyzer: func(ctx *Context) (*Result, error) {
			return &Result{
				Format:     "test",
				Confidence: 0.9,
				Details: map[string]interface{}{
					"test": true,
				},
			}, nil
		},
	}
}

func TestRegisterPlugin(t *testing.T) {
	Reset()

	p := testPlugin()
	if err := Register(p); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	if len(List()) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(List()))
	}
}

func TestRegisterDuplicate(t *testing.T) {
	Reset()

	p := testPlugin()
	if err := Register(p); err != nil {
		t.Fatalf("failed to register plugin: %v", err)
	}

	if err := Register(p); err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestRegisterEmptyName(t *testing.T) {
	Reset()

	p := &Plugin{
		Version: "1.0.0",
		Analyzer: func(ctx *Context) (*Result, error) {
			return nil, nil
		},
	}

	if err := Register(p); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestRegisterEmptyVersion(t *testing.T) {
	Reset()

	p := &Plugin{
		Name: "test",
		Analyzer: func(ctx *Context) (*Result, error) {
			return nil, nil
		},
	}

	if err := Register(p); err == nil {
		t.Error("expected error for empty version")
	}
}

func TestRegisterNoHooks(t *testing.T) {
	Reset()

	p := &Plugin{
		Name:    "test",
		Version: "1.0.0",
	}

	if err := Register(p); err == nil {
		t.Error("expected error for plugin with no hooks")
	}
}

func TestGetPlugin(t *testing.T) {
	Reset()

	p := testPlugin()
	Register(p)

	got, ok := Get("test-plugin")
	if !ok {
		t.Fatal("plugin not found")
	}

	if got.Name != "test-plugin" {
		t.Errorf("expected name test-plugin, got %s", got.Name)
	}
}

func TestGetPluginNotFound(t *testing.T) {
	Reset()

	_, ok := Get("nonexistent")
	if ok {
		t.Error("expected plugin not found")
	}
}

func TestListPlugins(t *testing.T) {
	Reset()

	Register(&Plugin{
		Name:    "plugin-a",
		Version: "1.0.0",
		Analyzer: func(ctx *Context) (*Result, error) {
			return nil, nil
		},
	})
	Register(&Plugin{
		Name:    "plugin-b",
		Version: "1.0.0",
		Analyzer: func(ctx *Context) (*Result, error) {
			return nil, nil
		},
	})

	names := List()
	if len(names) != 2 {
		t.Errorf("expected 2 plugins, got %d", len(names))
	}
}

func TestAllPlugins(t *testing.T) {
	Reset()

	Register(testPlugin())

	all := All()
	if len(all) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(all))
	}
}

func TestGetAnalyzers(t *testing.T) {
	Reset()

	// Plugin with analyzer
	Register(testPlugin())

	// Plugin without analyzer
	Register(&Plugin{
		Name:    "formatter-only",
		Version: "1.0.0",
		Formatter: func(result *Result, format string) ([]byte, error) {
			return nil, nil
		},
	})

	analyzers := GetAnalyzers()
	if len(analyzers) != 1 {
		t.Errorf("expected 1 analyzer, got %d", len(analyzers))
	}
}

func TestRunAnalyzers(t *testing.T) {
	Reset()

	Register(testPlugin())

	logger := &mockLogger{}
	ctx := &Context{
		Path:     "/test/file.bin",
		Data:     []byte("test data"),
		FileInfo: FileInfo{Name: "file.bin", Size: 9},
		Options:  map[string]interface{}{},
		Logger:   logger,
	}

	results := RunAnalyzers(ctx)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Format != "test" {
		t.Errorf("expected format test, got %s", results[0].Format)
	}

	if results[0].Confidence != 0.9 {
		t.Errorf("expected confidence 0.9, got %f", results[0].Confidence)
	}
}

func TestRunAnalyzersError(t *testing.T) {
	Reset()

	// Plugin that fails
	Register(&Plugin{
		Name:    "failing-plugin",
		Version: "1.0.0",
		Analyzer: func(ctx *Context) (*Result, error) {
			return nil, fmt.Errorf("analysis failed")
		},
	})

	// Plugin that succeeds
	Register(testPlugin())

	logger := &mockLogger{}
	ctx := &Context{
		Path:     "/test/file.bin",
		Data:     []byte("test"),
		FileInfo: FileInfo{Name: "file.bin", Size: 4},
		Options:  map[string]interface{}{},
		Logger:   logger,
	}

	results := RunAnalyzers(ctx)
	if len(results) != 1 {
		t.Fatalf("expected 1 result (error logged), got %d", len(results))
	}

	if len(logger.errorLogs) != 1 {
		t.Errorf("expected 1 error log, got %d", len(logger.errorLogs))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		plugin  *Plugin
		wantErr bool
	}{
		{
			name: "valid",
			plugin: &Plugin{
				Name:    "test",
				Version: "1.0.0",
				Analyzer: func(ctx *Context) (*Result, error) {
					return nil, nil
				},
			},
			wantErr: false,
		},
		{
			name: "empty name",
			plugin: &Plugin{
				Version: "1.0.0",
				Analyzer: func(ctx *Context) (*Result, error) {
					return nil, nil
				},
			},
			wantErr: true,
		},
		{
			name: "empty version",
			plugin: &Plugin{
				Name: "test",
				Analyzer: func(ctx *Context) (*Result, error) {
					return nil, nil
				},
			},
			wantErr: true,
		},
		{
			name: "no hooks",
			plugin: &Plugin{
				Name:    "test",
				Version: "1.0.0",
			},
			wantErr: true,
		},
		{
			name: "formatter only",
			plugin: &Plugin{
				Name:    "test",
				Version: "1.0.0",
				Formatter: func(result *Result, format string) ([]byte, error) {
					return nil, nil
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plugin.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReset(t *testing.T) {
	Reset() // Start clean
	Register(testPlugin())
	if len(List()) != 1 {
		t.Fatal("expected 1 plugin before reset")
	}

	Reset()
	if len(List()) != 0 {
		t.Error("expected 0 plugins after reset")
	}
}

func TestPluginMetadata(t *testing.T) {
	p := &Plugin{
		Name:        "my-plugin",
		Version:     "2.0.0",
		Description: "My awesome plugin",
		Author:      "John Doe",
		URL:         "https://example.com",
		Analyzer: func(ctx *Context) (*Result, error) {
			return nil, nil
		},
	}

	if p.Name != "my-plugin" {
		t.Errorf("expected name my-plugin, got %s", p.Name)
	}
	if p.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", p.Version)
	}
	if p.Description != "My awesome plugin" {
		t.Errorf("expected description, got %s", p.Description)
	}
	if p.Author != "John Doe" {
		t.Errorf("expected author John Doe, got %s", p.Author)
	}
	if p.URL != "https://example.com" {
		t.Errorf("expected URL, got %s", p.URL)
	}
}

func TestResultJSON(t *testing.T) {
	r := &Result{
		Format:     "test",
		Confidence: 0.9,
		Details: map[string]interface{}{
			"key": "value",
		},
		Warnings: []string{"warning1"},
		Artifacts: []Artifact{
			{
				Name: "extracted.bin",
				Type: "extracted",
				Size: 1024,
			},
		},
	}

	if r.Format != "test" {
		t.Errorf("expected format test, got %s", r.Format)
	}
	if len(r.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(r.Warnings))
	}
	if len(r.Artifacts) != 1 {
		t.Errorf("expected 1 artifact, got %d", len(r.Artifacts))
	}
}

func TestArtifactJSON(t *testing.T) {
	a := Artifact{
		Name: "flag.txt",
		Type: "flagged",
		Path: "/tmp/flag.txt",
		Size: 32,
	}

	if a.Name != "flag.txt" {
		t.Errorf("expected name flag.txt, got %s", a.Name)
	}
	if a.Type != "flagged" {
		t.Errorf("expected type flagged, got %s", a.Type)
	}
}

func TestContextJSON(t *testing.T) {
	ctx := &Context{
		Path: "/test/file.bin",
		Data: []byte("test"),
		FileInfo: FileInfo{
			Name: "file.bin",
			Size: 4,
		},
		Options: map[string]interface{}{
			"verbose": true,
		},
	}

	if ctx.Path != "/test/file.bin" {
		t.Errorf("expected path, got %s", ctx.Path)
	}
	if ctx.FileInfo.Size != 4 {
		t.Errorf("expected size 4, got %d", ctx.FileInfo.Size)
	}
}
