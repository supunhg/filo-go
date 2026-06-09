package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}

	if cfg.Output.Format != "text" {
		t.Errorf("Expected default format 'text', got %s", cfg.Output.Format)
	}

	if cfg.Analysis.MaxDepth != 10 {
		t.Errorf("Expected default max depth 10, got %d", cfg.Analysis.MaxDepth)
	}

	if cfg.MCP.Port != 3000 {
		t.Errorf("Expected default MCP port 3000, got %d", cfg.MCP.Port)
	}
}

func TestDefaultColors(t *testing.T) {
	cfg := Default()
	if cfg.Output.Colors == nil {
		t.Fatal("Expected colors to be set")
	}

	if !*cfg.Output.Colors {
		t.Error("Expected colors to be enabled by default")
	}
}

func TestValidate(t *testing.T) {
	cfg := Default()

	// Test valid config
	if err := cfg.Validate(); err != nil {
		t.Errorf("Expected valid config, got error: %v", err)
	}

	// Test invalid output format
	cfg.Output.Format = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid output format")
	}

	// Test invalid export format
	cfg = Default()
	cfg.Export.DefaultFormat = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid export format")
	}

	// Test negative max depth
	cfg = Default()
	cfg.Analysis.MaxDepth = -1
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for negative max depth")
	}

	// Test invalid MCP port
	cfg = Default()
	cfg.MCP.Port = 99999
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid MCP port")
	}
}

func TestString(t *testing.T) {
	cfg := Default()
	str := cfg.String()

	if str == "" {
		t.Error("Expected non-empty string")
	}

	if !contains(str, "filo config:") {
		t.Error("Expected string to contain 'filo config:'")
	}
}

func TestUserConfigDir(t *testing.T) {
	// Test with XDG_CONFIG_HOME set
	original := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", original)

	os.Setenv("XDG_CONFIG_HOME", "/tmp/test-config")
	dir := UserConfigDir()
	if dir != "/tmp/test-config/filo" {
		t.Errorf("Expected /tmp/test-config/filo, got %s", dir)
	}

	// Test without XDG_CONFIG_HOME
	os.Unsetenv("XDG_CONFIG_HOME")
	dir = UserConfigDir()
	if dir == "" {
		t.Error("Expected non-empty config dir")
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	cfg := Default()

	// Set environment variables
	originals := map[string]string{
		"FILO_OUTPUT_FORMAT":        os.Getenv("FILO_OUTPUT_FORMAT"),
		"FILO_OUTPUT_QUIET":         os.Getenv("FILO_OUTPUT_QUIET"),
		"FILO_OUTPUT_VERBOSE":       os.Getenv("FILO_OUTPUT_VERBOSE"),
		"FILO_ANALYSIS_DEEP_SCAN":   os.Getenv("FILO_ANALYSIS_DEEP_SCAN"),
		"FILO_ANALYSIS_NO_ML":       os.Getenv("FILO_ANALYSIS_NO_ML"),
		"FILO_LINEAGE_ENABLED":      os.Getenv("FILO_LINEAGE_ENABLED"),
		"FILO_MCP_PORT":             os.Getenv("FILO_MCP_PORT"),
		"FILO_EXPORT_FORMAT":        os.Getenv("FILO_EXPORT_FORMAT"),
		"FILO_DATABASE_FORMATS_DIR": os.Getenv("FILO_DATABASE_FORMATS_DIR"),
	}

	defer func() {
		for k, v := range originals {
			os.Setenv(k, v)
		}
	}()

	// Test each override
	os.Setenv("FILO_OUTPUT_FORMAT", "json")
	os.Setenv("FILO_OUTPUT_QUIET", "true")
	os.Setenv("FILO_OUTPUT_VERBOSE", "1")
	os.Setenv("FILO_ANALYSIS_DEEP_SCAN", "true")
	os.Setenv("FILO_ANALYSIS_NO_ML", "1")
	os.Setenv("FILO_LINEAGE_ENABLED", "true")
	os.Setenv("FILO_MCP_PORT", "8080")
	os.Setenv("FILO_EXPORT_FORMAT", "csv")
	os.Setenv("FILO_DATABASE_FORMATS_DIR", "/custom/path")

	loadEnvOverrides(cfg)

	if cfg.Output.Format != "json" {
		t.Errorf("Expected format 'json', got %s", cfg.Output.Format)
	}

	if !cfg.Output.Quiet {
		t.Error("Expected quiet to be true")
	}

	if !cfg.Output.Verbose {
		t.Error("Expected verbose to be true")
	}

	if !cfg.Analysis.DeepScan {
		t.Error("Expected deep scan to be true")
	}

	if !cfg.Analysis.NoML {
		t.Error("Expected no ML to be true")
	}

	if !cfg.Lineage.Enabled {
		t.Error("Expected lineage to be enabled")
	}

	if cfg.MCP.Port != 8080 {
		t.Errorf("Expected MCP port 8080, got %d", cfg.MCP.Port)
	}

	if cfg.Export.DefaultFormat != "csv" {
		t.Errorf("Expected export format 'csv', got %s", cfg.Export.DefaultFormat)
	}

	if cfg.Database.FormatsDir != "/custom/path" {
		t.Errorf("Expected formats dir '/custom/path', got %s", cfg.Database.FormatsDir)
	}
}

func TestLoadProjectConfig(t *testing.T) {
	// Create temp directory with config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, ".filo.yaml")

	configContent := `
output:
  format: json
  verbose: true
analysis:
  max_depth: 20
  deep_scan: true
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to temp directory
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	cfg := Default()
	if err := loadProjectConfig(cfg); err != nil {
		t.Fatalf("Failed to load project config: %v", err)
	}

	if cfg.Output.Format != "json" {
		t.Errorf("Expected format 'json', got %s", cfg.Output.Format)
	}

	if !cfg.Output.Verbose {
		t.Error("Expected verbose to be true")
	}

	if cfg.Analysis.MaxDepth != 20 {
		t.Errorf("Expected max depth 20, got %d", cfg.Analysis.MaxDepth)
	}

	if !cfg.Analysis.DeepScan {
		t.Error("Expected deep scan to be true")
	}
}

func TestLoadProjectConfigMissing(t *testing.T) {
	// Create temp directory without config file
	tmpDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	cfg := Default()
	if err := loadProjectConfig(cfg); err != nil {
		t.Fatalf("Failed to load project config: %v", err)
	}

	// Config should remain unchanged
	if cfg.Output.Format != "text" {
		t.Errorf("Expected format 'text', got %s", cfg.Output.Format)
	}
}

func TestLoadUserConfigMissing(t *testing.T) {
	// Set XDG_CONFIG_HOME to a non-existent directory
	original := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", original)
	os.Setenv("XDG_CONFIG_HOME", "/nonexistent/path")

	cfg := Default()
	if err := loadUserConfig(cfg); err != nil {
		t.Fatalf("Failed to load user config: %v", err)
	}

	// Config should remain unchanged
	if cfg.Output.Format != "text" {
		t.Errorf("Expected format 'text', got %s", cfg.Output.Format)
	}
}

func TestLoadFullConfig(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}

	// Should have valid defaults
	if err := cfg.Validate(); err != nil {
		t.Errorf("Config validation failed: %v", err)
	}
}

func TestConfigSerialization(t *testing.T) {
	cfg := Default()

	// Test String method
	str := cfg.String()
	if str == "" {
		t.Error("Expected non-empty string")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"", "", true},
		{"hello", "", true},
	}

	for _, tt := range tests {
		got := contains(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
