package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the filo tool.
type Config struct {
	// General
	Output   OutputConfig   `yaml:"output"`
	Analysis AnalysisConfig `yaml:"analysis"`
	Lineage  LineageConfig  `yaml:"lineage"`
	MCP      MCPConfig      `yaml:"mcp"`
	Export   ExportConfig   `yaml:"export"`
	Database DatabaseConfig `yaml:"database"`
}

// OutputConfig controls how results are displayed.
type OutputConfig struct {
	Format  string `yaml:"format"`  // json, text, csv, sarif
	Colors  *bool  `yaml:"colors"`  // enable/disable colors
	Verbose bool   `yaml:"verbose"` // verbose output
	Quiet   bool   `yaml:"quiet"`   // minimal output
}

// AnalysisConfig controls analysis behavior.
type AnalysisConfig struct {
	DeepScan   bool     `yaml:"deep_scan"`   // enable deep analysis by default
	NoML       bool     `yaml:"no_ml"`       // disable ML detection
	MaxDepth   int      `yaml:"max_depth"`   // max recursion depth for archives
	MaxSize    int64    `yaml:"max_size"`    // max file size in bytes (0 = unlimited)
	YaraRules  []string `yaml:"yara_rules"`  // default YARA rule files
	EntropyViz bool     `yaml:"entropy_viz"` // show entropy visualization
}

// LineageConfig controls chain-of-custody tracking.
type LineageConfig struct {
	Enabled bool   `yaml:"enabled"` // enable lineage tracking
	DBPath  string `yaml:"db_path"` // BoltDB path
}

// MCPConfig controls the MCP server.
type MCPConfig struct {
	Host string `yaml:"host"` // MCP server host
	Port int    `yaml:"port"` // MCP server port
}

// ExportConfig controls export behavior.
type ExportConfig struct {
	DefaultFormat string `yaml:"default_format"` // default export format
	OutputDir     string `yaml:"output_dir"`     // default output directory
}

// DatabaseConfig controls database paths.
type DatabaseConfig struct {
	FormatsDir string `yaml:"formats_dir"` // custom formats directory
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	colors := true
	return &Config{
		Output: OutputConfig{
			Format:  "text",
			Colors:  &colors,
			Verbose: false,
			Quiet:   false,
		},
		Analysis: AnalysisConfig{
			DeepScan:   false,
			NoML:       false,
			MaxDepth:   10,
			MaxSize:    0,
			YaraRules:  nil,
			EntropyViz: false,
		},
		Lineage: LineageConfig{
			Enabled: false,
			DBPath:  "",
		},
		MCP: MCPConfig{
			Host: "127.0.0.1",
			Port: 3000,
		},
		Export: ExportConfig{
			DefaultFormat: "json",
			OutputDir:     "",
		},
		Database: DatabaseConfig{
			FormatsDir: "",
		},
	}
}

// Load reads configuration from multiple sources with the following precedence:
// 1. Environment variables (highest)
// 2. Project-local .filo.yaml
// 3. User config (~/.config/filo/config.yaml)
// 4. Built-in defaults (lowest)
func Load() (*Config, error) {
	cfg := Default()

	// Layer 1: User config (XDG)
	if err := loadUserConfig(cfg); err != nil {
		return nil, fmt.Errorf("loading user config: %w", err)
	}

	// Layer 2: Project-local config
	if err := loadProjectConfig(cfg); err != nil {
		return nil, fmt.Errorf("loading project config: %w", err)
	}

	// Layer 3: Environment variables
	loadEnvOverrides(cfg)

	return cfg, nil
}

// UserConfigDir returns the XDG-compliant config directory for filo.
func UserConfigDir() string {
	// XDG_CONFIG_HOME
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "filo")
	}

	// Fallback to ~/.config/filo
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "filo")
	}

	return ""
}

// loadUserConfig loads ~/.config/filo/config.yaml
func loadUserConfig(cfg *Config) error {
	dir := UserConfigDir()
	if dir == "" {
		return nil
	}

	path := filepath.Join(dir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no user config is fine
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}

	return yaml.Unmarshal(data, cfg)
}

// loadProjectConfig loads .filo.yaml from the current working directory.
func loadProjectConfig(cfg *Config) error {
	path := ".filo.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}

	return yaml.Unmarshal(data, cfg)
}

// loadEnvOverrides applies environment variable overrides.
// Format: FILO_OUTPUT_FORMAT=json, FILO_ANALYSIS_DEEP_SCAN=true, etc.
func loadEnvOverrides(cfg *Config) {
	if v := os.Getenv("FILO_OUTPUT_FORMAT"); v != "" {
		cfg.Output.Format = v
	}
	if v := os.Getenv("FILO_OUTPUT_QUIET"); v == "true" || v == "1" {
		cfg.Output.Quiet = true
	}
	if v := os.Getenv("FILO_OUTPUT_VERBOSE"); v == "true" || v == "1" {
		cfg.Output.Verbose = true
	}
	if v := os.Getenv("FILO_ANALYSIS_DEEP_SCAN"); v == "true" || v == "1" {
		cfg.Analysis.DeepScan = true
	}
	if v := os.Getenv("FILO_ANALYSIS_NO_ML"); v == "true" || v == "1" {
		cfg.Analysis.NoML = true
	}
	if v := os.Getenv("FILO_LINEAGE_ENABLED"); v == "true" || v == "1" {
		cfg.Lineage.Enabled = true
	}
	if v := os.Getenv("FILO_MCP_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil && port > 0 {
			cfg.MCP.Port = port
		}
	}
	if v := os.Getenv("FILO_EXPORT_FORMAT"); v != "" {
		cfg.Export.DefaultFormat = v
	}
	if v := os.Getenv("FILO_DATABASE_FORMATS_DIR"); v != "" {
		cfg.Database.FormatsDir = v
	}
}

// Validate checks the configuration for invalid values.
func (c *Config) Validate() error {
	validFormats := map[string]bool{"json": true, "text": true, "csv": true, "sarif": true}
	if !validFormats[c.Output.Format] {
		return fmt.Errorf("invalid output format %q: must be json, text, csv, or sarif", c.Output.Format)
	}

	validExportFormats := map[string]bool{"json": true, "csv": true, "sarif": true, "markdown": true}
	if !validExportFormats[c.Export.DefaultFormat] {
		return fmt.Errorf("invalid export format %q: must be json, csv, sarif, or markdown", c.Export.DefaultFormat)
	}

	if c.Analysis.MaxDepth < 0 {
		return fmt.Errorf("max_depth must be non-negative, got %d", c.Analysis.MaxDepth)
	}

	if c.MCP.Port < 0 || c.MCP.Port > 65535 {
		return fmt.Errorf("MCP port must be between 0 and 65535, got %d", c.MCP.Port)
	}

	return nil
}

// String returns a human-readable representation of the config.
func (c *Config) String() string {
	var b strings.Builder
	b.WriteString("filo config:\n")
	b.WriteString(fmt.Sprintf("  output.format:    %s\n", c.Output.Format))
	b.WriteString(fmt.Sprintf("  output.verbose:   %v\n", c.Output.Verbose))
	b.WriteString(fmt.Sprintf("  output.quiet:     %v\n", c.Output.Quiet))
	b.WriteString(fmt.Sprintf("  analysis.deep:    %v\n", c.Analysis.DeepScan))
	b.WriteString(fmt.Sprintf("  analysis.no_ml:   %v\n", c.Analysis.NoML))
	b.WriteString(fmt.Sprintf("  analysis.max_depth: %d\n", c.Analysis.MaxDepth))
	b.WriteString(fmt.Sprintf("  lineage.enabled:  %v\n", c.Lineage.Enabled))
	b.WriteString(fmt.Sprintf("  mcp.host:         %s\n", c.MCP.Host))
	b.WriteString(fmt.Sprintf("  mcp.port:         %d\n", c.MCP.Port))
	b.WriteString(fmt.Sprintf("  export.format:    %s\n", c.Export.DefaultFormat))
	return b.String()
}
