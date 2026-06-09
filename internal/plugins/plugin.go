// Package plugins provides an extensible plugin system for filo-go.
//
// Plugins can:
// - Register custom analyzers
// - Add new file format detection
// - Extend CLI with new commands
// - Hook into analysis pipeline
//
// Example plugin:
//
//	package main
//
//	import "github.com/supunhg/filo-go/internal/plugins"
//
//	func init() {
//	    plugins.Register(&plugins.Plugin{
//	        Name:        "my-analyzer",
//	        Version:     "1.0.0",
//	        Description: "Custom file analyzer",
//	        Analyzer:    myAnalyze,
//	    })
//	}
//
//	func myAnalyze(ctx *plugins.Context) (*plugins.Result, error) {
//	    // Your analysis logic
//	    return &plugins.Result{
//	        Format: "custom",
//	        Details: map[string]interface{}{},
//	    }, nil
//	}
package plugins

import (
	"fmt"
	"plugin"
	"sync"
)

// Plugin represents a filo-go plugin.
type Plugin struct {
	// Metadata
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      string `json:"author,omitempty"`
	URL         string `json:"url,omitempty"`

	// Hooks
	Analyzer    AnalyzerFunc    `json:"-"`
	Formatter   FormatterFunc   `json:"-"`
	Validator   ValidatorFunc   `json:"-"`
	Transformer TransformerFunc `json:"-"`
}

// Context provides analysis context to plugins.
type Context struct {
	// File info
	Path     string
	Data     []byte
	FileInfo FileInfo

	// Analysis state
	Options map[string]interface{}
	Logger  Logger
}

// FileInfo contains basic file information.
type FileInfo struct {
	Name    string
	Size    int64
	Mode    uint32
	ModTime int64
}

// Result is what plugins return.
type Result struct {
	Format     string                 `json:"format"`
	Confidence float64                `json:"confidence"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Warnings   []string               `json:"warnings,omitempty"`
	Artifacts  []Artifact             `json:"artifacts,omitempty"`
}

// Artifact is a file extracted or created during analysis.
type Artifact struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // "extracted", "generated", "flagged"
	Path    string `json:"path,omitempty"`
	Content []byte `json:"content,omitempty"`
	Size    int64  `json:"size"`
}

// AnalyzerFunc is the signature for analysis functions.
type AnalyzerFunc func(ctx *Context) (*Result, error)

// FormatterFunc is the signature for output formatters.
type FormatterFunc func(result *Result, format string) ([]byte, error)

// ValidatorFunc validates plugin compatibility.
type ValidatorFunc func() error

// TransformerFunc transforms data before/after analysis.
type TransformerFunc func(data []byte) ([]byte, error)

// Logger is the plugin logging interface.
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Registry holds all registered plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*Plugin
	order   []string
}

// global is the global plugin registry.
var global = &Registry{
	plugins: make(map[string]*Plugin),
}

// Register adds a plugin to the global registry.
func Register(p *Plugin) error {
	global.mu.Lock()
	defer global.mu.Unlock()

	if p.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if _, exists := global.plugins[p.Name]; exists {
		return fmt.Errorf("plugin %q already registered", p.Name)
	}

	if err := p.Validate(); err != nil {
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	global.plugins[p.Name] = p
	global.order = append(global.order, p.Name)
	return nil
}

// Get returns a plugin by name.
func Get(name string) (*Plugin, bool) {
	global.mu.RLock()
	defer global.mu.RUnlock()
	p, ok := global.plugins[name]
	return p, ok
}

// List returns all registered plugin names.
func List() []string {
	global.mu.RLock()
	defer global.mu.RUnlock()
	result := make([]string, len(global.order))
	copy(result, global.order)
	return result
}

// All returns all registered plugins.
func All() []*Plugin {
	global.mu.RLock()
	defer global.mu.RUnlock()
	result := make([]*Plugin, 0, len(global.order))
	for _, name := range global.order {
		result = append(result, global.plugins[name])
	}
	return result
}

// GetAnalyzers returns all plugins with analyzers.
func GetAnalyzers() []*Plugin {
	global.mu.RLock()
	defer global.mu.RUnlock()
	var result []*Plugin
	for _, name := range global.order {
		p := global.plugins[name]
		if p.Analyzer != nil {
			result = append(result, p)
		}
	}
	return result
}

// RunAnalyzers runs all registered analyzers on the context.
func RunAnalyzers(ctx *Context) []*Result {
	analyzers := GetAnalyzers()
	var results []*Result

	for _, p := range analyzers {
		result, err := p.Analyzer(ctx)
		if err != nil {
			ctx.Logger.Error("plugin %s failed: %v", p.Name, err)
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results
}

// Load dynamically loads a plugin from a .so file.
func Load(path string) (*Plugin, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin: %w", err)
	}

	sym, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("plugin does not export 'Plugin' symbol")
	}

	pluginPtr, ok := sym.(*Plugin)
	if !ok {
		return nil, fmt.Errorf("Plugin symbol is not *Plugin")
	}

	if err := Register(pluginPtr); err != nil {
		return nil, err
	}

	return pluginPtr, nil
}

// Validate checks plugin compatibility.
func (p *Plugin) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Version == "" {
		return fmt.Errorf("version is required")
	}
	if p.Analyzer == nil && p.Formatter == nil && p.Transformer == nil {
		return fmt.Errorf("plugin must implement at least one hook")
	}
	return nil
}

// Reset clears the global registry (for testing).
func Reset() {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.plugins = make(map[string]*Plugin)
	global.order = nil
}
