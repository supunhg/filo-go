package formats

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FormatSpec represents a single file format definition.
type FormatSpec struct {
	Format           string              `yaml:"format"`
	Version          string              `yaml:"version"`
	MIME             []string            `yaml:"mime"`
	Category         string              `yaml:"category"`
	ConfidenceWeight float64             `yaml:"confidence_weight"`
	Extensions       []string            `yaml:"extensions"`
	Description      string              `yaml:"description"`
	References       []string            `yaml:"references"`
	Signatures       []Signature         `yaml:"signatures"`
	Footers          []Footer            `yaml:"footers"`
	Structure        *Structure          `yaml:"structure,omitempty"`
	Templates        map[string]Template `yaml:"templates,omitempty"`
	RepairStrategies []RepairStrategy    `yaml:"repair_strategies,omitempty"`
	Validation       []Validation        `yaml:"validation,omitempty"`
}

// Signature represents a magic byte signature.
type Signature struct {
	Offset      int     `yaml:"offset"`
	OffsetMax   int     `yaml:"offset_max,omitempty"`
	Hex         string  `yaml:"hex"`
	Description string  `yaml:"description"`
	Weight      float64 `yaml:"weight"`
}

// Footer represents a file footer signature.
type Footer struct {
	Hex         string `yaml:"hex"`
	Description string `yaml:"description"`
}

// Structure represents file structure requirements.
type Structure struct {
	Chunks      []Chunk `yaml:"chunks,omitempty"`
	HeaderSize  int     `yaml:"header_size,omitempty"`
	Endianness   string  `yaml:"endianness,omitempty"`
}

// Chunk represents a required file chunk.
type Chunk struct {
	ID          string `yaml:"id"`
	Required    bool   `yaml:"required"`
	MinCount    int    `yaml:"min_count,omitempty"`
	Position    int    `yaml:"position,omitempty"`
	Description string `yaml:"description"`
}

// Template represents a repair template.
type Template struct {
	Hex       string            `yaml:"hex"`
	Variables map[string]string `yaml:"variables,omitempty"`
}

// RepairStrategy represents a repair strategy.
type RepairStrategy struct {
	Name        string `yaml:"name"`
	Priority    int    `yaml:"priority"`
	Description string `yaml:"description"`
}

// Validation represents a validation command.
type Validation struct {
	Command      []string `yaml:"command"`
	SuccessCodes []int    `yaml:"success_codes"`
	Description  string   `yaml:"description"`
}

// Database holds all loaded format definitions.
type Database struct {
	formats map[string]*FormatSpec
	dir     string
}

// NewDatabase loads format definitions from a directory.
func NewDatabase(dir string) (*Database, error) {
	db := &Database{
		formats: make(map[string]*FormatSpec),
		dir:     dir,
	}

	if err := db.LoadAll(); err != nil {
		return nil, err
	}

	return db, nil
}

// LoadAll loads all YAML format definitions from the directory.
func (db *Database) LoadAll() error {
	entries, err := os.ReadDir(db.dir)
	if err != nil {
		return fmt.Errorf("failed to read formats directory %s: %w", db.dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		path := filepath.Join(db.dir, entry.Name())
		if err := db.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load %s: %w", path, err)
		}
	}

	return nil
}

// LoadFile loads a single YAML format definition.
func (db *Database) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var spec FormatSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return err
	}

	if spec.Format == "" {
		return fmt.Errorf("format definition missing 'format' field in %s", path)
	}

	if spec.ConfidenceWeight == 0 {
		spec.ConfidenceWeight = 0.8
	}

	db.formats[spec.Format] = &spec
	return nil
}

// Get returns a format spec by name.
func (db *Database) Get(name string) (*FormatSpec, bool) {
	spec, ok := db.formats[name]
	return spec, ok
}

// List returns all format names.
func (db *Database) List() []string {
	names := make([]string, 0, len(db.formats))
	for name := range db.formats {
		names = append(names, name)
	}
	return names
}

// ByCategory returns formats filtered by category.
func (db *Database) ByCategory(category string) []*FormatSpec {
	var result []*FormatSpec
	for _, spec := range db.formats {
		if spec.Category == category {
			result = append(result, spec)
		}
	}
	return result
}

// ByExtension returns formats that match a file extension.
func (db *Database) ByExtension(ext string) []*FormatSpec {
	ext = strings.TrimPrefix(ext, ".")
	var result []*FormatSpec
	for _, spec := range db.formats {
		for _, e := range spec.Extensions {
			if e == ext {
				result = append(result, spec)
				break
			}
		}
	}
	return result
}

// Match attempts to match file data against all format signatures.
func (db *Database) Match(data []byte) []*MatchResult {
	var results []*MatchResult

	for _, spec := range db.formats {
		result := matchFormat(data, spec)
		if result != nil && result.Confidence > 0 {
			results = append(results, result)
		}
	}

	// Sort by confidence (descending)
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Confidence > results[i].Confidence {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	return results
}

// MatchResult holds the result of matching against a format.
type MatchResult struct {
	Format      *FormatSpec
	Confidence  float64
	MatchedSigs []string
}

func matchFormat(data []byte, spec *FormatSpec) *MatchResult {
	if len(spec.Signatures) == 0 {
		return nil
	}

	totalWeight := 0.0
	matchedWeight := 0.0
	var matchedSigs []string

	for _, sig := range spec.Signatures {
		totalWeight += sig.Weight

		offset := sig.Offset
		offsetMax := sig.OffsetMax
		if offsetMax == 0 {
			offsetMax = offset + len(sig.Hex)/2
		}

		hexBytes, err := hexToBytes(sig.Hex)
		if err != nil {
			continue
		}

		// Check if signature matches at any offset in range
		for off := offset; off <= offsetMax && off+len(hexBytes) <= len(data); off++ {
			match := true
			for i, b := range hexBytes {
				if data[off+i] != b {
					match = false
					break
				}
			}
			if match {
				matchedWeight += sig.Weight
				matchedSigs = append(matchedSigs, sig.Description)
				break
			}
		}
	}

	if totalWeight == 0 || matchedWeight == 0 {
		return nil
	}

	confidence := (matchedWeight / totalWeight) * spec.ConfidenceWeight

	// Apply minimum threshold
	if confidence < 0.25 {
		return nil
	}

	return &MatchResult{
		Format:      spec,
		Confidence:  confidence,
		MatchedSigs: matchedSigs,
	}
}

func hexToBytes(hexStr string) ([]byte, error) {
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length: %d", len(hexStr))
	}

	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := hexStr[i+j]
			switch {
			case c >= '0' && c <= '9':
				b = b*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				b = b*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				b = b*16 + (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i/2] = b
	}
	return result, nil
}
