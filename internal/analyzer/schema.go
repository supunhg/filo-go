package analyzer

import (
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the current output schema version.
const SchemaVersion = "2.0.0"

// OutputSchema represents the complete analysis output.
type OutputSchema struct {
	Meta      AnalysisMeta     `json:"meta"`
	File      FileInfo         `json:"file"`
	Detection DetectionResult  `json:"detection"`
	Entropy   EntropyResult    `json:"entropy"`
	Content   ContentAnalysis  `json:"content"`
	Security  SecurityAnalysis `json:"security"`
	Artifacts []Artifact       `json:"artifacts,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
}

// AnalysisMeta contains metadata about the analysis.
type AnalysisMeta struct {
	SchemaVersion string    `json:"schema_version"`
	Analyzer      string    `json:"analyzer"`
	Version       string    `json:"version"`
	Timestamp     time.Time `json:"timestamp"`
}

// FileInfo contains basic file information.
type FileInfo struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Extension string    `json:"extension"`
	Size      int64     `json:"size"`
	SizeHuman string    `json:"size_human"`
	ModTime   time.Time `json:"mod_time,omitempty"`
	Hashes    HashInfo  `json:"hashes"`
}

// HashInfo contains file hashes.
type HashInfo struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512,omitempty"`
}

// DetectionResult contains format detection results.
type DetectionResult struct {
	Primary      FormatInfo   `json:"primary"`
	Alternatives []FormatInfo `json:"alternatives,omitempty"`
	Confidence   float64      `json:"confidence"`
	MIME         string       `json:"mime"`
	Category     string       `json:"category"`
}

// FormatInfo represents a detected format.
type FormatInfo struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	MIME       string  `json:"mime"`
	Confidence float64 `json:"confidence"`
}

// EntropyResult contains entropy analysis.
type EntropyResult struct {
	Overall float64 `json:"overall"`
	Label   string  `json:"label"`
}

// ContentAnalysis contains content extraction results.
type ContentAnalysis struct {
	Embedded []EmbeddedFile `json:"embedded,omitempty"`
}

// EmbeddedFile represents an embedded file.
type EmbeddedFile struct {
	Offset     int64   `json:"offset"`
	Size       int64   `json:"size"`
	Format     string  `json:"format"`
	Confidence float64 `json:"confidence"`
}

// SecurityAnalysis contains security-related findings.
type SecurityAnalysis struct {
	RiskScore float64 `json:"risk_score"`
	RiskLevel string  `json:"risk_level"`
}

// Artifact represents an extracted file.
type Artifact struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// ToJSON converts the result to the standardized JSON schema.
func (r *Result) ToJSON() ([]byte, error) {
	schema := r.toOutputSchema()
	return json.MarshalIndent(schema, "", "  ")
}

// ToJSONCompact converts to compact JSON.
func (r *Result) ToJSONCompact() ([]byte, error) {
	schema := r.toOutputSchema()
	return json.Marshal(schema)
}

func (r *Result) toOutputSchema() *OutputSchema {
	schema := &OutputSchema{
		Meta: AnalysisMeta{
			SchemaVersion: SchemaVersion,
			Analyzer:      "filo-go",
			Version:       "0.2.0",
			Timestamp:     time.Now(),
		},
		File: FileInfo{
			Path:      r.FilePath,
			Name:      r.FileName,
			Extension: getExtension(r.FileName),
			Size:      r.FileSize,
			SizeHuman: humanSize(r.FileSize),
			Hashes: HashInfo{
				SHA256: r.SHA256,
			},
		},
		Detection: DetectionResult{
			Primary: FormatInfo{
				Name:       r.PrimaryFormat,
				MIME:       r.PrimaryMIME,
				Confidence: r.Confidence,
			},
			Confidence: r.Confidence,
			MIME:       r.PrimaryMIME,
			Category:   categorizeFormat(r.PrimaryFormat),
		},
		Entropy: EntropyResult{
			Overall: r.Entropy,
			Label:   interpretEntropy(r.Entropy),
		},
		Security: SecurityAnalysis{
			RiskScore: calculateRiskScore(r),
			RiskLevel: getRiskLevel(calculateRiskScore(r)),
		},
	}

	for _, alt := range r.AlternativeFormats {
		schema.Detection.Alternatives = append(schema.Detection.Alternatives, FormatInfo{
			Name:       alt.Format,
			MIME:       alt.MIME,
			Confidence: alt.Confidence,
		})
	}

	for _, embed := range r.EmbeddedObjects {
		schema.Content.Embedded = append(schema.Content.Embedded, EmbeddedFile{
			Offset:     embed.Offset,
			Format:     embed.Format,
			Confidence: embed.Confidence,
		})
	}

	schema.Warnings = r.Contradictions
	return schema
}

func interpretEntropy(e float64) string {
	switch {
	case e < 1.0:
		return "very_low"
	case e < 3.0:
		return "low"
	case e < 5.0:
		return "medium"
	case e < 7.0:
		return "high"
	default:
		return "very_high"
	}
}

func getExtension(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i+1:]
		}
	}
	return ""
}

func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func categorizeFormat(format string) string {
	categories := map[string]string{
		"zip": "archive", "tar": "archive", "gz": "archive",
		"bz2": "archive", "xz": "archive", "7z": "archive",
		"rar": "archive",
		"png": "image", "jpg": "image", "jpeg": "image",
		"gif": "image", "bmp": "image",
		"pdf": "document",
		"elf": "executable", "pe": "executable", "macho": "executable",
		"sqlite": "database",
		"pcap":   "network",
		"evtx":   "logs",
	}
	if cat, ok := categories[format]; ok {
		return cat
	}
	return "unknown"
}

func calculateRiskScore(r *Result) float64 {
	score := 0.0
	if r.Entropy > 7.0 {
		score += 0.3
	}
	if r.CryptoIndicators != nil && r.CryptoIndicators.Detected {
		score += 0.2
	}
	score += float64(len(r.Contradictions)) * 0.1
	score += float64(len(r.EmbeddedObjects)) * 0.05
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func getRiskLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.2:
		return "low"
	default:
		return "info"
	}
}
