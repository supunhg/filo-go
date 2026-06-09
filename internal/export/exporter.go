package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Format represents export format type.
type Format string

const (
	JSON  Format = "json"
	SARIF Format = "sarif"
	CSV   Format = "csv"
)

// Exporter handles result export.
type Exporter struct {
	format Format
}

// NewExporter creates a new exporter.
func NewExporter(format Format) *Exporter {
	return &Exporter{format: format}
}

// ExportResult exports a single analysis result.
func (e *Exporter) ExportResult(result interface{}, outputPath string) error {
	switch e.format {
	case JSON:
		return exportJSON(result, outputPath)
	case SARIF:
		return exportSARIFResult(result, outputPath)
	case CSV:
		return exportCSVResult(result, outputPath)
	default:
		return fmt.Errorf("unsupported format: %s", e.format)
	}
}

// ExportBatch exports batch results.
func (e *Exporter) ExportBatch(results interface{}, outputPath string) error {
	switch e.format {
	case JSON:
		return exportJSON(results, outputPath)
	case SARIF:
		return exportSARIFBatch(results, outputPath)
	case CSV:
		return exportCSVBatch(results, outputPath)
	default:
		return fmt.Errorf("unsupported format: %s", e.format)
	}
}

func exportJSON(data interface{}, outputPath string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if outputPath == "" {
		fmt.Println(string(jsonData))
		return nil
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}

// SARIFResult represents a SARIF result entry.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// SARIFAnalysisResult is the expected structure of an analysis result for SARIF export.
type SARIFAnalysisResult struct {
	FilePath       string   `json:"file_path"`
	FileName       string   `json:"file_name"`
	PrimaryFormat  string   `json:"primary_format"`
	Confidence     float64  `json:"confidence"`
	Entropy        float64  `json:"entropy"`
	Contradictions []string `json:"contradictions,omitempty"`
}

func exportSARIFResult(data interface{}, outputPath string) error {
	result, ok := data.(*SARIFAnalysisResult)
	if !ok {
		// Try to marshal as-is if not the expected type
		return exportJSON(data, outputPath)
	}

	sarif := buildSARIF([]SARIFResult{
		{
			RuleID:    "filo-format-detection",
			RuleIndex: 0,
			Level:     getSARIFLevel(result),
			Message: SARIFMessage{
				Text: fmt.Sprintf("File %s detected as %s with %.1f%% confidence",
					result.FileName, result.PrimaryFormat, result.Confidence*100),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: result.FilePath,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"format":     result.PrimaryFormat,
				"confidence": result.Confidence,
				"entropy":    result.Entropy,
			},
		},
	})

	return writeSARIF(sarif, outputPath)
}

func exportSARIFBatch(data interface{}, outputPath string) error {
	results, ok := data.([]*SARIFAnalysisResult)
	if !ok {
		return exportJSON(data, outputPath)
	}

	var sarifResults []SARIFResult
	for i, result := range results {
		sarifResults = append(sarifResults, SARIFResult{
			RuleID:    "filo-format-detection",
			RuleIndex: i,
			Level:     getSARIFLevel(result),
			Message: SARIFMessage{
				Text: fmt.Sprintf("File %s detected as %s with %.1f%% confidence",
					result.FileName, result.PrimaryFormat, result.Confidence*100),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: result.FilePath,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"format":     result.PrimaryFormat,
				"confidence": result.Confidence,
				"entropy":    result.Entropy,
			},
		})
	}

	sarif := buildSARIF(sarifResults)
	return writeSARIF(sarif, outputPath)
}

func getSARIFLevel(result *SARIFAnalysisResult) string {
	if len(result.Contradictions) > 0 {
		return "warning"
	}
	if result.Entropy > 7.0 {
		return "note"
	}
	return "none"
}

func buildSARIF(results []SARIFResult) map[string]interface{} {
	return map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "filo-go",
						"version":        "0.1.0",
						"informationUri": "https://github.com/supunhg/filo-go",
						"rules": []map[string]interface{}{
							{
								"id":   "filo-format-detection",
								"name": "File Format Detection",
								"description": map[string]interface{}{
									"text": "Detects file format and analyzes security indicators",
								},
								"helpUri": "https://github.com/supunhg/filo-go",
							},
						},
					},
				},
				"results": results,
				"invocations": []map[string]interface{}{
					{
						"executionSuccessful":        true,
						"toolExecutionNotifications": []map[string]interface{}{},
						"startTimeUtc":               time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}
}

func writeSARIF(sarif map[string]interface{}, outputPath string) error {
	jsonData, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}

	if outputPath == "" {
		fmt.Println(string(jsonData))
		return nil
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}

func exportCSVResult(data interface{}, outputPath string) error {
	result, ok := data.(*SARIFAnalysisResult)
	if !ok {
		return fmt.Errorf("unsupported data type for CSV export")
	}

	records := [][]string{
		{"file", "format", "confidence", "entropy", "contradictions"},
		{
			result.FilePath,
			result.PrimaryFormat,
			fmt.Sprintf("%.2f", result.Confidence),
			fmt.Sprintf("%.2f", result.Entropy),
			fmt.Sprintf("%d", len(result.Contradictions)),
		},
	}

	return writeCSV(records, outputPath)
}

func exportCSVBatch(data interface{}, outputPath string) error {
	results, ok := data.([]*SARIFAnalysisResult)
	if !ok {
		return fmt.Errorf("unsupported data type for CSV batch export")
	}

	records := [][]string{
		{"file", "format", "confidence", "entropy", "contradictions"},
	}

	for _, r := range results {
		records = append(records, []string{
			r.FilePath,
			r.PrimaryFormat,
			fmt.Sprintf("%.2f", r.Confidence),
			fmt.Sprintf("%.2f", r.Entropy),
			fmt.Sprintf("%d", len(r.Contradictions)),
		})
	}

	return writeCSV(records, outputPath)
}

func writeCSV(records [][]string, outputPath string) error {
	if outputPath == "" {
		// Print to stdout
		for _, record := range records {
			fmt.Println(joinCSV(record))
		}
		return nil
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func joinCSV(record []string) string {
	result := ""
	for i, field := range record {
		if i > 0 {
			result += ","
		}
		result += field
	}
	return result
}
