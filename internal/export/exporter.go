package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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
		return exportSARIF(result, outputPath)
	case CSV:
		return exportCSV(result, outputPath)
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

func exportSARIF(data interface{}, outputPath string) error {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "filo-go",
						"version":        "0.1.0",
						"informationUri": "https://github.com/supunhg/filo-go",
					},
				},
				"results": []map[string]interface{}{},
			},
		},
	}

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

func exportSARIFBatch(results interface{}, outputPath string) error {
	return exportSARIF(results, outputPath)
}

func exportCSV(data interface{}, outputPath string) error {
	records := toCSVRecords(data)

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

func exportCSVBatch(results interface{}, outputPath string) error {
	return exportCSV(results, outputPath)
}

func toCSVRecords(data interface{}) [][]string {
	// Simple conversion - would need proper type handling for real use
	return [][]string{{"format", "confidence", "file"}}
}
