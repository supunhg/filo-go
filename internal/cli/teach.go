package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/analyzer"
)

var teachFormat string

var teachCmd = &cobra.Command{
	Use:   "teach [file]",
	Short: "Teach Filo the correct format for a file (ML learning)",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeach,
}

func init() {
	teachCmd.Flags().StringVarP(&teachFormat, "format", "f", "", "Correct format name (required)")
	teachCmd.MarkFlagRequired("format")
}

type teachEntry struct {
	FilePath    string            `json:"file_path"`
	FileName    string            `json:"file_name"`
	Format      string            `json:"format"`
	Size        int64             `json:"size"`
	Features    map[string]string `json:"features"`
	Timestamp   string            `json:"timestamp"`
}

func runTeach(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", filePath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	// Analyze to extract features
	result, err := analyzer.Analyze(data, filePath, &analyzer.Options{
		FormatsDir: getFormatsDir(),
	})
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Create training entry
	entry := teachEntry{
		FilePath:  filePath,
		FileName:  filepath.Base(filePath),
		Format:    teachFormat,
		Size:      info.Size(),
		Features:  extractFeatures(result),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Save to training database
	dbDir := filepath.Join(os.Getenv("HOME"), ".filo", "training")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create training dir: %w", err)
	}

	dbFile := filepath.Join(dbDir, "training.json")
	var entries []teachEntry
	if existing, err := os.ReadFile(dbFile); err == nil {
		json.Unmarshal(existing, &entries)
	}
	entries = append(entries, entry)

	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal training data: %w", err)
	}

	if err := os.WriteFile(dbFile, out, 0644); err != nil {
		return fmt.Errorf("failed to write training data: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Training entry saved:\n")
	fmt.Printf("    File:   %s\n", filePath)
	fmt.Printf("    Format: %s\n", teachFormat)
	fmt.Printf("    Size:   %d bytes\n", info.Size())
	fmt.Printf("    DB:     %s\n", dbFile)
	fmt.Println()

	return nil
}

func extractFeatures(r *analyzer.Result) map[string]string {
	features := make(map[string]string)
	features["detected_format"] = r.PrimaryFormat
	features["mime_type"] = r.PrimaryMIME
	features["confidence"] = fmt.Sprintf("%.2f", r.Confidence)
	features["has_embedded"] = fmt.Sprintf("%v", len(r.EmbeddedObjects) > 0)
	return features
}
