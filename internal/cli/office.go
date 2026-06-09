package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/office"
)

var (
	officeJSON bool
)

var officeCmd = &cobra.Command{
	Use:   "office [file]",
	Short: "Analyze Office documents (DOCX, XLSX, PPTX)",
	Long: `Analyze Microsoft Office Open XML documents:
  - Extract metadata (author, title, dates)
  - Detect document properties
  - Show application-specific info`,
	Args: cobra.ExactArgs(1),
	RunE: runOffice,
}

func init() {
	officeCmd.Flags().BoolVar(&officeJSON, "json", false, "Output as JSON")
}

func runOffice(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	// Detect OOXML type
	docType := office.DetectOOXML(filePath)
	if docType == "" {
		// Try other office formats
		return fmt.Errorf("not a supported Office document")
	}

	fmt.Printf("\n  Office Document Analysis: %s\n\n", filePath)

	// Extract metadata
	doc, err := office.ExtractOOXML(filePath)
	if err != nil {
		return err
	}

	// Display results
	fmt.Println(office.FormatOOXML(doc))

	return nil
}
