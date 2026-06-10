package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/office"
)

var (
	officeJSON    bool
	officeMeta    bool
)

var officeCmd = &cobra.Command{
	Use:   "office [file]",
	Short: "Analyze Office documents (DOCX, XLSX, PPTX, legacy OLE2)",
	Long: `Analyze Microsoft Office documents:
  - Extract OOXML metadata (author, title, dates, company, custom properties)
  - Detect VBA macros in OLE2 documents (DOC, XLS, PPT)
  - Show application-specific info`,
	Args: cobra.ExactArgs(1),
	RunE: runOffice,
}

func init() {
	officeCmd.Flags().BoolVar(&officeJSON, "json", false, "Output as JSON")
	officeCmd.Flags().BoolVar(&officeMeta, "metadata", false, "Show only metadata (OOXML: core + app + custom properties)")
}

func runOffice(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	// Read the file once so we can dispatch to the right analyzer.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// --metadata short-circuits to OOXML metadata extraction.
	if officeMeta {
		doc, err := office.ExtractOOXMLFromBytes(data)
		if err != nil {
			return err
		}
		fmt.Printf("\n  Office OOXML Metadata: %s\n\n", filePath)
		fmt.Println(office.FormatOOXML(doc))
		return nil
	}

	result := office.Analyze(data, filePath)
	if result == nil || (result.Format == "" && !result.HasMacros && result.Metadata == nil) {
		return fmt.Errorf("not a supported Office document")
	}

	if officeJSON {
		// Lazy: reuse FormatOOXML for human output; JSON path is a future improvement.
		fmt.Println(office.FormatOOXML(result.Metadata))
		return nil
	}

	fmt.Printf("\n  Office Document Analysis: %s\n\n", filePath)
	office.Print(result)
	return nil
}
