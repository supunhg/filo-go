package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/carver"
)

var (
	extractOutput    string
	extractRecursive bool
	extractMaxDepth  int
	extractFormat    string
	extractOffset    int64
	extractLength    int64
)

var extractCmd = &cobra.Command{
	Use:   "extract [file]",
	Short: "Extract embedded files from a binary",
	Long: `Extract embedded files from a binary by scanning for signatures.

Examples:
  filo extract firmware.bin                    # Extract all to ./extracted/
  filo extract firmware.bin -o /tmp/out        # Custom output directory
  filo extract firmware.bin --format zip       # Only extract ZIP files
  filo extract firmware.bin --offset 1024      # Start at offset`,
	Args: cobra.ExactArgs(1),
	RunE: runExtract,
}

func init() {
	extractCmd.Flags().StringVarP(&extractOutput, "output", "o", "extracted", "Output directory")
	extractCmd.Flags().BoolVarP(&extractRecursive, "recursive", "r", true, "Recursively extract")
	extractCmd.Flags().IntVar(&extractMaxDepth, "max-depth", 10, "Maximum nesting depth")
	extractCmd.Flags().StringVarP(&extractFormat, "format", "f", "", "Filter by format")
	extractCmd.Flags().Int64VarP(&extractOffset, "offset", "O", 0, "Start offset")
	extractCmd.Flags().Int64VarP(&extractLength, "length", "L", 0, "Length to extract")
}

func runExtract(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	fmt.Println()
	fmt.Printf("  Extract: %s", filePath)
	fmt.Println()
	fmt.Printf("  Size: %d bytes", len(data))
	fmt.Println()
	fmt.Println()

	// If specific offset/length, extract that region
	if extractOffset > 0 || extractLength > 0 {
		extractor := carver.NewExtractor(&carver.ExtractorOptions{
			OutputDir: extractOutput,
		})

		result, err := extractor.ExtractSpecific(data, extractFormat, extractOffset, extractLength, "")
		if err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}

		if result != nil {
			fmt.Printf("  ✓ Extracted: %s (%d bytes)", result.OutputPath, result.Size)
			fmt.Println()
		}
	} else {
		// Scan and extract all
		extractor := carver.NewExtractor(&carver.ExtractorOptions{
			OutputDir: extractOutput,
			Recursive: extractRecursive,
		})

		opts := &carver.ExtractorOptions{
			OutputDir: extractOutput,
		}
		if extractFormat != "" {
			opts.Formats = []string{extractFormat}
		}

		result, err := extractor.Extract(data, filePath, opts)
		if err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}

		if len(result.Files) == 0 {
			fmt.Println("  No files extracted")
		} else {
			fmt.Printf("  Extracted %d file(s):", len(result.Files))
			fmt.Println()
			fmt.Println()

			for _, f := range result.Files {
				fmt.Printf("  %s", f.OutputPath)
				fmt.Println()
				fmt.Printf("    Format: %s  Size: %d bytes  Offset: 0x%X", f.Format, f.Size, f.Offset)
				fmt.Println()
			}
		}

		if len(result.Errors) > 0 {
			fmt.Println()
			fmt.Printf("  Errors: %d", len(result.Errors))
			fmt.Println()
			for _, e := range result.Errors {
				fmt.Printf("    %s", e)
				fmt.Println()
			}
		}
	}

	fmt.Println()
	return nil
}
