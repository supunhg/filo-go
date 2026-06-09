package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/stego"
)

var (
	stegoAll     bool
	stegoExtract string
	stegoOutput  string
	stegoLimit   int
)

var stegoCmd = &cobra.Command{
	Use:   "stego [file]",
	Short: "Detect steganography in files",
	Args:  cobra.ExactArgs(1),
	RunE:  runStego,
}

func init() {
	stegoCmd.Flags().BoolVarP(&stegoAll, "all", "a", false, "Show all methods")
	stegoCmd.Flags().StringVarP(&stegoExtract, "extract", "E", "", "Extract data from method")
	stegoCmd.Flags().StringVarP(&stegoOutput, "output", "o", "", "Save extracted data")
	stegoCmd.Flags().IntVar(&stegoLimit, "limit", 256, "Limit bytes checked")
}

func runStego(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	result, err := stego.Detect(data, filePath)
	if err != nil {
		return fmt.Errorf("stego analysis failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Steganography Analysis: %s\n", result.FileName)
	fmt.Printf("  Format: %s\n", result.Format)
	fmt.Println()

	if len(result.Methods) == 0 {
		fmt.Println("  No steganography detected")
	} else {
		fmt.Printf("  Found %d method(s):\n\n", len(result.Methods))
		for _, m := range result.Methods {
			fmt.Printf("    Method: %s\n", m.Name)
			fmt.Printf("    Confidence: %.0f%%\n", m.Confidence*100)
			if m.HasFlag {
				fmt.Printf("    ⚠  FLAG DETECTED: %s\n", m.Data)
			} else if m.Preview != "" {
				preview := m.Preview
				if len(preview) > 100 {
					preview = preview[:100] + "..."
				}
				fmt.Printf("    Data: %s\n", preview)
			}
			fmt.Println()
		}
	}

	if len(result.Flags) > 0 {
		fmt.Println("  Flags Found:")
		for _, f := range result.Flags {
			fmt.Printf("    %s\n", f)
		}
		fmt.Println()
	}

	return nil
}
