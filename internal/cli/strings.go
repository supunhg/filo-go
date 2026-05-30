package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/strings"
)

var (
	stringsMinLen  int
	stringsEntropy float64
	stringsEncode  bool
	stringsRegex   string
	stringsType    string
	stringsCount   int
	stringsJSON    bool
	stringsOffsets bool
)

var stringsCmd = &cobra.Command{
	Use:   "strings [file]",
	Short: "Extract strings from binary files",
	Args:  cobra.ExactArgs(1),
	RunE:  runStrings,
}

func init() {
	stringsCmd.Flags().IntVarP(&stringsMinLen, "min-len", "n", 4, "Minimum string length")
	stringsCmd.Flags().Float64VarP(&stringsEntropy, "entropy", "e", 0, "Minimum entropy filter")
	stringsCmd.Flags().BoolVar(&stringsEncode, "encode-detect", false, "Detect encoding")
	stringsCmd.Flags().StringVar(&stringsRegex, "regex", "", "Regex pattern to search")
	stringsCmd.Flags().StringVar(&stringsType, "type", "all", "String type: ascii, unicode, all")
	stringsCmd.Flags().IntVarP(&stringsCount, "count", "c", 0, "Limit number of strings")
	stringsCmd.Flags().BoolVar(&stringsJSON, "json", false, "Output as JSON")
	stringsCmd.Flags().BoolVar(&stringsOffsets, "offsets", true, "Show byte offsets")
}

func runStrings(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	result, err := strings.Extract(data, filePath, &strings.Options{
		MinLength:    stringsMinLen,
		MinEntropy:   stringsEntropy,
		MaxCount:     stringsCount,
		Type:         stringsType,
		Regex:        stringsRegex,
		EncodeDetect: stringsEncode,
	})
	if err != nil {
		return fmt.Errorf("string extraction failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  String Extraction: %s\n", result.FileName)
	fmt.Printf("  Found %d strings\n\n", result.Total)

	for i, s := range result.Strings {
		if stringsCount > 0 && i >= stringsCount {
			break
		}
		fmt.Printf("  %8d  [%s]  %s\n", s.Offset, s.Type, s.Value)
	}
	fmt.Println()

	return nil
}
