package cli

import (
	"fmt"

	"github.com/spf13/cobra"
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
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("String extraction from %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
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
