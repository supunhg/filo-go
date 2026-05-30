package cli

import (
	"fmt"

	"github.com/spf13/cobra"
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
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Steganography analysis of %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
}

func init() {
	stegoCmd.Flags().BoolVarP(&stegoAll, "all", "a", false, "Show all methods")
	stegoCmd.Flags().StringVarP(&stegoExtract, "extract", "E", "", "Extract data from method")
	stegoCmd.Flags().StringVarP(&stegoOutput, "output", "o", "", "Save extracted data")
	stegoCmd.Flags().IntVar(&stegoLimit, "limit", 256, "Limit bytes checked")
}
