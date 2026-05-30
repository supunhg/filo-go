package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	extractOutput    string
	extractRecursive bool
	extractMaxDepth  int
)

var extractCmd = &cobra.Command{
	Use:   "extract [file]",
	Short: "Extract nested archives and polyglots recursively",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Extracting from %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
}

func init() {
	extractCmd.Flags().StringVarP(&extractOutput, "output", "o", "", "Output directory")
	extractCmd.Flags().BoolVarP(&extractRecursive, "recursive", "r", true, "Recursively extract")
	extractCmd.Flags().IntVar(&extractMaxDepth, "max-depth", 10, "Maximum nesting depth")
}
