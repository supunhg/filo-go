package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var teachFormat string

var teachCmd = &cobra.Command{
	Use:   "teach [file]",
	Short: "Teach Filo the correct format for a file (ML learning)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Teaching format %s for %s\n", teachFormat, args[0])
		fmt.Println("Not yet implemented")
	},
}

func init() {
	teachCmd.Flags().StringVarP(&teachFormat, "format", "f", "", "Correct format name (required)")
}
