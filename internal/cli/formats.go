package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	formatsCategory string
)

var formatsCmd = &cobra.Command{
	Use:   "formats",
	Short: "Manage format database",
}

var formatsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available formats",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Format database listing")
		fmt.Println("(YAML format definitions will be loaded from formats/ directory)")
	},
}

var formatsShowCmd = &cobra.Command{
	Use:   "show [format]",
	Short: "Show detailed information about a format",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Format details: %s\n", args[0])
	},
}

func init() {
	formatsListCmd.Flags().StringVarP(&formatsCategory, "category", "c", "", "Filter by category")
	formatsCmd.AddCommand(formatsListCmd)
	formatsCmd.AddCommand(formatsShowCmd)
}
