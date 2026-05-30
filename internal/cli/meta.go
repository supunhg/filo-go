package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	metaJSON  bool
	metaSus   bool
)

var metaCmd = &cobra.Command{
	Use:   "meta [file]",
	Short: "Extract metadata from image files",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Metadata extraction from %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
}

func init() {
	metaCmd.Flags().BoolVar(&metaJSON, "json", false, "Output as JSON")
	metaCmd.Flags().BoolVarP(&metaSus, "sus", "s", false, "Only show suspicious metadata")
}
