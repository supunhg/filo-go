package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile [file]",
	Short: "Profile performance of file analysis",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Profiling analysis of %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
}
