package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var pcapCmd = &cobra.Command{
	Use:   "pcap [file]",
	Short: "Analyze PCAP network capture files",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("PCAP analysis of %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
}
