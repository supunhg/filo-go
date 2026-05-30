package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	carveFormats string
	carveOutput  string
	carveMinSize int
	carveMaxSize int
)

var carveCmd = &cobra.Command{
	Use:   "carve [file]",
	Short: "Carve embedded files from disk images or binary blobs",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Carving from %s\n", args[0])
		fmt.Println("Not yet implemented")
	},
}

func init() {
	carveCmd.Flags().StringVarP(&carveFormats, "formats", "f", "", "Comma-separated formats to carve")
	carveCmd.Flags().StringVarP(&carveOutput, "output-dir", "o", "carved", "Output directory")
	carveCmd.Flags().IntVar(&carveMinSize, "min-size", 512, "Minimum file size")
	carveCmd.Flags().IntVar(&carveMaxSize, "max-size", 0, "Maximum file size")
}
