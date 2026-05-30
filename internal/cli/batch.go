package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	batchRecursive bool
	batchWorkers   int
	batchMaxSize   int
	batchExport    string
	batchOutput    string
)

var batchCmd = &cobra.Command{
	Use:   "batch [directory]",
	Short: "Batch analyze all files in a directory",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Batch analysis of %s (workers: %d, recursive: %v)\n", args[0], batchWorkers, batchRecursive)
		fmt.Println("Not yet implemented")
	},
}

func init() {
	batchCmd.Flags().BoolVarP(&batchRecursive, "recursive", "r", true, "Recursively process subdirectories")
	batchCmd.Flags().IntVarP(&batchWorkers, "workers", "w", 4, "Number of parallel workers")
	batchCmd.Flags().IntVar(&batchMaxSize, "max-size", 100, "Max file size in MB")
	batchCmd.Flags().StringVar(&batchExport, "export", "", "Export format: json or sarif")
	batchCmd.Flags().StringVarP(&batchOutput, "output", "o", "", "Output file for export")
}
