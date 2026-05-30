package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/batch"
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
	RunE:  runBatch,
}

func init() {
	batchCmd.Flags().BoolVarP(&batchRecursive, "recursive", "r", true, "Recursively process subdirectories")
	batchCmd.Flags().IntVarP(&batchWorkers, "workers", "w", 4, "Number of parallel workers")
	batchCmd.Flags().IntVar(&batchMaxSize, "max-size", 100, "Max file size in MB")
	batchCmd.Flags().StringVar(&batchExport, "export", "", "Export format: json or sarif")
	batchCmd.Flags().StringVarP(&batchOutput, "output", "o", "", "Output file for export")
}

func runBatch(cmd *cobra.Command, args []string) error {
	dir := args[0]

	fmt.Printf("Batch analysis of %s (workers: %d, recursive: %v)\n\n", dir, batchWorkers, batchRecursive)

	result, err := batch.Process(dir, &batch.Options{
		Recursive:  batchRecursive,
		Workers:    batchWorkers,
		MaxSizeMB:  batchMaxSize,
		FormatsDir: getFormatsDir(),
	})
	if err != nil {
		return fmt.Errorf("batch processing failed: %w", err)
	}

	batch.PrintResults(result)
	return nil
}
