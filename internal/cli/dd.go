package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/carver"
)

var (
	ddBlockSize int64
	ddCount     int64
	ddSkip      int64
	ddSeek      int64
)

var ddCmd = &cobra.Command{
	Use:   "dd if=<input> of=<output>",
	Short: "Extract raw bytes from a file (like dd)",
	Long: `Extract raw bytes from a file, similar to the Unix dd command.

Examples:
  filo dd if=firmware.bin of=extracted.bin bs=1 count=100
  filo dd if=firmware.bin of=chunk.bin skip=1024 count=512
  filo dd if=disk.img of=partition.bin skip=2048 bs=512`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDD,
}

func init() {
	ddCmd.Flags().Int64VarP(&ddBlockSize, "bs", "b", 512, "Block size")
	ddCmd.Flags().Int64VarP(&ddCount, "count", "c", 0, "Number of blocks (0=all)")
	ddCmd.Flags().Int64VarP(&ddSkip, "skip", "s", 0, "Blocks to skip")
	ddCmd.Flags().Int64VarP(&ddSeek, "seek", "S", 0, "Blocks to seek in output")

	rootCmd.AddCommand(ddCmd)
}

func runDD(cmd *cobra.Command, args []string) error {
	// Parse arguments
	options := carver.ParseDDOptions(args)

	// Apply flags
	if options.InputPath == "" && len(args) > 0 {
		options.InputPath = args[0]
	}
	if options.OutputPath == "" {
		options.OutputPath = "output.bin"
	}
	if ddBlockSize > 0 {
		options.BlockSize = ddBlockSize
	}
	if ddCount > 0 {
		options.Count = ddCount
	}
	if ddSkip > 0 {
		options.Skip = ddSkip
	}

	fmt.Println()
	fmt.Printf("  DD Extraction")
	fmt.Println()
	fmt.Printf("  Input:  %s", options.InputPath)
	fmt.Println()
	fmt.Printf("  Output: %s", options.OutputPath)
	fmt.Println()
	fmt.Printf("  Block size: %d", options.BlockSize)
	fmt.Println()
	if options.Count > 0 {
		fmt.Printf("  Count: %d blocks", options.Count)
		fmt.Println()
	}
	if options.Skip > 0 {
		fmt.Printf("  Skip: %d blocks", options.Skip)
		fmt.Println()
	}
	fmt.Println()

	if err := options.Run(); err != nil {
		return fmt.Errorf("dd failed: %w", err)
	}

	// Get output file info
	info, err := os.Stat(options.OutputPath)
	if err != nil {
		return fmt.Errorf("cannot stat output: %w", err)
	}

	fmt.Printf("  ✓ Extracted %d bytes", info.Size())
	fmt.Println()
	fmt.Println()

	return nil
}
