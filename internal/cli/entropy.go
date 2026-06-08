package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/entropy"
)

var (
	entropyWidth  int
	entropyHeight int
	entropyColor  bool
	entropyMini   bool
)

var entropyCmd = &cobra.Command{
	Use:   "entropy [file]",
	Short: "Visualize file entropy (like binwalk -E)",
	Long:  `Analyze and visualize the entropy distribution of a file to detect encrypted or compressed sections.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runEntropy,
}

func init() {
	entropyCmd.Flags().IntVarP(&entropyWidth, "width", "w", 80, "Graph width")
	entropyCmd.Flags().IntVarP(&entropyHeight, "height", "H", 20, "Graph height")
	entropyCmd.Flags().BoolVarP(&entropyColor, "color", "c", true, "Enable colors")
	entropyCmd.Flags().BoolVarP(&entropyMini, "mini", "m", false, "Single-line output")
	rootCmd.AddCommand(entropyCmd)
}

func runEntropy(cmd *cobra.Command, args []string) error {
	path := args[0]

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Compute overall entropy
	overall := entropy.Calculate(data)
	fmt.Printf("\n  File: %s\n", path)
	fmt.Printf("  Size: %d bytes\n", len(data))
	fmt.Printf("  Entropy: %.2f / 8.00\n", overall)
	fmt.Printf("  Analysis: %s\n\n", entropy.InterpretEntropy(overall))

	if entropyMini {
		// Single-line mode
		fmt.Println("  " + entropy.MiniViz(data, entropyWidth))
	} else {
		// Full visualization
		opts := &entropy.VizOptions{
			Width:  entropyWidth,
			Height: entropyHeight,
			Color:  entropyColor,
		}
		fmt.Println(entropy.Visualize(data, opts))
	}

	return nil
}
