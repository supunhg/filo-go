package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/metadata"
)

var (
	metaJSON  bool
	metaSus   bool
)

var metaCmd = &cobra.Command{
	Use:   "meta [file]",
	Short: "Extract metadata from image files",
	Args:  cobra.ExactArgs(1),
	RunE:  runMeta,
}

func init() {
	metaCmd.Flags().BoolVar(&metaJSON, "json", false, "Output as JSON")
	metaCmd.Flags().BoolVarP(&metaSus, "sus", "s", false, "Only show suspicious metadata")
}

func runMeta(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	result, err := metadata.Extract(data, filePath)
	if err != nil {
		return fmt.Errorf("metadata extraction failed: %w", err)
	}

	metadata.Print(result)
	return nil
}
