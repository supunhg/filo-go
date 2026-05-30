package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/registry"
)

var registryCmd = &cobra.Command{
	Use:   "registry [file]",
	Short: "Analyze Windows Registry hive files",
	Args:  cobra.ExactArgs(1),
	RunE:  runRegistry,
}

func runRegistry(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	result, err := registry.Analyze(data, filePath)
	if err != nil {
		return fmt.Errorf("registry analysis failed: %w", err)
	}

	registry.Print(result)
	return nil
}
