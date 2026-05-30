package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/evtx"
)

var evtxCmd = &cobra.Command{
	Use:   "evtx [file]",
	Short: "Analyze Windows Event Log (EVTX) files",
	Args:  cobra.ExactArgs(1),
	RunE:  runEVTX,
}

func runEVTX(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	result, err := evtx.Analyze(data, filePath)
	if err != nil {
		return fmt.Errorf("EVTX analysis failed: %w", err)
	}

	evtx.Print(result)
	return nil
}
