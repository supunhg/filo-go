package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/sigma"
)

var sigmaCmd = &cobra.Command{
	Use:   "sigma [file]",
	Short: "Scan files with Sigma detection rules",
	Args:  cobra.ExactArgs(1),
	RunE:  runSigma,
}

func runSigma(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	engine := sigma.NewEngine()
	engine.LoadBuiltinRules()

	matches := engine.Scan(data, filePath)
	sigma.PrintMatches(matches, filePath)

	return nil
}
