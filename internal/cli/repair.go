package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/repair"
)

var (
	repairFormat   string
	repairOutput   string
	repairStrategy string
	repairNoBackup bool
	repairDryRun   bool
)

var repairCmd = &cobra.Command{
	Use:   "repair [file]",
	Short: "Repair a corrupted file",
	Args:  cobra.ExactArgs(1),
	RunE:  runRepair,
}

func init() {
	repairCmd.Flags().StringVarP(&repairFormat, "format", "f", "", "Target format (required)")
	repairCmd.Flags().StringVarP(&repairOutput, "output", "o", "", "Output file path")
	repairCmd.Flags().StringVarP(&repairStrategy, "strategy", "s", "auto", "Repair strategy")
	repairCmd.Flags().BoolVar(&repairNoBackup, "no-backup", false, "Do not create backup")
	repairCmd.Flags().BoolVar(&repairDryRun, "dry-run", false, "Simulate repair")
}

func runRepair(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	result, err := repair.Repair(data, filePath, &repair.Options{
		TargetFormat: repairFormat,
		OutputPath:   repairOutput,
		Strategy:     repairStrategy,
		NoBackup:     repairNoBackup,
		DryRun:       repairDryRun,
	})
	if err != nil {
		return fmt.Errorf("repair failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Repair Result: %s\n", result.FileName)
	fmt.Println()

	if result.Success {
		fmt.Printf("  Status: %s\n", "SUCCESS")
		fmt.Printf("  Strategy: %s\n", result.Strategy)
		fmt.Printf("  Original Size: %d bytes\n", result.OriginalSize)
		fmt.Printf("  Repaired Size: %d bytes\n", result.RepairedSize)
		if result.BackupCreated {
			fmt.Println("  Backup: Created")
		}
	} else {
		fmt.Printf("  Status: %s\n", "FAILED")
	}

	if len(result.Changes) > 0 {
		fmt.Println("\n  Changes:")
		for _, c := range result.Changes {
			fmt.Printf("    ✓ %s\n", c)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n  Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("    ⚠  %s\n", w)
		}
	}

	fmt.Println()
	return nil
}
