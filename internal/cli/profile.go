package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/analyzer"
)

var (
	profileIterations int
	profileDeepScan   bool
	profileNoML       bool
)

var profileCmd = &cobra.Command{
	Use:   "profile [file]",
	Short: "Profile performance of file analysis",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfile,
}

func init() {
	profileCmd.Flags().IntVarP(&profileIterations, "iterations", "i", 10, "Number of iterations")
	profileCmd.Flags().BoolVar(&profileDeepScan, "deep", false, "Enable deep scan")
	profileCmd.Flags().BoolVar(&profileNoML, "no-ml", false, "Disable ML detection")
}

func runProfile(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot access %s: %w", filePath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", filePath)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	fmt.Println()
	fmt.Printf("  Profiling: %s (%d bytes)\n", filePath, len(data))
	fmt.Printf("  Iterations: %d\n\n", profileIterations)

	opts := &analyzer.Options{
		DeepScan: profileDeepScan,
		NoML:     profileNoML,
		FormatsDir: getFormatsDir(),
	}

	var totalTime time.Duration
	var minTime time.Duration
	var maxTime time.Duration

	for i := 0; i < profileIterations; i++ {
		start := time.Now()
		_, err := analyzer.Analyze(data, filePath, opts)
		elapsed := time.Since(start)

		if err != nil {
			return fmt.Errorf("analysis failed on iteration %d: %w", i+1, err)
		}

		if i == 0 {
			minTime = elapsed
			maxTime = elapsed
		} else {
			if elapsed < minTime {
				minTime = elapsed
			}
			if elapsed > maxTime {
				maxTime = elapsed
			}
		}
		totalTime += elapsed

		fmt.Printf("  Run %2d: %v\n", i+1, elapsed)
	}

	avgTime := totalTime / time.Duration(profileIterations)

	fmt.Println()
	fmt.Printf("  Summary:\n")
	fmt.Printf("    Min:   %v\n", minTime)
	fmt.Printf("    Max:   %v\n", maxTime)
	fmt.Printf("    Avg:   %v\n", avgTime)
	fmt.Printf("    Total: %v\n\n", totalTime)

	return nil
}
