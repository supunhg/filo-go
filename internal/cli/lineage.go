package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/lineage"
)

var (
	lineageFormat string
	lineageOutput string
	lineageDBPath string
)

var lineageCmd = &cobra.Command{
	Use:   "lineage [hash]",
	Short: "Show hash lineage chain-of-custody",
	Args:  cobra.ExactArgs(1),
	RunE:  runLineage,
}

var lineageHistoryCmd = &cobra.Command{
	Use:   "lineage-history",
	Short: "Show recent lineage tracking history",
	RunE:  runLineageHistory,
}

var lineageStatsCmd = &cobra.Command{
	Use:   "lineage-stats",
	Short: "Show lineage tracking statistics",
	RunE:  runLineageStats,
}

func init() {
	lineageCmd.Flags().StringVar(&lineageFormat, "format", "text", "Output format: text or json")
	lineageCmd.Flags().StringVarP(&lineageOutput, "output", "o", "", "Save to file")
	lineageCmd.PersistentFlags().StringVar(&lineageDBPath, "db", "", "Lineage database path")
}

func getLineageTracker() (*lineage.Tracker, error) {
	dbPath := lineageDBPath
	if dbPath == "" {
		home, _ := os.UserHomeDir()
		dbPath = filepath.Join(home, ".filo", "lineage.db")
		os.MkdirAll(filepath.Dir(dbPath), 0755)
	}
	return lineage.NewTracker(dbPath)
}

func runLineage(cmd *cobra.Command, args []string) error {
	hash := args[0]

	tracker, err := getLineageTracker()
	if err != nil {
		return fmt.Errorf("failed to open lineage database: %w", err)
	}
	defer tracker.Close()

	records, err := tracker.GetFullChain(hash)
	if err != nil {
		return fmt.Errorf("failed to get lineage: %w", err)
	}

	lineage.Print(records)
	return nil
}

func runLineageHistory(cmd *cobra.Command, args []string) error {
	fmt.Println("  Lineage History")
	fmt.Println()
	fmt.Println("  Not yet implemented - lineage database is empty")
	fmt.Println()
	return nil
}

func runLineageStats(cmd *cobra.Command, args []string) error {
	tracker, err := getLineageTracker()
	if err != nil {
		return fmt.Errorf("failed to open lineage database: %w", err)
	}
	defer tracker.Close()

	stats, err := tracker.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Println()
	fmt.Println("  Lineage Statistics")
	fmt.Println()
	fmt.Printf("  Total Records: %v\n", stats["total_records"])
	if ops, ok := stats["operations"].(map[string]int); ok {
		fmt.Println("  Operations:")
		for op, count := range ops {
			fmt.Printf("    %-15d %s\n", count, op)
		}
	}
	fmt.Println()
	return nil
}
