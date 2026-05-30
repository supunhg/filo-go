package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/formats"
)

var (
	formatsCategory string
	formatsDir      string
)

var formatsCmd = &cobra.Command{
	Use:   "formats",
	Short: "Manage format database",
}

var formatsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available formats",
	RunE:  runFormatsList,
}

var formatsShowCmd = &cobra.Command{
	Use:   "show [format]",
	Short: "Show detailed information about a format",
	Args:  cobra.ExactArgs(1),
	RunE:  runFormatsShow,
}

func init() {
	formatsListCmd.Flags().StringVarP(&formatsCategory, "category", "c", "", "Filter by category")
	formatsCmd.PersistentFlags().StringVar(&formatsDir, "formats-dir", "", "Format definitions directory")
	formatsCmd.AddCommand(formatsListCmd)
	formatsCmd.AddCommand(formatsShowCmd)
}

func getFormatsDir() string {
	if formatsDir != "" {
		return formatsDir
	}
	// Try to find formats relative to executable
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "formats"),
		filepath.Join(dir, "..", "formats"),
		filepath.Join(dir, "..", "..", "formats"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return "formats"
}

func runFormatsList(cmd *cobra.Command, args []string) error {
	dir := getFormatsDir()
	db, err := formats.NewDatabase(dir)
	if err != nil {
		return fmt.Errorf("failed to load format database: %w", err)
	}

	var formatList []*formats.FormatSpec
	if formatsCategory != "" {
		formatList = db.ByCategory(formatsCategory)
	} else {
		names := db.List()
		for _, name := range names {
			spec, _ := db.Get(name)
			formatList = append(formatList, spec)
		}
	}

	fmt.Printf("\n  Format Database (%d formats)\n\n", len(formatList))
	for _, spec := range formatList {
		exts := ""
		if len(spec.Extensions) > 0 {
			exts = " (." + spec.Extensions[0]
			if len(spec.Extensions) > 1 {
				exts += ", ..."
			}
			exts += ")"
		}
		fmt.Printf("  %-15s %s%s\n", spec.Format, spec.Description, exts)
	}
	fmt.Println()
	return nil
}

func runFormatsShow(cmd *cobra.Command, args []string) error {
	dir := getFormatsDir()
	db, err := formats.NewDatabase(dir)
	if err != nil {
		return fmt.Errorf("failed to load format database: %w", err)
	}

	spec, ok := db.Get(args[0])
	if !ok {
		return fmt.Errorf("format '%s' not found", args[0])
	}

	fmt.Printf("\n  Format: %s\n", spec.Format)
	fmt.Printf("  Version: %s\n", spec.Version)
	fmt.Printf("  Category: %s\n", spec.Category)
	fmt.Printf("  MIME Types: %v\n", spec.MIME)
	fmt.Printf("  Extensions: %v\n", spec.Extensions)
	fmt.Printf("  Confidence Weight: %.2f\n", spec.ConfidenceWeight)
	fmt.Printf("  Description: %s\n", spec.Description)

	if len(spec.Signatures) > 0 {
		fmt.Println("\n  Signatures:")
		for _, sig := range spec.Signatures {
			fmt.Printf("    offset=%d hex=%s weight=%.2f %s\n", sig.Offset, sig.Hex, sig.Weight, sig.Description)
		}
	}

	if len(spec.Footers) > 0 {
		fmt.Println("\n  Footers:")
		for _, f := range spec.Footers {
			fmt.Printf("    hex=%s %s\n", f.Hex, f.Description)
		}
	}

	if len(spec.RepairStrategies) > 0 {
		fmt.Println("\n  Repair Strategies:")
		for _, s := range spec.RepairStrategies {
			fmt.Printf("    [%d] %s - %s\n", s.Priority, s.Name, s.Description)
		}
	}

	fmt.Println()
	return nil
}
