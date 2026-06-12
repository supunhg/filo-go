package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/carver"
)

var (
	carveFormats string
	carveOutput  string
	carveMinSize int
	carveMaxSize int
)

var carveCmd = &cobra.Command{
	Use:   "carve [file]",
	Short: "Carve embedded files from disk images or binary blobs",
	Args:  cobra.ExactArgs(1),
	RunE:  runCarve,
}

func init() {
	carveCmd.Flags().StringVarP(&carveFormats, "formats", "f", "", "Comma-separated formats to carve")
	carveCmd.Flags().StringVarP(&carveOutput, "output-dir", "o", "carved", "Output directory")
	carveCmd.Flags().IntVar(&carveMinSize, "min-size", 512, "Minimum file size")
	carveCmd.Flags().IntVar(&carveMaxSize, "max-size", 0, "Maximum file size")
}

func runCarve(cmd *cobra.Command, args []string) error {
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

	var formats []string
	if carveFormats != "" {
		formats = strings.Split(carveFormats, ",")
		for i, f := range formats {
			formats[i] = strings.TrimSpace(f)
		}
	}

	result, err := carver.Carve(data, filePath, &carver.Options{
		Formats:   formats,
		OutputDir: carveOutput,
		MinSize:   carveMinSize,
		MaxSize:   carveMaxSize,
	})
	if err != nil {
		return fmt.Errorf("carving failed: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Carving Results: %s\n", filePath)
	fmt.Printf("  Files found: %d\n\n", result.TotalFound)

	for _, f := range result.Carved {
		fmt.Printf("  %8d  %8d  %-8s  %s\n", f.Offset, f.Size, f.Format, f.FilePath)
	}
	fmt.Println()

	return nil
}
