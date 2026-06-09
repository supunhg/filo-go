package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/carver"
)

var (
	hexOffset  int64
	hexLength  int
	hexNoColor bool
)

var hexCmd = &cobra.Command{
	Use:   "hex [file]",
	Short: "Display hex dump of a file",
	Long: `Display a hex dump of a file with optional color highlighting.

Examples:
  filo hex firmware.bin              # Show first 256 bytes
  filo hex firmware.bin -o 1024      # Start at offset 1024
  filo hex firmware.bin -l 512       # Show 512 bytes
  filo hex firmware.bin --no-color   # Disable colors`,
	Args: cobra.ExactArgs(1),
	RunE: runHex,
}

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan file for embedded signatures",
	Long: `Scan a file for known file signatures (magic bytes).

Examples:
  filo scan firmware.bin             # Scan for all signatures
  filo scan firmware.bin --format    # Filter by format`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

var searchCmd = &cobra.Command{
	Use:   "search [file] [pattern]",
	Short: "Search for pattern in file",
	Long: `Search for a text or hex pattern in a file.

Examples:
  filo search file.bin "http://"    # Search for text
  filo search file.bin --hex "50 4B" # Search for hex bytes`,
	Args: cobra.ExactArgs(2),
	RunE: runSearch,
}

var searchHex bool

func init() {
	hexCmd.Flags().Int64VarP(&hexOffset, "offset", "o", 0, "Start offset")
	hexCmd.Flags().IntVarP(&hexLength, "length", "l", 256, "Number of bytes")
	hexCmd.Flags().BoolVar(&hexNoColor, "no-color", false, "Disable colors")

	searchCmd.Flags().BoolVar(&searchHex, "hex", false, "Search for hex pattern")

	rootCmd.AddCommand(hexCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(searchCmd)
}

func runHex(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	fmt.Println()
	fmt.Printf("  Hex Dump: %s", filePath)
	fmt.Println()
	fmt.Printf("  Size: %d bytes", len(data))
	fmt.Println()
	fmt.Println()

	opts := &carver.HexDumpOptions{
		Offset:    hexOffset,
		Length:    hexLength,
		Colored:   !hexNoColor,
		ShowASCII: true,
		Width:     16,
	}

	output := carver.HexDump(data, opts)
	fmt.Print(output)
	fmt.Println()

	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	fmt.Println()
	fmt.Printf("  Signature Scan: %s", filePath)
	fmt.Println()
	fmt.Printf("  Size: %d bytes", len(data))
	fmt.Println()
	fmt.Println()

	results := carver.ScanSignatures(data)

	if len(results) == 0 {
		fmt.Println("  No signatures found")
	} else {
		fmt.Printf("  Found %d signature(s):", len(results))
		fmt.Println()
		fmt.Println()

		for _, r := range results {
			fmt.Printf("  Offset: 0x%08X", r.Offset)
			fmt.Println()
			fmt.Printf("  Format: %s", r.Format)
			fmt.Println()
			if r.MIME != "" {
				fmt.Printf("  MIME:   %s", r.MIME)
				fmt.Println()
			}
			fmt.Println()
		}
	}

	return nil
}

func runSearch(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	pattern := args[1]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	fmt.Println()
	fmt.Printf("  Search: %s", filePath)
	fmt.Println()
	if searchHex {
		fmt.Printf("  Pattern (hex): %s", pattern)
	} else {
		fmt.Printf("  Pattern (text): %s", pattern)
	}
	fmt.Println()
	fmt.Println()

	var offsets []int64
	if searchHex {
		offsets, err = carver.SearchHex(data, pattern)
	} else {
		offsets = carver.SearchStrings(data, pattern)
	}

	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if len(offsets) == 0 {
		fmt.Println("  No matches found")
	} else {
		fmt.Printf("  Found %d match(es):", len(offsets))
		fmt.Println()
		fmt.Println()

		for i, offset := range offsets {
			if i >= 20 {
				fmt.Printf("  ... and %d more matches", len(offsets)-20)
				fmt.Println()
				break
			}
			fmt.Printf("  0x%08X", offset)
			fmt.Println()
		}
	}

	fmt.Println()
	return nil
}
