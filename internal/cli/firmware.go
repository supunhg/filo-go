package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/firmware"
)

var (
	firmwareJSON    bool
	firmwareExtract bool
	firmwareOutput  string
)

var firmwareCmd = &cobra.Command{
	Use:   "firmware [file]",
	Short: "Analyze and extract firmware images",
	Long: `Analyze and extract firmware images including:
  - SquashFS filesystems
  - CramFS filesystems
  - JFFS2 filesystems`,
	Args: cobra.ExactArgs(1),
	RunE: runFirmware,
}

func init() {
	firmwareCmd.Flags().BoolVar(&firmwareJSON, "json", false, "Output as JSON")
	firmwareCmd.Flags().BoolVarP(&firmwareExtract, "extract", "x", false, "Extract files")
	firmwareCmd.Flags().StringVarP(&firmwareOutput, "output", "o", "", "Output directory for extraction")
}

func runFirmware(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	fmt.Printf("\n  Firmware Analysis: %s\n\n", filePath)

	// Detect format
	format := firmware.DetectFirmware(filePath)
	if format == "unknown" {
		fmt.Println("  Not a recognized firmware format")
		return nil
	}

	fmt.Printf("  Format: %s\n\n", format)

	// Parse and display info
	switch format {
	case "squashfs":
		sb, err := firmware.ParseSquashFS(filePath)
		if err != nil {
			return err
		}
		fmt.Println(firmware.FormatSquashFSSuperblock(sb))

	case "cramfs":
		sb, err := firmware.ParseCramFS(filePath)
		if err != nil {
			return err
		}
		fmt.Println(firmware.FormatCramFSSuperblock(sb))

	case "jffs2":
		sb, err := firmware.ParseJFFS2(filePath)
		if err != nil {
			return err
		}
		fmt.Println(firmware.FormatJFFS2Superblock(sb))
	}

	// Extract if requested
	if firmwareExtract {
		outputDir := firmwareOutput
		if outputDir == "" {
			outputDir = filePath + "_extracted"
		}

		fmt.Printf("\n  Extracting to: %s\n", outputDir)

		result, err := firmware.ExtractFirmware(filePath, outputDir, format)
		if err != nil {
			return err
		}

		fmt.Printf("  Extracted %d files\n", len(result.Files))
	}

	fmt.Println()
	return nil
}
