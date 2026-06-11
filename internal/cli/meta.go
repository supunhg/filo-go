package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/metadata"
)

var (
	metaJSON bool
	metaSus  bool
	metaAll  bool
)

var metaCmd = &cobra.Command{
	Use:   "meta [file]",
	Short: "Extract metadata from image files",
	Long: `Extract metadata from image files including:
  - EXIF data (camera info, settings, GPS)
  - XMP data (Adobe metadata)
  - IPTC data (editorial metadata)
  - ICC profiles (color management)
  - Maker notes (camera-specific data)`,
	Args: cobra.ExactArgs(1),
	RunE: runMeta,
}

func init() {
	metaCmd.Flags().BoolVar(&metaJSON, "json", false, "Output as JSON")
	metaCmd.Flags().BoolVarP(&metaSus, "sus", "s", false, "Only show suspicious metadata")
	metaCmd.Flags().BoolVarP(&metaAll, "all", "a", false, "Show all metadata formats")
}

func runMeta(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	fmt.Printf("\n  Metadata Analysis: %s\n\n", filePath)

	// Extract EXIF
	exif, err := metadata.ExtractEXIF(filePath)
	if err == nil && exif != nil {
		fmt.Println(metadata.FormatEXIFResult(exif))
	}

	// Extract XMP
	xmp, err := metadata.ExtractXMP(filePath)
	if err == nil && xmp != nil {
		fmt.Println(metadata.FormatXMPData(xmp))
	}

	// Extract IPTC
	iptc, err := metadata.ExtractIPTC(filePath)
	if err == nil && iptc != nil {
		fmt.Println(metadata.FormatIPTCData(iptc))
	}

	// Check for suspicious metadata
	if metaSus {
		fmt.Println("\n  Suspicious Indicators:")
		if exif != nil {
			// Check for unusual software
			if software, ok := exif.Tags["Software"]; ok {
				if sw, ok := software.(string); ok {
					fmt.Printf("    - Software: %s\n", sw)
				}
			}
			// Check for GPS data
			if _, ok := exif.Tags["GPSLatitude"]; ok {
				fmt.Println("    - GPS coordinates present")
			}
		}
	}

	// If no metadata found
	if exif == nil && xmp == nil && len(iptc) == 0 {
		fmt.Println("  No metadata found")
	}

	fmt.Println()
	return nil
}
