package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/executable"
)

var (
	execDeepScan       bool
	execExtractStrings bool
	execMinStringLen   int
	execJSONOutput     bool
)

var executableCmd = &cobra.Command{
	Use:   "executable [file]",
	Short: "Deep analysis of PE/ELF/Mach-O executables",
	Long: `Perform comprehensive analysis of executable files including:
  - PE: Import/Export tables, sections, TLS, debug info, resources
  - ELF: Sections, segments, security features, dynamic dependencies
  - Mach-O: Load commands, segments, code signatures, dylibs
  - Packing detection for common packers (UPX, VMProtect, Themida, etc.)`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutable,
}

func init() {
	executableCmd.Flags().BoolVar(&execDeepScan, "deep", false, "Enable deep analysis (slower, more thorough)")
	executableCmd.Flags().BoolVar(&execExtractStrings, "strings", false, "Extract printable strings")
	executableCmd.Flags().IntVarP(&execMinStringLen, "min-string-len", "n", 4, "Minimum string length for extraction")
	executableCmd.Flags().BoolVarP(&execJSONOutput, "json", "j", false, "Output as JSON")
}

func runExecutable(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	opts := &executable.Options{
		DeepScan:       execDeepScan,
		ExtractStrings: execExtractStrings,
		MinStringLen:   execMinStringLen,
	}

	result, err := executable.Analyze(data, filePath, opts)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	if execJSONOutput {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("JSON marshaling failed: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		executable.Print(result)
	}

	return nil
}
