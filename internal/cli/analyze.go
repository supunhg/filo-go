package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/crypto"
	"github.com/supunhg/filo-go/internal/metadata"
)

var (
	jsonOutput   bool
	deepScan     bool
	noML         bool
	allEvidence  bool
	allEmbedded  bool
	explainMode  bool
	entropyViz   bool
	yaraRules    []string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [file]",
	Short: "Analyze a file to detect its format",
	Args:  cobra.ExactArgs(1),
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	analyzeCmd.Flags().BoolVar(&deepScan, "deep", false, "Deep analysis (slower, more thorough)")
	analyzeCmd.Flags().BoolVar(&noML, "no-ml", false, "Disable ML-based detection")
	analyzeCmd.Flags().BoolVarP(&allEvidence, "all-evidence", "a", false, "Show all detection evidence")
	analyzeCmd.Flags().BoolVarP(&allEmbedded, "all-embedded", "e", false, "Show all embedded artifacts")
	analyzeCmd.Flags().BoolVar(&explainMode, "explain", false, "Show confidence breakdown")
	analyzeCmd.Flags().BoolVar(&entropyViz, "entropy-viz", false, "Show entropy visualization")
	analyzeCmd.Flags().StringArrayVar(&yaraRules, "yara", nil, "YARA rule file(s)")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", filePath, err)
	}

	// Core analysis
	result, err := analyzer.Analyze(data, filePath, &analyzer.Options{
		DeepScan:    deepScan,
		NoML:        noML,
		AllEvidence: allEvidence,
		AllEmbedded: allEmbedded,
		ExplainMode: explainMode,
		EntropyViz:  entropyViz,
		YaraRules:   yaraRules,
		FormatsDir:  getFormatsDir(),
	})
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Crypto analysis
	cryptoResult := crypto.Analyze(data)

	// Metadata extraction (for supported formats)
	metaResult, _ := metadata.Extract(data, filePath)

	if jsonOutput {
		fmt.Println(result.JSON())
	} else {
		result.Print()

		// Print crypto results
		if cryptoResult.Detected {
			crypto.Print(cryptoResult)
		}

		// Print metadata
		if metaResult != nil && len(metaResult.Metadata) > 0 {
			metadata.Print(metaResult)
		}
	}
	return nil
}
