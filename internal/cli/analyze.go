package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/supunhg/filo-go/internal/analyzer"
	"github.com/supunhg/filo-go/internal/metadata"
)

var (
	jsonOutput  bool
	allEmbedded bool
	explainMode bool
	entropyViz  bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze FILE",
	Short: "Identify a file and report what is inside it",
	Long: `Identify a file's format from its structure (not its extension) and report
hashes, entropy, embedded files, structural problems such as truncation or
appended data, encryption containers, CPU architecture and metadata.`,
	Example: `  filo analyze sample.bin
  filo analyze --json photo.jpg | jq .embedded_objects`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	analyzeCmd.Flags().BoolVarP(&allEmbedded, "nested", "n", false, "Also report signatures inside other embedded files")
	analyzeCmd.Flags().BoolVar(&explainMode, "explain", false, "Show how the confidence score was reached")
	analyzeCmd.Flags().BoolVar(&entropyViz, "entropy-viz", false, "Include per-block entropy (JSON) ")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	data, err := readInput(filePath)
	if err != nil {
		return err
	}

	result, err := analyzer.Analyze(data, filePath, &analyzer.Options{
		AllEmbedded: allEmbedded,
		ExplainMode: explainMode,
		EntropyViz:  entropyViz,
		FormatsDir:  getFormatsDir(),
	})
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	if jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), result.JSON())
		return nil
	}

	result.Print()
	if meta, _ := metadata.Extract(data, filePath); meta != nil && len(meta.Metadata) > 0 {
		metadata.Print(meta)
	}
	return nil
}
