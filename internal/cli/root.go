package cli

import (
	"github.com/spf13/cobra"

	"github.com/supunhg/filo-go/internal/term"
	"github.com/supunhg/filo-go/internal/version"
)

var (
	verbose   bool
	quiet     bool
	colorMode string
	rootCmd   = &cobra.Command{
		Use:   "filo",
		Short: "Fast, single-binary file forensics",
		Long: `filo identifies, dissects and extracts files: format detection, embedded
signature scanning, carving, metadata, strings, hashes and entropy, in a
single static binary with JSON output and a built-in MCP server.`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			m, err := term.ParseMode(colorMode)
			if err != nil {
				return err
			}
			if m != term.Auto {
				term.SetMode(m)
			}
			return nil
		},
	}
)

// Execute runs the root command. Callers are responsible for reporting the
// returned error, because the command tree silences cobra's own printing.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-essential output")
	rootCmd.PersistentFlags().StringVar(&colorMode, "color", "auto", "Colorize output: auto, always or never")
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(formatsCmd)
	rootCmd.AddCommand(repairCmd)
	rootCmd.AddCommand(stegoCmd)
	rootCmd.AddCommand(carveCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(metaCmd)
	rootCmd.AddCommand(firmwareCmd)
	rootCmd.AddCommand(officeCmd)

	rootCmd.AddCommand(stringsCmd)
	rootCmd.AddCommand(lineageCmd)
	rootCmd.AddCommand(lineageHistoryCmd)
	rootCmd.AddCommand(lineageStatsCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(teachCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(hashCmd)
	rootCmd.AddCommand(evtxCmd)
	rootCmd.AddCommand(registryCmd)
	rootCmd.AddCommand(timelineCmd)
	rootCmd.AddCommand(sigmaCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(sqliteCmd)
	rootCmd.AddCommand(executableCmd)
}
