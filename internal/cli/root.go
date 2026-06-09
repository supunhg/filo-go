package cli

import (
	"github.com/spf13/cobra"
)

var (
	version   = "0.1.0"
	verbose   bool
	quiet     bool
	rootCmd   = &cobra.Command{
		Use:   "filo",
		Short: "Filo - Forensic Intelligence & Learning Operator",
		Long:  `Battle-tested file forensics platform for security professionals.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress non-essential output")
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(formatsCmd)
	rootCmd.AddCommand(repairCmd)
	rootCmd.AddCommand(stegoCmd)
	rootCmd.AddCommand(carveCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(metaCmd)

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
