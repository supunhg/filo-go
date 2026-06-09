package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/config"
)

var (
	configShowCmd = &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE:  runConfigShow,
	}

	configInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Create a default .filo.yaml in the current directory",
		RunE:  runConfigInit,
	}

	configPathCmd = &cobra.Command{
		Use:   "path",
		Short: "Print the user config directory path",
		RunE:  runConfigPath,
	}
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage filo configuration",
	Long: `View, create, and manage filo configuration files.

Configuration is loaded from multiple sources (highest precedence first):
  1. Environment variables (FILO_*)
  2. Project-local .filo.yaml
  3. User config ~/.config/filo/config.yaml
  4. Built-in defaults`,
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configPathCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	fmt.Print(cfg.String())
	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	if _, err := os.Stat(".filo.yaml"); err == nil {
		return fmt.Errorf(".filo.yaml already exists in the current directory")
	}

	data := `# filo configuration
# See https://github.com/supunhg/filo-go for documentation

output:
  format: text          # json, text, csv, sarif
  verbose: false
  quiet: false

analysis:
  deep_scan: false
  no_ml: false
  max_depth: 10         # max archive recursion depth
  # yara_rules: []      # default YARA rule files

lineage:
  enabled: false
  # db_path: ""         # BoltDB path (default: ~/.local/share/filo/lineage.db)

mcp:
  host: "127.0.0.1"
  port: 3000

export:
  default_format: json  # json, csv, sarif, markdown
  # output_dir: ""

database:
  # formats_dir: ""     # custom format definitions directory
`
	if err := os.WriteFile(".filo.yaml", []byte(data), 0644); err != nil {
		return fmt.Errorf("writing .filo.yaml: %w", err)
	}
	fmt.Println("Created .filo.yaml in the current directory")
	return nil
}

func runConfigPath(cmd *cobra.Command, args []string) error {
	dir := config.UserConfigDir()
	if dir == "" {
		return fmt.Errorf("cannot determine user config directory")
	}
	fmt.Println(dir)
	return nil
}
