package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/sqlite"
)

var sqliteJSON bool

var sqliteCmd = &cobra.Command{
	Use:   "sqlite [file]",
	Short: "Analyze SQLite database files",
	Long: `Parse SQLite database files to extract schema, detect WAL journals,
count rows, and recover deleted records from freelist pages.

Examples:
  filo sqlite browser.db
  filo sqlite --json browser.db
  filo sqlite evidence.db-wal`,
	Args: cobra.ExactArgs(1),
	RunE: runSQLite,
}

func init() {
	sqliteCmd.Flags().BoolVar(&sqliteJSON, "json", false, "Output as JSON")
}

func runSQLite(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	result, err := sqlite.Parse(filePath)
	if err != nil {
		return fmt.Errorf("sqlite analysis failed: %w", err)
	}

	if sqliteJSON {
		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		fmt.Println(string(out))
	} else {
		sqlite.Print(result)
	}

	return nil
}
