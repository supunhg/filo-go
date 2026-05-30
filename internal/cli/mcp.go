package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server for AI-assisted analysis",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("MCP Server starting...")
		fmt.Println("Not yet implemented")
		fmt.Println("Available tools:")
		fmt.Println("  - analyze: Analyze a file")
		fmt.Println("  - batch: Batch analyze files")
		fmt.Println("  - hash: Hash files with BLAKE3/SHA-256")
		fmt.Println("  - extract: Extract strings/metadata")
	},
}
