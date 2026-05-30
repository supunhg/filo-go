package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/mcp"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server for AI-assisted analysis",
	RunE:  runMCP,
}

func runMCP(cmd *cobra.Command, args []string) error {
	fmt.Fprintln(cmd.OutOrStdout(), "Starting MCP server...")
	fmt.Fprintln(cmd.OutOrStdout(), "Listening on stdin/stdout (JSON-RPC)")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Available tools:")
	fmt.Fprintln(cmd.OutOrStdout(), "  - analyze: Analyze a file format and security")
	fmt.Fprintln(cmd.OutOrStdout(), "  - hash: Compute SHA-256 hash")
	fmt.Fprintln(cmd.OutOrStdout(), "  - batch: Batch analyze directory")
	fmt.Fprintln(cmd.OutOrStdout(), "  - crypto: Detect encryption")
	fmt.Fprintln(cmd.OutOrStdout(), "  - strings: Extract strings")
	fmt.Fprintln(cmd.OutOrStdout())

	server := mcp.NewServer()
	return server.Run()
}
