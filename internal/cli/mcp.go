package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/supunhg/filo-go/internal/mcp"
)

var mcpRoot string

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run an MCP server on stdio for AI agents",
	Long: `Run a Model Context Protocol server on stdin/stdout, exposing filo's
analyzers as read-only tools: analyze, scan, hash, strings, crypto, stego,
metadata, container, sqlite and batch.

Add it to an MCP client such as Claude Desktop or Claude Code:

  {"mcpServers": {"filo": {"command": "filo", "args": ["mcp"]}}}

Use --root to limit the files the agent can read to one directory tree. This
is recommended when the agent processes untrusted content, which could try
to make it read other files.`,
	Example: `  filo mcp
  filo mcp --root ~/cases/2026-041
  claude mcp add filo -- filo mcp --root .`,
	Args: cobra.NoArgs,
	RunE: runMCP,
}

func init() {
	mcpCmd.Flags().StringVar(&mcpRoot, "root", "", "Only allow tools to read files under this directory")
}

func runMCP(cmd *cobra.Command, args []string) error {
	// stdout carries the protocol; never print anything else to it.
	server, err := mcp.NewServerWithRoot(mcpRoot)
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	return server.Run()
}
