package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/api"
)

var (
	apiAddr string
	apiPort int
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start REST API server for remote analysis",
	RunE:  runAPI,
}

func init() {
	apiCmd.Flags().StringVarP(&apiAddr, "addr", "a", ":8080", "Address to listen on (e.g., :8080)")
	apiCmd.Flags().IntVarP(&apiPort, "port", "p", 0, "Port to listen on (alternative to --addr)")
	rootCmd.AddCommand(apiCmd)
}

func runAPI(cmd *cobra.Command, args []string) error {
	if apiPort > 0 {
		apiAddr = fmt.Sprintf(":%d", apiPort)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Starting filo-go REST API server...")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "Endpoints:")
	fmt.Fprintln(cmd.OutOrStdout(), "  GET  /api/health    - Health check")
	fmt.Fprintln(cmd.OutOrStdout(), "  GET  /api/version   - Version info")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/analyze   - Analyze file")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/hash      - Compute hashes")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/strings   - Extract strings")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/crypto    - Detect encryption")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/stego     - Detect steganography")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/metadata  - Extract metadata")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/batch     - Batch analysis")
	fmt.Fprintln(cmd.OutOrStdout(), "  POST /api/upload    - Upload and analyze")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "Listening on %s\n", apiAddr)
	fmt.Fprintln(cmd.OutOrStdout())

	server := api.NewServer(apiAddr, version)
	return server.Run()
}
