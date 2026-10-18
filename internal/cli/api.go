package cli

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/supunhg/filo-go/internal/api"
	"github.com/supunhg/filo-go/internal/version"
)

var (
	apiAddr       string
	apiPort       int
	apiRoot       string
	apiToken      string
	apiNoAuth     bool
	apiMaxUploadM int64
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the REST API server",
	Long: `Start a REST API server for remote analysis.

The server is locked down by default:
  - it listens on 127.0.0.1 only;
  - listening on any other address requires a bearer token (--token or the
    FILO_API_TOKEN environment variable);
  - endpoints that take a file path are disabled unless --root is given, and
    then only serve files inside that directory. /api/upload always works.`,
	Example: `  filo api --root ./evidence
  FILO_API_TOKEN=$(openssl rand -hex 32) filo api --addr 0.0.0.0:8080 --root /data
  curl -s localhost:8080/api/analyze -d '{"path":"sample.bin"}'
  curl -s localhost:8080/api/upload -F file=@sample.bin`,
	Args: cobra.NoArgs,
	RunE: runAPI,
}

func init() {
	apiCmd.Flags().StringVarP(&apiAddr, "addr", "a", api.DefaultAddr, "Address to listen on")
	apiCmd.Flags().IntVarP(&apiPort, "port", "p", 0, "Port to listen on, keeping the host from --addr")
	apiCmd.Flags().StringVar(&apiRoot, "root", "", "Serve file-path endpoints for files under this directory")
	apiCmd.Flags().StringVar(&apiToken, "token", "", "Require this bearer token (default $FILO_API_TOKEN)")
	apiCmd.Flags().BoolVar(&apiNoAuth, "insecure-no-auth", false, "Allow a non-loopback address without a token (only behind an authenticating proxy)")
	apiCmd.Flags().Int64Var(&apiMaxUploadM, "max-upload", api.DefaultMaxUpload>>20, "Maximum upload size in MiB")
	rootCmd.AddCommand(apiCmd)
}

func runAPI(cmd *cobra.Command, args []string) error {
	addr := apiAddr
	if apiPort > 0 {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = "127.0.0.1"
		}
		addr = net.JoinHostPort(host, strconv.Itoa(apiPort))
	}
	token := apiToken
	if token == "" {
		token = os.Getenv("FILO_API_TOKEN")
	}

	srv, err := api.NewServer(api.Config{
		Addr:              addr,
		Version:           version.Version,
		Root:              apiRoot,
		Token:             token,
		AllowRemoteNoAuth: apiNoAuth,
		MaxUpload:         apiMaxUploadM << 20,
	})
	if err != nil {
		return err
	}

	out := cmd.ErrOrStderr()
	fmt.Fprintf(out, "filo %s REST API listening on http://%s\n", version.Version, srv.Addr())
	if srv.Root() != "" {
		fmt.Fprintf(out, "  file access: %s\n", srv.Root())
	} else {
		fmt.Fprintln(out, "  file access: disabled (use --root DIR to enable path endpoints)")
	}
	if srv.AuthRequired() {
		fmt.Fprintln(out, "  auth:        bearer token required")
	} else if !api.IsLoopback(srv.Addr()) {
		fmt.Fprintln(out, "  auth:        DISABLED on a non-loopback address (--insecure-no-auth)")
	}
	fmt.Fprintln(out, "  endpoints:   GET /api/health, GET /api/version, POST /api/{analyze,scan,hash,strings,crypto,stego,metadata,batch,upload}")

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}
