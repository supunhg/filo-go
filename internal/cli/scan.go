package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/supunhg/filo-go/internal/signature"
	"github.com/supunhg/filo-go/internal/term"
)

var (
	scanJSON    bool
	scanFormats []string
	scanNested  bool
	scanLimit   int
)

var scanCmd = &cobra.Command{
	Use:   "scan FILE",
	Short: "Find files embedded anywhere inside a binary",
	Long: `Scan a file for embedded files and filesystems, like binwalk.

Every candidate is validated against the format's header structure before it
is reported, and its size is computed where the format allows. Matches that
lie inside an already identified file (for example the entries of a ZIP
archive) are hidden unless --nested is given.`,
	Example: `  filo scan firmware.bin
  filo scan --format squashfs,uimage firmware.bin
  filo scan --json disk.img | jq '.[] | select(.format == "jpeg")'`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Output as JSON")
	scanCmd.Flags().StringSliceVarP(&scanFormats, "format", "f", nil, "Only report these formats (comma-separated)")
	scanCmd.Flags().BoolVar(&scanNested, "nested", false, "Also report matches inside other embedded files")
	scanCmd.Flags().IntVar(&scanLimit, "limit", 0, "Stop after this many matches (0 = no limit)")
	_ = scanCmd.RegisterFlagCompletionFunc("format", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return signature.Formats(), cobra.ShellCompDirectiveNoFileComp
	})
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]
	known := map[string]bool{}
	for _, f := range signature.Formats() {
		known[f] = true
	}
	for _, f := range scanFormats {
		if !known[f] {
			return fmt.Errorf("unknown format %q (supported: %s)", f, strings.Join(signature.Formats(), ", "))
		}
	}

	data, err := readInput(path)
	if err != nil {
		return err
	}
	matches := signature.Scan(data, signature.Options{
		IncludeNested: scanNested,
		Limit:         scanLimit,
		Formats:       scanFormats,
	})

	out := cmd.OutOrStdout()
	if scanJSON {
		if matches == nil {
			matches = []signature.Match{}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(matches)
	}

	fmt.Fprintf(out, "%s%-12s %-12s %-10s %s%s\n", term.C(term.Bold), "DECIMAL", "HEXADECIMAL", "SIZE", "DESCRIPTION", term.C(term.Reset))
	fmt.Fprintln(out, strings.Repeat("-", 78))
	for _, m := range matches {
		size := "-"
		if m.Size > 0 {
			size = humanBytes(m.Size)
		}
		fmt.Fprintf(out, "%-12d 0x%-10X %-10s %s\n", m.Offset, m.Offset, size, m.Description)
	}
	if len(matches) == 0 {
		fmt.Fprintln(out, "No embedded files found.")
	}
	return nil
}

// readInput reads a regular file, rejecting directories with a clear error.
func readInput(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fileError(path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s: is a directory, not a file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fileError(path, err)
	}
	return data, nil
}

// fileError turns an *os.PathError into a short, platform-neutral message
// such as "evidence.img: no such file or directory".
func fileError(path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: no such file or directory", path)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s: permission denied", path)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %v", path, pe.Err)
	}
	return err
}

// humanBytes formats n using binary units.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
