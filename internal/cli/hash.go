package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/supunhg/filo-go/internal/hashing"
)

var (
	hashAlgorithms []string
	hashJSON       bool
)

var hashCmd = &cobra.Command{
	Use:   "hash FILE...",
	Short: "Compute file hashes using multiple algorithms",
	Long: `Compute several digests of each file in a single read.

With exactly one algorithm the output matches coreutils (sha256sum and
friends), so it can be checked with "sha256sum -c".

Supported algorithms: md5, sha1, sha256, sha512, sha3-256, sha3-512.`,
	Example: `  filo hash evidence.img
  filo hash -a sha256 *.bin > SHA256SUMS
  filo hash -a md5,sha256 --json sample.exe`,
	Args: cobra.MinimumNArgs(1),
	RunE: runHash,
}

func init() {
	hashCmd.Flags().StringSliceVarP(&hashAlgorithms, "algorithm", "a", []string{"md5", "sha1", "sha256"}, "Hash algorithms to compute (comma-separated or repeated)")
	hashCmd.Flags().BoolVar(&hashJSON, "json", false, "Output as JSON")
}

type hashOutput struct {
	File   string            `json:"file"`
	Size   int64             `json:"size"`
	Hashes map[string]string `json:"hashes"`
}

func runHash(cmd *cobra.Command, args []string) error {
	var algorithms []hashing.Algorithm
	for _, a := range hashAlgorithms {
		alg, err := hashing.ParseAlgorithm(a)
		if err != nil {
			return err
		}
		algorithms = append(algorithms, alg)
	}

	out := cmd.OutOrStdout()
	var results []hashOutput
	var failed int
	for _, path := range args {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			err = fmt.Errorf("is a directory")
		}
		var r *hashing.Result
		if err == nil {
			r, err = hashing.ComputeFile(path, algorithms)
		}
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "filo: %s: %v\n", path, err)
			failed++
			continue
		}

		switch {
		case hashJSON:
			results = append(results, hashOutput{File: path, Size: r.FileSize, Hashes: r.Algorithms})
		case len(r.Order) == 1:
			// coreutils format: "<hex>  <path>"
			fmt.Fprintf(out, "%s  %s\n", r.Algorithms[r.Order[0]], path)
		default:
			fmt.Fprintf(out, "%s (%d bytes)\n", path, r.FileSize)
			for _, a := range r.Order {
				fmt.Fprintf(out, "  %-9s %s\n", a, r.Algorithms[a])
			}
		}
	}

	if hashJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d file(s) could not be hashed", failed, len(args))
	}
	return nil
}

// hashAlgorithmNames is used by shell completion.
func hashAlgorithmNames() []string {
	names := make([]string, len(hashing.Supported))
	for i, a := range hashing.Supported {
		names[i] = strings.ToLower(string(a))
	}
	return names
}

func init() {
	_ = hashCmd.RegisterFlagCompletionFunc("algorithm", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return hashAlgorithmNames(), cobra.ShellCompDirectiveNoFileComp
	})
}
