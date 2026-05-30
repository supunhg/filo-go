package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/hashing"
)

var hashAlgorithms []string

var hashCmd = &cobra.Command{
	Use:   "hash [file]",
	Short: "Compute file hashes using multiple algorithms",
	Args:  cobra.ExactArgs(1),
	RunE:  runHash,
}

func init() {
	hashCmd.Flags().StringArrayVarP(&hashAlgorithms, "algorithm", "a", []string{"md5", "sha1", "sha256"}, "Hash algorithms to use")
}

func runHash(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	var algorithms []hashing.Algorithm
	for _, a := range hashAlgorithms {
		algorithms = append(algorithms, hashing.Algorithm(strings.ToLower(a)))
	}

	result, err := hashing.ComputeFile(filePath, algorithms)
	if err != nil {
		return fmt.Errorf("hashing failed: %w", err)
	}

	hashing.Print(result)
	return nil
}
