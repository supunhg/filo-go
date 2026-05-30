package main

import (
	"os"

	"github.com/supunhg/filo-go/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
