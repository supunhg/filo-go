package main

import (
	"fmt"
	"os"

	"github.com/supunhg/filo-go/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "filo: "+err.Error())
		os.Exit(1)
	}
}
