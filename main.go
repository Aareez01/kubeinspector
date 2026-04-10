package main

import (
	"fmt"
	"os"

	"github.com/Aareez01/kubeinspector/cmd"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
