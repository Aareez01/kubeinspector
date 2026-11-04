package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is overridable at build time:
//
//	go build -ldflags "-X github.com/Aareez01/kubeinspector/cmd.version=$(git describe --tags)"
var version = "0.3.0"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
}
