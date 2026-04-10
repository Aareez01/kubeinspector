package cmd

import (
	"github.com/spf13/cobra"
)

func newCostCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "cost",
		Short: "Rough per-namespace cost estimate from resource requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("cost")
		},
	}
}
