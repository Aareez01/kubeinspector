package cmd

import (
	"github.com/spf13/cobra"
)

func newOrphansCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "orphans",
		Short: "Find orphaned resources (PVCs, ConfigMaps, Secrets, ReplicaSets, Services)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("orphans")
		},
	}
}
