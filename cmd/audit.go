package cmd

import (
	"github.com/spf13/cobra"
)

func newAuditCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Run all checks and produce a combined report",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("audit")
		},
	}
}
