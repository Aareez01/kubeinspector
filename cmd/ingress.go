package cmd

import (
	"github.com/spf13/cobra"
)

func newIngressCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "ingress",
		Short: "Audit Ingresses for duplicate hosts, missing TLS, orphaned backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			return notImplemented("ingress")
		},
	}
}
