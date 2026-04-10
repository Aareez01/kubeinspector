package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/ingress"
	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/spf13/cobra"
)

func newIngressCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "ingress",
		Short: "Audit Ingresses for duplicate hosts, missing TLS, orphaned backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, defaultNS, err := kube.NewClient(opts.Kubeconfig)
			if err != nil {
				return err
			}
			ns := opts.Namespace
			if !opts.AllNS && ns == "" {
				ns = defaultNS
			}
			if opts.AllNS {
				ns = ""
			}

			findings, err := ingress.Audit(cmd.Context(), client, ingress.Options{Namespace: ns})
			if err != nil {
				return err
			}
			return renderIngressFindings(cmd.OutOrStdout(), findings)
		},
	}
}

func renderIngressFindings(w io.Writer, findings []ingress.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No ingress issues found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tNAMESPACE\tINGRESS\tRULE\tMESSAGE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Namespace, f.Ingress, f.Rule, f.Message)
	}
	return tw.Flush()
}
