package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/Aareez01/kubeinspector/pkg/node"
	"github.com/spf13/cobra"
)

func newNodeCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "node",
		Short: "Check node health: conditions, over-commitment, blocking taints",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, err := kube.NewClient(opts.Kubeconfig)
			if err != nil {
				return err
			}
			findings, err := node.Audit(cmd.Context(), client, node.Options{})
			if err != nil {
				return err
			}
			return renderNodeFindings(cmd.OutOrStdout(), findings)
		},
	}
}

func renderNodeFindings(w io.Writer, findings []node.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No node health issues found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tNODE\tCHECK\tMESSAGE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.Name, f.Check, f.Message)
	}
	return tw.Flush()
}
