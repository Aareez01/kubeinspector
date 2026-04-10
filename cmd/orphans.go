package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/Aareez01/kubeinspector/pkg/orphans"
	"github.com/spf13/cobra"
)

func newOrphansCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "orphans",
		Short: "Find orphaned resources (PVCs, ConfigMaps, Secrets, ReplicaSets, Services)",
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

			findings, err := orphans.FindOrphanPVCs(cmd.Context(), client, orphans.Options{Namespace: ns})
			if err != nil {
				return err
			}
			return renderFindings(cmd.OutOrStdout(), findings)
		},
	}
}

func renderFindings(w io.Writer, findings []orphans.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No orphaned resources found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tNAMESPACE\tNAME\tAGE\tREASON")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Kind, f.Namespace, f.Name, f.Age, f.Reason)
	}
	return tw.Flush()
}
