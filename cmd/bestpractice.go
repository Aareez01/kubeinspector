package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/bestpractice"
	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/spf13/cobra"
)

func newBestPracticeCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:     "bestpractice",
		Aliases: []string{"bp"},
		Short:   "Check reliability best practices and networking gaps",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, defaultNS, err := kube.NewClient(opts.Kubeconfig)
			if err != nil {
				return err
			}
			ns := resolveNS(opts, defaultNS)
			ctx := cmd.Context()
			o := bestpractice.Options{Namespace: ns}

			var all []bestpractice.Finding
			for _, step := range []func() ([]bestpractice.Finding, error){
				func() ([]bestpractice.Finding, error) { return bestpractice.AuditReliability(ctx, client, o) },
				func() ([]bestpractice.Finding, error) { return bestpractice.AuditPodImages(ctx, client, o) },
				func() ([]bestpractice.Finding, error) { return bestpractice.AuditNetworkPolicies(ctx, client, o) },
				func() ([]bestpractice.Finding, error) { return bestpractice.AuditNodePorts(ctx, client, o) },
				func() ([]bestpractice.Finding, error) { return bestpractice.AuditLoadBalancers(ctx, client, o) },
			} {
				f, err := step()
				if err != nil {
					return err
				}
				all = append(all, f...)
			}
			return renderBPFindings(cmd.OutOrStdout(), all)
		},
	}
}

func renderBPFindings(w io.Writer, findings []bestpractice.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No best practice issues found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tKIND\tNAMESPACE\tNAME\tCHECK\tMESSAGE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Kind, f.Namespace, f.Name, f.Check, f.Message)
	}
	return tw.Flush()
}
