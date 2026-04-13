package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/Aareez01/kubeinspector/pkg/workload"
	"github.com/spf13/cobra"
)

func newWorkloadCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "workload",
		Short: "Check workload health: CrashLoopBackOff, pending pods, dead deployments, failed jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, defaultNS, err := kube.NewClient(opts.Kubeconfig)
			if err != nil {
				return err
			}
			ns := resolveNS(opts, defaultNS)
			ctx := cmd.Context()
			o := workload.Options{Namespace: ns}

			var all []workload.Finding
			for _, step := range []func() ([]workload.Finding, error){
				func() ([]workload.Finding, error) { return workload.AuditPods(ctx, client, o) },
				func() ([]workload.Finding, error) { return workload.AuditDeployments(ctx, client, o) },
				func() ([]workload.Finding, error) { return workload.AuditServiceSelectors(ctx, client, o) },
				func() ([]workload.Finding, error) { return workload.AuditJobs(ctx, client, o) },
			} {
				f, err := step()
				if err != nil {
					return err
				}
				all = append(all, f...)
			}
			return renderWorkloadFindings(cmd.OutOrStdout(), all)
		},
	}
}

func renderWorkloadFindings(w io.Writer, findings []workload.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No workload health issues found.")
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
