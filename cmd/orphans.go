package cmd

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/Aareez01/kubeinspector/pkg/orphans"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
)

func newOrphansCmd(opts *GlobalOptions) *cobra.Command {
	var skipReplicaSets bool
	cmd := &cobra.Command{
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

			o := orphans.Options{Namespace: ns}
			ctx := cmd.Context()

			var all []orphans.Finding
			for _, step := range orphanSteps(ctx, client, o, skipReplicaSets) {
				f, err := step()
				if err != nil {
					return err
				}
				all = append(all, f...)
			}
			return renderFindings(cmd.OutOrStdout(), filterOrphans(all, nsFilter(opts)))
		},
	}
	cmd.Flags().BoolVar(&skipReplicaSets, "skip-replicasets", false,
		"skip scaled-to-zero ReplicaSets (Deployment rollback history, usually the bulk of the findings)")
	return cmd
}

// orphanSteps returns the orphan checks to run, in report order.
func orphanSteps(ctx context.Context, client kubernetes.Interface, o orphans.Options, skipReplicaSets bool) []func() ([]orphans.Finding, error) {
	steps := []func() ([]orphans.Finding, error){
		func() ([]orphans.Finding, error) { return orphans.FindOrphanPVCs(ctx, client, o) },
		func() ([]orphans.Finding, error) { return orphans.FindOrphanConfigMaps(ctx, client, o) },
		func() ([]orphans.Finding, error) { return orphans.FindOrphanSecrets(ctx, client, o) },
		func() ([]orphans.Finding, error) { return orphans.FindOrphanServices(ctx, client, o) },
	}
	if !skipReplicaSets {
		steps = append(steps, func() ([]orphans.Finding, error) { return orphans.FindOrphanReplicaSets(ctx, client, o) })
	}
	return steps
}

func renderFindings(w io.Writer, findings []orphans.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No orphaned resources found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tKIND\tNAMESPACE\tNAME\tAGE\tREASON")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Kind, f.Namespace, f.Name, f.Age, f.Reason)
	}
	return tw.Flush()
}
