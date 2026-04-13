package cmd

import (
	"os"

	"github.com/Aareez01/kubeinspector/pkg/cost"
	"github.com/Aareez01/kubeinspector/pkg/ingress"
	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/Aareez01/kubeinspector/pkg/node"
	"github.com/Aareez01/kubeinspector/pkg/orphans"
	"github.com/Aareez01/kubeinspector/pkg/report"
	"github.com/Aareez01/kubeinspector/pkg/security"
	"github.com/Aareez01/kubeinspector/pkg/workload"
	"github.com/spf13/cobra"
)

func newAuditCmd(opts *GlobalOptions) *cobra.Command {
	var pricingPath string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run all checks and produce a combined report",
		Long: `Run orphans + ingress + cost against the target namespace(s) and
produce a combined report.

Exit codes:
  0 — no findings
  1 — at least one warning-level finding
  2 — at least one error-level finding

Use --output markdown to produce something suitable for posting as a PR
or issue comment in CI.`,
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

			ctx := cmd.Context()
			r := &report.Report{}

			orphanOpts := orphans.Options{Namespace: ns}
			for _, step := range []func() ([]orphans.Finding, error){
				func() ([]orphans.Finding, error) { return orphans.FindOrphanPVCs(ctx, client, orphanOpts) },
				func() ([]orphans.Finding, error) { return orphans.FindOrphanConfigMaps(ctx, client, orphanOpts) },
				func() ([]orphans.Finding, error) { return orphans.FindOrphanSecrets(ctx, client, orphanOpts) },
				func() ([]orphans.Finding, error) { return orphans.FindOrphanReplicaSets(ctx, client, orphanOpts) },
				func() ([]orphans.Finding, error) { return orphans.FindOrphanServices(ctx, client, orphanOpts) },
			} {
				f, err := step()
				if err != nil {
					return err
				}
				r.Orphans = append(r.Orphans, f...)
			}

			wlOpts := workload.Options{Namespace: ns}
			for _, step := range []func() ([]workload.Finding, error){
				func() ([]workload.Finding, error) { return workload.AuditPods(ctx, client, wlOpts) },
				func() ([]workload.Finding, error) { return workload.AuditDeployments(ctx, client, wlOpts) },
				func() ([]workload.Finding, error) { return workload.AuditServiceSelectors(ctx, client, wlOpts) },
				func() ([]workload.Finding, error) { return workload.AuditJobs(ctx, client, wlOpts) },
			} {
				f, err := step()
				if err != nil {
					return err
				}
				r.Workload = append(r.Workload, f...)
			}

			ingressFindings, err := ingress.Audit(ctx, client, ingress.Options{Namespace: ns})
			if err != nil {
				return err
			}
			r.Ingress = ingressFindings

			secOpts := security.Options{Namespace: ns}
			for _, step := range []func() ([]security.Finding, error){
				func() ([]security.Finding, error) { return security.AuditPods(ctx, client, secOpts) },
				func() ([]security.Finding, error) { return security.AuditRBAC(ctx, client, secOpts) },
				func() ([]security.Finding, error) { return security.AuditMiners(ctx, client, secOpts) },
				func() ([]security.Finding, error) { return security.AuditResourceAbuse(ctx, client, secOpts) },
			} {
				f, err := step()
				if err != nil {
					return err
				}
				r.Security = append(r.Security, f...)
			}

			nodeFindings, err := node.Audit(ctx, client, node.Options{})
			if err != nil {
				return err
			}
			r.Node = nodeFindings

			pricing, err := cost.LoadPricing(pricingPath)
			if err != nil {
				return err
			}
			costReport, err := cost.Estimate(ctx, client, cost.Options{Namespace: ns, Pricing: pricing})
			if err != nil {
				return err
			}
			r.Cost = costReport

			if err := report.Render(cmd.OutOrStdout(), r, report.Format(opts.Output)); err != nil {
				return err
			}
			os.Exit(report.ExitCode(r))
			return nil
		},
	}
	cmd.Flags().StringVar(&pricingPath, "pricing", "", "path to pricing.yaml (defaults to built-in rates)")
	return cmd
}
