package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/cost"
	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/spf13/cobra"
)

func newCostCmd(opts *GlobalOptions) *cobra.Command {
	var pricingPath string
	cmd := &cobra.Command{
		Use:   "cost",
		Short: "Rough per-namespace cost estimate from resource requests",
		Long: `Estimate monthly cost per namespace based on the sum of pod resource
requests and PVC storage requests, multiplied by a per-unit pricing file.

This is intentionally simple — it's not a replacement for Kubecost or cloud
billing. The goal is to give a small team a "which namespaces burn the most"
signal without running another cluster component.

Pricing defaults to rough US on-demand rates (AWS m5.large equivalent).
Override with --pricing pointing at a YAML file like:

  cpu_core_hour: 0.0316
  memory_gb_hour: 0.00456
  storage_gb_month:
    gp3: 0.08
    standard: 0.04
  currency: USD`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pricing, err := cost.LoadPricing(pricingPath)
			if err != nil {
				return err
			}

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

			report, err := cost.Estimate(cmd.Context(), client, cost.Options{Namespace: ns, Pricing: pricing})
			if err != nil {
				return err
			}
			return renderCostReport(cmd.OutOrStdout(), report)
		},
	}
	cmd.Flags().StringVar(&pricingPath, "pricing", "", "path to pricing.yaml (defaults to built-in rates)")
	return cmd
}

func renderCostReport(w io.Writer, report *cost.Report) error {
	if len(report.Namespaces) == 0 {
		fmt.Fprintln(w, "No workloads found to estimate.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAMESPACE\tCPU\tMEMORY\tSTORAGE\tCPU $/mo\tMEM $/mo\tSTORAGE $/mo\tTOTAL $/mo")
	for _, e := range report.Namespaces {
		fmt.Fprintf(tw,
			"%s\t%.2f cores\t%.2f GiB\t%.1f GiB\t%.2f\t%.2f\t%.2f\t%.2f\n",
			e.Namespace, e.CPUCores, e.MemoryGB, e.StorageGB,
			e.CPUCostMonth, e.MemoryCostMonth, e.StorageCostMonth, e.TotalMonth,
		)
	}
	fmt.Fprintf(tw, "\t\t\t\t\t\tTOTAL (%s)\t%.2f\n", report.Currency, report.Total)
	return tw.Flush()
}
