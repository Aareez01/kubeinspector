package cmd

import (
	"github.com/spf13/cobra"
)

type GlobalOptions struct {
	Kubeconfig string
	Namespace  string
	Output     string
	AllNS      bool
}

func NewRootCmd() *cobra.Command {
	opts := &GlobalOptions{}

	root := &cobra.Command{
		Use:   "kubeinspector",
		Short: "Audit Kubernetes clusters for orphans, cost, and ingress issues",
		Long: `kubeinspector scans a Kubernetes cluster for cruft and misconfigurations:
orphaned PVCs and ConfigMaps, Ingresses with missing TLS or duplicate hosts,
and a rough per-namespace cost estimate based on resource requests.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&opts.Kubeconfig, "kubeconfig", "", "path to kubeconfig (defaults to $KUBECONFIG or ~/.kube/config)")
	root.PersistentFlags().StringVarP(&opts.Namespace, "namespace", "n", "", "namespace to scan (default: current context namespace)")
	root.PersistentFlags().BoolVarP(&opts.AllNS, "all-namespaces", "A", false, "scan all namespaces")
	root.PersistentFlags().StringVarP(&opts.Output, "output", "o", "text", "output format: text, json, markdown")

	root.AddCommand(newOrphansCmd(opts))
	root.AddCommand(newIngressCmd(opts))
	root.AddCommand(newCostCmd(opts))
	root.AddCommand(newAuditCmd(opts))
	root.AddCommand(newVersionCmd())

	return root
}
