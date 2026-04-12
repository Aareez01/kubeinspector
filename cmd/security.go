package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/kube"
	"github.com/Aareez01/kubeinspector/pkg/security"
	"github.com/spf13/cobra"
)

func newSecurityCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "security",
		Short: "Audit pods and RBAC for common security misconfigurations",
		Long: `Scan pods for privileged containers, host namespace usage, dangerous
capabilities, writable root filesystems, missing resource limits, default
ServiceAccount tokens, secrets exposed via environment variables,
cryptocurrency mining indicators, and abnormal resource consumption.

Also checks ClusterRoleBindings for non-system cluster-admin grants and
roles with wildcard permissions.`,
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
			o := security.Options{Namespace: ns}

			var all []security.Finding
			for _, step := range []func() ([]security.Finding, error){
				func() ([]security.Finding, error) { return security.AuditPods(ctx, client, o) },
				func() ([]security.Finding, error) { return security.AuditRBAC(ctx, client, o) },
				func() ([]security.Finding, error) { return security.AuditMiners(ctx, client, o) },
				func() ([]security.Finding, error) { return security.AuditResourceAbuse(ctx, client, o) },
			} {
				f, err := step()
				if err != nil {
					return err
				}
				all = append(all, f...)
			}
			return renderSecurityFindings(cmd.OutOrStdout(), all)
		},
	}
}

func renderSecurityFindings(w io.Writer, findings []security.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No security issues found.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tKIND\tNAMESPACE\tNAME\tCONTAINER\tCHECK\tMESSAGE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Kind, f.Namespace, f.Name, f.Container, f.Check, f.Message)
	}
	return tw.Flush()
}
