// Package report renders combined audit results in text, JSON, or markdown.
// It's the common rendering layer used by the `audit` subcommand so each
// individual check package stays focused on detection.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Aareez01/kubeinspector/pkg/cost"
	"github.com/Aareez01/kubeinspector/pkg/ingress"
	"github.com/Aareez01/kubeinspector/pkg/orphans"
	"github.com/Aareez01/kubeinspector/pkg/security"
	"github.com/Aareez01/kubeinspector/pkg/workload"
)

// Report is the combined output of an audit run.
type Report struct {
	Orphans  []orphans.Finding  `json:"orphans,omitempty"`
	Ingress  []ingress.Finding  `json:"ingress,omitempty"`
	Security []security.Finding `json:"security,omitempty"`
	Workload []workload.Finding `json:"workload,omitempty"`
	Cost     *cost.Report       `json:"cost,omitempty"`
}

// Format selects the output format.
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// Render writes the report to w in the requested format.
func Render(w io.Writer, r *Report, format Format) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, r)
	case FormatMarkdown:
		return renderMarkdown(w, r)
	case FormatText, "":
		return renderText(w, r)
	default:
		return fmt.Errorf("unknown output format %q (want text, json, or markdown)", format)
	}
}

// ExitCode returns the suggested process exit code for this report:
//
//	0 — no findings
//	1 — at least one warning-level finding
//	2 — at least one error-level finding
//
// Errors take precedence over warnings.
func ExitCode(r *Report) int {
	hasError, hasWarning := false, false
	for _, f := range r.Ingress {
		switch f.Severity {
		case ingress.SeverityError:
			hasError = true
		case ingress.SeverityWarning:
			hasWarning = true
		}
	}
	for _, f := range r.Security {
		switch f.Severity {
		case security.SeverityCritical:
			hasError = true
		case security.SeverityWarning:
			hasWarning = true
		}
	}
	for _, f := range r.Workload {
		switch f.Severity {
		case workload.SeverityCritical:
			hasError = true
		case workload.SeverityWarning:
			hasWarning = true
		}
	}
	if len(r.Orphans) > 0 {
		hasWarning = true
	}
	switch {
	case hasError:
		return 2
	case hasWarning:
		return 1
	default:
		return 0
	}
}

func renderJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func renderText(w io.Writer, r *Report) error {
	fmt.Fprintln(w, "== Orphaned resources ==")
	if len(r.Orphans) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  KIND\tNAMESPACE\tNAME\tAGE\tREASON")
		for _, f := range r.Orphans {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", f.Kind, f.Namespace, f.Name, f.Age, f.Reason)
		}
		tw.Flush()
	}

	fmt.Fprintln(w, "\n== Ingress issues ==")
	if len(r.Ingress) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tNAMESPACE\tINGRESS\tRULE\tMESSAGE")
		for _, f := range r.Ingress {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", f.Severity, f.Namespace, f.Ingress, f.Rule, f.Message)
		}
		tw.Flush()
	}

	fmt.Fprintln(w, "\n== Workload health ==")
	if len(r.Workload) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tKIND\tNAMESPACE\tNAME\tCHECK\tMESSAGE")
		for _, f := range r.Workload {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				f.Severity, f.Kind, f.Namespace, f.Name, f.Check, f.Message)
		}
		tw.Flush()
	}

	fmt.Fprintln(w, "\n== Security ==")
	if len(r.Security) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tKIND\tNAMESPACE\tNAME\tCONTAINER\tCHECK\tMESSAGE")
		for _, f := range r.Security {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				f.Severity, f.Kind, f.Namespace, f.Name, f.Container, f.Check, f.Message)
		}
		tw.Flush()
	}

	fmt.Fprintln(w, "\n== Cost estimate ==")
	if r.Cost == nil || len(r.Cost.Namespaces) == 0 {
		fmt.Fprintln(w, "  no workloads")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAMESPACE\tCPU\tMEMORY\tSTORAGE\tTOTAL $/mo")
		for _, e := range r.Cost.Namespaces {
			fmt.Fprintf(tw, "  %s\t%.2f\t%.2f GiB\t%.1f GiB\t%.2f\n",
				e.Namespace, e.CPUCores, e.MemoryGB, e.StorageGB, e.TotalMonth)
		}
		fmt.Fprintf(tw, "  \t\t\t%s total\t%.2f\n", r.Cost.Currency, r.Cost.Total)
		tw.Flush()
	}

	return nil
}

func renderMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder

	b.WriteString("# kubeinspector audit\n\n")

	b.WriteString("## Orphaned resources\n\n")
	if len(r.Orphans) == 0 {
		b.WriteString("_None_\n\n")
	} else {
		b.WriteString("| Kind | Namespace | Name | Age | Reason |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, f := range r.Orphans {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.Kind, f.Namespace, f.Name, f.Age, f.Reason)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Ingress issues\n\n")
	if len(r.Ingress) == 0 {
		b.WriteString("_None_\n\n")
	} else {
		b.WriteString("| Severity | Namespace | Ingress | Rule | Message |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, f := range r.Ingress {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.Severity, f.Namespace, f.Ingress, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Workload health\n\n")
	if len(r.Workload) == 0 {
		b.WriteString("_None_\n\n")
	} else {
		b.WriteString("| Severity | Kind | Namespace | Name | Check | Message |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, f := range r.Workload {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
				f.Severity, f.Kind, f.Namespace, f.Name, f.Check, f.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Security\n\n")
	if len(r.Security) == 0 {
		b.WriteString("_None_\n\n")
	} else {
		b.WriteString("| Severity | Kind | Namespace | Name | Container | Check | Message |\n")
		b.WriteString("|---|---|---|---|---|---|---|\n")
		for _, f := range r.Security {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
				f.Severity, f.Kind, f.Namespace, f.Name, f.Container, f.Check, f.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Cost estimate\n\n")
	if r.Cost == nil || len(r.Cost.Namespaces) == 0 {
		b.WriteString("_No workloads_\n\n")
	} else {
		b.WriteString("| Namespace | CPU | Memory | Storage | Total $/mo |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, e := range r.Cost.Namespaces {
			fmt.Fprintf(&b, "| %s | %.2f cores | %.2f GiB | %.1f GiB | %.2f |\n",
				e.Namespace, e.CPUCores, e.MemoryGB, e.StorageGB, e.TotalMonth)
		}
		fmt.Fprintf(&b, "\n**Total (%s): %.2f/month**\n", r.Cost.Currency, r.Cost.Total)
	}

	_, err := io.WriteString(w, b.String())
	return err
}
