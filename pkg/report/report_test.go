package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Aareez01/kubeinspector/pkg/cost"
	"github.com/Aareez01/kubeinspector/pkg/ingress"
	"github.com/Aareez01/kubeinspector/pkg/orphans"
	"github.com/Aareez01/kubeinspector/pkg/security"
)

func sample() *Report {
	return &Report{
		Orphans: []orphans.Finding{
			{Kind: "PersistentVolumeClaim", Namespace: "app", Name: "stale", Reason: "not mounted"},
		},
		Ingress: []ingress.Finding{
			{Severity: ingress.SeverityWarning, Namespace: "web", Ingress: "site", Message: "no spec.tls"},
			{Severity: ingress.SeverityError, Namespace: "web", Ingress: "site", Message: "TLS secret missing"},
		},
		Security: []security.Finding{
			{Severity: security.SeverityCritical, Kind: "Pod", Namespace: "app", Name: "api", Container: "app", Check: "privileged", Message: "runs privileged"},
		},
		Cost: &cost.Report{
			Currency: "USD",
			Total:    42.00,
			Namespaces: []cost.NamespaceEstimate{
				{Namespace: "app", CPUCores: 1.0, MemoryGB: 2.0, StorageGB: 10, TotalMonth: 42.00},
			},
		},
	}
}

func TestRender_textContainsSections(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample(), FormatText); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Orphaned resources", "Ingress issues", "Security", "Cost estimate", "stale", "site", "privileged"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestRender_markdownTables(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample(), FormatMarkdown); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"# kubeinspector audit", "| Kind |", "| Severity |", "## Security", "privileged", "Total (USD)"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestRender_jsonIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample(), FormatJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"orphans"`) {
		t.Errorf("expected orphans key in JSON output, got: %s", buf.String())
	}
}

func TestRender_unknownFormatErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sample(), Format("xml")); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		r    *Report
		want int
	}{
		{"clean", &Report{}, 0},
		{"orphans → warning", &Report{Orphans: []orphans.Finding{{Kind: "PVC"}}}, 1},
		{"ingress warn → 1", &Report{Ingress: []ingress.Finding{{Severity: ingress.SeverityWarning}}}, 1},
		{"ingress error → 2", &Report{Ingress: []ingress.Finding{{Severity: ingress.SeverityError}}}, 2},
		{"security critical → 2", &Report{Security: []security.Finding{{Severity: security.SeverityCritical}}}, 2},
		{"security warning → 1", &Report{Security: []security.Finding{{Severity: security.SeverityWarning}}}, 1},
		{"mixed → 2", &Report{
			Orphans: []orphans.Finding{{Kind: "PVC"}},
			Ingress: []ingress.Finding{{Severity: ingress.SeverityError}},
		}, 2},
	}
	for _, tc := range cases {
		if got := ExitCode(tc.r); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
