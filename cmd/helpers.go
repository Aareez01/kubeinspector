package cmd

import (
	"github.com/Aareez01/kubeinspector/pkg/bestpractice"
	"github.com/Aareez01/kubeinspector/pkg/cost"
	"github.com/Aareez01/kubeinspector/pkg/filter"
	"github.com/Aareez01/kubeinspector/pkg/ingress"
	"github.com/Aareez01/kubeinspector/pkg/orphans"
	"github.com/Aareez01/kubeinspector/pkg/security"
	"github.com/Aareez01/kubeinspector/pkg/workload"
)

func resolveNS(opts *GlobalOptions, defaultNS string) string {
	if opts.AllNS {
		return ""
	}
	if opts.Namespace != "" {
		return opts.Namespace
	}
	return defaultNS
}

// nsFilter builds the namespace exclusion filter from --exclude-namespaces and
// --exclude-system.
func nsFilter(opts *GlobalOptions) filter.Namespaces {
	patterns := append([]string{}, opts.ExcludeNamespaces...)
	if opts.ExcludeSystem {
		patterns = append(patterns, filter.SystemNamespaces...)
	}
	return filter.New(patterns)
}

// The filter* helpers below exist because each check package has its own
// Finding type with no shared interface; a tiny accessor per type keeps the
// packages decoupled without reflection.

func filterOrphans(f []orphans.Finding, ns filter.Namespaces) []orphans.Finding {
	return filter.Apply(f, ns, func(x orphans.Finding) string { return x.Namespace })
}

func filterIngress(f []ingress.Finding, ns filter.Namespaces) []ingress.Finding {
	return filter.Apply(f, ns, func(x ingress.Finding) string { return x.Namespace })
}

func filterSecurity(f []security.Finding, ns filter.Namespaces) []security.Finding {
	return filter.Apply(f, ns, func(x security.Finding) string { return x.Namespace })
}

func filterWorkload(f []workload.Finding, ns filter.Namespaces) []workload.Finding {
	return filter.Apply(f, ns, func(x workload.Finding) string { return x.Namespace })
}

func filterBestPractice(f []bestpractice.Finding, ns filter.Namespaces) []bestpractice.Finding {
	return filter.Apply(f, ns, func(x bestpractice.Finding) string { return x.Namespace })
}

// filterCost drops excluded namespaces from a cost report and recomputes the
// total, so the printed total always matches the rows above it.
func filterCost(r *cost.Report, ns filter.Namespaces) *cost.Report {
	if r == nil || ns.Empty() {
		return r
	}
	kept := filter.Apply(r.Namespaces, ns, func(e cost.NamespaceEstimate) string { return e.Namespace })
	total := 0.0
	for _, e := range kept {
		total += e.TotalMonth
	}
	out := *r
	out.Namespaces = kept
	out.Total = total
	return &out
}
