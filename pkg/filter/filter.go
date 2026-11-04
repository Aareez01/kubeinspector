// Package filter provides namespace exclusion shared by every check.
//
// Filtering happens on findings rather than on the List calls that produce
// them. That is deliberate: checks like orphan detection decide whether a
// ConfigMap is referenced by scanning pods across the whole cluster, so
// narrowing the List would turn a referenced object into a false orphan.
// Excluding at the reporting stage keeps cross-namespace reference checks
// correct while still dropping the noise.
package filter

import "path"

// SystemNamespaces holds namespaces whose workloads are managed by the cluster
// provider or by cluster add-ons. Their pods legitimately run privileged, on
// the host network, and without resource limits, so reporting them buries the
// findings an operator can actually act on.
//
// This is a convenience preset for --exclude-system, not an allowlist: a
// compromised workload can hide in kube-system precisely because it is boring,
// so the exclusion is opt-in rather than the default.
var SystemNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"kube-flannel",
	"local-path-storage",
	"calico-system",
	"tigera-operator",
	"gatekeeper-system",
	"amazon-cloudwatch",
	"aws-observability",
}

// Namespaces reports whether a namespace should be excluded from a report.
// Patterns are matched with path.Match, so "kube-*" excludes every
// kube-prefixed namespace. The zero value excludes nothing.
type Namespaces struct {
	patterns []string
}

// New builds a filter from literal namespace names or glob patterns. Empty
// patterns are ignored, so a bare --exclude-namespaces= does not silently
// exclude everything.
func New(patterns []string) Namespaces {
	var kept []string
	for _, p := range patterns {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return Namespaces{patterns: kept}
}

// Excluded reports whether ns matches any pattern.
//
// Cluster-scoped findings (ClusterRoleBindings, nodes) carry an empty
// namespace and are never excluded — there is no namespace to match them
// against, and dropping them would hide the highest-severity RBAC checks.
func (f Namespaces) Excluded(ns string) bool {
	if ns == "" {
		return false
	}
	for _, p := range f.patterns {
		if p == ns {
			return true
		}
		if ok, err := path.Match(p, ns); err == nil && ok {
			return true
		}
	}
	return false
}

// Empty reports whether this filter would exclude nothing, letting callers
// skip a copy of the findings slice.
func (f Namespaces) Empty() bool { return len(f.patterns) == 0 }

// Apply returns the items whose namespace is not excluded, preserving order.
// nsOf extracts the namespace from a finding, which differs per check package.
func Apply[T any](items []T, f Namespaces, nsOf func(T) string) []T {
	if f.Empty() || len(items) == 0 {
		return items
	}
	kept := make([]T, 0, len(items))
	for _, it := range items {
		if !f.Excluded(nsOf(it)) {
			kept = append(kept, it)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}
