package filter

import "testing"

func TestExcluded(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		ns       string
		want     bool
	}{
		{"no patterns excludes nothing", nil, "kube-system", false},
		{"exact match", []string{"kube-system"}, "kube-system", true},
		{"exact non-match", []string{"kube-system"}, "production", false},
		{"glob prefix", []string{"kube-*"}, "kube-node-lease", true},
		{"glob does not over-match", []string{"kube-*"}, "mykube-system", false},
		{"glob suffix", []string{"*-system"}, "calico-system", true},
		{"second pattern matches", []string{"staging", "production"}, "production", true},

		// Cluster-scoped findings (ClusterRoleBinding, Node) have no
		// namespace; excluding them would silently drop the critical
		// cluster-admin RBAC checks.
		{"empty namespace never excluded", []string{"kube-system"}, "", false},
		{"empty namespace not matched by star", []string{"*"}, "", false},

		// A bare --exclude-namespaces= must not nuke the whole report.
		{"empty pattern ignored", []string{""}, "production", false},

		// path.Match rejects an unterminated [ — the bad pattern should be
		// skipped rather than silently matching or panicking.
		{"malformed glob does not match", []string{"[bad"}, "production", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := New(tc.patterns).Excluded(tc.ns); got != tc.want {
				t.Errorf("Excluded(%q) with %v = %v, want %v", tc.ns, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestEmpty(t *testing.T) {
	if !New(nil).Empty() {
		t.Error("New(nil) should be empty")
	}
	if !New([]string{"", ""}).Empty() {
		t.Error("filter of only blank patterns should be empty")
	}
	if New([]string{"kube-system"}).Empty() {
		t.Error("filter with a pattern should not be empty")
	}
}

type finding struct{ ns, name string }

func nsOf(f finding) string { return f.ns }

func TestApply(t *testing.T) {
	items := []finding{
		{"kube-system", "aws-node"},
		{"production", "webapp"},
		{"kube-public", "cluster-info"},
		{"staging", "api"},
	}

	got := Apply(items, New([]string{"kube-*"}), nsOf)
	if len(got) != 2 || got[0].name != "webapp" || got[1].name != "api" {
		t.Fatalf("expected webapp and api in order, got %v", got)
	}

	// Order must survive filtering — reports are read top to bottom.
	all := Apply(items, New(nil), nsOf)
	if len(all) != len(items) {
		t.Errorf("empty filter should pass everything, got %d of %d", len(all), len(items))
	}

	if got := Apply(items, New([]string{"*"}), nsOf); got != nil {
		t.Errorf("excluding everything should yield nil, got %v", got)
	}

	if got := Apply(nil, New([]string{"kube-*"}), nsOf); got != nil {
		t.Errorf("nil input should yield nil, got %v", got)
	}
}

func TestSystemNamespacesCoversCommonAddons(t *testing.T) {
	f := New(SystemNamespaces)
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease"} {
		if !f.Excluded(ns) {
			t.Errorf("SystemNamespaces should cover %q", ns)
		}
	}
	// User namespaces must never be swept up by the preset.
	for _, ns := range []string{"production", "staging", "default"} {
		if f.Excluded(ns) {
			t.Errorf("SystemNamespaces must not cover %q", ns)
		}
	}
}
