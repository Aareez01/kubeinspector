package cmd

import "testing"

func TestVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	if cmd.Use != "version" {
		t.Fatalf("expected Use=version, got %q", cmd.Use)
	}
}

func TestRootHasSubcommands(t *testing.T) {
	root := NewRootCmd()
	want := []string{"orphans", "ingress", "cost", "security", "audit", "version"}
	for _, name := range want {
		found := false
		for _, c := range root.Commands() {
			if c.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing subcommand: %s", name)
		}
	}
}
