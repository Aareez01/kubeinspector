package security

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuditRBAC_clusterAdminBinding(t *testing.T) {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "dev-admin"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{
			Kind: "User", Name: "developer@example.com",
		}},
	}
	cs := fake.NewSimpleClientset(crb)
	got, err := AuditRBAC(context.Background(), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "cluster-admin-binding")
	if len(hits) != 1 {
		t.Fatalf("expected 1 cluster-admin-binding finding, got %d: %+v", len(hits), got)
	}
	if hits[0].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", hits[0].Severity)
	}
}

func TestAuditRBAC_systemSubjectSkipped(t *testing.T) {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "system-binding"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{
			Kind: "User", Name: "system:admin",
		}},
	}
	cs := fake.NewSimpleClientset(crb)
	got, _ := AuditRBAC(context.Background(), cs, Options{})
	hits := findCheck(got, "cluster-admin-binding")
	if len(hits) != 0 {
		t.Fatalf("system subjects should be skipped, got %+v", hits)
	}
}

func TestAuditRBAC_wildcardClusterRole(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "overly-permissive"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}
	cs := fake.NewSimpleClientset(cr)
	got, _ := AuditRBAC(context.Background(), cs, Options{})
	hits := findCheck(got, "wildcard-permissions")
	if len(hits) != 1 {
		t.Fatalf("expected wildcard-permissions finding, got %+v", got)
	}
}

func TestAuditRBAC_builtInRolesSkipped(t *testing.T) {
	// Built-in roles like "admin", "edit", "view", "cluster-admin" have
	// wildcards but should not be flagged.
	for _, name := range []string{"admin", "edit", "view", "cluster-admin"} {
		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
			}},
		}
		cs := fake.NewSimpleClientset(cr)
		got, _ := AuditRBAC(context.Background(), cs, Options{})
		if len(findCheck(got, "wildcard-permissions")) != 0 {
			t.Errorf("built-in role %q should be skipped", name)
		}
	}
}

func TestAuditRBAC_wildcardNamespacedRole(t *testing.T) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-wildcard", Namespace: "app"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"},
		}},
	}
	cs := fake.NewSimpleClientset(role)
	got, _ := AuditRBAC(context.Background(), cs, Options{Namespace: "app"})
	hits := findCheck(got, "wildcard-permissions")
	if len(hits) != 1 || hits[0].Kind != "Role" {
		t.Fatalf("expected namespaced Role wildcard finding, got %+v", got)
	}
}
