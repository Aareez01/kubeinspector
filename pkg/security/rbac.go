package security

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// systemSubjectPrefixes are service accounts and groups that are expected to
// hold cluster-admin. We don't flag these because they're standard Kubernetes
// bootstrapping.
var systemSubjectPrefixes = []string{
	"system:",
	"eks:",
	"gke-",
}

// AuditRBAC checks ClusterRoleBindings and ClusterRoles for dangerous
// permission grants.
func AuditRBAC(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	var findings []Finding

	crbFindings, err := checkClusterAdminBindings(ctx, client)
	if err != nil {
		return nil, err
	}
	findings = append(findings, crbFindings...)

	crFindings, err := checkWildcardRoles(ctx, client)
	if err != nil {
		return nil, err
	}
	findings = append(findings, crFindings...)

	roleFindings, err := checkWildcardNamespacedRoles(ctx, client, opts)
	if err != nil {
		return nil, err
	}
	findings = append(findings, roleFindings...)

	return findings, nil
}

// checkClusterAdminBindings flags ClusterRoleBindings that grant cluster-admin
// to subjects that aren't part of the kube-system bootstrapping.
func checkClusterAdminBindings(ctx context.Context, client kubernetes.Interface) ([]Finding, error) {
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}

	var findings []Finding
	for _, crb := range crbs.Items {
		if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subj := range crb.Subjects {
			if isSystemSubject(subj) {
				continue
			}
			findings = append(findings, Finding{
				Severity:  SeverityCritical,
				Kind:      "ClusterRoleBinding",
				Namespace: subj.Namespace,
				Name:      crb.Name,
				Check:     "cluster-admin-binding",
				Message: fmt.Sprintf("%s %q bound to cluster-admin — has full control over the entire cluster",
					subj.Kind, qualifiedSubject(subj)),
			})
		}
	}
	return findings, nil
}

// checkWildcardRoles flags ClusterRoles with wildcard resources or verbs.
func checkWildcardRoles(ctx context.Context, client kubernetes.Interface) ([]Finding, error) {
	roles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}

	var findings []Finding
	for _, role := range roles.Items {
		if isSystemRole(role.Name) {
			continue
		}
		for _, rule := range role.Rules {
			if hasWildcard(rule.Resources) || hasWildcard(rule.Verbs) {
				findings = append(findings, Finding{
					Severity: SeverityWarning,
					Kind:     "ClusterRole",
					Name:     role.Name,
					Check:    "wildcard-permissions",
					Message:  fmt.Sprintf("rule grants wildcard permissions: resources=%v verbs=%v", rule.Resources, rule.Verbs),
				})
			}
		}
	}
	return findings, nil
}

// checkWildcardNamespacedRoles checks namespace-scoped Roles for wildcards.
func checkWildcardNamespacedRoles(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	roles, err := client.RbacV1().Roles(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}

	var findings []Finding
	for _, role := range roles.Items {
		for _, rule := range role.Rules {
			if hasWildcard(rule.Resources) || hasWildcard(rule.Verbs) {
				findings = append(findings, Finding{
					Severity:  SeverityWarning,
					Kind:      "Role",
					Namespace: role.Namespace,
					Name:      role.Name,
					Check:     "wildcard-permissions",
					Message:   fmt.Sprintf("rule grants wildcard permissions: resources=%v verbs=%v", rule.Resources, rule.Verbs),
				})
			}
		}
	}
	return findings, nil
}

func isSystemSubject(subj rbacv1.Subject) bool {
	name := subj.Name
	if subj.Kind == "ServiceAccount" {
		name = subj.Namespace + ":" + subj.Name
	}
	for _, prefix := range systemSubjectPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func isSystemRole(name string) bool {
	for _, prefix := range systemSubjectPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	// Built-in roles
	switch name {
	case "cluster-admin", "admin", "edit", "view":
		return true
	}
	return false
}

func qualifiedSubject(subj rbacv1.Subject) string {
	if subj.Namespace != "" {
		return subj.Namespace + "/" + subj.Name
	}
	return subj.Name
}

func hasWildcard(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}
