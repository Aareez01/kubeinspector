// Package ingress audits Kubernetes Ingress resources for common
// misconfigurations: duplicate host+path combinations, missing TLS,
// TLS secrets that don't exist, and backends pointing at Services or
// ports that don't exist.
package ingress

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Severity of a finding.
type Severity string

const (
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Finding is one issue detected on an Ingress resource.
type Finding struct {
	Severity  Severity `json:"severity"`
	Namespace string   `json:"namespace"`
	Ingress   string   `json:"ingress"`
	Rule      string   `json:"rule,omitempty"`
	Message   string   `json:"message"`
}

// Options configures the audit.
type Options struct {
	// Namespace to scan. Empty means all namespaces.
	Namespace string
}

// Audit runs all ingress checks and returns the combined findings.
func Audit(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	ingresses, err := client.NetworkingV1().Ingresses(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses: %w", err)
	}

	var findings []Finding
	findings = append(findings, checkDuplicateHosts(ingresses.Items)...)
	findings = append(findings, checkMissingTLS(ingresses.Items)...)

	tlsFindings, err := checkTLSSecrets(ctx, client, ingresses.Items)
	if err != nil {
		return nil, err
	}
	findings = append(findings, tlsFindings...)

	backendFindings, err := checkBackends(ctx, client, ingresses.Items)
	if err != nil {
		return nil, err
	}
	findings = append(findings, backendFindings...)

	return findings, nil
}

// checkDuplicateHosts flags (host, path) pairs claimed by more than one
// Ingress. Which one actually serves traffic is controller-specific, so this
// is almost always a mistake.
func checkDuplicateHosts(items []networkingv1.Ingress) []Finding {
	type key struct{ host, path string }
	seen := make(map[key][]string) // key → list of "namespace/name"

	for _, ing := range items {
		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				k := key{host: host, path: path.Path}
				seen[k] = append(seen[k], ing.Namespace+"/"+ing.Name)
			}
		}
	}

	var findings []Finding
	for k, owners := range seen {
		if len(owners) < 2 {
			continue
		}
		for _, o := range owners {
			ns, name := splitNN(o)
			findings = append(findings, Finding{
				Severity:  SeverityError,
				Namespace: ns,
				Ingress:   name,
				Rule:      fmt.Sprintf("%s%s", k.host, k.path),
				Message:   fmt.Sprintf("duplicate host+path also claimed by %v", others(owners, o)),
			})
		}
	}
	return findings
}

func checkMissingTLS(items []networkingv1.Ingress) []Finding {
	var findings []Finding
	for _, ing := range items {
		hasHost := false
		for _, r := range ing.Spec.Rules {
			if r.Host != "" {
				hasHost = true
				break
			}
		}
		if !hasHost {
			continue
		}
		if len(ing.Spec.TLS) == 0 {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Namespace: ing.Namespace,
				Ingress:   ing.Name,
				Message:   "hosts defined but no spec.tls block — traffic will be plain HTTP",
			})
		}
	}
	return findings
}

func checkTLSSecrets(ctx context.Context, client kubernetes.Interface, items []networkingv1.Ingress) ([]Finding, error) {
	var findings []Finding
	for _, ing := range items {
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName == "" {
				continue
			}
			_, err := client.CoreV1().Secrets(ing.Namespace).Get(ctx, tls.SecretName, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				findings = append(findings, Finding{
					Severity:  SeverityError,
					Namespace: ing.Namespace,
					Ingress:   ing.Name,
					Rule:      tls.SecretName,
					Message:   fmt.Sprintf("TLS secret %q does not exist", tls.SecretName),
				})
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("get secret %s/%s: %w", ing.Namespace, tls.SecretName, err)
			}
		}
	}
	return findings, nil
}

func checkBackends(ctx context.Context, client kubernetes.Interface, items []networkingv1.Ingress) ([]Finding, error) {
	var findings []Finding
	for _, ing := range items {
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				if p.Backend.Service == nil {
					continue
				}
				svcName := p.Backend.Service.Name
				svc, err := client.CoreV1().Services(ing.Namespace).Get(ctx, svcName, metav1.GetOptions{})
				if errors.IsNotFound(err) {
					findings = append(findings, Finding{
						Severity:  SeverityError,
						Namespace: ing.Namespace,
						Ingress:   ing.Name,
						Rule:      fmt.Sprintf("%s%s", rule.Host, p.Path),
						Message:   fmt.Sprintf("backend Service %q does not exist", svcName),
					})
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("get service %s/%s: %w", ing.Namespace, svcName, err)
				}
				if !servicePortDefined(svc.Spec.Ports, p.Backend.Service.Port) {
					findings = append(findings, Finding{
						Severity:  SeverityError,
						Namespace: ing.Namespace,
						Ingress:   ing.Name,
						Rule:      fmt.Sprintf("%s%s", rule.Host, p.Path),
						Message:   fmt.Sprintf("backend Service %q has no matching port", svcName),
					})
				}
			}
		}
	}
	return findings, nil
}

func servicePortDefined(ports []corev1.ServicePort, wanted networkingv1.ServiceBackendPort) bool {
	for _, sp := range ports {
		if wanted.Name != "" && sp.Name == wanted.Name {
			return true
		}
		if wanted.Number != 0 && sp.Port == wanted.Number {
			return true
		}
	}
	return false
}

func splitNN(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:]
		}
	}
	return "", s
}

func others(all []string, self string) []string {
	out := make([]string, 0, len(all)-1)
	for _, x := range all {
		if x != self {
			out = append(out, x)
		}
	}
	return out
}
