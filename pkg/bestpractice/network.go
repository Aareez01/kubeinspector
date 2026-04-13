package bestpractice

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// AuditNetworkPolicies checks for pods that have zero NetworkPolicies
// applied to them, leaving them fully open to intra-cluster traffic.
func AuditNetworkPolicies(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	policies, err := client.NetworkingV1().NetworkPolicies(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}

	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	// For each pod, check if any NetworkPolicy selects it
	var findings []Finding
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		covered := false
		for _, np := range policies.Items {
			if np.Namespace != pod.Namespace {
				continue
			}
			sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
			if err != nil {
				continue
			}
			if sel.Matches(labels.Set(pod.Labels)) {
				covered = true
				break
			}
		}
		if !covered {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Check:     "no-network-policy",
				Message:   "no NetworkPolicy applies to this pod — all intra-cluster traffic is allowed",
			})
		}
	}
	return findings, nil
}

// AuditNodePorts checks for Services of type NodePort, which expose ports on
// every cluster node and are often unintentional external attack surface.
func AuditNodePorts(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	svcs, err := client.CoreV1().Services(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	var findings []Finding
	for _, svc := range svcs.Items {
		if svc.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		ports := make([]string, 0, len(svc.Spec.Ports))
		for _, p := range svc.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%d→%d", p.NodePort, p.Port))
		}
		findings = append(findings, Finding{
			Severity:  SeverityWarning,
			Kind:      "Service",
			Namespace: svc.Namespace,
			Name:      svc.Name,
			Check:     "nodeport-exposed",
			Message: fmt.Sprintf("NodePort service exposes ports %v on every node — verify this is intentional",
				ports),
		})
	}
	return findings, nil
}

// AuditLoadBalancers checks for LoadBalancer services that might be
// unintentionally exposing internal services to the internet.
func AuditLoadBalancers(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	svcs, err := client.CoreV1().Services(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	var findings []Finding
	for _, svc := range svcs.Items {
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		isInternal := false
		for _, annotation := range []string{
			"service.beta.kubernetes.io/aws-load-balancer-internal",
			"cloud.google.com/load-balancer-type",
			"service.beta.kubernetes.io/azure-load-balancer-internal",
		} {
			if v, ok := svc.Annotations[annotation]; ok {
				if v == "true" || v == "Internal" {
					isInternal = true
				}
			}
		}
		if isInternal {
			continue
		}

		status := "pending"
		if len(svc.Status.LoadBalancer.Ingress) > 0 {
			ing := svc.Status.LoadBalancer.Ingress[0]
			if ing.Hostname != "" {
				status = ing.Hostname
			} else if ing.IP != "" {
				status = ing.IP
			}
		}
		findings = append(findings, Finding{
			Severity:  SeverityWarning,
			Kind:      "Service",
			Namespace: svc.Namespace,
			Name:      svc.Name,
			Check:     "public-lb",
			Message:   fmt.Sprintf("public LoadBalancer (%s) — verify this should be internet-facing", status),
		})
	}
	return findings, nil
}
