package workload

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// AuditServiceSelectors checks for Services whose label selector doesn't
// match any pod at all — a step beyond "no endpoints" (which could be
// transient), this indicates a label-selector mismatch that will never resolve
// without a fix.
func AuditServiceSelectors(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	svcs, err := client.CoreV1().Services(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var findings []Finding
	for _, svc := range svcs.Items {
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		matched := false
		for _, pod := range pods.Items {
			if pod.Namespace != svc.Namespace {
				continue
			}
			if sel.Matches(labels.Set(pod.Labels)) {
				matched = true
				break
			}
		}
		if !matched {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Service",
				Namespace: svc.Namespace,
				Name:      svc.Name,
				Check:     "selector-mismatch",
				Message: fmt.Sprintf("selector %v matches zero pods — broken label selector or missing workload",
					svc.Spec.Selector),
			})
		}
	}
	return findings, nil
}
