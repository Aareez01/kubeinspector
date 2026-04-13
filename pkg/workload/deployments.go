package workload

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AuditDeployments checks for Deployments with zero ready replicas.
func AuditDeployments(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	deploys, err := client.AppsV1().Deployments(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}

	var findings []Finding
	for _, d := range deploys.Items {
		if d.Spec.Replicas != nil && *d.Spec.Replicas == 0 {
			// Intentionally scaled to zero — skip.
			continue
		}
		if d.Status.ReadyReplicas == 0 {
			desired := int32(1)
			if d.Spec.Replicas != nil {
				desired = *d.Spec.Replicas
			}
			findings = append(findings, Finding{
				Severity:  SeverityCritical,
				Kind:      "Deployment",
				Namespace: d.Namespace,
				Name:      d.Name,
				Check:     "zero-ready-replicas",
				Message: fmt.Sprintf("0/%d replicas ready — workload is completely down",
					desired),
			})
		}
	}
	return findings, nil
}
