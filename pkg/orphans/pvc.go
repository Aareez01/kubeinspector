package orphans

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// FindOrphanPVCs returns PVCs that exist but are not mounted by any pod.
// PVCs younger than opts.GracePeriod are skipped.
func FindOrphanPVCs(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	grace := opts.GracePeriod
	if grace == 0 {
		grace = 10 * time.Minute
	}

	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	// key: namespace/claimName → mounted
	mounted := make(map[string]bool)
	for _, pod := range pods.Items {
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim == nil {
				continue
			}
			mounted[pod.Namespace+"/"+vol.PersistentVolumeClaim.ClaimName] = true
		}
	}

	pvcs, err := client.CoreV1().PersistentVolumeClaims(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pvcs: %w", err)
	}

	now := time.Now()
	var findings []Finding
	for _, pvc := range pvcs.Items {
		if pvc.Annotations[KeepAnnotation] == "true" {
			continue
		}
		age := now.Sub(pvc.CreationTimestamp.Time)
		if age < grace {
			continue
		}
		if mounted[pvc.Namespace+"/"+pvc.Name] {
			continue
		}
		findings = append(findings, Finding{
			Kind:      "PersistentVolumeClaim",
			Namespace: pvc.Namespace,
			Name:      pvc.Name,
			Age:       age.Truncate(time.Second),
			Reason:    "not mounted by any pod",
		})
	}
	return findings, nil
}
