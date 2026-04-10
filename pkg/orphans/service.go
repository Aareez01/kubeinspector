package orphans

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// FindOrphanServices returns Services whose Endpoints object has no ready
// addresses — typically caused by a label-selector mismatch or a deleted
// backing Deployment. ExternalName services and headless Services used purely
// for StatefulSet DNS are skipped.
func FindOrphanServices(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	grace := opts.GracePeriod
	if grace == 0 {
		grace = 10 * time.Minute
	}

	svcs, err := client.CoreV1().Services(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}

	now := time.Now()
	var findings []Finding
	for _, svc := range svcs.Items {
		if svc.Annotations[KeepAnnotation] == "true" {
			continue
		}
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			// Headless / manually-managed endpoints, user knows what they're doing.
			continue
		}
		age := now.Sub(svc.CreationTimestamp.Time)
		if age < grace {
			continue
		}

		ep, err := client.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			findings = append(findings, Finding{
				Kind:      "Service",
				Namespace: svc.Namespace,
				Name:      svc.Name,
				Age:       age.Truncate(time.Second),
				Reason:    "no Endpoints object exists",
			})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("get endpoints %s/%s: %w", svc.Namespace, svc.Name, err)
		}
		if hasReadyAddresses(ep) {
			continue
		}
		findings = append(findings, Finding{
			Kind:      "Service",
			Namespace: svc.Namespace,
			Name:      svc.Name,
			Age:       age.Truncate(time.Second),
			Reason:    "selector matches no ready pods",
		})
	}
	return findings, nil
}

func hasReadyAddresses(ep *corev1.Endpoints) bool {
	for _, s := range ep.Subsets {
		if len(s.Addresses) > 0 {
			return true
		}
	}
	return false
}
