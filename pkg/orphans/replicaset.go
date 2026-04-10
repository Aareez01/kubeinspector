package orphans

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultReplicaSetGrace is the minimum age for a scaled-to-zero ReplicaSet
// before it's considered cruft. Kubernetes' revisionHistoryLimit already keeps
// recent rollback history; this catches older leftovers.
const DefaultReplicaSetGrace = 7 * 24 * time.Hour

// FindOrphanReplicaSets returns Deployment-owned ReplicaSets that have been
// scaled to zero for longer than opts.GracePeriod (default 7d).
func FindOrphanReplicaSets(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	grace := opts.GracePeriod
	if grace == 0 {
		grace = DefaultReplicaSetGrace
	}

	rsList, err := client.AppsV1().ReplicaSets(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list replicasets: %w", err)
	}

	now := time.Now()
	var findings []Finding
	for _, rs := range rsList.Items {
		if rs.Annotations[KeepAnnotation] == "true" {
			continue
		}
		if rs.Status.Replicas != 0 || (rs.Spec.Replicas != nil && *rs.Spec.Replicas != 0) {
			continue
		}
		if !ownedByDeployment(rs.OwnerReferences) {
			continue
		}
		age := now.Sub(rs.CreationTimestamp.Time)
		if age < grace {
			continue
		}
		findings = append(findings, Finding{
			Kind:      "ReplicaSet",
			Namespace: rs.Namespace,
			Name:      rs.Name,
			Age:       age.Truncate(time.Second),
			Reason:    "scaled to zero, owned by Deployment (rollback history)",
		})
	}
	return findings, nil
}

func ownedByDeployment(refs []metav1.OwnerReference) bool {
	for _, o := range refs {
		if o.Kind == "Deployment" {
			return true
		}
	}
	return false
}
