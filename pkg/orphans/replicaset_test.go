package orphans

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func int32p(v int32) *int32 { return &v }

func rs(name, ns string, ageDays int, ownedByDeploy bool, specReplicas, statusReplicas int32) *appsv1.ReplicaSet {
	r := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour)),
		},
		Spec:   appsv1.ReplicaSetSpec{Replicas: int32p(specReplicas)},
		Status: appsv1.ReplicaSetStatus{Replicas: statusReplicas},
	}
	if ownedByDeploy {
		r.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment", Name: "parent"}}
	}
	return r
}

func TestFindOrphanReplicaSets_scaledZeroOldOwned(t *testing.T) {
	cs := fake.NewSimpleClientset(
		rs("old-stale", "default", 10, true, 0, 0),
		rs("new-stale", "default", 2, true, 0, 0), // inside grace (7d)
		rs("live", "default", 10, true, 3, 3),
		rs("unowned", "default", 10, false, 0, 0),
	)
	got, err := FindOrphanReplicaSets(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "old-stale" {
		t.Fatalf("expected only old-stale, got %+v", got)
	}
}
