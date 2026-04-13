package workload

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func int32p(v int32) *int32 { return &v }

func TestAuditDeployments_zeroReady(t *testing.T) {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32p(3)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 0},
	}
	cs := fake.NewSimpleClientset(d)
	got, err := AuditDeployments(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "zero-ready-replicas")
	if len(hits) != 1 {
		t.Fatalf("expected zero-ready finding, got %+v", got)
	}
	if hits[0].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", hits[0].Severity)
	}
}

func TestAuditDeployments_scaledToZeroSkipped(t *testing.T) {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "idle", Namespace: "default"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32p(0)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 0},
	}
	cs := fake.NewSimpleClientset(d)
	got, _ := AuditDeployments(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("intentionally scaled-to-zero should be skipped, got %+v", got)
	}
}

func TestAuditDeployments_healthy(t *testing.T) {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "default"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32p(3)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 3},
	}
	cs := fake.NewSimpleClientset(d)
	got, _ := AuditDeployments(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("healthy deployment should have no findings, got %+v", got)
	}
}
