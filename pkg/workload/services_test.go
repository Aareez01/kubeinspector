package workload

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuditServiceSelectors_mismatch(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api", "version": "v2"},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "api", "version": "v1"}, // v1 not v2
		},
	}
	cs := fake.NewSimpleClientset(svc, pod)
	got, err := AuditServiceSelectors(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "selector-mismatch")
	if len(hits) != 1 {
		t.Fatalf("expected selector-mismatch, got %+v", got)
	}
}

func TestAuditServiceSelectors_matching(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "api"}},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api-pod", Namespace: "default",
			Labels: map[string]string{"app": "api", "tier": "backend"},
		},
	}
	cs := fake.NewSimpleClientset(svc, pod)
	got, _ := AuditServiceSelectors(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("matching selector should have no findings, got %+v", got)
	}
}
