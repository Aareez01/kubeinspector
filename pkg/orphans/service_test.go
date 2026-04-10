package orphans

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func svc(name, ns string, ageMin int, t corev1.ServiceType, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Duration(ageMin) * time.Minute)),
		},
		Spec: corev1.ServiceSpec{Type: t, Selector: selector},
	}
}

func endpoints(name, ns string, ready bool) *corev1.Endpoints {
	ep := &corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	if ready {
		ep.Subsets = []corev1.EndpointSubset{{
			Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}},
		}}
	}
	return ep
}

func TestFindOrphanServices_emptyEndpoints(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("dead", "default", 60, corev1.ServiceTypeClusterIP, map[string]string{"app": "gone"}),
		endpoints("dead", "default", false),
		svc("alive", "default", 60, corev1.ServiceTypeClusterIP, map[string]string{"app": "ok"}),
		endpoints("alive", "default", true),
	)
	got, err := FindOrphanServices(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "dead" {
		t.Fatalf("expected dead, got %+v", got)
	}
}

func TestFindOrphanServices_skipsExternalName(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("ext", "default", 60, corev1.ServiceTypeExternalName, nil),
	)
	got, _ := FindOrphanServices(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("ExternalName should be skipped, got %+v", got)
	}
}

func TestFindOrphanServices_skipsHeadless(t *testing.T) {
	// No selector → headless, managed manually, skip.
	cs := fake.NewSimpleClientset(
		svc("headless", "default", 60, corev1.ServiceTypeClusterIP, nil),
	)
	got, _ := FindOrphanServices(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("headless should be skipped, got %+v", got)
	}
}
