package cost

import (
	"context"
	"math"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func pod(ns, name, cpu, mem string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse(cpu),
						corev1.ResourceMemory: resource.MustParse(mem),
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func pvc(ns, name, storage, sc string) *corev1.PersistentVolumeClaim {
	scPtr := sc
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: &scPtr,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse(storage),
				},
			},
		},
	}
}

func approx(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s: got %.4f, want %.4f (tol %.4f)", name, got, want, tol)
	}
}

func TestEstimate_sumsPodRequestsByNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pod("app", "api-1", "500m", "1Gi", corev1.PodRunning),
		pod("app", "api-2", "500m", "1Gi", corev1.PodRunning),
		pod("infra", "db", "1", "2Gi", corev1.PodRunning),
		pod("app", "finished", "8", "16Gi", corev1.PodSucceeded), // should be skipped
	)
	rep, err := Estimate(context.Background(), cs, Options{Pricing: DefaultPricing()})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Namespaces) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(rep.Namespaces))
	}

	byName := map[string]NamespaceEstimate{}
	for _, e := range rep.Namespaces {
		byName[e.Namespace] = e
	}
	approx(t, "app cpu", byName["app"].CPUCores, 1.0, 0.001)
	approx(t, "app mem", byName["app"].MemoryGB, 2.0, 0.001)
	approx(t, "infra cpu", byName["infra"].CPUCores, 1.0, 0.001)
	approx(t, "infra mem", byName["infra"].MemoryGB, 2.0, 0.001)
}

func TestEstimate_pvcStorageCost(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pvc("app", "data", "100Gi", "gp3"),
	)
	rep, err := Estimate(context.Background(), cs, Options{Pricing: DefaultPricing()})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Namespaces) != 1 {
		t.Fatalf("expected 1 namespace, got %d", len(rep.Namespaces))
	}
	e := rep.Namespaces[0]
	approx(t, "storage gb", e.StorageGB, 100.0, 0.001)
	// gp3 @ 0.08 * 100 = 8.00
	approx(t, "storage cost", e.StorageCostMonth, 8.0, 0.001)
}

func TestEstimate_sortedByCostDescending(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pod("small", "a", "100m", "128Mi", corev1.PodRunning),
		pod("big", "b", "4", "8Gi", corev1.PodRunning),
	)
	rep, _ := Estimate(context.Background(), cs, Options{Pricing: DefaultPricing()})
	if rep.Namespaces[0].Namespace != "big" {
		t.Fatalf("expected 'big' first, got %s", rep.Namespaces[0].Namespace)
	}
}

func TestLoadPricing_defaultsWhenEmpty(t *testing.T) {
	p, err := LoadPricing("")
	if err != nil {
		t.Fatal(err)
	}
	if p.CPUCoreHour == 0 || p.MemoryGBHour == 0 {
		t.Fatalf("expected non-zero defaults, got %+v", p)
	}
}
