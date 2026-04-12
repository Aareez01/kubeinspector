package security

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func podWithResources(name string, cpuReq, cpuLim, memReq, memLim string) *corev1.Pod {
	c := corev1.Container{Name: "app", Image: "nginx"}
	c.Resources.Requests = corev1.ResourceList{}
	c.Resources.Limits = corev1.ResourceList{}
	if cpuReq != "" {
		c.Resources.Requests[corev1.ResourceCPU] = resource.MustParse(cpuReq)
	}
	if cpuLim != "" {
		c.Resources.Limits[corev1.ResourceCPU] = resource.MustParse(cpuLim)
	}
	if memReq != "" {
		c.Resources.Requests[corev1.ResourceMemory] = resource.MustParse(memReq)
	}
	if memLim != "" {
		c.Resources.Limits[corev1.ResourceMemory] = resource.MustParse(memLim)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{c}},
	}
}

func TestAuditResourceAbuse_excessiveCPU(t *testing.T) {
	cs := fake.NewSimpleClientset(podWithResources("hog", "16", "16", "1Gi", "1Gi"))
	got, err := AuditResourceAbuse(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	reqHits := findCheck(got, "excessive-cpu-request")
	limHits := findCheck(got, "excessive-cpu-limit")
	if len(reqHits) != 1 {
		t.Errorf("expected excessive-cpu-request, got %+v", got)
	}
	if len(limHits) != 1 {
		t.Errorf("expected excessive-cpu-limit, got %+v", got)
	}
}

func TestAuditResourceAbuse_excessiveMemory(t *testing.T) {
	cs := fake.NewSimpleClientset(podWithResources("memhog", "1", "1", "64Gi", "64Gi"))
	got, _ := AuditResourceAbuse(context.Background(), cs, Options{Namespace: "default"})
	reqHits := findCheck(got, "excessive-memory-request")
	limHits := findCheck(got, "excessive-memory-limit")
	if len(reqHits) != 1 {
		t.Errorf("expected excessive-memory-request, got %+v", got)
	}
	if len(limHits) != 1 {
		t.Errorf("expected excessive-memory-limit, got %+v", got)
	}
}

func TestAuditResourceAbuse_hugeLimitRatio(t *testing.T) {
	// Request 100m, limit 10 cores → 100x ratio
	cs := fake.NewSimpleClientset(podWithResources("burst", "100m", "10", "128Mi", "16Gi"))
	got, _ := AuditResourceAbuse(context.Background(), cs, Options{Namespace: "default"})
	cpuRatio := findCheck(got, "cpu-limit-ratio")
	memRatio := findCheck(got, "memory-limit-ratio")
	if len(cpuRatio) != 1 {
		t.Errorf("expected cpu-limit-ratio finding, got %+v", got)
	}
	if len(memRatio) != 1 {
		t.Errorf("expected memory-limit-ratio finding, got %+v", got)
	}
}

func TestAuditResourceAbuse_normalPodNoFindings(t *testing.T) {
	cs := fake.NewSimpleClientset(podWithResources("normal", "500m", "1", "512Mi", "1Gi"))
	got, _ := AuditResourceAbuse(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("normal pod should have no findings, got %+v", got)
	}
}
