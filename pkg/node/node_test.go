package node

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func findCheck(findings []Finding, check string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func baseNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:   corev1.NodeReady,
				Status: corev1.ConditionTrue,
			}},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
		},
	}
}

func TestAudit_notReady(t *testing.T) {
	n := baseNode("n1")
	n.Status.Conditions = []corev1.NodeCondition{{
		Type: corev1.NodeReady, Status: corev1.ConditionFalse, Message: "kubelet stopped",
	}}
	cs := fake.NewSimpleClientset(n)
	got, err := Audit(context.Background(), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "not-ready")
	if len(hits) != 1 {
		t.Fatalf("expected not-ready, got %+v", got)
	}
	if hits[0].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", hits[0].Severity)
	}
}

func TestAudit_memoryPressure(t *testing.T) {
	n := baseNode("n1")
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue, Message: "high memory usage",
	})
	cs := fake.NewSimpleClientset(n)
	got, _ := Audit(context.Background(), cs, Options{})
	if len(findCheck(got, "memory-pressure")) != 1 {
		t.Fatalf("expected memory-pressure, got %+v", got)
	}
}

func TestAudit_diskPressure(t *testing.T) {
	n := baseNode("n1")
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue, Message: "disk full",
	})
	cs := fake.NewSimpleClientset(n)
	got, _ := Audit(context.Background(), cs, Options{})
	if len(findCheck(got, "disk-pressure")) != 1 {
		t.Fatalf("expected disk-pressure, got %+v", got)
	}
}

func TestAudit_cpuOvercommit(t *testing.T) {
	n := baseNode("n1") // 4 CPU allocatable
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hog", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName: "n1",
			Containers: []corev1.Container{{
				Name: "c",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("5"), // 5 > 4
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(n, pod)
	got, _ := Audit(context.Background(), cs, Options{})
	hits := findCheck(got, "cpu-overcommit")
	if len(hits) != 1 {
		t.Fatalf("expected cpu-overcommit, got %+v", got)
	}
}

func TestAudit_noOvercommit(t *testing.T) {
	n := baseNode("n1") // 4 CPU
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName: "n1",
			Containers: []corev1.Container{{
				Name: "c",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU: resource.MustParse("2"),
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(n, pod)
	got, _ := Audit(context.Background(), cs, Options{})
	if len(findCheck(got, "cpu-overcommit")) != 0 {
		t.Fatalf("should not flag under-committed node, got %+v", got)
	}
}

func TestAudit_taintBlocking(t *testing.T) {
	n := baseNode("n1")
	n.Spec.Taints = []corev1.Taint{{
		Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule,
	}}
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "stuck", Namespace: "default"},
		Spec:       corev1.PodSpec{}, // no tolerations
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := fake.NewSimpleClientset(n, pending)
	got, _ := Audit(context.Background(), cs, Options{})
	hits := findCheck(got, "taint-blocking")
	if len(hits) != 1 {
		t.Fatalf("expected taint-blocking, got %+v", got)
	}
}

func TestAudit_taintTolerated(t *testing.T) {
	n := baseNode("n1")
	n.Spec.Taints = []corev1.Taint{{
		Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule,
	}}
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "default"},
		Spec: corev1.PodSpec{
			Tolerations: []corev1.Toleration{{
				Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu",
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := fake.NewSimpleClientset(n, pending)
	got, _ := Audit(context.Background(), cs, Options{})
	if len(findCheck(got, "taint-blocking")) != 0 {
		t.Fatalf("tolerated taint should not be flagged, got %+v", got)
	}
}

func TestAudit_healthyNode(t *testing.T) {
	cs := fake.NewSimpleClientset(baseNode("n1"))
	got, _ := Audit(context.Background(), cs, Options{})
	if len(got) != 0 {
		t.Fatalf("healthy node should have no findings, got %+v", got)
	}
}
