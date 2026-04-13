package workload

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
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

func TestAuditPods_crashLoop(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "crash", Namespace: "default"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "app",
				RestartCount: 42,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
				},
				LastTerminationState: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 137},
				},
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	got, err := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "crash-loop")
	if len(hits) != 1 {
		t.Fatalf("expected 1 crash-loop finding, got %d: %+v", len(hits), got)
	}
	if hits[0].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", hits[0].Severity)
	}
}

func TestAuditPods_pendingUnschedulable(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "stuck", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{
				Type:    corev1.PodScheduled,
				Status:  corev1.ConditionFalse,
				Message: "0/3 nodes are available: 3 Insufficient cpu.",
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "pending-pod")
	if len(hits) != 1 {
		t.Fatalf("expected pending-pod, got %+v", got)
	}
}

func TestAuditPods_pendingImagePull(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pull", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  "ImagePullBackOff",
						Message: "Back-off pulling image \"nonexistent:latest\"",
					},
				},
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "pending-pod")
	if len(hits) != 1 {
		t.Fatalf("expected pending-pod for image pull, got %+v", got)
	}
}

func TestAuditPods_runningNoFindings(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("healthy pod should have no findings, got %+v", got)
	}
}
