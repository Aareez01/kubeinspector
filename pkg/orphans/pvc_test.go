package orphans

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func pvc(name, ns string, ageMinutes int, annotations map[string]string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			Annotations:       annotations,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Duration(ageMinutes) * time.Minute)),
		},
	}
}

func podWithPVC(name, ns, claimName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: claimName,
					},
				},
			}},
		},
	}
}

func TestFindOrphanPVCs_unmounted(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pvc("mounted", "default", 60, nil),
		pvc("orphan", "default", 60, nil),
		podWithPVC("app", "default", "mounted"),
	)

	got, err := FindOrphanPVCs(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Name != "orphan" {
		t.Errorf("expected orphan, got %s", got[0].Name)
	}
}

func TestFindOrphanPVCs_respectsGracePeriod(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pvc("young", "default", 2, nil), // 2 minutes old, grace is 10m
	)
	got, err := FindOrphanPVCs(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 findings inside grace period, got %d", len(got))
	}
}

func TestFindOrphanPVCs_respectsKeepAnnotation(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pvc("kept", "default", 60, map[string]string{KeepAnnotation: "true"}),
	)
	got, err := FindOrphanPVCs(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 findings with keep annotation, got %d", len(got))
	}
}

func TestFindOrphanPVCs_allNamespaces(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pvc("a", "ns1", 60, nil),
		pvc("b", "ns2", 60, nil),
		podWithPVC("app", "ns1", "a"),
	)
	got, err := FindOrphanPVCs(context.Background(), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Namespace != "ns2" || got[0].Name != "b" {
		t.Fatalf("expected single orphan ns2/b, got %+v", got)
	}
}
