package bestpractice

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func int32p(v int32) *int32 { return &v }

func findCheck(findings []Finding, check string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func deploy(name, ns, image string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32p(replicas),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: image,
					}},
				},
			},
		},
	}
}

func TestAuditReliability_noProbes(t *testing.T) {
	cs := fake.NewSimpleClientset(deploy("api", "default", "nginx:1.25", 3))
	got, err := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findCheck(got, "no-liveness-probe")) != 1 {
		t.Error("expected no-liveness-probe")
	}
	if len(findCheck(got, "no-readiness-probe")) != 1 {
		t.Error("expected no-readiness-probe")
	}
}

func TestAuditReliability_latestTag(t *testing.T) {
	for _, img := range []string{"nginx:latest", "nginx", "myregistry.io/app"} {
		cs := fake.NewSimpleClientset(deploy("api", "default", img, 1))
		got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
		if len(findCheck(got, "latest-image-tag")) != 1 {
			t.Errorf("image %q should trigger latest-image-tag", img)
		}
	}
}

func TestAuditReliability_pinnedTag(t *testing.T) {
	cs := fake.NewSimpleClientset(deploy("api", "default", "nginx:1.25.3", 1))
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "latest-image-tag")) != 0 {
		t.Error("pinned tag should not trigger latest-image-tag")
	}
}

func TestAuditReliability_singleReplica(t *testing.T) {
	cs := fake.NewSimpleClientset(deploy("api", "default", "nginx:1.25", 1))
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "single-replica")) != 1 {
		t.Error("expected single-replica finding")
	}
}

func TestAuditReliability_multiReplicaNoSingleFinding(t *testing.T) {
	cs := fake.NewSimpleClientset(deploy("api", "default", "nginx:1.25", 3))
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "single-replica")) != 0 {
		t.Error("multi-replica should not trigger single-replica")
	}
}

func TestAuditReliability_noPDB(t *testing.T) {
	cs := fake.NewSimpleClientset(deploy("api", "default", "nginx:1.25", 3))
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "no-pdb")) != 1 {
		t.Error("expected no-pdb finding")
	}
}

func TestAuditReliability_withPDB(t *testing.T) {
	d := deploy("api", "default", "nginx:1.25", 3)
	minAvail := intstr.FromInt(2)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "api-pdb", Namespace: "default"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvail,
			Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		},
	}
	cs := fake.NewSimpleClientset(d, pdb)
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "no-pdb")) != 0 {
		t.Error("PDB present — should not flag")
	}
}

func TestAuditReliability_noAntiAffinity(t *testing.T) {
	cs := fake.NewSimpleClientset(deploy("api", "default", "nginx:1.25", 3))
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "no-anti-affinity")) != 1 {
		t.Error("expected no-anti-affinity finding")
	}
}

func TestAuditReliability_withAntiAffinity(t *testing.T) {
	d := deploy("api", "default", "nginx:1.25", 3)
	d.Spec.Template.Spec.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight: 100,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
					TopologyKey:   "kubernetes.io/hostname",
				},
			}},
		},
	}
	cs := fake.NewSimpleClientset(d)
	got, _ := AuditReliability(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "no-anti-affinity")) != 0 {
		t.Error("anti-affinity present — should not flag")
	}
}
