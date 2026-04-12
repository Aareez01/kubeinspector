package security

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func boolp(v bool) *bool   { return &v }
func int64p(v int64) *int64 { return &v }

func basePod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx",
			}},
		},
	}
}

func findCheck(findings []Finding, check string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func TestAuditPods_privileged(t *testing.T) {
	pod := basePod("priv")
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		Privileged: boolp(true),
	}
	cs := fake.NewSimpleClientset(pod)
	got, err := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "privileged")
	if len(hits) != 1 {
		t.Fatalf("expected 1 privileged finding, got %d: %+v", len(hits), got)
	}
	if hits[0].Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", hits[0].Severity)
	}
}

func TestAuditPods_hostNetwork(t *testing.T) {
	pod := basePod("host")
	pod.Spec.HostNetwork = true
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "host-network")
	if len(hits) != 1 {
		t.Fatalf("expected host-network finding, got %+v", got)
	}
}

func TestAuditPods_hostPIDAndIPC(t *testing.T) {
	pod := basePod("hostns")
	pod.Spec.HostPID = true
	pod.Spec.HostIPC = true
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "host-pid")) != 1 {
		t.Error("expected host-pid finding")
	}
	if len(findCheck(got, "host-ipc")) != 1 {
		t.Error("expected host-ipc finding")
	}
}

func TestAuditPods_runAsRoot_explicit(t *testing.T) {
	pod := basePod("root")
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		RunAsUser: int64p(0),
	}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "run-as-root")
	if len(hits) != 1 {
		t.Fatalf("expected run-as-root finding, got %+v", got)
	}
}

func TestAuditPods_runAsNonRoot_noFinding(t *testing.T) {
	pod := basePod("safe")
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: boolp(true),
	}
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		ReadOnlyRootFilesystem: boolp(true),
	}
	pod.Spec.Containers[0].Resources.Limits = corev1.ResourceList{
		corev1.ResourceCPU:    {},
		corev1.ResourceMemory: {},
	}
	pod.Spec.AutomountServiceAccountToken = boolp(false)
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "run-as-root")
	if len(hits) != 0 {
		t.Fatalf("expected no run-as-root finding when runAsNonRoot is true, got %+v", hits)
	}
}

func TestAuditPods_dangerousCap(t *testing.T) {
	pod := basePod("caps")
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{"SYS_ADMIN", "NET_RAW"},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "dangerous-cap")
	if len(hits) != 2 {
		t.Fatalf("expected 2 dangerous-cap findings, got %d: %+v", len(hits), hits)
	}
}

func TestAuditPods_writableRootFS(t *testing.T) {
	pod := basePod("rw")
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "writable-rootfs")
	if len(hits) != 1 {
		t.Fatalf("expected writable-rootfs finding, got %+v", got)
	}
}

func TestAuditPods_noResourceLimits(t *testing.T) {
	pod := basePod("nolimits")
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	cpuHits := findCheck(got, "no-cpu-limit")
	memHits := findCheck(got, "no-memory-limit")
	if len(cpuHits) != 1 || len(memHits) != 1 {
		t.Fatalf("expected no-cpu-limit and no-memory-limit, got cpu=%d mem=%d", len(cpuHits), len(memHits))
	}
}

func TestAuditPods_defaultSAToken(t *testing.T) {
	pod := basePod("defaultsa")
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "default-sa-token")
	if len(hits) != 1 {
		t.Fatalf("expected default-sa-token finding, got %+v", got)
	}
}

func TestAuditPods_disabledSAToken_noFinding(t *testing.T) {
	pod := basePod("nosa")
	pod.Spec.AutomountServiceAccountToken = boolp(false)
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "default-sa-token")
	if len(hits) != 0 {
		t.Fatalf("expected no finding when auto-mount is disabled, got %+v", hits)
	}
}

func TestAuditPods_secretInEnv(t *testing.T) {
	pod := basePod("envleak")
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{
		Name: "DB_PASSWORD",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"},
				Key:                  "password",
			},
		},
	}}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "secret-in-env")
	if len(hits) != 1 {
		t.Fatalf("expected secret-in-env finding, got %+v", got)
	}
}

func TestAuditPods_secretInEnvFrom(t *testing.T) {
	pod := basePod("envfromleak")
	pod.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{
		SecretRef: &corev1.SecretEnvSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "all-secrets"},
		},
	}}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditPods(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "secret-in-env")
	if len(hits) != 1 {
		t.Fatalf("expected secret-in-env finding for envFrom, got %+v", got)
	}
}
