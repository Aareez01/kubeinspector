package security

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func minerPod(name, image string, envVars []corev1.EnvVar, command, args []string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "miner",
				Image:   image,
				Env:     envVars,
				Command: command,
				Args:    args,
			}},
		},
	}
}

func TestAuditMiners_knownImage(t *testing.T) {
	for _, img := range []string{
		"xmrig/xmrig:latest",
		"docker.io/library/minergate-cli",
		"evil/cpuminer-multi:v1",
		"user/moneroocean-miner:latest",
	} {
		cs := fake.NewSimpleClientset(minerPod("m", img, nil, nil, nil))
		got, err := AuditMiners(context.Background(), cs, Options{Namespace: "default"})
		if err != nil {
			t.Fatal(err)
		}
		hits := findCheck(got, "crypto-miner-image")
		if len(hits) != 1 {
			t.Errorf("image %q: expected crypto-miner-image finding, got %+v", img, got)
		}
		if hits[0].Severity != SeverityCritical {
			t.Errorf("expected critical, got %s", hits[0].Severity)
		}
	}
}

func TestAuditMiners_cleanImage(t *testing.T) {
	cs := fake.NewSimpleClientset(minerPod("clean", "nginx:latest", nil, nil, nil))
	got, _ := AuditMiners(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "crypto-miner-image")
	if len(hits) != 0 {
		t.Fatalf("nginx should not be flagged, got %+v", hits)
	}
}

func TestAuditMiners_suspiciousEnv(t *testing.T) {
	envs := []corev1.EnvVar{
		{Name: "POOL_URL", Value: "stratum+tcp://pool.example.com:3333"},
		{Name: "WALLET", Value: "4ABC..."},
	}
	cs := fake.NewSimpleClientset(minerPod("env", "alpine", envs, nil, nil))
	got, _ := AuditMiners(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "crypto-miner-env")
	if len(hits) < 2 {
		t.Fatalf("expected at least 2 env findings, got %+v", hits)
	}
}

func TestAuditMiners_suspiciousCommand(t *testing.T) {
	cs := fake.NewSimpleClientset(minerPod("cmd", "alpine",
		nil,
		[]string{"/usr/bin/xmrig"},
		[]string{"--algo=randomx", "--url=stratum+tcp://pool.example.com:3333"},
	))
	got, _ := AuditMiners(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "crypto-miner-command")
	if len(hits) != 1 {
		t.Fatalf("expected crypto-miner-command finding, got %+v", got)
	}
}

func TestAuditMiners_initContainerAlsoScanned(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "init", Namespace: "default"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "setup",
				Image: "evil/xmrig-setup:latest",
			}},
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx",
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	got, _ := AuditMiners(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "crypto-miner-image")
	if len(hits) != 1 || hits[0].Container != "setup" {
		t.Fatalf("expected init container flagged, got %+v", got)
	}
}
