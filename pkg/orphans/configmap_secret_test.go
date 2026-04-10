package orphans

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func cm(name, ns string, ageMin int) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:              name,
		Namespace:         ns,
		CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Duration(ageMin) * time.Minute)),
	}}
}

func secret(name, ns string, ageMin int, t corev1.SecretType) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Duration(ageMin) * time.Minute)),
		},
		Type: t,
	}
}

func TestFindOrphanConfigMaps_volumeRef(t *testing.T) {
	used := cm("used", "default", 60)
	unused := cm("unused", "default", 60)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "cfg",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "used"},
				},
			},
		}}},
	}
	cs := fake.NewSimpleClientset(used, unused, pod)
	got, err := FindOrphanConfigMaps(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "unused" {
		t.Fatalf("expected only unused to be flagged, got %+v", got)
	}
}

func TestFindOrphanConfigMaps_envFromRef(t *testing.T) {
	used := cm("used", "default", 60)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c",
			EnvFrom: []corev1.EnvFromSource{{
				ConfigMapRef: &corev1.ConfigMapEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "used"},
				},
			}},
		}}},
	}
	cs := fake.NewSimpleClientset(used, pod)
	got, err := FindOrphanConfigMaps(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no orphans, got %+v", got)
	}
}

func TestFindOrphanConfigMaps_skipsKubeRootCA(t *testing.T) {
	cs := fake.NewSimpleClientset(cm("kube-root-ca.crt", "default", 60))
	got, _ := FindOrphanConfigMaps(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("kube-root-ca.crt should be exempt, got %+v", got)
	}
}

func TestFindOrphanSecrets_skipsServiceAccountTokens(t *testing.T) {
	cs := fake.NewSimpleClientset(
		secret("default-token-abc", "default", 60, corev1.SecretTypeServiceAccountToken),
	)
	got, _ := FindOrphanSecrets(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("SA token secrets should be exempt, got %+v", got)
	}
}

func TestFindOrphanSecrets_referencedByIngressTLS(t *testing.T) {
	tlsSecret := secret("tls-cert", "default", 60, corev1.SecretTypeTLS)
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{SecretName: "tls-cert", Hosts: []string{"example.com"}}},
		},
	}
	cs := fake.NewSimpleClientset(tlsSecret, ing)
	got, _ := FindOrphanSecrets(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("TLS secret referenced by ingress should not be flagged, got %+v", got)
	}
}

func TestFindOrphanSecrets_imagePullSecret(t *testing.T) {
	pull := secret("regcred", "default", 60, corev1.SecretTypeDockerConfigJson)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: corev1.PodSpec{
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
		},
	}
	cs := fake.NewSimpleClientset(pull, pod)
	got, _ := FindOrphanSecrets(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("imagePullSecret should not be flagged, got %+v", got)
	}
}

func TestFindOrphanSecrets_unreferenced(t *testing.T) {
	cs := fake.NewSimpleClientset(
		secret("stale", "default", 60, corev1.SecretTypeOpaque),
	)
	got, _ := FindOrphanSecrets(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 1 || got[0].Name != "stale" {
		t.Fatalf("expected stale to be flagged, got %+v", got)
	}
}
