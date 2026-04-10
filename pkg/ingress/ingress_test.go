package ingress

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func ing(name, ns string, rules []networkingv1.IngressRule, tls []networkingv1.IngressTLS) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       networkingv1.IngressSpec{Rules: rules, TLS: tls},
	}
}

func rule(host, path, svcName string, svcPort int32) networkingv1.IngressRule {
	pt := networkingv1.PathTypePrefix
	return networkingv1.IngressRule{
		Host: host,
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path:     path,
					PathType: &pt,
					Backend: networkingv1.IngressBackend{
						Service: &networkingv1.IngressServiceBackend{
							Name: svcName,
							Port: networkingv1.ServiceBackendPort{Number: svcPort},
						},
					},
				}},
			},
		},
	}
}

func svc(name, ns string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: port, TargetPort: intstr.FromInt(int(port))}},
		},
	}
}

func secret(name, ns string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Type: corev1.SecretTypeTLS}
}

func TestAudit_duplicateHostPath(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("web", "default", 80),
		ing("a", "default", []networkingv1.IngressRule{rule("example.com", "/", "web", 80)}, nil),
		ing("b", "default", []networkingv1.IngressRule{rule("example.com", "/", "web", 80)}, nil),
	)
	got, err := Audit(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	dupCount := 0
	for _, f := range got {
		if f.Severity == SeverityError && containsSubstring(f.Message, "duplicate") {
			dupCount++
		}
	}
	if dupCount != 2 {
		t.Fatalf("expected 2 duplicate findings (one per ingress), got %d: %+v", dupCount, got)
	}
}

func TestAudit_missingTLS(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("web", "default", 80),
		ing("plain", "default", []networkingv1.IngressRule{rule("example.com", "/", "web", 80)}, nil),
	)
	got, _ := Audit(context.Background(), cs, Options{Namespace: "default"})
	found := false
	for _, f := range got {
		if containsSubstring(f.Message, "no spec.tls") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing-TLS warning, got %+v", got)
	}
}

func TestAudit_tlsSecretMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("web", "default", 80),
		ing("x", "default",
			[]networkingv1.IngressRule{rule("example.com", "/", "web", 80)},
			[]networkingv1.IngressTLS{{Hosts: []string{"example.com"}, SecretName: "nope"}},
		),
	)
	got, _ := Audit(context.Background(), cs, Options{Namespace: "default"})
	found := false
	for _, f := range got {
		if containsSubstring(f.Message, "TLS secret") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected TLS-secret-missing error, got %+v", got)
	}
}

func TestAudit_tlsSecretPresent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("web", "default", 80),
		secret("tls-cert", "default"),
		ing("x", "default",
			[]networkingv1.IngressRule{rule("example.com", "/", "web", 80)},
			[]networkingv1.IngressTLS{{Hosts: []string{"example.com"}, SecretName: "tls-cert"}},
		),
	)
	got, _ := Audit(context.Background(), cs, Options{Namespace: "default"})
	for _, f := range got {
		if containsSubstring(f.Message, "TLS secret") || containsSubstring(f.Message, "no spec.tls") {
			t.Fatalf("unexpected TLS finding: %+v", f)
		}
	}
}

func TestAudit_backendServiceMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ing("x", "default", []networkingv1.IngressRule{rule("example.com", "/", "gone", 80)}, nil),
	)
	got, _ := Audit(context.Background(), cs, Options{Namespace: "default"})
	found := false
	for _, f := range got {
		if containsSubstring(f.Message, "backend Service") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing-backend-service error, got %+v", got)
	}
}

func TestAudit_backendPortMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(
		svc("web", "default", 8080),
		ing("x", "default", []networkingv1.IngressRule{rule("example.com", "/", "web", 80)}, nil),
	)
	got, _ := Audit(context.Background(), cs, Options{Namespace: "default"})
	found := false
	for _, f := range got {
		if containsSubstring(f.Message, "no matching port") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing-port error, got %+v", got)
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
