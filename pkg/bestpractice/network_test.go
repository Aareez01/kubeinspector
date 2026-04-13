package bestpractice

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuditNetworkPolicies_uncovered(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: "default",
			Labels: map[string]string{"app": "web"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pod) // no NetworkPolicies
	got, err := AuditNetworkPolicies(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "no-network-policy")
	if len(hits) != 1 {
		t.Fatalf("expected no-network-policy, got %+v", got)
	}
}

func TestAuditNetworkPolicies_covered(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "app", Namespace: "default",
			Labels: map[string]string{"app": "web"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "default"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	cs := fake.NewSimpleClientset(pod, np)
	got, _ := AuditNetworkPolicies(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "no-network-policy")) != 0 {
		t.Fatalf("covered pod should not be flagged, got %+v", got)
	}
}

func TestAuditNodePorts_exposed(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{Port: 80, NodePort: 30080}},
		},
	}
	cs := fake.NewSimpleClientset(svc)
	got, err := AuditNodePorts(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "nodeport-exposed")
	if len(hits) != 1 {
		t.Fatalf("expected nodeport-exposed, got %+v", got)
	}
}

func TestAuditNodePorts_clusterIPSkipped(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "internal", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}
	cs := fake.NewSimpleClientset(svc)
	got, _ := AuditNodePorts(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("ClusterIP should not be flagged, got %+v", got)
	}
}

func TestAuditLoadBalancers_publicLB(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	cs := fake.NewSimpleClientset(svc)
	got, _ := AuditLoadBalancers(context.Background(), cs, Options{Namespace: "default"})
	if len(findCheck(got, "public-lb")) != 1 {
		t.Fatalf("expected public-lb, got %+v", got)
	}
}

func TestAuditLoadBalancers_internalSkipped(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "api", Namespace: "default",
			Annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	cs := fake.NewSimpleClientset(svc)
	got, _ := AuditLoadBalancers(context.Background(), cs, Options{Namespace: "default"})
	if len(got) != 0 {
		t.Fatalf("internal LB should not be flagged, got %+v", got)
	}
}
