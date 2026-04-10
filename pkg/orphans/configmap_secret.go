package orphans

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// systemConfigMaps are managed by Kubernetes itself and should never be
// reported as orphans even when nothing user-visible references them.
var systemConfigMaps = map[string]bool{
	"kube-root-ca.crt": true,
}

// FindOrphanConfigMaps returns ConfigMaps not referenced by any pod (via
// volumes, envFrom, or valueFrom) or by any Ingress TLS block.
func FindOrphanConfigMaps(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	refs, err := collectReferences(ctx, client, opts.Namespace)
	if err != nil {
		return nil, err
	}

	cms, err := client.CoreV1().ConfigMaps(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list configmaps: %w", err)
	}

	return filterConfigMapOrphans(cms.Items, refs.configMaps, systemConfigMaps, opts), nil
}

// FindOrphanSecrets returns Secrets not referenced by any pod or Ingress.
// Service-account token secrets and Helm release secrets are skipped.
func FindOrphanSecrets(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	refs, err := collectReferences(ctx, client, opts.Namespace)
	if err != nil {
		return nil, err
	}

	secrets, err := client.CoreV1().Secrets(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	grace := opts.GracePeriod
	if grace == 0 {
		grace = 10 * time.Minute
	}
	now := time.Now()

	var findings []Finding
	for _, s := range secrets.Items {
		if isManagedSecret(s) {
			continue
		}
		if s.Annotations[KeepAnnotation] == "true" {
			continue
		}
		age := now.Sub(s.CreationTimestamp.Time)
		if age < grace {
			continue
		}
		if refs.secrets[s.Namespace+"/"+s.Name] {
			continue
		}
		findings = append(findings, Finding{
			Kind:      "Secret",
			Namespace: s.Namespace,
			Name:      s.Name,
			Age:       age.Truncate(time.Second),
			Reason:    "not referenced by any pod or ingress",
		})
	}
	return findings, nil
}

func isManagedSecret(s corev1.Secret) bool {
	switch s.Type {
	case corev1.SecretTypeServiceAccountToken,
		"helm.sh/release.v1":
		return true
	}
	return strings.HasPrefix(s.Name, "sh.helm.release.v1.")
}

func filterConfigMapOrphans(items []corev1.ConfigMap, referenced map[string]bool, system map[string]bool, opts Options) []Finding {
	grace := opts.GracePeriod
	if grace == 0 {
		grace = 10 * time.Minute
	}
	now := time.Now()

	var findings []Finding
	for _, cm := range items {
		if system[cm.Name] {
			continue
		}
		if cm.Annotations[KeepAnnotation] == "true" {
			continue
		}
		age := now.Sub(cm.CreationTimestamp.Time)
		if age < grace {
			continue
		}
		if referenced[cm.Namespace+"/"+cm.Name] {
			continue
		}
		findings = append(findings, Finding{
			Kind:      "ConfigMap",
			Namespace: cm.Namespace,
			Name:      cm.Name,
			Age:       age.Truncate(time.Second),
			Reason:    "not referenced by any pod or ingress",
		})
	}
	return findings
}

type referenceSet struct {
	configMaps map[string]bool // namespace/name
	secrets    map[string]bool
}

func collectReferences(ctx context.Context, client kubernetes.Interface, namespace string) (*referenceSet, error) {
	refs := &referenceSet{
		configMaps: make(map[string]bool),
		secrets:    make(map[string]bool),
	}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	for _, pod := range pods.Items {
		collectPodRefs(&pod, refs)
	}

	ingresses, err := client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses: %w", err)
	}
	for _, ing := range ingresses.Items {
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName != "" {
				refs.secrets[ing.Namespace+"/"+tls.SecretName] = true
			}
		}
	}

	return refs, nil
}

func collectPodRefs(pod *corev1.Pod, refs *referenceSet) {
	ns := pod.Namespace
	for _, vol := range pod.Spec.Volumes {
		if vol.ConfigMap != nil {
			refs.configMaps[ns+"/"+vol.ConfigMap.Name] = true
		}
		if vol.Secret != nil {
			refs.secrets[ns+"/"+vol.Secret.SecretName] = true
		}
		if vol.Projected != nil {
			for _, src := range vol.Projected.Sources {
				if src.ConfigMap != nil {
					refs.configMaps[ns+"/"+src.ConfigMap.Name] = true
				}
				if src.Secret != nil {
					refs.secrets[ns+"/"+src.Secret.Name] = true
				}
			}
		}
	}
	for _, ips := range pod.Spec.ImagePullSecrets {
		refs.secrets[ns+"/"+ips.Name] = true
	}
	containers := append([]corev1.Container{}, pod.Spec.Containers...)
	containers = append(containers, pod.Spec.InitContainers...)
	for _, c := range containers {
		for _, ef := range c.EnvFrom {
			if ef.ConfigMapRef != nil {
				refs.configMaps[ns+"/"+ef.ConfigMapRef.Name] = true
			}
			if ef.SecretRef != nil {
				refs.secrets[ns+"/"+ef.SecretRef.Name] = true
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom == nil {
				continue
			}
			if e.ValueFrom.ConfigMapKeyRef != nil {
				refs.configMaps[ns+"/"+e.ValueFrom.ConfigMapKeyRef.Name] = true
			}
			if e.ValueFrom.SecretKeyRef != nil {
				refs.secrets[ns+"/"+e.ValueFrom.SecretKeyRef.Name] = true
			}
		}
	}
}
