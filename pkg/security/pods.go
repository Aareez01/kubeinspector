package security

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// dangerousCaps is the set of Linux capabilities that grant near-root or
// network-level access inside a container.
var dangerousCaps = map[corev1.Capability]bool{
	"ALL":              true,
	"SYS_ADMIN":       true,
	"NET_ADMIN":       true,
	"NET_RAW":         true,
	"SYS_PTRACE":      true,
	"DAC_OVERRIDE":    true,
	"AUDIT_WRITE":     true,
	"SETUID":          true,
	"SETGID":          true,
}

// AuditPods scans pods for common security misconfigurations.
func AuditPods(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var findings []Finding
	for i := range pods.Items {
		pod := &pods.Items[i]
		findings = append(findings, checkPodLevel(pod)...)
		findings = append(findings, checkContainers(pod, pod.Spec.InitContainers, true)...)
		findings = append(findings, checkContainers(pod, pod.Spec.Containers, false)...)
	}
	return findings, nil
}

func checkPodLevel(pod *corev1.Pod) []Finding {
	var findings []Finding
	spec := pod.Spec

	if spec.HostNetwork {
		findings = append(findings, podFinding(pod, SeverityCritical, "host-network",
			"pod uses hostNetwork — bypasses network policies"))
	}
	if spec.HostPID {
		findings = append(findings, podFinding(pod, SeverityCritical, "host-pid",
			"pod uses hostPID — can see all host processes"))
	}
	if spec.HostIPC {
		findings = append(findings, podFinding(pod, SeverityCritical, "host-ipc",
			"pod uses hostIPC — can access host shared memory"))
	}

	// Default service account with auto-mounted token
	saName := "default"
	if spec.ServiceAccountName != "" {
		saName = spec.ServiceAccountName
	}
	autoMount := spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken
	if saName == "default" && autoMount {
		findings = append(findings, podFinding(pod, SeverityWarning, "default-sa-token",
			"uses default ServiceAccount with auto-mounted token — if compromised, attacker gets API access"))
	}

	return findings
}

func checkContainers(pod *corev1.Pod, containers []corev1.Container, isInit bool) []Finding {
	var findings []Finding
	for _, c := range containers {
		sc := effectiveSecurityContext(pod, &c)

		// Privileged
		if sc.privileged {
			findings = append(findings, containerFinding(pod, c.Name, SeverityCritical, "privileged",
				"container runs in privileged mode — equivalent to root on the host"))
		}

		// Running as root
		if sc.runAsRoot {
			findings = append(findings, containerFinding(pod, c.Name, SeverityWarning, "run-as-root",
				"container may run as root (runAsNonRoot not set or runAsUser is 0)"))
		}

		// Dangerous capabilities
		if sc.caps != nil {
			for _, cap := range sc.caps.Add {
				if dangerousCaps[cap] {
					findings = append(findings, containerFinding(pod, c.Name, SeverityCritical, "dangerous-cap",
						fmt.Sprintf("adds dangerous capability %s", cap)))
				}
			}
		}

		// Writable root filesystem
		if !sc.readOnlyRootFS {
			findings = append(findings, containerFinding(pod, c.Name, SeverityWarning, "writable-rootfs",
				"root filesystem is writable (readOnlyRootFilesystem not set)"))
		}

		// No resource limits (skip init containers — they run briefly)
		if !isInit {
			if _, ok := c.Resources.Limits[corev1.ResourceCPU]; !ok {
				findings = append(findings, containerFinding(pod, c.Name, SeverityWarning, "no-cpu-limit",
					"no CPU limit set — can starve neighboring pods"))
			}
			if _, ok := c.Resources.Limits[corev1.ResourceMemory]; !ok {
				findings = append(findings, containerFinding(pod, c.Name, SeverityWarning, "no-memory-limit",
					"no memory limit set — can OOM-kill neighbors"))
			}
		}

		// Secrets in env vars
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				findings = append(findings, containerFinding(pod, c.Name, SeverityWarning, "secret-in-env",
					fmt.Sprintf("secret %q exposed via env var %s — env vars leak into logs and crash dumps; prefer volume mounts",
						e.ValueFrom.SecretKeyRef.Name, e.Name)))
			}
		}
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				findings = append(findings, containerFinding(pod, c.Name, SeverityWarning, "secret-in-env",
					fmt.Sprintf("entire secret %q exposed via envFrom — env vars leak into logs; prefer volume mounts",
						ef.SecretRef.Name)))
			}
		}
	}
	return findings
}

type resolvedSC struct {
	privileged     bool
	runAsRoot      bool
	readOnlyRootFS bool
	caps           *corev1.Capabilities
}

// effectiveSecurityContext merges pod-level and container-level security
// context, with container taking precedence (matching kubelet behavior).
func effectiveSecurityContext(pod *corev1.Pod, c *corev1.Container) resolvedSC {
	r := resolvedSC{}

	// Pod-level defaults
	podSC := pod.Spec.SecurityContext
	var podRunAsNonRoot *bool
	var podRunAsUser *int64
	if podSC != nil {
		podRunAsNonRoot = podSC.RunAsNonRoot
		podRunAsUser = podSC.RunAsUser
	}

	// Container-level overrides
	cSC := c.SecurityContext
	if cSC != nil {
		if cSC.Privileged != nil && *cSC.Privileged {
			r.privileged = true
		}
		if cSC.ReadOnlyRootFilesystem != nil && *cSC.ReadOnlyRootFilesystem {
			r.readOnlyRootFS = true
		}
		r.caps = cSC.Capabilities

		// runAsRoot: container-level overrides pod-level
		runAsNonRoot := cSC.RunAsNonRoot
		if runAsNonRoot == nil {
			runAsNonRoot = podRunAsNonRoot
		}
		runAsUser := cSC.RunAsUser
		if runAsUser == nil {
			runAsUser = podRunAsUser
		}
		r.runAsRoot = mayRunAsRoot(runAsNonRoot, runAsUser)
	} else {
		r.runAsRoot = mayRunAsRoot(podRunAsNonRoot, podRunAsUser)
	}

	return r
}

func mayRunAsRoot(runAsNonRoot *bool, runAsUser *int64) bool {
	if runAsNonRoot != nil && *runAsNonRoot {
		return false
	}
	if runAsUser != nil && *runAsUser == 0 {
		return true
	}
	if runAsUser != nil && *runAsUser != 0 {
		return false
	}
	// Neither set — container image default, which is often root.
	return runAsNonRoot == nil
}

func podFinding(pod *corev1.Pod, severity Severity, check, message string) Finding {
	return Finding{
		Severity:  severity,
		Kind:      "Pod",
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Check:     check,
		Message:   message,
	}
}

func containerFinding(pod *corev1.Pod, container string, severity Severity, check, message string) Finding {
	return Finding{
		Severity:  severity,
		Kind:      "Pod",
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Container: container,
		Check:     check,
		Message:   message,
	}
}
