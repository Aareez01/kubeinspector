package security

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ResourceThresholds controls what's considered "abnormally large" for a
// single container. These defaults are generous — most legitimate workloads
// stay well under these, but a crypto miner or DoS container will blow past
// them.
type ResourceThresholds struct {
	CPUCores  float64 // flag containers requesting more than this (default 8)
	MemoryGB  float64 // flag containers requesting more than this (default 32)
	LimitRatio float64 // flag when limit/request ratio > this (default 10)
}

var defaultThresholds = ResourceThresholds{
	CPUCores:   8,
	MemoryGB:   32,
	LimitRatio: 10,
}

// AuditResourceAbuse scans pods for containers with abnormally high resource
// requests or limits that suggest resource abuse (crypto mining, intentional
// DoS, or misconfigured workloads that could starve neighbors).
func AuditResourceAbuse(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	thresholds := defaultThresholds
	var findings []Finding
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, c := range pod.Spec.Containers {
			findings = append(findings, checkResourceAbuse(pod, c, thresholds)...)
		}
	}
	return findings, nil
}

func checkResourceAbuse(pod *corev1.Pod, c corev1.Container, t ResourceThresholds) []Finding {
	var findings []Finding

	// High CPU request
	if cpuReq, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
		cores := float64(cpuReq.MilliValue()) / 1000.0
		if cores >= t.CPUCores {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "excessive-cpu-request",
				Message:   fmt.Sprintf("requests %.1f CPU cores (threshold: %.0f) — potential resource abuse or misconfiguration", cores, t.CPUCores),
			})
		}
	}

	// High CPU limit
	if cpuLim, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
		cores := float64(cpuLim.MilliValue()) / 1000.0
		if cores >= t.CPUCores {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "excessive-cpu-limit",
				Message:   fmt.Sprintf("CPU limit is %.1f cores (threshold: %.0f) — could starve neighboring pods", cores, t.CPUCores),
			})
		}
	}

	// High memory request
	if memReq, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
		gb := float64(memReq.Value()) / (1024 * 1024 * 1024)
		if gb >= t.MemoryGB {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "excessive-memory-request",
				Message:   fmt.Sprintf("requests %.1f GiB memory (threshold: %.0f) — potential resource abuse or misconfiguration", gb, t.MemoryGB),
			})
		}
	}

	// High memory limit
	if memLim, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
		gb := float64(memLim.Value()) / (1024 * 1024 * 1024)
		if gb >= t.MemoryGB {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "excessive-memory-limit",
				Message:   fmt.Sprintf("memory limit is %.1f GiB (threshold: %.0f) — could OOM-kill neighbors if node is constrained", gb, t.MemoryGB),
			})
		}
	}

	// Huge gap between request and limit (limit >> request means the
	// container can burst far beyond what it reserved, starving other pods)
	cpuReq := c.Resources.Requests[corev1.ResourceCPU]
	cpuLim := c.Resources.Limits[corev1.ResourceCPU]
	if !cpuReq.IsZero() && !cpuLim.IsZero() {
		ratio := float64(cpuLim.MilliValue()) / float64(cpuReq.MilliValue())
		if ratio >= t.LimitRatio {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "cpu-limit-ratio",
				Message:   fmt.Sprintf("CPU limit/request ratio is %.0fx (request: %s, limit: %s) — can burst and starve neighbors", ratio, formatCPU(cpuReq), formatCPU(cpuLim)),
			})
		}
	}

	memReq := c.Resources.Requests[corev1.ResourceMemory]
	memLim := c.Resources.Limits[corev1.ResourceMemory]
	if !memReq.IsZero() && !memLim.IsZero() {
		ratio := float64(memLim.Value()) / float64(memReq.Value())
		if ratio >= t.LimitRatio {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "memory-limit-ratio",
				Message:   fmt.Sprintf("memory limit/request ratio is %.0fx (request: %s, limit: %s) — can burst and OOM neighbors", ratio, memReq.String(), memLim.String()),
			})
		}
	}

	return findings
}

func formatCPU(q resource.Quantity) string {
	m := q.MilliValue()
	if m%1000 == 0 {
		return fmt.Sprintf("%d", m/1000)
	}
	return fmt.Sprintf("%dm", m)
}
