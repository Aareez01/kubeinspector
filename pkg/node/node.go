// Package node audits Kubernetes node health: conditions (NotReady,
// MemoryPressure, DiskPressure, PIDPressure), resource over-commitment,
// and taints that block scheduling.
package node

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
)

type Finding struct {
	Severity Severity `json:"severity"`
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Check    string   `json:"check"`
	Message  string   `json:"message"`
}

type Options struct{}

// Audit runs all node checks and returns combined findings.
func Audit(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var findings []Finding
	for _, n := range nodes.Items {
		findings = append(findings, checkConditions(n)...)
		findings = append(findings, checkOvercommit(n, pods.Items)...)
		findings = append(findings, checkTaints(n, pods.Items)...)
	}
	return findings, nil
}

func checkConditions(n corev1.Node) []Finding {
	var findings []Finding
	for _, cond := range n.Status.Conditions {
		switch cond.Type {
		case corev1.NodeReady:
			if cond.Status != corev1.ConditionTrue {
				findings = append(findings, Finding{
					Severity: SeverityCritical,
					Kind:     "Node",
					Name:     n.Name,
					Check:    "not-ready",
					Message:  fmt.Sprintf("node is NotReady: %s", cond.Message),
				})
			}
		case corev1.NodeMemoryPressure:
			if cond.Status == corev1.ConditionTrue {
				findings = append(findings, Finding{
					Severity: SeverityCritical,
					Kind:     "Node",
					Name:     n.Name,
					Check:    "memory-pressure",
					Message:  fmt.Sprintf("node under MemoryPressure: %s", cond.Message),
				})
			}
		case corev1.NodeDiskPressure:
			if cond.Status == corev1.ConditionTrue {
				findings = append(findings, Finding{
					Severity: SeverityCritical,
					Kind:     "Node",
					Name:     n.Name,
					Check:    "disk-pressure",
					Message:  fmt.Sprintf("node under DiskPressure: %s", cond.Message),
				})
			}
		case corev1.NodePIDPressure:
			if cond.Status == corev1.ConditionTrue {
				findings = append(findings, Finding{
					Severity: SeverityWarning,
					Kind:     "Node",
					Name:     n.Name,
					Check:    "pid-pressure",
					Message:  fmt.Sprintf("node under PIDPressure: %s", cond.Message),
				})
			}
		}
	}
	return findings
}

func checkOvercommit(n corev1.Node, pods []corev1.Pod) []Finding {
	allocCPU := int64(0)
	allocMem := int64(0)
	for _, pod := range pods {
		if pod.Spec.NodeName != n.Name {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, c := range pod.Spec.Containers {
			cpu := c.Resources.Requests[corev1.ResourceCPU]
			mem := c.Resources.Requests[corev1.ResourceMemory]
			allocCPU += cpu.MilliValue()
			allocMem += mem.Value()
		}
	}

	capCPU := n.Status.Allocatable[corev1.ResourceCPU]
	capMem := n.Status.Allocatable[corev1.ResourceMemory]
	capCPUMilli := capCPU.MilliValue()
	capMemBytes := capMem.Value()

	var findings []Finding
	if capCPUMilli > 0 {
		pct := float64(allocCPU) / float64(capCPUMilli) * 100
		if pct > 100 {
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Kind:     "Node",
				Name:     n.Name,
				Check:    "cpu-overcommit",
				Message:  fmt.Sprintf("CPU requests (%.0fm) exceed allocatable (%.0fm) — %.0f%% committed", float64(allocCPU), float64(capCPUMilli), pct),
			})
		}
	}
	if capMemBytes > 0 {
		pct := float64(allocMem) / float64(capMemBytes) * 100
		if pct > 100 {
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Kind:     "Node",
				Name:     n.Name,
				Check:    "memory-overcommit",
				Message:  fmt.Sprintf("memory requests (%.1f GiB) exceed allocatable (%.1f GiB) — %.0f%% committed", float64(allocMem)/(1024*1024*1024), float64(capMemBytes)/(1024*1024*1024), pct),
			})
		}
	}
	return findings
}

func checkTaints(n corev1.Node, pods []corev1.Pod) []Finding {
	if len(n.Spec.Taints) == 0 {
		return nil
	}

	// Check if any pending pod can't schedule here due to taints
	var findings []Finding
	blockingTaints := 0
	for _, taint := range n.Spec.Taints {
		if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
			blockingTaints++
		}
	}

	if blockingTaints > 0 {
		// Count pending pods that might be blocked
		pendingCount := 0
		for _, pod := range pods {
			if pod.Status.Phase == corev1.PodPending && pod.Spec.NodeName == "" {
				if !toleratesAllTaints(pod.Spec.Tolerations, n.Spec.Taints) {
					pendingCount++
				}
			}
		}
		if pendingCount > 0 {
			findings = append(findings, Finding{
				Severity: SeverityWarning,
				Kind:     "Node",
				Name:     n.Name,
				Check:    "taint-blocking",
				Message:  fmt.Sprintf("%d taint(s) blocking scheduling, %d pending pod(s) cannot tolerate them", blockingTaints, pendingCount),
			})
		}
	}
	return findings
}

func toleratesAllTaints(tolerations []corev1.Toleration, taints []corev1.Taint) bool {
	for _, taint := range taints {
		if taint.Effect != corev1.TaintEffectNoSchedule && taint.Effect != corev1.TaintEffectNoExecute {
			continue
		}
		tolerated := false
		for _, tol := range tolerations {
			if tol.Operator == corev1.TolerationOpExists && tol.Key == "" {
				tolerated = true
				break
			}
			if tol.Key == taint.Key {
				if tol.Operator == corev1.TolerationOpExists {
					tolerated = true
					break
				}
				if tol.Operator == corev1.TolerationOpEqual && tol.Value == taint.Value {
					tolerated = true
					break
				}
			}
		}
		if !tolerated {
			return false
		}
	}
	return true
}
