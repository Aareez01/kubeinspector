package workload

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AuditPods checks for CrashLoopBackOff pods and stuck pending pods.
func AuditPods(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var findings []Finding
	for i := range pods.Items {
		pod := &pods.Items[i]
		findings = append(findings, checkCrashLoop(pod)...)
		findings = append(findings, checkPending(pod)...)
	}
	return findings, nil
}

func checkCrashLoop(pod *corev1.Pod) []Finding {
	var findings []Finding
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			exitCode := int32(-1)
			if cs.LastTerminationState.Terminated != nil {
				exitCode = cs.LastTerminationState.Terminated.ExitCode
			}
			findings = append(findings, Finding{
				Severity:  SeverityCritical,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Check:     "crash-loop",
				Message: fmt.Sprintf("container %q in CrashLoopBackOff (restarts: %d, last exit code: %d)",
					cs.Name, cs.RestartCount, exitCode),
			})
		}
	}
	return findings
}

func checkPending(pod *corev1.Pod) []Finding {
	if pod.Status.Phase != corev1.PodPending {
		return nil
	}

	reason := diagnosePending(pod)
	return []Finding{{
		Severity:  SeverityWarning,
		Kind:      "Pod",
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Check:     "pending-pod",
		Message:   reason,
	}}
}

func diagnosePending(pod *corev1.Pod) string {
	// Check conditions for scheduling failures
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
			msg := cond.Message
			switch {
			case strings.Contains(msg, "Insufficient cpu"):
				return fmt.Sprintf("unschedulable: insufficient CPU — %s", msg)
			case strings.Contains(msg, "Insufficient memory"):
				return fmt.Sprintf("unschedulable: insufficient memory — %s", msg)
			case strings.Contains(msg, "didn't match pod affinity"):
				return fmt.Sprintf("unschedulable: affinity rules not satisfied — %s", msg)
			case strings.Contains(msg, "didn't match Pod's node affinity"):
				return fmt.Sprintf("unschedulable: node affinity not satisfied — %s", msg)
			case strings.Contains(msg, "node(s) had untolerated taint"):
				return fmt.Sprintf("unschedulable: untolerated taint — %s", msg)
			case strings.Contains(msg, "persistentvolumeclaim"):
				return fmt.Sprintf("unschedulable: PVC not bound — %s", msg)
			default:
				if msg != "" {
					return fmt.Sprintf("unschedulable: %s", msg)
				}
			}
		}
	}

	// Check container statuses for image pull issues
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			switch cs.State.Waiting.Reason {
			case "ImagePullBackOff", "ErrImagePull":
				return fmt.Sprintf("image pull failure on container %q: %s",
					cs.Name, cs.State.Waiting.Message)
			case "CreateContainerConfigError":
				return fmt.Sprintf("config error on container %q: %s",
					cs.Name, cs.State.Waiting.Message)
			}
		}
	}

	return "pod is pending (reason unknown — check kubectl describe)"
}
