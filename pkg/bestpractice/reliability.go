package bestpractice

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// AuditReliability checks deployments for missing probes, single replicas,
// latest tags, missing PDBs, and missing anti-affinity.
func AuditReliability(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	deploys, err := client.AppsV1().Deployments(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}

	pdbs, err := client.PolicyV1().PodDisruptionBudgets(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pdbs: %w", err)
	}

	var findings []Finding
	for _, d := range deploys.Items {
		if d.Spec.Replicas != nil && *d.Spec.Replicas == 0 {
			continue
		}
		findings = append(findings, checkProbes(d)...)
		findings = append(findings, checkLatestTag(d)...)
		findings = append(findings, checkSingleReplica(d)...)
		findings = append(findings, checkPDB(d, pdbs.Items)...)
		findings = append(findings, checkAntiAffinity(d)...)
	}
	return findings, nil
}

func checkProbes(d appsv1.Deployment) []Finding {
	var findings []Finding
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.LivenessProbe == nil {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Deployment",
				Namespace: d.Namespace,
				Name:      d.Name,
				Check:     "no-liveness-probe",
				Message:   fmt.Sprintf("container %q has no liveness probe — kubelet can't restart stuck processes", c.Name),
			})
		}
		if c.ReadinessProbe == nil {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Deployment",
				Namespace: d.Namespace,
				Name:      d.Name,
				Check:     "no-readiness-probe",
				Message:   fmt.Sprintf("container %q has no readiness probe — traffic may be sent before it's ready", c.Name),
			})
		}
	}
	return findings
}

func checkLatestTag(d appsv1.Deployment) []Finding {
	var findings []Finding
	for _, c := range d.Spec.Template.Spec.Containers {
		if isLatestTag(c.Image) {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Deployment",
				Namespace: d.Namespace,
				Name:      d.Name,
				Check:     "latest-image-tag",
				Message:   fmt.Sprintf("container %q uses image %q — :latest is mutable and breaks reproducibility", c.Name, c.Image),
			})
		}
	}
	return findings
}

func isLatestTag(image string) bool {
	if strings.HasSuffix(image, ":latest") {
		return true
	}
	// No tag at all defaults to :latest
	if !strings.Contains(image, ":") && !strings.Contains(image, "@") {
		return true
	}
	return false
}

func checkSingleReplica(d appsv1.Deployment) []Finding {
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	if replicas == 1 {
		return []Finding{{
			Severity:  SeverityWarning,
			Kind:      "Deployment",
			Namespace: d.Namespace,
			Name:      d.Name,
			Check:     "single-replica",
			Message:   "only 1 replica — no high availability; any disruption causes downtime",
		}}
	}
	return nil
}

func checkPDB(d appsv1.Deployment, pdbs []policyv1.PodDisruptionBudget) []Finding {
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	if replicas < 2 {
		return nil // PDB is meaningless on single-replica
	}

	dLabels := d.Spec.Template.Labels
	for _, pdb := range pdbs {
		if pdb.Namespace != d.Namespace {
			continue
		}
		if pdb.Spec.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(dLabels)) {
			return nil // PDB covers this deployment
		}
	}
	return []Finding{{
		Severity:  SeverityWarning,
		Kind:      "Deployment",
		Namespace: d.Namespace,
		Name:      d.Name,
		Check:     "no-pdb",
		Message:   fmt.Sprintf("no PodDisruptionBudget covers this %d-replica deployment — voluntary disruptions may take it fully down", replicas),
	}}
}

func checkAntiAffinity(d appsv1.Deployment) []Finding {
	replicas := int32(1)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	if replicas < 2 {
		return nil
	}

	affinity := d.Spec.Template.Spec.Affinity
	if affinity != nil && affinity.PodAntiAffinity != nil {
		anti := affinity.PodAntiAffinity
		if len(anti.PreferredDuringSchedulingIgnoredDuringExecution) > 0 ||
			len(anti.RequiredDuringSchedulingIgnoredDuringExecution) > 0 {
			return nil
		}
	}
	return []Finding{{
		Severity:  SeverityWarning,
		Kind:      "Deployment",
		Namespace: d.Namespace,
		Name:      d.Name,
		Check:     "no-anti-affinity",
		Message:   fmt.Sprintf("no pod anti-affinity on %d-replica deployment — all replicas may land on the same node", replicas),
	}}
}

// AuditPodImages checks all running pods for latest tags (catches
// workloads beyond Deployments: StatefulSets, DaemonSets, bare pods).
func AuditPodImages(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	// Track which pods are owned by a Deployment (already checked above)
	deployOwned := make(map[string]bool)
	rsList, _ := client.AppsV1().ReplicaSets(opts.Namespace).List(ctx, metav1.ListOptions{})
	if rsList != nil {
		for _, rs := range rsList.Items {
			for _, ref := range rs.OwnerReferences {
				if ref.Kind == "Deployment" {
					// Mark all pods owned by this RS
					sel, _ := metav1.LabelSelectorAsSelector(rs.Spec.Selector)
					if sel != nil {
						for _, pod := range pods.Items {
							if pod.Namespace == rs.Namespace && sel.Matches(labels.Set(pod.Labels)) {
								deployOwned[pod.Namespace+"/"+pod.Name] = true
							}
						}
					}
				}
			}
		}
	}

	var findings []Finding
	for _, pod := range pods.Items {
		if deployOwned[pod.Namespace+"/"+pod.Name] {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, c := range pod.Spec.Containers {
			if isLatestTag(c.Image) {
				findings = append(findings, Finding{
					Severity:  SeverityWarning,
					Kind:      "Pod",
					Namespace: pod.Namespace,
					Name:      pod.Name,
					Check:     "latest-image-tag",
					Message:   fmt.Sprintf("container %q uses image %q", c.Name, c.Image),
				})
			}
		}
	}
	return findings, nil
}
