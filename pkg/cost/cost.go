package cost

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NamespaceEstimate is the cost breakdown for a single namespace.
type NamespaceEstimate struct {
	Namespace       string  `json:"namespace"`
	CPUCores        float64 `json:"cpu_cores"`
	MemoryGB        float64 `json:"memory_gb"`
	StorageGB       float64 `json:"storage_gb"`
	CPUCostMonth    float64 `json:"cpu_cost_month"`
	MemoryCostMonth float64 `json:"memory_cost_month"`
	StorageCostMonth float64 `json:"storage_cost_month"`
	TotalMonth      float64 `json:"total_month"`
}

// Report is the full output of Estimate.
type Report struct {
	Currency   string              `json:"currency"`
	Namespaces []NamespaceEstimate `json:"namespaces"`
	Total      float64             `json:"total_month"`
}

// Options controls the scan.
type Options struct {
	Namespace string // empty = all namespaces
	Pricing   Pricing
}

// Estimate walks running pods and PVCs and returns a per-namespace cost
// report. Only pods in Running or Pending phase are counted — completed or
// failed pods don't consume reserved resources.
func Estimate(ctx context.Context, client kubernetes.Interface, opts Options) (*Report, error) {
	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	pvcs, err := client.CoreV1().PersistentVolumeClaims(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pvcs: %w", err)
	}

	byNS := make(map[string]*NamespaceEstimate)
	ensure := func(ns string) *NamespaceEstimate {
		if e, ok := byNS[ns]; ok {
			return e
		}
		e := &NamespaceEstimate{Namespace: ns}
		byNS[ns] = e
		return e
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning && pod.Status.Phase != corev1.PodPending {
			continue
		}
		cpu, mem := sumPodRequests(&pod)
		e := ensure(pod.Namespace)
		e.CPUCores += cpu
		e.MemoryGB += mem
	}

	for _, pvc := range pvcs.Items {
		req := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
		gb := float64(req.Value()) / (1024 * 1024 * 1024)
		e := ensure(pvc.Namespace)
		e.StorageGB += gb

		sc := ""
		if pvc.Spec.StorageClassName != nil {
			sc = *pvc.Spec.StorageClassName
		}
		rate := lookupStorageRate(opts.Pricing, sc)
		e.StorageCostMonth += gb * rate
	}

	report := &Report{Currency: opts.Pricing.Currency}
	for _, e := range byNS {
		e.CPUCostMonth = e.CPUCores * opts.Pricing.CPUCoreHour * hoursPerMonth
		e.MemoryCostMonth = e.MemoryGB * opts.Pricing.MemoryGBHour * hoursPerMonth
		e.TotalMonth = e.CPUCostMonth + e.MemoryCostMonth + e.StorageCostMonth
		report.Total += e.TotalMonth
		report.Namespaces = append(report.Namespaces, *e)
	}
	sort.Slice(report.Namespaces, func(i, j int) bool {
		return report.Namespaces[i].TotalMonth > report.Namespaces[j].TotalMonth
	})
	return report, nil
}

func sumPodRequests(pod *corev1.Pod) (cpuCores, memGB float64) {
	for _, c := range pod.Spec.Containers {
		cpu := c.Resources.Requests[corev1.ResourceCPU]
		mem := c.Resources.Requests[corev1.ResourceMemory]
		cpuCores += float64(cpu.MilliValue()) / 1000.0
		memGB += float64(mem.Value()) / (1024 * 1024 * 1024)
	}
	return cpuCores, memGB
}

func lookupStorageRate(p Pricing, storageClass string) float64 {
	if rate, ok := p.StoragePerGBMonth[storageClass]; ok {
		return rate
	}
	return p.StoragePerGBMonth[""]
}
