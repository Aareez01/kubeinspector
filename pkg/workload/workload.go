// Package workload detects unhealthy Kubernetes workloads: CrashLoopBackOff
// pods, stuck pending pods, Deployments with zero ready replicas, broken
// Service label selectors, and failed Jobs/CronJobs.
package workload

// Severity of a workload health finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
)

// Finding is a single workload health issue.
type Finding struct {
	Severity  Severity `json:"severity"`
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Check     string   `json:"check"`
	Message   string   `json:"message"`
}

// Options configures the workload health audit.
type Options struct {
	Namespace string
}
