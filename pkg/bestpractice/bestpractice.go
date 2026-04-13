// Package bestpractice checks Kubernetes workloads against reliability and
// operational best practices: missing probes, single-replica deployments,
// latest image tags, missing PDBs, missing anti-affinity, NetworkPolicy
// coverage, and exposed NodePort services.
package bestpractice

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
)

type Finding struct {
	Severity  Severity `json:"severity"`
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Check     string   `json:"check"`
	Message   string   `json:"message"`
}

type Options struct {
	Namespace string
}
