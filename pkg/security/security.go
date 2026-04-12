// Package security audits Kubernetes workloads and RBAC for common security
// misconfigurations: privileged containers, host namespaces, dangerous
// capabilities, missing resource limits, overly permissive RBAC, and
// secrets exposed via environment variables.
package security

// Severity of a security finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
)

// Finding is a single security issue detected in the cluster.
type Finding struct {
	Severity  Severity `json:"severity"`
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Container string   `json:"container,omitempty"`
	Check     string   `json:"check"`
	Message   string   `json:"message"`
}

// Options configures the security audit.
type Options struct {
	Namespace string
}
