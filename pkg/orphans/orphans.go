// Package orphans detects Kubernetes resources that are no longer referenced
// by any live workload and are candidates for cleanup.
package orphans

import "time"

// Severity ranks how much attention an orphan deserves. Orphans are never
// errors — nothing is broken, the resource is just unreferenced.
type Severity string

const (
	// SeverityWarning marks an orphan that holds real resources or real
	// secrets: unmounted PVCs still cost money, stale Secrets still leak.
	SeverityWarning Severity = "warning"

	// SeverityInfo marks an orphan that is expected to exist. Scaled-to-zero
	// ReplicaSets are Deployment rollback history, so Kubernetes creates them
	// on every rollout by design and prunes them at revisionHistoryLimit.
	SeverityInfo Severity = "info"
)

// Finding is a single orphaned-resource report entry.
type Finding struct {
	Severity  Severity      `json:"severity"`
	Kind      string        `json:"kind"`
	Namespace string        `json:"namespace"`
	Name      string        `json:"name"`
	Age       time.Duration `json:"age"`
	Reason    string        `json:"reason"`
}

// Options controls orphan detection behavior.
type Options struct {
	// Namespace to scan. Empty string means all namespaces.
	Namespace string

	// GracePeriod skips resources younger than this, to avoid flagging
	// objects created mid-rollout. Default: 10 minutes.
	GracePeriod time.Duration
}

// KeepAnnotation marks a resource as intentionally retained; findings are
// suppressed when this annotation is set to "true".
const KeepAnnotation = "kubeinspector.io/keep"
