// Package orphans detects Kubernetes resources that are no longer referenced
// by any live workload and are candidates for cleanup.
package orphans

import "time"

// Finding is a single orphaned-resource report entry.
type Finding struct {
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
