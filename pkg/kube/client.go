// Package kube provides helpers for building a Kubernetes client from a
// kubeconfig path, an in-cluster config, or the environment's defaults.
package kube

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient builds a kubernetes.Interface. Resolution order:
//  1. explicit kubeconfigPath argument if non-empty
//  2. $KUBECONFIG environment variable
//  3. in-cluster config (when running as a pod)
//  4. ~/.kube/config
func NewClient(kubeconfigPath string) (kubernetes.Interface, string, error) {
	cfg, ns, err := loadConfig(kubeconfigPath)
	if err != nil {
		return nil, "", err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("build clientset: %w", err)
	}
	return cs, ns, nil
}

func loadConfig(explicit string) (*rest.Config, string, error) {
	if explicit == "" {
		explicit = os.Getenv("KUBECONFIG")
	}

	if explicit == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, "default", nil
		}
		if home, err := os.UserHomeDir(); err == nil {
			candidate := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(candidate); err == nil {
				explicit = candidate
			}
		}
	}

	if explicit == "" {
		return nil, "", fmt.Errorf("no kubeconfig found: set --kubeconfig, $KUBECONFIG, or run inside a cluster")
	}

	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: explicit},
		&clientcmd.ConfigOverrides{},
	)
	cfg, err := loader.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig %q: %w", explicit, err)
	}
	ns, _, err := loader.Namespace()
	if err != nil || ns == "" {
		ns = "default"
	}
	return cfg, ns, nil
}
