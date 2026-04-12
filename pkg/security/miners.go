package security

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// knownMinerImages are container image names (or substrings) associated with
// well-known cryptocurrency mining software. Attackers frequently push these
// images into compromised clusters.
var knownMinerImages = []string{
	"xmrig",
	"xmr-stak",
	"minergate",
	"minerd",
	"cpuminer",
	"cgminer",
	"bfgminer",
	"ethminer",
	"nbminer",
	"t-rex",
	"phoenixminer",
	"lolminer",
	"gminer",
	"teamredminer",
	"srbminer",
	"nicehash",
	"moneroocean",
	"cryptonight",
	"randomx",
	"stratum+tcp",
}

// minerEnvHints are environment variable names that suggest a container is
// configured for mining. These appear in popular mining pool setups.
var minerEnvHints = []string{
	"POOL",
	"WALLET",
	"MINING_POOL",
	"STRATUM",
	"WORKER",
	"COIN",
	"ALGO",
	"POOL_URL",
	"POOL_USER",
	"POOL_PASS",
	"XMRIG_",
	"MINER_",
}

// minerCommandHints are substrings that suggest a container is running a
// mining binary, detected in the container's command or args.
var minerCommandHints = []string{
	"xmrig",
	"minerd",
	"cpuminer",
	"stratum+tcp://",
	"stratum+ssl://",
	"stratum2+tcp://",
	"--coin=",
	"--algo=cryptonight",
	"--algo=randomx",
	"--donate-level",
	"-o pool.",
	"pool.minexmr",
	"pool.hashvault",
	"moneroocean.stream",
}

// AuditMiners scans pods for signs of cryptocurrency mining software.
func AuditMiners(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	pods, err := client.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var findings []Finding
	for i := range pods.Items {
		pod := &pods.Items[i]
		allContainers := append([]corev1.Container{}, pod.Spec.InitContainers...)
		allContainers = append(allContainers, pod.Spec.Containers...)

		for _, c := range allContainers {
			findings = append(findings, checkMinerImage(pod, c)...)
			findings = append(findings, checkMinerEnv(pod, c)...)
			findings = append(findings, checkMinerCommand(pod, c)...)
		}
	}
	return findings, nil
}

func checkMinerImage(pod *corev1.Pod, c corev1.Container) []Finding {
	img := strings.ToLower(c.Image)
	for _, hint := range knownMinerImages {
		if strings.Contains(img, hint) {
			return []Finding{{
				Severity:  SeverityCritical,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "crypto-miner-image",
				Message:   fmt.Sprintf("image %q matches known mining software pattern %q", c.Image, hint),
			}}
		}
	}
	return nil
}

func checkMinerEnv(pod *corev1.Pod, c corev1.Container) []Finding {
	var findings []Finding
	for _, e := range c.Env {
		name := strings.ToUpper(e.Name)
		for _, hint := range minerEnvHints {
			if strings.Contains(name, hint) {
				findings = append(findings, Finding{
					Severity:  SeverityWarning,
					Kind:      "Pod",
					Namespace: pod.Namespace,
					Name:      pod.Name,
					Container: c.Name,
					Check:     "crypto-miner-env",
					Message:   fmt.Sprintf("env var %q matches mining config pattern %q", e.Name, hint),
				})
				break
			}
		}
	}
	return findings
}

func checkMinerCommand(pod *corev1.Pod, c corev1.Container) []Finding {
	words := append([]string{}, c.Command...)
	words = append(words, c.Args...)
	combined := strings.ToLower(strings.Join(words, " "))

	for _, hint := range minerCommandHints {
		if strings.Contains(combined, hint) {
			return []Finding{{
				Severity:  SeverityCritical,
				Kind:      "Pod",
				Namespace: pod.Namespace,
				Name:      pod.Name,
				Container: c.Name,
				Check:     "crypto-miner-command",
				Message:   fmt.Sprintf("command/args contain mining-related pattern %q", hint),
			}}
		}
	}
	return nil
}
