// Package cost produces rough per-namespace monthly cost estimates from
// Kubernetes resource requests. It's intentionally simple: the goal is to
// give a small team a "which namespaces burn the most" signal without
// running Kubecost or a cloud billing pipeline. Accuracy is ballpark only.
package cost

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Pricing holds per-unit rates. CPU and memory are per-hour because that's
// how cloud providers usually quote compute; storage is per-month because
// that's how block storage is billed.
type Pricing struct {
	CPUCoreHour   float64            `json:"cpu_core_hour"`
	MemoryGBHour  float64            `json:"memory_gb_hour"`
	StoragePerGBMonth map[string]float64 `json:"storage_gb_month"`
	Currency      string             `json:"currency"`
}

// DefaultPricing returns ballpark US rates roughly matching AWS on-demand
// m5.large pricing as of early 2026. Provided so users can run `cost` out
// of the box without writing a pricing.yaml first.
func DefaultPricing() Pricing {
	return Pricing{
		CPUCoreHour:  0.0316,
		MemoryGBHour: 0.00456,
		StoragePerGBMonth: map[string]float64{
			"":         0.08, // unknown / default
			"gp3":      0.08,
			"gp2":      0.10,
			"standard": 0.04,
			"io1":      0.125,
			"io2":      0.125,
		},
		Currency: "USD",
	}
}

// LoadPricing reads a pricing file from disk. Any field missing from the
// file falls back to the DefaultPricing value.
func LoadPricing(path string) (Pricing, error) {
	p := DefaultPricing()
	if path == "" {
		return p, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read pricing file: %w", err)
	}
	var override Pricing
	if err := yaml.Unmarshal(data, &override); err != nil {
		return p, fmt.Errorf("parse pricing file: %w", err)
	}
	if override.CPUCoreHour > 0 {
		p.CPUCoreHour = override.CPUCoreHour
	}
	if override.MemoryGBHour > 0 {
		p.MemoryGBHour = override.MemoryGBHour
	}
	if override.Currency != "" {
		p.Currency = override.Currency
	}
	for k, v := range override.StoragePerGBMonth {
		p.StoragePerGBMonth[k] = v
	}
	return p, nil
}

// hoursPerMonth is the standard billing-month conversion cloud providers use.
const hoursPerMonth = 730.0
