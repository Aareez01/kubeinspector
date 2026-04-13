package workload

import (
	"context"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AuditJobs checks for failed or stuck Jobs and CronJobs whose last
// scheduled job failed.
func AuditJobs(ctx context.Context, client kubernetes.Interface, opts Options) ([]Finding, error) {
	jobs, err := client.BatchV1().Jobs(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}

	var findings []Finding
	for _, job := range jobs.Items {
		findings = append(findings, checkJob(job)...)
	}

	cronFindings, err := checkCronJobs(ctx, client, opts, jobs.Items)
	if err != nil {
		return nil, err
	}
	findings = append(findings, cronFindings...)

	return findings, nil
}

func checkJob(job batchv1.Job) []Finding {
	var findings []Finding

	// Failed job
	for _, cond := range job.Status.Conditions {
		if cond.Type == batchv1.JobFailed && cond.Status == "True" {
			findings = append(findings, Finding{
				Severity:  SeverityCritical,
				Kind:      "Job",
				Namespace: job.Namespace,
				Name:      job.Name,
				Check:     "job-failed",
				Message:   fmt.Sprintf("job failed: %s", cond.Message),
			})
			return findings
		}
	}

	// Stuck job: running for too long without completing
	if job.Status.CompletionTime == nil && job.Status.StartTime != nil {
		duration := time.Since(job.Status.StartTime.Time)
		deadline := 1 * time.Hour
		if job.Spec.ActiveDeadlineSeconds != nil {
			deadline = time.Duration(*job.Spec.ActiveDeadlineSeconds) * time.Second
		}
		if duration > deadline {
			findings = append(findings, Finding{
				Severity:  SeverityWarning,
				Kind:      "Job",
				Namespace: job.Namespace,
				Name:      job.Name,
				Check:     "job-stuck",
				Message:   fmt.Sprintf("job running for %s without completing", duration.Truncate(time.Minute)),
			})
		}
	}

	return findings
}

func checkCronJobs(ctx context.Context, client kubernetes.Interface, opts Options, jobs []batchv1.Job) ([]Finding, error) {
	cronJobs, err := client.BatchV1().CronJobs(opts.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list cronjobs: %w", err)
	}

	// Index jobs by owner
	jobsByOwner := make(map[string][]batchv1.Job)
	for _, j := range jobs {
		for _, ref := range j.OwnerReferences {
			if ref.Kind == "CronJob" {
				key := j.Namespace + "/" + ref.Name
				jobsByOwner[key] = append(jobsByOwner[key], j)
			}
		}
	}

	var findings []Finding
	for _, cj := range cronJobs.Items {
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			continue
		}
		key := cj.Namespace + "/" + cj.Name
		owned := jobsByOwner[key]
		if len(owned) == 0 {
			continue
		}

		// Find the most recent job
		var latest batchv1.Job
		for _, j := range owned {
			if j.CreationTimestamp.After(latest.CreationTimestamp.Time) {
				latest = j
			}
		}

		for _, cond := range latest.Status.Conditions {
			if cond.Type == batchv1.JobFailed && cond.Status == "True" {
				findings = append(findings, Finding{
					Severity:  SeverityWarning,
					Kind:      "CronJob",
					Namespace: cj.Namespace,
					Name:      cj.Name,
					Check:     "cronjob-last-failed",
					Message:   fmt.Sprintf("last scheduled job %q failed: %s", latest.Name, cond.Message),
				})
				break
			}
		}
	}
	return findings, nil
}
