package workload

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuditJobs_failed(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "migrate", Namespace: "default"},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{{
				Type:    batchv1.JobFailed,
				Status:  "True",
				Message: "BackoffLimitExceeded",
			}},
		},
	}
	cs := fake.NewSimpleClientset(job)
	got, err := AuditJobs(context.Background(), cs, Options{Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	hits := findCheck(got, "job-failed")
	if len(hits) != 1 {
		t.Fatalf("expected job-failed, got %+v", got)
	}
}

func TestAuditJobs_stuck(t *testing.T) {
	start := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "long", Namespace: "default"},
		Status: batchv1.JobStatus{
			StartTime: &start,
		},
	}
	cs := fake.NewSimpleClientset(job)
	got, _ := AuditJobs(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "job-stuck")
	if len(hits) != 1 {
		t.Fatalf("expected job-stuck, got %+v", got)
	}
}

func TestAuditJobs_cronJobLastFailed(t *testing.T) {
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "default"},
		Spec:       batchv1.CronJobSpec{Schedule: "0 2 * * *"},
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backup-12345",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "CronJob", Name: "backup",
			}},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
		},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{{
				Type:    batchv1.JobFailed,
				Status:  "True",
				Message: "BackoffLimitExceeded",
			}},
		},
	}
	cs := fake.NewSimpleClientset(cj, job)
	got, _ := AuditJobs(context.Background(), cs, Options{Namespace: "default"})
	hits := findCheck(got, "cronjob-last-failed")
	if len(hits) != 1 {
		t.Fatalf("expected cronjob-last-failed, got %+v", got)
	}
}
