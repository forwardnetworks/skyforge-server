package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/cron"
	"encore.dev/rlog"
)

// Periodically update task queue gauges so operational dashboards can show
// whether jobs are piling up (or running) without having to infer state from
// counters.
var _ = cron.NewJob("skyforge-task-queue-metrics", cron.JobConfig{
	Title:    "Update task queue metrics",
	Every:    1 * cron.Minute,
	Endpoint: UpdateTaskQueueMetrics,
})

// UpdateTaskQueueMetrics refreshes gauges for queued/running tasks.
//
//encore:api private method=POST path=/internal/tasks/metrics
func UpdateTaskQueueMetrics(ctx context.Context) error {
	if defaultService == nil || defaultService.db == nil {
		return nil
	}
	db := defaultService.db

	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	taskTypes, err := listTaskTypesSince(ctxReq, db, 30*24*time.Hour)
	cancel()
	if err != nil {
		rlog.Error("task metrics: list task types failed", "err", err)
		return err
	}
	for _, taskType := range taskTypes {
		taskType = strings.TrimSpace(taskType)
		if taskType == "" {
			continue
		}
		labels := taskTypeLabels{TaskType: taskType}
		taskQueuedCurrent.With(labels).Set(0)
		taskQueuedOldestAgeSeconds.With(labels).Set(0)
		taskRunningCurrent.With(labels).Set(0)
	}

	queuedTotal := float64(0)
	runningTotal := float64(0)
	oldestQueuedAge := float64(0)

	ctxReq, cancel = context.WithTimeout(ctx, 3*time.Second)
	queuedRows, err := listTaskStatusCounts(ctxReq, db, "queued")
	cancel()
	if err != nil {
		rlog.Error("task metrics: queued query failed", "err", err)
		return err
	}
	for _, row := range queuedRows {
		taskType := strings.TrimSpace(row.TaskType)
		if taskType == "" {
			continue
		}
		labels := taskTypeLabels{TaskType: taskType}
		taskQueuedCurrent.With(labels).Set(float64(row.Count))
		if row.OldestAgeSeconds > 0 {
			taskQueuedOldestAgeSeconds.With(labels).Set(row.OldestAgeSeconds)
			if row.OldestAgeSeconds > oldestQueuedAge {
				oldestQueuedAge = row.OldestAgeSeconds
			}
		} else {
			taskQueuedOldestAgeSeconds.With(labels).Set(0)
		}
		queuedTotal += float64(row.Count)
	}

	ctxReq, cancel = context.WithTimeout(ctx, 3*time.Second)
	runningRows, err := listTaskStatusCounts(ctxReq, db, "running")
	cancel()
	if err != nil {
		rlog.Error("task metrics: running query failed", "err", err)
		return err
	}
	for _, row := range runningRows {
		taskType := strings.TrimSpace(row.TaskType)
		if taskType == "" {
			continue
		}
		labels := taskTypeLabels{TaskType: taskType}
		taskRunningCurrent.With(labels).Set(float64(row.Count))
		runningTotal += float64(row.Count)
	}

	taskQueuedCurrentTotal.Set(queuedTotal)
	taskRunningCurrentTotal.Set(runningTotal)
	taskQueuedOldestAgeSecondsTotal.Set(oldestQueuedAge)

	return nil
}
