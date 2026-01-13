package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/rlog"
)

func (s *Service) startTaskQueueMetricsLoop() {
	if s == nil || s.db == nil || !s.cfg.TaskWorkerEnabled {
		return
	}
	interval := 1 * time.Minute
	go func() {
		rlog.Info("task queue metrics loop enabled", "interval", interval.String())
		_ = s.updateTaskQueueMetrics(context.Background())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			_ = s.updateTaskQueueMetrics(context.Background())
		}
	}()
}

func (s *Service) updateTaskQueueMetrics(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	db := s.db

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
