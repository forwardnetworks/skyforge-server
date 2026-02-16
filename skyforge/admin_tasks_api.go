package skyforge

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.app/internal/taskheartbeats"
	"encore.app/internal/taskqueue"
	"encore.app/internal/taskreconcile"
	"encore.app/internal/taskstore"
	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type ReconcileTasksRequest struct {
	// Limit caps the number of queued tasks to republish.
	Limit int `json:"limit,omitempty"`
}

type ReconcileTasksResponse struct {
	Status          string `json:"status"`
	ConsideredTasks int    `json:"consideredTasks"`
	Republished     int    `json:"republished"`
	PublishErrors   int    `json:"publishErrors"`
}

// ReconcileQueuedTasks republishes queue events for tasks stuck in "queued".
//
// This is an admin-only manual guardrail; the worker also runs an automatic reconciler via cron.
//
//encore:api auth method=POST path=/api/admin/tasks/reconcile tag:admin
func (s *Service) ReconcileQueuedTasks(ctx context.Context, req *ReconcileTasksRequest) (*ReconcileTasksResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("task store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	limit := 200
	if req != nil && req.Limit > 0 {
		if req.Limit > 2000 {
			limit = 2000
		} else {
			limit = req.Limit
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	items, err := taskreconcile.ListQueuedTasks(ctx, s.db, limit)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to list queued tasks").Err()
	}

	republished := 0
	publishErrors := 0
	for _, item := range items {
		if item.TaskID <= 0 || strings.TrimSpace(item.Key) == "" {
			continue
		}
		ev := &taskqueue.TaskEnqueuedEvent{TaskID: item.TaskID, Key: item.Key}
		if item.Priority < taskstore.PriorityInteractive {
			if _, err := taskqueue.BackgroundTopic.Publish(ctx, ev); err != nil {
				publishErrors++
				rlog.Error("task reconcile publish failed", "task_id", item.TaskID, "err", err)
				continue
			}
			republished++
			continue
		}
		if _, err := taskqueue.InteractiveTopic.Publish(ctx, ev); err != nil {
			publishErrors++
			rlog.Error("task reconcile publish failed", "task_id", item.TaskID, "err", err)
			continue
		}
		republished++
	}

	return &ReconcileTasksResponse{
		Status:          "ok",
		ConsideredTasks: len(items),
		Republished:     republished,
		PublishErrors:   publishErrors,
	}, nil
}

type TaskQueueDiagResponse struct {
	Status string `json:"status"`

	Queued                int    `json:"queued"`
	Running               int    `json:"running"`
	OldestQueuedAgeSec    int    `json:"oldestQueuedAgeSec"`
	WorkerHeartbeatAgeSec int    `json:"workerHeartbeatAgeSec"`
	WorkerEnabled         bool   `json:"workerEnabled"`
	PublishFailures10m    int    `json:"publishFailures10m"`
	PublishFailuresLatest string `json:"publishFailuresLatest,omitempty"`
}

// TaskQueueDiag provides admin diagnostics for the task queue.
//
// This is intended to answer: "are tasks queued because of real backlog, or because
// queue event delivery/worker execution is broken?"
//
//encore:api auth method=GET path=/api/admin/tasks/diag tag:admin
func (s *Service) TaskQueueDiag(ctx context.Context) (*TaskQueueDiagResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("task store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	queued, running, oldestAge, err := taskQueueSummary(ctx, s.db)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to read task queue summary").Err()
	}

	heartbeatAge := 0
	if s.cfg.TaskWorkerEnabled {
		if age, err := taskheartbeats.MostRecentWorkerHeartbeatAgeSeconds(ctx, s.db); err == nil && age > 0 {
			heartbeatAge = int(age)
		}
	}

	failCount := 0
	var latest sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
SELECT
  COUNT(*) AS failures,
  MAX(created_at) AS latest
FROM sf_task_events
WHERE event_type='task.enqueue.publish_failed'
  AND created_at > now() - interval '10 minutes'
`).Scan(&failCount, &latest); err != nil {
		// Best-effort; don't fail diag endpoint if this query fails.
		rlog.Error("task queue diag publish failure query failed", "err", err)
	}
	latestStr := ""
	if latest.Valid {
		latestStr = latest.Time.UTC().Format(time.RFC3339)
	}

	out := &TaskQueueDiagResponse{
		Status:                "ok",
		Queued:                queued,
		Running:               running,
		OldestQueuedAgeSec:    oldestAge,
		WorkerHeartbeatAgeSec: heartbeatAge,
		WorkerEnabled:         s.cfg.TaskWorkerEnabled,
		PublishFailures10m:    failCount,
		PublishFailuresLatest: latestStr,
	}
	// Basic heuristics to flag queue health quickly.
	if queued > 0 && heartbeatAge > 120 && s.cfg.TaskWorkerEnabled {
		out.Status = "degraded"
	}
	if queued > 0 && oldestAge > 300 && s.cfg.TaskWorkerEnabled {
		out.Status = "degraded"
	}
	if failCount > 0 {
		out.Status = "degraded"
	}
	if queued > 0 && !s.cfg.TaskWorkerEnabled {
		out.Status = "degraded"
	}
	return out, nil
}

type ReconcileRunningTasksRequest struct {
	// Limit caps the number of running tasks to consider.
	Limit int `json:"limit,omitempty"`
	// HardMaxRuntimeMinutes marks tasks as failed when they have been running longer than this.
	HardMaxRuntimeMinutes int `json:"hardMaxRuntimeMinutes,omitempty"`
	// MaxIdleMinutes marks tasks as failed when they have had no logs for this long.
	MaxIdleMinutes int `json:"maxIdleMinutes,omitempty"`
}

type ReconcileRunningTasksResponse struct {
	Status          string `json:"status"`
	ConsideredTasks int    `json:"consideredTasks"`
	MarkedFailed    int    `json:"markedFailed"`
	FinishErrors    int    `json:"finishErrors"`
}

// ReconcileRunningTasks marks tasks that appear stuck in "running" as failed.
//
// This is an admin-only manual guardrail; the worker also runs an automatic reconciler via cron.
//
//encore:api auth method=POST path=/api/admin/tasks/reconcile-running tag:admin
func (s *Service) ReconcileRunningTasks(ctx context.Context, req *ReconcileRunningTasksRequest) (*ReconcileRunningTasksResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("task store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}

	limit := 50
	if req != nil && req.Limit > 0 {
		if req.Limit > 500 {
			limit = 500
		} else {
			limit = req.Limit
		}
	}

	hardMax := 12 * time.Hour
	if req != nil && req.HardMaxRuntimeMinutes > 0 {
		if req.HardMaxRuntimeMinutes > 24*60 {
			hardMax = 24 * time.Hour
		} else {
			hardMax = time.Duration(req.HardMaxRuntimeMinutes) * time.Minute
		}
	}

	maxIdle := 2 * time.Hour
	if req != nil && req.MaxIdleMinutes > 0 {
		if req.MaxIdleMinutes > 12*60 {
			maxIdle = 12 * time.Hour
		} else {
			maxIdle = time.Duration(req.MaxIdleMinutes) * time.Minute
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	items, err := taskreconcile.FindStuckRunningTasks(ctx, s.db, taskreconcile.RunningReconcileOptions{
		Limit:          limit,
		HardMaxRuntime: hardMax,
		MaxIdle:        maxIdle,
	})
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to find stuck running tasks").Err()
	}

	markedFailed := 0
	finishErrors := 0
	for _, item := range items {
		if item.TaskID <= 0 {
			continue
		}
		rec, err := taskstore.GetTask(ctx, s.db, item.TaskID)
		if err != nil || rec == nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rec.Status), "running") {
			continue
		}

		errMsg := "task appears stuck (no recent activity); marked failed by admin reconciler"
		rlog.Warn("admin reconcile running task", "task_id", item.TaskID, "owner", item.OwnerID, "deployment", item.DeploymentID)

		if err := taskstore.FinishTask(ctx, s.db, item.TaskID, "failed", errMsg); err != nil {
			finishErrors++
			rlog.Error("admin reconcile running task finish failed", "task_id", item.TaskID, "err", err)
			continue
		}
		markedFailed++

		_, _ = taskqueue.StatusTopic.Publish(ctx, &taskqueue.TaskStatusEvent{
			TaskID: item.TaskID,
			Status: "failed",
			Error:  errMsg,
		})
	}

	return &ReconcileRunningTasksResponse{
		Status:          "ok",
		ConsideredTasks: len(items),
		MarkedFailed:    markedFailed,
		FinishErrors:    finishErrors,
	}, nil
}
