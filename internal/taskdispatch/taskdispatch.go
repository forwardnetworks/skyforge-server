package taskdispatch

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskstore"
)

// DecodeTaskSpec decodes a JSON spec from task metadata at key "spec".
func DecodeTaskSpec[T any](task *taskstore.TaskRecord, out *T) error {
	if task == nil || out == nil {
		return fmt.Errorf("task unavailable")
	}
	raw, ok := task.Metadata["spec"]
	if !ok || len(raw) == 0 {
		return fmt.Errorf("task spec missing (retry the run)")
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("task spec decode failed: %w", err)
	}
	return nil
}

// WithTaskStep emits task.step.* events around fn execution.
func WithTaskStep(ctx context.Context, db *sql.DB, taskID int, stepKey string, fn func() error) error {
	if db == nil || taskID <= 0 {
		if fn == nil {
			return nil
		}
		return fn()
	}
	stepKey = strings.TrimSpace(stepKey)
	if stepKey == "" {
		stepKey = "step"
	}

	startedAt := time.Now()
	_ = taskstore.AppendTaskEvent(context.Background(), db, taskID, "task.step.started", map[string]any{
		"step": stepKey,
	})
	if fn == nil {
		_ = taskstore.AppendTaskEvent(context.Background(), db, taskID, "task.step.succeeded", map[string]any{
			"step":        stepKey,
			"duration_ms": time.Since(startedAt).Milliseconds(),
		})
		return nil
	}

	err := fn()
	if err != nil {
		_ = taskstore.AppendTaskEvent(context.Background(), db, taskID, "task.step.failed", map[string]any{
			"step":        stepKey,
			"duration_ms": time.Since(startedAt).Milliseconds(),
			"error":       strings.TrimSpace(err.Error()),
		})
		return err
	}
	_ = taskstore.AppendTaskEvent(context.Background(), db, taskID, "task.step.succeeded", map[string]any{
		"step":        stepKey,
		"duration_ms": time.Since(startedAt).Milliseconds(),
	})
	return nil
}
