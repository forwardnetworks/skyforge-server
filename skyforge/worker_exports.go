package skyforge

import (
	"context"
	"fmt"

	"encore.app/internal/maintenance"
)

// DefaultService returns the process-wide Skyforge service instance.
//
// This is used by the dedicated task worker service to reuse Skyforge’s task runner logic.
func DefaultService() *Service {
	return defaultService
}

// TaskWorkerEnabled reports whether this process is configured to run tasks.
func (s *Service) TaskWorkerEnabled() bool {
	return s != nil && s.cfg.TaskWorkerEnabled
}

// ProcessQueuedTask runs the queued task (best-effort no-op if already started/finished).
func (s *Service) ProcessQueuedTask(ctx context.Context, taskID int) error {
	if s == nil {
		return fmt.Errorf("service unavailable")
	}
	return s.processQueuedTask(ctx, taskID)
}

// HandleMaintenanceEvent handles a maintenance event published by cron/automation.
func (s *Service) HandleMaintenanceEvent(ctx context.Context, msg *maintenance.MaintenanceEvent) error {
	if s == nil {
		return fmt.Errorf("service unavailable")
	}
	return s.handleMaintenanceEvent(ctx, msg)
}
