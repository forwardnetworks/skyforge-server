package skyforge

import (
	"context"
	"database/sql"
	"time"

	"encore.app/internal/taskstore"
)

type (
	TaskRecord             = taskstore.TaskRecord
	TaskLogEntry           = taskstore.TaskLogEntry
	TaskEventEntry         = taskstore.TaskEventEntry
	taskStatusCountRow     = taskstore.TaskStatusCountRow
	deploymentQueueSummary = taskstore.DeploymentQueueSummary
	taskLogRow             = taskstore.TaskLogRow
	taskEventRow           = taskstore.TaskEventRow
)

const (
	taskPriorityBackground  = taskstore.PriorityBackground
	taskPriorityInteractive = taskstore.PriorityInteractive
)

func defaultTaskPriority(taskType string) int { return taskstore.DefaultTaskPriority(taskType) }

func createTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap) (*TaskRecord, error) {
	return taskstore.CreateTask(ctx, db, workspaceID, deploymentID, taskType, message, createdBy, metadata)
}

func createTaskAllowActive(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap) (*TaskRecord, error) {
	return taskstore.CreateTaskAllowActive(ctx, db, workspaceID, deploymentID, taskType, message, createdBy, metadata)
}

func hasRecentTaskByDedupeKey(ctx context.Context, db *sql.DB, taskType, dedupeKey string, maxAge time.Duration) (bool, error) {
	return taskstore.HasRecentTaskByDedupeKey(ctx, db, taskType, dedupeKey, maxAge)
}

func findActiveTaskByDedupeKey(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, dedupeKey string) (*TaskRecord, error) {
	return taskstore.FindActiveTaskByDedupeKey(ctx, db, workspaceID, deploymentID, taskType, dedupeKey)
}

func hasActiveDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (bool, error) {
	return taskstore.HasActiveDeploymentTask(ctx, db, workspaceID, deploymentID)
}

func getActiveDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (*TaskRecord, error) {
	return taskstore.GetActiveDeploymentTask(ctx, db, workspaceID, deploymentID)
}

func getOldestQueuedDeploymentTaskID(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (int, error) {
	return taskstore.GetOldestQueuedDeploymentTaskID(ctx, db, workspaceID, deploymentID)
}

func getOldestQueuedWorkspaceTaskID(ctx context.Context, db *sql.DB, workspaceID string) (int, error) {
	return taskstore.GetOldestQueuedWorkspaceTaskID(ctx, db, workspaceID)
}

func getDeploymentQueueSummary(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (*deploymentQueueSummary, error) {
	return taskstore.GetDeploymentQueueSummary(ctx, db, workspaceID, deploymentID)
}

func markTaskStarted(ctx context.Context, db *sql.DB, taskID int) (bool, error) {
	return taskstore.MarkTaskStarted(ctx, db, taskID)
}

func finishTask(ctx context.Context, db *sql.DB, taskID int, status string, errMsg string) error {
	return taskstore.FinishTask(ctx, db, taskID, status, errMsg)
}

func cancelTask(ctx context.Context, db *sql.DB, taskID int) error {
	return taskstore.CancelTask(ctx, db, taskID)
}

func appendTaskLog(ctx context.Context, db *sql.DB, taskID int, stream string, output string) error {
	return taskstore.AppendTaskLog(ctx, db, taskID, stream, output)
}

func appendTaskEvent(ctx context.Context, db *sql.DB, taskID int, eventType string, payload map[string]any) error {
	return taskstore.AppendTaskEvent(ctx, db, taskID, eventType, payload)
}

func updateTaskMetadata(ctx context.Context, db *sql.DB, taskID int, metadata JSONMap) error {
	return taskstore.UpdateTaskMetadata(ctx, db, taskID, metadata)
}

func listTasks(ctx context.Context, db *sql.DB, workspaceID string, limit int) ([]TaskRecord, error) {
	return taskstore.ListTasks(ctx, db, workspaceID, limit)
}

func getTask(ctx context.Context, db *sql.DB, taskID int) (*TaskRecord, error) {
	return taskstore.GetTask(ctx, db, taskID)
}

func getLatestDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string, taskType string) (*TaskRecord, error) {
	return taskstore.GetLatestDeploymentTask(ctx, db, workspaceID, deploymentID, taskType)
}

func listTaskTypesSince(ctx context.Context, db *sql.DB, window time.Duration) ([]string, error) {
	return taskstore.ListTaskTypesSince(ctx, db, window)
}

func listTaskStatusCounts(ctx context.Context, db *sql.DB, status string) ([]taskStatusCountRow, error) {
	return taskstore.ListTaskStatusCounts(ctx, db, status)
}

func listTaskLogs(ctx context.Context, db *sql.DB, taskID int, limit int) ([]TaskLogEntry, error) {
	return taskstore.ListTaskLogs(ctx, db, taskID, limit)
}

func listTaskLogsAfter(ctx context.Context, db *sql.DB, taskID int, afterID int64, limit int) ([]taskLogRow, error) {
	return taskstore.ListTaskLogsAfter(ctx, db, taskID, afterID, limit)
}

func listTaskEventsAfter(ctx context.Context, db *sql.DB, taskID int, afterID int64, limit int) ([]taskEventRow, error) {
	return taskstore.ListTaskEventsAfter(ctx, db, taskID, afterID, limit)
}

func taskToRunInfo(task TaskRecord) map[string]any {
	return taskstore.TaskToRunInfo(task)
}
