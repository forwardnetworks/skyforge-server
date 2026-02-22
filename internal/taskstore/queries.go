package taskstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type DeploymentQueueSummary struct {
	QueueDepth       int
	ActiveTaskID     int
	ActiveTaskStatus string
}

type TaskLogRow struct {
	ID    int64
	Entry TaskLogEntry
}

type TaskEventRow struct {
	ID    int64
	Entry TaskEventEntry
}

func HasRecentTaskByDedupeKey(ctx context.Context, db *sql.DB, taskType, dedupeKey string, maxAge time.Duration) (bool, error) {
	if db == nil {
		return false, errDBUnavailable
	}
	taskType = strings.TrimSpace(taskType)
	dedupeKey = strings.TrimSpace(dedupeKey)
	if taskType == "" || dedupeKey == "" {
		return false, nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_tasks
WHERE task_type=$1
  AND metadata->>'dedupeKey'=$2
  AND created_at > now() - $3::interval`, taskType, dedupeKey, fmt.Sprintf("%fs", maxAge.Seconds())).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func FindActiveTaskByDedupeKey(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, dedupeKey string) (*TaskRecord, error) {
	return findActiveTaskByDedupeKey(ctx, db, workspaceID, deploymentID, taskType, dedupeKey)
}

func GetActiveDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	if workspaceID == "" || deploymentID == "" {
		return nil, nil
	}
	var id int
	err := db.QueryRowContext(ctx, `SELECT id
FROM sf_tasks
WHERE username=$1
  AND deployment_id=$2
  AND status='running'
ORDER BY id DESC
LIMIT 1`, workspaceID, deploymentID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return GetTask(ctx, db, id)
}

func GetOldestQueuedDeploymentTaskID(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (int, error) {
	if db == nil {
		return 0, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	if workspaceID == "" || deploymentID == "" {
		return 0, nil
	}
	var id int
	err := db.QueryRowContext(ctx, `SELECT id
FROM sf_tasks
WHERE username=$1
  AND deployment_id=$2
  AND status='queued'
ORDER BY priority DESC, id ASC
LIMIT 1`, workspaceID, deploymentID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return id, nil
}

func GetOldestQueuedWorkspaceTaskID(ctx context.Context, db *sql.DB, workspaceID string) (int, error) {
	if db == nil {
		return 0, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return 0, nil
	}
	var id int
	err := db.QueryRowContext(ctx, `SELECT id
FROM sf_tasks
WHERE username=$1
  AND deployment_id IS NULL
  AND status='queued'
ORDER BY priority DESC, id ASC
LIMIT 1`, workspaceID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return id, nil
}

func GetDeploymentQueueSummary(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (*DeploymentQueueSummary, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	if workspaceID == "" || deploymentID == "" {
		return nil, nil
	}

	var (
		queuedCount  sql.NullInt64
		runningCount sql.NullInt64
		oldestQueued sql.NullInt64
		runningID    sql.NullInt64
	)
	err := db.QueryRowContext(ctx, `SELECT
  SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END) AS queued,
  SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) AS running,
  MIN(id) FILTER (WHERE status='queued') AS oldest_queued_id,
  MAX(id) FILTER (WHERE status='running') AS running_id
FROM sf_tasks
WHERE username=$1
  AND deployment_id=$2
  AND status IN ('queued','running')`, workspaceID, deploymentID).Scan(&queuedCount, &runningCount, &oldestQueued, &runningID)
	if err != nil {
		return nil, err
	}

	q := int(queuedCount.Int64)
	r := int(runningCount.Int64)
	if q == 0 && r == 0 {
		return nil, nil
	}

	out := &DeploymentQueueSummary{QueueDepth: q}
	if r > 0 && runningID.Valid {
		out.ActiveTaskStatus = "running"
		out.ActiveTaskID = int(runningID.Int64)
		return out, nil
	}
	if q > 0 && oldestQueued.Valid {
		out.ActiveTaskStatus = "queued"
		out.ActiveTaskID = int(oldestQueued.Int64)
		return out, nil
	}
	return out, nil
}

func ListTasks(ctx context.Context, db *sql.DB, workspaceID string, limit int) ([]TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 5
	}
	rows, err := db.QueryContext(ctx, `SELECT id, username, deployment_id, task_type, priority, status, message, metadata, created_by, created_at, started_at, finished_at, error
FROM sf_tasks
WHERE username=$1
ORDER BY created_at DESC
LIMIT $2`, workspaceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskRecord{}
	for rows.Next() {
		var rec TaskRecord
		var metaBytes []byte
		if err := rows.Scan(&rec.ID, &rec.WorkspaceID, &rec.DeploymentID, &rec.TaskType, &rec.Priority, &rec.Status, &rec.Message, &metaBytes, &rec.CreatedBy, &rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Error); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaBytes, &rec.Metadata)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func GetLatestDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string, taskType string) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	taskType = strings.TrimSpace(taskType)
	if workspaceID == "" || deploymentID == "" {
		return nil, nil
	}
	var id int
	query := `SELECT id
FROM sf_tasks
WHERE username=$1
  AND deployment_id=$2`
	args := []any{workspaceID, deploymentID}
	if taskType != "" {
		query += ` AND task_type=$3`
		args = append(args, taskType)
	}
	query += ` ORDER BY id DESC LIMIT 1`
	err := db.QueryRowContext(ctx, query, args...).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return GetTask(ctx, db, id)
}

func ListTaskTypesSince(ctx context.Context, db *sql.DB, window time.Duration) ([]string, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	since := time.Now().Add(-window)
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT task_type
FROM sf_tasks
WHERE created_at >= $1
ORDER BY task_type ASC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ListTaskStatusCounts(ctx context.Context, db *sql.DB, status string) ([]TaskStatusCountRow, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	status = strings.TrimSpace(status)
	if status == "" {
		return nil, errors.New("status is required")
	}
	rows, err := db.QueryContext(ctx, `SELECT task_type,
  COUNT(*) AS cnt,
  COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at))), 0) AS oldest_age
FROM sf_tasks
WHERE status=$1
GROUP BY task_type
ORDER BY task_type ASC`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskStatusCountRow{}
	for rows.Next() {
		var row TaskStatusCountRow
		if err := rows.Scan(&row.TaskType, &row.Count, &row.OldestAgeSeconds); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ListTaskLogs(ctx context.Context, db *sql.DB, taskID int, limit int) ([]TaskLogEntry, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if taskID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := db.QueryContext(ctx, `SELECT created_at, stream, output
FROM sf_task_logs
WHERE task_id=$1
ORDER BY id ASC
LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskLogEntry{}
	for rows.Next() {
		var output, stream string
		var createdAt time.Time
		if err := rows.Scan(&createdAt, &stream, &output); err != nil {
			return nil, err
		}
		out = append(out, TaskLogEntry{
			Output: output,
			Time:   createdAt.UTC().Format(time.RFC3339),
			Stream: strings.TrimSpace(stream),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ListTaskLogsAfter(ctx context.Context, db *sql.DB, taskID int, afterID int64, limit int) ([]TaskLogRow, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if taskID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	if afterID < 0 {
		afterID = 0
	}
	rows, err := db.QueryContext(ctx, `SELECT id, stream, output, created_at
FROM sf_task_logs
WHERE task_id=$1 AND id > $2
ORDER BY id ASC
LIMIT $3`, taskID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskLogRow{}
	for rows.Next() {
		var createdAt time.Time
		var (
			id     int64
			stream string
			output string
		)
		if err := rows.Scan(&id, &stream, &output, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, TaskLogRow{
			ID: id,
			Entry: TaskLogEntry{
				Output: output,
				Time:   createdAt.UTC().Format(time.RFC3339),
				Stream: stream,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ListTaskEventsAfter(ctx context.Context, db *sql.DB, taskID int, afterID int64, limit int) ([]TaskEventRow, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if taskID <= 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	if afterID < 0 {
		afterID = 0
	}
	rows, err := db.QueryContext(ctx, `SELECT id, event_type, payload, created_at
FROM sf_task_events
WHERE task_id=$1 AND id > $2
ORDER BY id ASC
LIMIT $3`, taskID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskEventRow{}
	for rows.Next() {
		var createdAt time.Time
		var (
			id         int64
			eventType  string
			payload    []byte
			payloadMap map[string]any
		)
		if err := rows.Scan(&id, &eventType, &payload, &createdAt); err != nil {
			return nil, err
		}
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &payloadMap)
		}
		out = append(out, TaskEventRow{
			ID: id,
			Entry: TaskEventEntry{
				Type:    strings.TrimSpace(eventType),
				Time:    createdAt.UTC().Format(time.RFC3339),
				Payload: payloadMap,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func TaskToRunInfo(task TaskRecord) map[string]any {
	run := map[string]any{
		"id":        task.ID,
		"tpl_alias": task.TaskType,
		"tpl_app":   "skyforge",
		"status":    task.Status,
		"user_name": task.CreatedBy,
		"created":   task.CreatedAt.UTC().Format(time.RFC3339),
	}
	if strings.TrimSpace(task.WorkspaceID) != "" {
		run["userId"] = strings.TrimSpace(task.WorkspaceID)
	}
	if task.DeploymentID.Valid {
		dep := strings.TrimSpace(task.DeploymentID.String)
		if dep != "" {
			run["deploymentId"] = dep
		}
	}
	if task.Message.Valid {
		run["message"] = task.Message.String
	}
	if task.StartedAt.Valid {
		run["start"] = task.StartedAt.Time.UTC().Format(time.RFC3339)
	}
	if task.FinishedAt.Valid {
		run["end"] = task.FinishedAt.Time.UTC().Format(time.RFC3339)
	}
	if task.Error.Valid {
		run["status_text"] = task.Error.String
	}
	if task.Metadata != nil {
		for key, value := range task.Metadata {
			if _, exists := run[key]; !exists {
				run[key] = value
			}
		}
	}
	return run
}
