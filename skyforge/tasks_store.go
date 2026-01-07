package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"encore.dev/beta/errs"
)

type TaskRecord struct {
	ID           int
	WorkspaceID  string
	DeploymentID sql.NullString
	TaskType     string
	Status       string
	Message      sql.NullString
	Metadata     JSONMap
	CreatedBy    string
	CreatedAt    time.Time
	StartedAt    sql.NullTime
	FinishedAt   sql.NullTime
	Error        sql.NullString
}

type TaskLogEntry struct {
	Output string `json:"output"`
	Time   string `json:"time"`
	Stream string `json:"stream,omitempty"`
}

func createTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap) (*TaskRecord, error) {
	return createTaskWithActiveCheck(ctx, db, workspaceID, deploymentID, taskType, message, createdBy, metadata, false)
}

func createTaskAllowActive(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap) (*TaskRecord, error) {
	return createTaskWithActiveCheck(ctx, db, workspaceID, deploymentID, taskType, message, createdBy, metadata, true)
}

func createTaskWithActiveCheck(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap, allowActive bool) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if metadata == nil {
		metadata = JSONMap{}
	}
	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	var dep sql.NullString
	if deploymentID != nil && *deploymentID != "" {
		dep = sql.NullString{String: *deploymentID, Valid: true}
		if !allowActive {
			active, err := hasActiveDeploymentTask(ctx, db, workspaceID, dep.String)
			if err != nil {
				return nil, err
			}
			if active {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("deployment already has an active run").Err()
			}
		}
	}
	var msg sql.NullString
	if message != "" {
		msg = sql.NullString{String: message, Valid: true}
	}
	row := db.QueryRowContext(ctx, `INSERT INTO sf_tasks (
  workspace_id,
  deployment_id,
  task_type,
  status,
  message,
  metadata,
  created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING id, created_at`, workspaceID, dep, taskType, "queued", msg, metaBytes, createdBy)
	rec := &TaskRecord{WorkspaceID: workspaceID, DeploymentID: dep, TaskType: taskType, Status: "queued", Message: msg, Metadata: metadata, CreatedBy: createdBy}
	if err := row.Scan(&rec.ID, &rec.CreatedAt); err != nil {
		return nil, err
	}
	return rec, nil
}

func hasActiveDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (bool, error) {
	if db == nil {
		return false, errDBUnavailable
	}
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*)
FROM sf_tasks
WHERE workspace_id=$1
  AND deployment_id=$2
  AND status IN ('queued','running')`, workspaceID, deploymentID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func getActiveDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	row := db.QueryRowContext(ctx, `SELECT id, workspace_id, deployment_id, task_type, status, message, metadata, created_by, created_at, started_at, finished_at, error
FROM sf_tasks
WHERE workspace_id=$1
  AND deployment_id=$2
  AND status IN ('queued','running')
ORDER BY created_at DESC
LIMIT 1`, workspaceID, deploymentID)
	rec := TaskRecord{}
	var metaBytes []byte
	if err := row.Scan(&rec.ID, &rec.WorkspaceID, &rec.DeploymentID, &rec.TaskType, &rec.Status, &rec.Message, &metaBytes, &rec.CreatedBy, &rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Error); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if len(metaBytes) > 0 {
		_ = json.Unmarshal(metaBytes, &rec.Metadata)
	}
	return &rec, nil
}

func markTaskStarted(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil {
		return errDBUnavailable
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_tasks SET status='running', started_at=now() WHERE id=$1`, taskID)
	return err
}

func finishTask(ctx context.Context, db *sql.DB, taskID int, status string, errMsg string) error {
	if db == nil {
		return errDBUnavailable
	}
	var errVal sql.NullString
	if errMsg != "" {
		errVal = sql.NullString{String: errMsg, Valid: true}
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_tasks SET status=$1, finished_at=now(), error=$2 WHERE id=$3`, status, errVal, taskID)
	return err
}

func cancelTask(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil {
		return errDBUnavailable
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_tasks SET status='canceled', finished_at=now() WHERE id=$1`, taskID)
	return err
}

func appendTaskLog(ctx context.Context, db *sql.DB, taskID int, stream string, output string) error {
	if db == nil {
		return errDBUnavailable
	}
	if output == "" {
		return nil
	}
	if stream == "" {
		stream = "stdout"
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_task_logs (task_id, stream, output) VALUES ($1,$2,$3)`, taskID, stream, output)
	return err
}

func updateTaskMetadata(ctx context.Context, db *sql.DB, taskID int, metadata JSONMap) error {
	if db == nil {
		return errDBUnavailable
	}
	if metadata == nil {
		metadata = JSONMap{}
	}
	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE sf_tasks SET metadata=$1 WHERE id=$2`, metaBytes, taskID)
	return err
}

func listTasks(ctx context.Context, db *sql.DB, workspaceID string, limit int) ([]TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if limit <= 0 {
		limit = 5
	}
	rows, err := db.QueryContext(ctx, `SELECT id, workspace_id, deployment_id, task_type, status, message, metadata, created_by, created_at, started_at, finished_at, error
FROM sf_tasks
WHERE workspace_id=$1
ORDER BY created_at DESC
LIMIT $2`, workspaceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskRecord{}
	for rows.Next() {
		rec := TaskRecord{}
		var metaBytes []byte
		if err := rows.Scan(&rec.ID, &rec.WorkspaceID, &rec.DeploymentID, &rec.TaskType, &rec.Status, &rec.Message, &metaBytes, &rec.CreatedBy, &rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Error); err != nil {
			return nil, err
		}
		if len(metaBytes) > 0 {
			_ = json.Unmarshal(metaBytes, &rec.Metadata)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func getTask(ctx context.Context, db *sql.DB, taskID int) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	row := db.QueryRowContext(ctx, `SELECT id, workspace_id, deployment_id, task_type, status, message, metadata, created_by, created_at, started_at, finished_at, error
FROM sf_tasks
WHERE id=$1`, taskID)
	rec := TaskRecord{}
	var metaBytes []byte
	if err := row.Scan(&rec.ID, &rec.WorkspaceID, &rec.DeploymentID, &rec.TaskType, &rec.Status, &rec.Message, &metaBytes, &rec.CreatedBy, &rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Error); err != nil {
		return nil, err
	}
	if len(metaBytes) > 0 {
		_ = json.Unmarshal(metaBytes, &rec.Metadata)
	}
	return &rec, nil
}

func getLatestDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string, taskType string) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	row := db.QueryRowContext(ctx, `SELECT id, workspace_id, deployment_id, task_type, status, message, metadata, created_by, created_at, started_at, finished_at, error
FROM sf_tasks
WHERE workspace_id=$1
  AND deployment_id=$2
  AND ($3 = '' OR task_type=$3)
ORDER BY created_at DESC
LIMIT 1`, workspaceID, deploymentID, taskType)
	rec := TaskRecord{}
	var metaBytes []byte
	if err := row.Scan(&rec.ID, &rec.WorkspaceID, &rec.DeploymentID, &rec.TaskType, &rec.Status, &rec.Message, &metaBytes, &rec.CreatedBy, &rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Error); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if len(metaBytes) > 0 {
		_ = json.Unmarshal(metaBytes, &rec.Metadata)
	}
	return &rec, nil
}

func listTaskLogs(ctx context.Context, db *sql.DB, taskID int, limit int) ([]TaskLogEntry, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if limit <= 0 {
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
		var createdAt time.Time
		var stream string
		var output string
		if err := rows.Scan(&createdAt, &stream, &output); err != nil {
			return nil, err
		}
		out = append(out, TaskLogEntry{Output: output, Time: createdAt.UTC().Format(time.RFC3339), Stream: stream})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func taskToRunInfo(task TaskRecord) map[string]any {
	run := map[string]any{
		"id":        task.ID,
		"tpl_alias": task.TaskType,
		"tpl_app":   "skyforge",
		"status":    task.Status,
		"user_name": task.CreatedBy,
		"created":   task.CreatedAt.UTC().Format(time.RFC3339),
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

var errDBUnavailable = errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
