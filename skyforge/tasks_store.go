package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
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

type TaskEventEntry struct {
	Type    string         `json:"type"`
	Time    string         `json:"time"`
	Payload map[string]any `json:"payload,omitempty"`
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

	dedupeKey := strings.TrimSpace(getJSONMapString(metadata, "dedupeKey"))
	if dedupeKey != "" {
		rec, err := findActiveTaskByDedupeKey(ctx, db, workspaceID, deploymentID, taskType, dedupeKey)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			return rec, nil
		}
	}

	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	var dep sql.NullString
	if deploymentID != nil && *deploymentID != "" {
		dep = sql.NullString{String: *deploymentID, Valid: true}

		// Guardrail: prevent a single deployment from accumulating an unbounded task backlog
		// due to misclicks or broken automation.
		queued, err := countQueuedDeploymentTasks(ctx, db, workspaceID, dep.String)
		if err != nil {
			return nil, err
		}
		const maxQueuedPerDeployment = 25
		if queued >= maxQueuedPerDeployment {
			return nil, errs.B().Code(errs.ResourceExhausted).Msg("too many queued runs for this deployment").Err()
		}

		if !allowActive {
			active, err := hasActiveDeploymentTask(ctx, db, workspaceID, dep.String)
			if err != nil {
				return nil, err
			}
			if active {
				// Queue the task behind the active deployment run.
				// Execution is serialized per-deployment in the task runner.
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
	_ = appendTaskEvent(context.Background(), db, rec.ID, "task.queued", map[string]any{
		"status":       "queued",
		"taskType":     taskType,
		"deploymentId": strings.TrimSpace(dep.String),
	})
	return rec, nil
}

func countQueuedDeploymentTasks(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (int, error) {
	if db == nil {
		return 0, errDBUnavailable
	}
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*)
FROM sf_tasks
WHERE workspace_id=$1
  AND deployment_id=$2
  AND status='queued'`, workspaceID, deploymentID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func findActiveTaskByDedupeKey(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, dedupeKey string) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	workspaceID = strings.TrimSpace(workspaceID)
	taskType = strings.TrimSpace(taskType)
	dedupeKey = strings.TrimSpace(dedupeKey)
	if workspaceID == "" || taskType == "" || dedupeKey == "" {
		return nil, nil
	}

	dep := sql.NullString{}
	if deploymentID != nil && strings.TrimSpace(*deploymentID) != "" {
		dep = sql.NullString{String: strings.TrimSpace(*deploymentID), Valid: true}
	}

	query := `SELECT id
FROM sf_tasks
WHERE workspace_id=$1
  AND task_type=$2
  AND status IN ('queued','running')
  AND metadata->>'dedupeKey'=$3`
	args := []any{workspaceID, taskType, dedupeKey}
	if dep.Valid {
		query += "\n  AND deployment_id=$4"
		args = append(args, dep.String)
	} else {
		query += "\n  AND deployment_id IS NULL"
	}
	query += "\nORDER BY id DESC\nLIMIT 1"

	var id int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if id <= 0 {
		return nil, nil
	}
	return getTask(ctx, db, id)
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

func getOldestQueuedDeploymentTaskID(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (int, error) {
	if db == nil {
		return 0, errDBUnavailable
	}
	var id int
	err := db.QueryRowContext(ctx, `SELECT id
FROM sf_tasks
WHERE workspace_id=$1
  AND deployment_id=$2
  AND status='queued'
ORDER BY id ASC
LIMIT 1`, workspaceID, deploymentID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return id, nil
}

type deploymentQueueSummary struct {
	QueueDepth       int
	ActiveTaskID     int
	ActiveTaskStatus string
}

func getDeploymentQueueSummary(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (*deploymentQueueSummary, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if strings.TrimSpace(workspaceID) == "" || strings.TrimSpace(deploymentID) == "" {
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
WHERE workspace_id=$1
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

	out := &deploymentQueueSummary{QueueDepth: q}
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

func markTaskStarted(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil {
		return errDBUnavailable
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_tasks SET status='running', started_at=now() WHERE id=$1`, taskID)
	if err == nil {
		_ = appendTaskEvent(context.Background(), db, taskID, "task.started", map[string]any{"status": "running"})
	}
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
	if err == nil {
		payload := map[string]any{"status": status}
		if strings.TrimSpace(errMsg) != "" {
			payload["error"] = strings.TrimSpace(errMsg)
		}
		_ = appendTaskEvent(context.Background(), db, taskID, "task.finished", payload)
	}
	return err
}

func cancelTask(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil {
		return errDBUnavailable
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_tasks SET status='canceled', finished_at=now() WHERE id=$1`, taskID)
	if err == nil {
		_ = appendTaskEvent(context.Background(), db, taskID, "task.canceled", map[string]any{"status": "canceled"})
	}
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

func appendTaskEvent(ctx context.Context, db *sql.DB, taskID int, eventType string, payload map[string]any) error {
	if db == nil {
		return errDBUnavailable
	}
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return nil
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_task_events (task_id, event_type, payload) VALUES ($1,$2,$3)`, taskID, eventType, payloadBytes)
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

type taskLogRow struct {
	ID    int64
	Entry TaskLogEntry
}

type taskEventRow struct {
	ID    int64
	Entry TaskEventEntry
}

func listTaskLogsAfter(ctx context.Context, db *sql.DB, taskID int, afterID int64, limit int) ([]taskLogRow, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if limit <= 0 {
		limit = 500
	}
	if afterID < 0 {
		afterID = 0
	}
	rows, err := db.QueryContext(ctx, `SELECT id, created_at, stream, output
FROM sf_task_logs
WHERE task_id=$1
  AND id > $2
ORDER BY id ASC
LIMIT $3`, taskID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []taskLogRow{}
	for rows.Next() {
		var id int64
		var createdAt time.Time
		var stream string
		var output string
		if err := rows.Scan(&id, &createdAt, &stream, &output); err != nil {
			return nil, err
		}
		out = append(out, taskLogRow{
			ID:    id,
			Entry: TaskLogEntry{Output: output, Time: createdAt.UTC().Format(time.RFC3339), Stream: stream},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func listTaskEventsAfter(ctx context.Context, db *sql.DB, taskID int, afterID int64, limit int) ([]taskEventRow, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if limit <= 0 {
		limit = 500
	}
	if afterID < 0 {
		afterID = 0
	}
	rows, err := db.QueryContext(ctx, `SELECT id, created_at, event_type, payload
FROM sf_task_events
WHERE task_id=$1
  AND id > $2
ORDER BY id ASC
LIMIT $3`, taskID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []taskEventRow{}
	for rows.Next() {
		var (
			id         int64
			createdAt  time.Time
			eventType  string
			payload    []byte
			payloadMap map[string]any
		)
		if err := rows.Scan(&id, &createdAt, &eventType, &payload); err != nil {
			return nil, err
		}
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &payloadMap)
		}
		out = append(out, taskEventRow{
			ID: id,
			Entry: TaskEventEntry{
				Type:    eventType,
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
