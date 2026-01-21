package taskstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/jsonmap"
	"encore.app/internal/tasknotify"
	"encore.dev/beta/errs"
)

type JSONMap = jsonmap.JSONMap

type TaskRecord struct {
	ID           int
	WorkspaceID  string
	DeploymentID sql.NullString
	TaskType     string
	Priority     int
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

type TaskStatusCountRow struct {
	TaskType         string
	Count            int64
	OldestAgeSeconds float64
}

const (
	PriorityBackground  = 0
	PriorityInteractive = 10
)

func DefaultTaskPriority(taskType string) int {
	switch strings.ToLower(strings.TrimSpace(taskType)) {
	case "workspace.sync", "workspace_sync", "workspace-sync":
		return PriorityBackground
	case "cloud.checks", "cloud_checks", "cloud-checks":
		return PriorityBackground
	default:
		return PriorityInteractive
	}
}

func getJSONMapString(value JSONMap, key string) string { return jsonmap.GetString(value, key) }
func getJSONMapInt(value JSONMap, key string) int       { return jsonmap.GetInt(value, key) }

func taskDedupeLockKey(workspaceID string, deploymentID *string, taskType, dedupeKey string) int64 {
	workspaceID = strings.TrimSpace(workspaceID)
	taskType = strings.TrimSpace(taskType)
	dedupeKey = strings.TrimSpace(dedupeKey)
	dep := ""
	if deploymentID != nil {
		dep = strings.TrimSpace(*deploymentID)
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%s:%s", workspaceID, dep, taskType, dedupeKey))
	u := binary.LittleEndian.Uint64(sum[:8])
	return int64(u)
}

func pgTryAdvisoryLock(ctx context.Context, db *sql.DB, key int64) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("db unavailable")
	}
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func pgAdvisoryUnlock(ctx context.Context, db *sql.DB, key int64) error {
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&ok); err != nil {
		return err
	}
	return nil
}

func CreateTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap) (*TaskRecord, error) {
	return createTaskWithActiveCheck(ctx, db, workspaceID, deploymentID, taskType, message, createdBy, metadata, false)
}

func CreateTaskAllowActive(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap) (*TaskRecord, error) {
	return createTaskWithActiveCheck(ctx, db, workspaceID, deploymentID, taskType, message, createdBy, metadata, true)
}

func createTaskWithActiveCheck(ctx context.Context, db *sql.DB, workspaceID string, deploymentID *string, taskType string, message string, createdBy string, metadata JSONMap, allowActive bool) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	if metadata == nil {
		metadata = JSONMap{}
	}

	priority := getJSONMapInt(metadata, "priority")
	if _, ok := metadata["priority"]; !ok {
		priority = DefaultTaskPriority(taskType)
	}

	dedupeKey := strings.TrimSpace(getJSONMapString(metadata, "dedupeKey"))
	if dedupeKey != "" {
		lockKey := taskDedupeLockKey(workspaceID, deploymentID, taskType, dedupeKey)
		locked := false
		for {
			ok, err := pgTryAdvisoryLock(ctx, db, lockKey)
			if err != nil {
				return nil, err
			}
			if ok {
				locked = true
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		if locked {
			defer func() { _ = pgAdvisoryUnlock(context.Background(), db, lockKey) }()
		}

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

		queued, err := CountQueuedDeploymentTasks(ctx, db, workspaceID, dep.String)
		if err != nil {
			return nil, err
		}
		const maxQueuedPerDeployment = 25
		if queued >= maxQueuedPerDeployment {
			return nil, errs.B().Code(errs.ResourceExhausted).Msg("too many queued runs for this deployment").Err()
		}

		if !allowActive {
			// This check is advisory; tasks can still queue behind an active run.
			_, _ = HasActiveDeploymentTask(ctx, db, workspaceID, dep.String)
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
  priority,
  status,
  message,
  metadata,
  created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING id, created_at`, workspaceID, dep, taskType, priority, "queued", msg, metaBytes, createdBy)
	rec := &TaskRecord{WorkspaceID: workspaceID, DeploymentID: dep, TaskType: taskType, Priority: priority, Status: "queued", Message: msg, Metadata: metadata, CreatedBy: createdBy}
	if err := row.Scan(&rec.ID, &rec.CreatedAt); err != nil {
		return nil, err
	}
	_ = AppendTaskEvent(context.Background(), db, rec.ID, "task.queued", map[string]any{
		"status":       "queued",
		"taskType":     taskType,
		"deploymentId": strings.TrimSpace(dep.String),
	})
	return rec, nil
}

func CountQueuedDeploymentTasks(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (int, error) {
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

func HasActiveDeploymentTask(ctx context.Context, db *sql.DB, workspaceID string, deploymentID string) (bool, error) {
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
	return GetTask(ctx, db, id)
}

func MarkTaskStarted(ctx context.Context, db *sql.DB, taskID int) (bool, error) {
	if db == nil {
		return false, errDBUnavailable
	}
	res, err := db.ExecContext(ctx, `UPDATE sf_tasks
SET status='running', started_at=now()
WHERE id=$1 AND status='queued'`, taskID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n <= 0 {
		return false, nil
	}
	_ = AppendTaskEvent(context.Background(), db, taskID, "task.started", map[string]any{"status": "running"})
	return true, nil
}

func FinishTask(ctx context.Context, db *sql.DB, taskID int, status string, errMsg string) error {
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
		_ = AppendTaskEvent(context.Background(), db, taskID, "task.finished", payload)
	}
	return err
}

func CancelTask(ctx context.Context, db *sql.DB, taskID int) error {
	if db == nil {
		return errDBUnavailable
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_tasks SET status='canceled', finished_at=now() WHERE id=$1`, taskID)
	if err == nil {
		_ = AppendTaskEvent(context.Background(), db, taskID, "task.canceled", map[string]any{"status": "canceled"})
	}
	return err
}

func AppendTaskLog(ctx context.Context, db *sql.DB, taskID int, stream string, output string) error {
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
	if err == nil {
		// Only notify the task stream (logs), not the dashboard.
		// Dashboard doesn't show logs and shouldn't reload on every log line.
		_ = tasknotify.NotifyTaskUpdate(ctx, db, taskID)
	}
	return err
}

func AppendTaskEvent(ctx context.Context, db *sql.DB, taskID int, eventType string, payload map[string]any) error {
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
	if err == nil {
		publishTaskUpdate(ctx, db, taskID)
	}
	return err
}

func publishTaskUpdate(ctx context.Context, db *sql.DB, taskID int) {
	if taskID <= 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_ = tasknotify.NotifyTaskUpdate(ctx, db, taskID)
	_ = tasknotify.NotifyDashboardUpdate(ctx, db)
}

func UpdateTaskMetadata(ctx context.Context, db *sql.DB, taskID int, metadata JSONMap) error {
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

func GetTask(ctx context.Context, db *sql.DB, taskID int) (*TaskRecord, error) {
	if db == nil {
		return nil, errDBUnavailable
	}
	row := db.QueryRowContext(ctx, `SELECT id, workspace_id, deployment_id, task_type, priority, status, message, metadata, created_by, created_at, started_at, finished_at, error
FROM sf_tasks
WHERE id=$1`, taskID)
	rec := TaskRecord{}
	var metaBytes []byte
	if err := row.Scan(&rec.ID, &rec.WorkspaceID, &rec.DeploymentID, &rec.TaskType, &rec.Priority, &rec.Status, &rec.Message, &metaBytes, &rec.CreatedBy, &rec.CreatedAt, &rec.StartedAt, &rec.FinishedAt, &rec.Error); err != nil {
		return nil, err
	}
	if len(metaBytes) > 0 {
		_ = json.Unmarshal(metaBytes, &rec.Metadata)
	}
	return &rec, nil
}

var errDBUnavailable = errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
