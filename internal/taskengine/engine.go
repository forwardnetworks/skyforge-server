package taskengine

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskexec"
	"encore.app/internal/taskstore"
)

type Engine struct {
	cfg skyforgecore.Config
	db  *sql.DB
	box *secretBox
}

func New(cfg skyforgecore.Config, db *sql.DB) *Engine {
	return &Engine{
		cfg: cfg,
		db:  db,
		box: newSecretBox(cfg.SessionSecret),
	}
}

// DispatchTask executes a task if the engine supports it.
//
// Returns (handled=true) when the task type was recognized.
func (e *Engine) DispatchTask(ctx context.Context, task *taskstore.TaskRecord, log taskexec.Logger) (handled bool, err error) {
	if e == nil || e.db == nil || task == nil {
		return false, nil
	}
	typ := strings.TrimSpace(task.TaskType)
	switch {
	case typ == "user-bootstrap":
		return true, e.dispatchUserBootstrapTask(ctx, task, taskLogAdapter(log))
	case typ == "workspace-bootstrap":
		return true, e.dispatchWorkspaceBootstrapTask(ctx, task, taskLogAdapter(log))
	case typ == "netlab-run":
		return true, e.dispatchNetlabTask(ctx, task, log)
	case typ == "netlab-c9s-run":
		return true, e.dispatchNetlabC9sTask(ctx, task, taskLogAdapter(log))
	case typ == "containerlab-run":
		return true, e.dispatchContainerlabTask(ctx, task, taskLogAdapter(log))
	case typ == "clabernetes-run":
		return true, e.dispatchClabernetesTask(ctx, task, taskLogAdapter(log))
	case strings.HasPrefix(typ, "terraform-"):
		return true, e.dispatchTerraformTask(ctx, task, taskLogAdapter(log))
	case typ == "forward-sync":
		return true, e.dispatchForwardSyncTask(ctx, task, taskLogAdapter(log))
	default:
		return false, nil
	}
}

func decodeTaskSpec[T any](task *taskstore.TaskRecord, out *T) error {
	return taskdispatch.DecodeTaskSpec(task, out)
}

func taskLogAdapter(log taskexec.Logger) Logger {
	if log == nil {
		return noopLogger{}
	}
	return logAdapter{log: log}
}

type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Infof(string, ...any)  {}
func (noopLogger) Errorf(string, ...any) {}

type logAdapter struct {
	log taskexec.Logger
}

func (l logAdapter) Infof(format string, args ...any) {
	if l.log == nil {
		return
	}
	l.log.Infof(format, args...)
}

func (l logAdapter) Errorf(format string, args ...any) {
	if l.log == nil {
		return
	}
	l.log.Errorf(format, args...)
}

func (e *Engine) requireDB() (*sql.DB, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	return e.db, nil
}
