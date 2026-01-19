package taskengine

import (
	"context"
	"fmt"
	"strings"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type forwardInitTaskSpec struct {
	DeploymentID string `json:"deploymentId,omitempty"`
}

func (e *Engine) dispatchForwardInitTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if e == nil || task == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}

	var specIn forwardInitTaskSpec
	_ = decodeTaskSpec(task, &specIn)

	ws, err := e.loadWorkspaceByKey(ctx, task.WorkspaceID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &workspaceContext{
		workspace: *ws,
		claims: SessionClaims{
			Username: username,
		},
	}

	deploymentID := strings.TrimSpace(specIn.DeploymentID)
	if deploymentID == "" && task.DeploymentID.Valid {
		deploymentID = strings.TrimSpace(task.DeploymentID.String)
	}
	if deploymentID == "" {
		return fmt.Errorf("deployment id is required")
	}

	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "forward.init", func() error {
		return e.runForwardInitTask(ctx, pc, deploymentID, log)
	})
}

func (e *Engine) runForwardInitTask(ctx context.Context, pc *workspaceContext, deploymentID string, log Logger) error {
	if e == nil || e.db == nil {
		return fmt.Errorf("engine unavailable")
	}
	if pc == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	deploymentID = strings.TrimSpace(deploymentID)
	if deploymentID == "" {
		return fmt.Errorf("deployment id is required")
	}

	dep, err := e.loadDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return err
	}
	if dep == nil {
		return fmt.Errorf("deployment not found")
	}

	cfgAny, err := e.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil {
		return err
	}
	if err := e.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
		return err
	}
	if log != nil {
		if id, _ := cfgAny[forwardNetworkIDKey].(string); strings.TrimSpace(id) != "" {
			log.Infof("Forward network ensured (networkId=%s)", strings.TrimSpace(id))
		} else {
			log.Infof("Forward network init completed")
		}
	}
	return nil
}
