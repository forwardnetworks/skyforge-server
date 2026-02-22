package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type forwardSyncTaskSpec struct {
	DeploymentID string `json:"deploymentId,omitempty"`
}

func (e *Engine) dispatchForwardSyncTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if e == nil || task == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}

	var specIn forwardSyncTaskSpec
	_ = decodeTaskSpec(task, &specIn)

	ws, err := e.loadWorkspaceByKey(ctx, task.WorkspaceID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &userContext{
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

	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "forward.sync", func() error {
		return e.runForwardSyncTask(ctx, pc, deploymentID, task.ID, log)
	})
}

func (e *Engine) runForwardSyncTask(ctx context.Context, pc *userContext, deploymentID string, taskID int, log Logger) error {
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

	// Find the most recent topology artifact key and sync its mgmt IPs into Forward.
	taskTypes := []string{"netlab-c9s-run", "clabernetes-run", "containerlab-run", "eve-ng-run"}
	var topoKey string
	for _, t := range taskTypes {
		ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
		latest, err := taskstore.GetLatestDeploymentTask(ctxReq, e.db, pc.workspace.ID, dep.ID, t)
		cancel()
		if err != nil || latest == nil {
			continue
		}
		meta, _ := fromJSONMap(latest.Metadata)
		if meta != nil {
			if raw, ok := meta["topologyKey"]; ok {
				if s, ok := raw.(string); ok {
					topoKey = strings.TrimSpace(s)
				} else if raw != nil {
					topoKey = strings.TrimSpace(fmt.Sprintf("%v", raw))
				}
			}
		}
		if topoKey != "" {
			break
		}
	}
	if topoKey == "" {
		return fmt.Errorf("no topology artifact available yet for this deployment")
	}

	ctxRead, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := readWorkspaceArtifact(ctxRead, e.cfg, pc.workspace.ID, topoKey, 2<<20)
	if err != nil || len(raw) == 0 {
		return fmt.Errorf("failed to read topology artifact")
	}
	var graph TopologyGraph
	if err := json.Unmarshal(raw, &graph); err != nil {
		return fmt.Errorf("invalid topology artifact")
	}
	if len(graph.Nodes) == 0 {
		return fmt.Errorf("empty topology artifact")
	}

	n, err := e.syncForwardTopologyGraphDevices(ctx, taskID, pc, dep, &graph, forwardSyncOptions{
		StartConnectivity: true,
		StartCollection:   true,
	})
	if err != nil {
		return err
	}
	if log != nil {
		log.Infof("Forward sync completed (devices=%d)", n)
	}
	return nil
}
