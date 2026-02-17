package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type DeploymentForwardConfigRequest struct {
	Enabled           bool   `json:"enabled"`
	CollectorConfigID string `json:"collectorConfigId,omitempty"`
	CollectorUsername string `json:"collectorUsername,omitempty"`
}

type DeploymentForwardConfigResponse struct {
	UserContextID      string `json:"userContextId"`
	DeploymentID       string `json:"deploymentId"`
	Enabled            bool   `json:"enabled"`
	CollectorConfigID  string `json:"collectorConfigId,omitempty"`
	CollectorUsername  string `json:"collectorUsername,omitempty"`
	ForwardNetworkID   string `json:"forwardNetworkId,omitempty"`
	ForwardNetworkRef  string `json:"forwardNetworkRef,omitempty"`
	ForwardSnapshotURL string `json:"forwardSnapshotUrl,omitempty"`
}

// UpdateUserDeploymentForwardConfig updates the per-deployment Forward toggle and collector selection.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/deployments/:deploymentID/forward
func (s *Service) UpdateUserDeploymentForwardConfig(ctx context.Context, id, deploymentID string, req *DeploymentForwardConfigRequest) (*DeploymentForwardConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	dep, err := s.getUserDeployment(ctx, pc.userContext.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny["forwardEnabled"] = req.Enabled
	collectorConfigID := strings.TrimSpace(req.CollectorConfigID)
	collectorUsername := strings.TrimSpace(req.CollectorUsername)
	if !req.Enabled {
		delete(cfgAny, "forwardCollectorId")
		delete(cfgAny, "forwardCollectorUsername")
	} else if collectorConfigID != "" {
		cfgAny["forwardCollectorId"] = collectorConfigID
		// Keep backwards compat but do not require/force a specific Forward-side collector username here;
		// taskengine uses forwardCollectorId to select the user-managed collector config.
		delete(cfgAny, "forwardCollectorUsername")
	} else if collectorUsername != "" {
		cfgAny["forwardCollectorUsername"] = collectorUsername
		delete(cfgAny, "forwardCollectorId")
	} else {
		delete(cfgAny, "forwardCollectorId")
		delete(cfgAny, "forwardCollectorUsername")
	}

	cfg, err := toJSONMap(cfgAny)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
	}
	cfgBytes, _ := json.Marshal(cfg)

	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctxReq, `UPDATE sf_deployments SET config=$1, updated_at=now() WHERE workspace_id=$2 AND id=$3`, cfgBytes, pc.userContext.ID, dep.ID); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update deployment").Err()
	}

	resp := &DeploymentForwardConfigResponse{
		UserContextID:     pc.userContext.ID,
		DeploymentID:      dep.ID,
		Enabled:           req.Enabled,
		CollectorConfigID: collectorConfigID,
		CollectorUsername: collectorUsername,
	}
	if v, ok := cfgAny["forwardNetworkId"].(string); ok {
		resp.ForwardNetworkID = strings.TrimSpace(v)
	}
	if v, ok := cfgAny["forwardNetworkRef"].(string); ok {
		resp.ForwardNetworkRef = strings.TrimSpace(v)
	}
	return resp, nil
}

type DeploymentForwardSyncResponse struct {
	UserContextID string  `json:"userContextId"`
	DeploymentID  string  `json:"deploymentId"`
	Run           JSONMap `json:"run"`
}

// SyncWorkspaceDeploymentForward enqueues a Forward sync task for the deployment's latest topology.
//
//encore:api auth method=POST path=/api/user-contexts/:id/deployments/:deploymentID/forward/sync
func (s *Service) SyncWorkspaceDeploymentForward(ctx context.Context, id, deploymentID string) (*DeploymentForwardSyncResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	dep, err := s.getUserDeployment(ctx, pc.userContext.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	enabled, _ := cfgAny["forwardEnabled"].(bool)
	if !enabled {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is disabled for this deployment").Err()
	}
	if strings.TrimSpace(fmt.Sprintf("%v", cfgAny["forwardCollectorId"])) == "" &&
		strings.TrimSpace(fmt.Sprintf("%v", cfgAny["forwardCollectorUsername"])) == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("collector selection is required").Err()
	}

	metaAny := map[string]any{
		"deploymentId": dep.ID,
	}
	meta, _ := toJSONMap(metaAny)
	msg := fmt.Sprintf("Skyforge Forward sync (%s)", pc.claims.Username)
	task, err := createTaskAllowActive(ctx, s.db, pc.userContext.ID, &dep.ID, "forward-sync", msg, pc.claims.Username, meta)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to enqueue forward sync").Err()
	}
	s.enqueueTask(ctx, task)
	runJSON := JSONMap{}
	if runAny := taskToRunInfo(*task); runAny != nil {
		if converted, err := toJSONMap(runAny); err == nil {
			runJSON = converted
		}
	}
	return &DeploymentForwardSyncResponse{
		UserContextID: pc.userContext.ID,
		DeploymentID:  dep.ID,
		Run:           runJSON,
	}, nil
}
