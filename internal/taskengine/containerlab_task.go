package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

type containerlabTaskSpec struct {
	Action       string            `json:"action,omitempty"`
	NetlabServer string            `json:"netlabServer,omitempty"`
	Deployment   string            `json:"deployment,omitempty"`
	LabName      string            `json:"labName,omitempty"`
	Reconfigure  bool              `json:"reconfigure,omitempty"`
	SkipTLS      bool              `json:"skipTls,omitempty"`
	TopologyJSON string            `json:"topologyJSON,omitempty"`
	Environment  map[string]string `json:"environment,omitempty"`
	APIURL       string            `json:"apiUrl,omitempty"`
	Token        string            `json:"token,omitempty"`
}

type containerlabRunSpec struct {
	TaskID       int
	WorkspaceCtx *workspaceContext
	WorkspaceID  string
	DeploymentID string
	APIURL       string
	Token        string
	Action       string
	LabName      string
	Environment  map[string]string
	Topology     map[string]any
	Reconfigure  bool
	SkipTLS      bool
}

func (e *Engine) dispatchContainerlabTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn containerlabTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
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

	apiURL := strings.TrimSpace(specIn.APIURL)
	token := strings.TrimSpace(specIn.Token)
	skipTLS := specIn.SkipTLS

	// Best-effort: if we didn't precompute API URL/token, derive it again.
	if apiURL == "" || token == "" {
		serverRef := strings.TrimSpace(specIn.NetlabServer)
		if serverRef == "" {
			serverRef = strings.TrimSpace(pc.workspace.NetlabServer)
		}
		server, err := e.resolveWorkspaceNetlabServer(ctx, pc.workspace.ID, serverRef)
		if err != nil {
			return err
		}
		apiURL = containerlabAPIURL(e.cfg, *server)
		if apiURL == "" {
			return fmt.Errorf("containerlab api url is not configured")
		}
		tokenValue, tokenErr := containerlabTokenForUser(e.cfg, username)
		if tokenErr != nil {
			return tokenErr
		}
		token = tokenValue
		skipTLS = containerlabSkipTLS(e.cfg, *server)
	}

	runSpec := containerlabRunSpec{
		TaskID:       task.ID,
		WorkspaceCtx: pc,
		WorkspaceID:  strings.TrimSpace(task.WorkspaceID),
		DeploymentID: func() string {
			if task.DeploymentID.Valid {
				return strings.TrimSpace(task.DeploymentID.String)
			}
			return ""
		}(),
		APIURL:      apiURL,
		Token:       token,
		Action:      strings.TrimSpace(specIn.Action),
		LabName:     strings.TrimSpace(specIn.LabName),
		Environment: specIn.Environment,
		Topology:    nil,
		Reconfigure: specIn.Reconfigure,
		SkipTLS:     skipTLS,
	}
	if strings.TrimSpace(specIn.TopologyJSON) != "" {
		if err := json.Unmarshal([]byte(specIn.TopologyJSON), &runSpec.Topology); err != nil {
			return fmt.Errorf("failed to decode containerlab topology")
		}
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "containerlab."+action, func() error {
		return e.runContainerlabTask(ctx, runSpec, log)
	})
}

func (e *Engine) runContainerlabTask(ctx context.Context, spec containerlabRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("containerlab job canceled")
		}
	}
	switch strings.ToLower(strings.TrimSpace(spec.Action)) {
	case "deploy":
		labName := strings.TrimSpace(spec.LabName)
		payload := containerlabDeployRequest{TopologyContent: spec.Topology}
		url := fmt.Sprintf("%s/api/v1/labs", strings.TrimRight(strings.TrimSpace(spec.APIURL), "/"))
		if spec.Reconfigure {
			url += "?reconfigure=true"
		}
		resp, body, err := containerlabAPIDo(ctx, url, spec.Token, payload, spec.SkipTLS)
		if err != nil {
			return fmt.Errorf("failed to reach containerlab API: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("containerlab API rejected request: %s", strings.TrimSpace(string(body)))
		}
		if len(body) > 0 {
			log.Infof("%s", string(body))
		}
		if labName != "" && spec.TaskID > 0 && strings.TrimSpace(spec.WorkspaceID) != "" {
			graph, err := e.captureContainerlabTopologyArtifact(ctx, spec, labName)
			if err != nil {
				log.Infof("Containerlab topology capture skipped: %v", err)
			} else if graph != nil && spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" {
				dep, depErr := e.loadDeployment(ctx, spec.WorkspaceID, strings.TrimSpace(spec.DeploymentID))
				if depErr != nil {
					log.Infof("Forward sync skipped: failed to load deployment: %v", depErr)
				} else if dep == nil {
					log.Infof("Forward sync skipped: deployment not found")
				} else {
					_, _ = e.syncForwardTopologyGraphDevices(ctx, spec.TaskID, spec.WorkspaceCtx, dep, graph, forwardSyncOptions{
						StartCollection: true,
					})
				}
			}
		}
		return nil
	case "destroy":
		lab := strings.TrimSpace(spec.LabName)
		if lab == "" {
			return fmt.Errorf("containerlab lab name is required")
		}
		url := fmt.Sprintf("%s/api/v1/labs/%s", strings.TrimRight(strings.TrimSpace(spec.APIURL), "/"), lab)
		resp, body, err := containerlabAPIDelete(ctx, url, spec.Token, spec.SkipTLS)
		if err != nil {
			return fmt.Errorf("failed to reach containerlab API: %w", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			log.Infof("Containerlab lab not found; destroy treated as success.")
			return nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("containerlab API rejected request: %s", strings.TrimSpace(string(body)))
		}
		if len(body) > 0 {
			log.Infof("%s", string(body))
		}
		return nil
	default:
		return fmt.Errorf("unknown containerlab action")
	}
}

func (e *Engine) captureContainerlabTopologyArtifact(ctx context.Context, spec containerlabRunSpec, labName string) (*TopologyGraph, error) {
	if e == nil || spec.TaskID <= 0 || strings.TrimSpace(spec.WorkspaceID) == "" {
		return nil, fmt.Errorf("invalid task spec")
	}
	labName = strings.TrimSpace(labName)
	if labName == "" {
		return nil, fmt.Errorf("lab name is required")
	}
	url := fmt.Sprintf("%s/api/v1/labs/%s", strings.TrimRight(strings.TrimSpace(spec.APIURL), "/"), labName)
	resp, body, err := containerlabAPIGet(ctx, url, spec.Token, spec.SkipTLS)
	if err != nil {
		return nil, fmt.Errorf("failed to reach containerlab API: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("containerlab API rejected request: %s", strings.TrimSpace(string(body)))
	}
	graph, err := containerlabLabBytesToTopologyGraph(body)
	if err != nil {
		return nil, err
	}
	graphBytes, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("topology/containerlab/%s.json", sanitizeArtifactKeySegment(labName))
	ctxPut, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	putKey, err := putWorkspaceArtifact(ctxPut, e.cfg, spec.WorkspaceID, key, graphBytes, "application/json")
	if err != nil {
		return nil, err
	}
	e.setTaskMetadataKey(spec.TaskID, "topologyKey", putKey)
	return graph, nil
}

func sanitizeArtifactKeySegment(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	raw = strings.ToLower(raw)
	var b strings.Builder
	b.Grow(len(raw))
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_' || ch == '.':
			b.WriteRune(ch)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}
