package taskengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
	TaskID      int
	APIURL      string
	Token       string
	Action      string
	LabName     string
	Environment map[string]string
	Topology    map[string]any
	Reconfigure bool
	SkipTLS     bool
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
		if serverRef == "" {
			// backward-compat fallback
			serverRef = strings.TrimSpace(pc.workspace.EveServer)
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
		TaskID:      task.ID,
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
