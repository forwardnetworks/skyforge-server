package skyforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

var deploymentNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type ProjectDeployment struct {
	ID                string  `json:"id"`
	ProjectID         string  `json:"projectId"`
	Name              string  `json:"name"`
	Type              string  `json:"type"`
	Config            JSONMap `json:"config"`
	CreatedBy         string  `json:"createdBy"`
	CreatedAt         string  `json:"createdAt"`
	UpdatedAt         string  `json:"updatedAt"`
	LastTaskProjectID *int    `json:"lastTaskProjectId,omitempty"`
	LastTaskID        *int    `json:"lastTaskId,omitempty"`
	LastStatus        *string `json:"lastStatus,omitempty"`
	LastStartedAt     *string `json:"lastStartedAt,omitempty"`
	LastFinishedAt    *string `json:"lastFinishedAt,omitempty"`
}

type ProjectDeploymentListResponse struct {
	ProjectID   string               `json:"projectId"`
	Deployments []*ProjectDeployment `json:"deployments"`
}

type ProjectDeploymentCreateRequest struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	Config JSONMap `json:"config,omitempty"`
}

type ProjectDeploymentUpdateRequest struct {
	Name   string  `json:"name,omitempty"`
	Config JSONMap `json:"config,omitempty"`
}

type ProjectDeploymentActionResponse struct {
	ProjectID  string             `json:"projectId"`
	Deployment *ProjectDeployment `json:"deployment"`
	Run        JSONMap            `json:"run,omitempty"`
}

type ProjectDeploymentInfoResponse struct {
	ProjectID   string             `json:"projectId"`
	Deployment  *ProjectDeployment `json:"deployment"`
	Provider    string             `json:"provider"`
	RetrievedAt string             `json:"retrievedAt"`
	Status      string             `json:"status,omitempty"`
	Log         string             `json:"log,omitempty"`
	Note        string             `json:"note,omitempty"`
	Netlab      *NetlabInfo        `json:"netlab,omitempty"`
	Labpp       *LabppInfo         `json:"labpp,omitempty"`
}

type NetlabInfo struct {
	JobID      string `json:"jobId"`
	MultilabID int    `json:"multilabId"`
	APIURL     string `json:"apiUrl"`
}

type LabppInfo struct {
	EveServer string `json:"eveServer"`
	EveURL    string `json:"eveUrl,omitempty"`
	LabPath   string `json:"labPath"`
	Endpoint  string `json:"endpoint,omitempty"`
}

func normalizeDeploymentName(name string) (string, error) {
	name = slugify(name)
	if !deploymentNameRE.MatchString(name) {
		return "", errs.B().Code(errs.InvalidArgument).Msg("deployment name must be 2-63 chars (a-z0-9-)").Err()
	}
	return name, nil
}

func normalizeDeploymentType(raw string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(raw))
	switch t {
	case "tofu", "netlab", "labpp":
		return t, nil
	default:
		return "", errs.B().Code(errs.InvalidArgument).Msg("deployment type must be tofu, netlab, or labpp").Err()
	}
}

// ListProjectDeployments lists deployment definitions for a project.
//
//encore:api auth method=GET path=/api/projects/:id/deployments
func (s *Service) ListProjectDeployments(ctx context.Context, id string) (*ProjectDeploymentListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_project_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE project_id=$1
ORDER BY updated_at DESC`, pc.project.ID)
	if err != nil {
		log.Printf("deployments list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployments").Err()
	}
	defer rows.Close()

	out := make([]*ProjectDeployment, 0, 16)
	refresh := make([]*ProjectDeployment, 0, 4)
	for rows.Next() {
		var (
			rec               ProjectDeployment
			raw               json.RawMessage
			lastTaskProjectID sql.NullInt64
			lastTaskID        sql.NullInt64
			lastStatus        sql.NullString
			lastStarted       sql.NullTime
			lastFinished      sql.NullTime
			createdAt         time.Time
			updatedAt         time.Time
		)
		if err := rows.Scan(
			&rec.ID,
			&rec.Name,
			&rec.Type,
			&raw,
			&rec.CreatedBy,
			&createdAt,
			&updatedAt,
			&lastTaskProjectID,
			&lastTaskID,
			&lastStatus,
			&lastStarted,
			&lastFinished,
		); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode deployments").Err()
		}
		rec.ProjectID = pc.project.ID
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &rec.Config); err != nil {
				rec.Config = JSONMap{}
			}
		} else {
			rec.Config = JSONMap{}
		}
		if lastTaskProjectID.Valid {
			v := int(lastTaskProjectID.Int64)
			rec.LastTaskProjectID = &v
		}
		if lastTaskID.Valid {
			v := int(lastTaskID.Int64)
			rec.LastTaskID = &v
		}
		if lastStatus.Valid {
			v := lastStatus.String
			rec.LastStatus = &v
		}
		if lastStarted.Valid {
			v := lastStarted.Time.UTC().Format(time.RFC3339)
			rec.LastStartedAt = &v
		}
		if lastFinished.Valid {
			v := lastFinished.Time.UTC().Format(time.RFC3339)
			rec.LastFinishedAt = &v
		}
		out = append(out, &rec)
		if shouldRefreshDeploymentStatus(rec.LastStatus) && rec.LastTaskProjectID != nil && rec.LastTaskID != nil {
			refresh = append(refresh, &rec)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("deployments list rows: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployments").Err()
	}

	if len(refresh) > 0 {
		semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
		if err != nil {
			log.Printf("deployments status refresh: %v", err)
		} else {
			for _, dep := range refresh {
				task, err := fetchSemaphoreTask(semaphoreCfg, *dep.LastTaskProjectID, *dep.LastTaskID)
				if err != nil || task == nil {
					continue
				}
				status := strings.TrimSpace(firstString(task, "status", "state"))
				if status == "" {
					continue
				}
				if dep.LastStatus != nil && strings.EqualFold(*dep.LastStatus, status) {
					continue
				}
				finishedAt := parseDeploymentTimestamp(firstString(task, "end_time", "finished_at", "end", "stopped_at"))
				if finishedAt == nil && isTerminalDeploymentStatus(status) {
					now := time.Now().UTC()
					finishedAt = &now
				}
				if err := s.updateDeploymentStatus(ctx, pc.project.ID, dep.ID, status, finishedAt); err != nil {
					log.Printf("deployments status update: %v", err)
					continue
				}
				dep.LastStatus = &status
				if finishedAt != nil {
					v := finishedAt.UTC().Format(time.RFC3339)
					dep.LastFinishedAt = &v
				}
			}
		}
	}

	return &ProjectDeploymentListResponse{ProjectID: pc.project.ID, Deployments: out}, nil
}

// CreateProjectDeployment creates a deployment definition for a project.
//
//encore:api auth method=POST path=/api/projects/:id/deployments
func (s *Service) CreateProjectDeployment(ctx context.Context, id string, req *ProjectDeploymentCreateRequest) (*ProjectDeployment, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}
	typ, err := normalizeDeploymentType(req.Type)
	if err != nil {
		return nil, err
	}
	cfg := req.Config
	if cfg == nil {
		cfg = JSONMap{}
	}
	cfgAny, _ := fromJSONMap(cfg)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	getString := func(key string) string {
		raw, ok := cfgAny[key]
		if !ok {
			return ""
		}
		if v, ok := raw.(string); ok {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(fmt.Sprintf("%v", raw))
	}
	switch typ {
	case "tofu":
		cloud := strings.ToLower(getString("cloud"))
		if cloud == "" {
			cloud = "aws"
		}
		cfgAny["cloud"] = cloud
	case "netlab":
		if getString("netlabServer") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer is required").Err()
		}
		if getString("template") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
	case "labpp":
		if getString("eveServer") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("eveServer is required").Err()
		}
		if getString("template") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
	}
	cfg, _ = toJSONMap(cfgAny)
	cfgBytes, _ := json.Marshal(cfg)

	deploymentID := uuid.NewString()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_deployments (
  id, project_id, name, type, config, created_by
) VALUES ($1,$2,$3,$4,$5,$6)`, deploymentID, pc.project.ID, name, typ, cfgBytes, pc.claims.Username)
	if err != nil {
		log.Printf("deployments insert: %v", err)
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, errs.B().Code(errs.AlreadyExists).Msg("deployment name already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create deployment").Err()
	}
	return s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
}

// UpdateProjectDeployment updates an existing deployment definition.
//
//encore:api auth method=PUT path=/api/projects/:id/deployments/:deploymentID
func (s *Service) UpdateProjectDeployment(ctx context.Context, id, deploymentID string, req *ProjectDeploymentUpdateRequest) (*ProjectDeployment, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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

	fields := []string{}
	args := []any{}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if strings.TrimSpace(req.Name) != "" {
		name, err := normalizeDeploymentName(req.Name)
		if err != nil {
			return nil, err
		}
		fields = append(fields, "name="+arg(name))
	}
	if req.Config != nil {
		cfgBytes, _ := json.Marshal(req.Config)
		fields = append(fields, "config="+arg(cfgBytes))
	}
	fields = append(fields, "updated_at=now()")
	if len(fields) == 1 {
		return s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
	}

	args = append(args, pc.project.ID, deploymentID)
	query := fmt.Sprintf("UPDATE sf_deployments SET %s WHERE project_id=$%d AND id=$%d", strings.Join(fields, ", "), len(args)-1, len(args))
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		log.Printf("deployments update: %v", err)
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, errs.B().Code(errs.AlreadyExists).Msg("deployment name already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update deployment").Err()
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	return s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
}

// DeleteProjectDeployment removes a deployment definition from Skyforge.
//
//encore:api auth method=DELETE path=/api/projects/:id/deployments/:deploymentID
func (s *Service) DeleteProjectDeployment(ctx context.Context, id, deploymentID string) (*ProjectDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	existing, err := s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_deployments WHERE project_id=$1 AND id=$2`, pc.project.ID, deploymentID)
	if err != nil {
		log.Printf("deployments delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete deployment").Err()
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	return &ProjectDeploymentActionResponse{ProjectID: pc.project.ID, Deployment: existing}, nil
}

type ProjectDeploymentStartRequest struct {
	Action string `json:"action,omitempty"` // used for tofu (apply/destroy)
}

type ProjectDeploymentOpRequest struct {
	Action string `json:"action,omitempty"` // create, start, stop, destroy
}

// RunProjectDeploymentAction runs a deployment operation with consistent UX verbs.
//
//encore:api auth method=POST path=/api/projects/:id/deployments/:deploymentID/action
func (s *Service) RunProjectDeploymentAction(ctx context.Context, id, deploymentID string, req *ProjectDeploymentOpRequest) (*ProjectDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
		req = &ProjectDeploymentOpRequest{}
	}

	op := strings.ToLower(strings.TrimSpace(req.Action))
	if op == "" {
		op = "start"
	}
	switch op {
	case "create", "start", "stop", "destroy":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid deployment action (use create, start, stop, destroy)").Err()
	}

	dep, err := s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	infraCreated := false
	if v, ok := cfgAny["infraCreated"].(bool); ok {
		infraCreated = v
	}

	run := (*ProjectRunResponse)(nil)
	switch dep.Type {
	case "tofu":
		cloud, _ := cfgAny["cloud"].(string)
		cloud = strings.ToLower(strings.TrimSpace(cloud))
		if cloud == "" {
			cloud = "aws"
		}
		switch op {
		case "create":
			run, err = s.RunProjectTofuApply(ctx, id, &ProjectTofuApplyParams{Confirm: "true", Cloud: cloud, Action: "apply"})
		case "destroy":
			run, err = s.RunProjectTofuApply(ctx, id, &ProjectTofuApplyParams{Confirm: "true", Cloud: cloud, Action: "destroy"})
		default:
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unsupported tofu action (use create or destroy)").Err()
		}
		if err != nil {
			return nil, err
		}
	case "netlab":
		netlabServer, _ := cfgAny["netlabServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		branch, _ := cfgAny["gitBranch"].(string)
		message, _ := cfgAny["message"].(string)

		netlabServer = strings.TrimSpace(netlabServer)
		if netlabServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
		}
		if strings.TrimSpace(template) == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab template is required").Err()
		}
		if (op == "start" || op == "stop") && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab deployment must be created before start/stop").Err()
		}

		netlabAction := "up"
		cleanup := false
		switch op {
		case "create":
			netlabAction = "create"
		case "start":
			netlabAction = "up"
		case "stop":
			netlabAction = "down"
		case "destroy":
			netlabAction = "down"
			cleanup = true
		}

		run, err = s.RunProjectNetlab(ctx, id, &ProjectNetlabRunRequest{
			Message:          message,
			GitBranch:        branch,
			Action:           netlabAction,
			Cleanup:          cleanup,
			NetlabServer:     netlabServer,
			NetlabMultilabID: dep.ID,
			NetlabDeployment: dep.Name,
			TemplateSource:   strings.TrimSpace(templateSource),
			TemplateRepo:     strings.TrimSpace(templateRepo),
			TemplatesDir:     strings.TrimSpace(templatesDir),
			Template:         strings.TrimSpace(template),
		})
		if err != nil {
			return nil, err
		}
	case "labpp":
		template, _ := cfgAny["template"].(string)
		eveServer, _ := cfgAny["eveServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		templatesDestRoot, _ := cfgAny["templatesDestRoot"].(string)
		labPath, _ := cfgAny["labPath"].(string)
		threadCount, _ := cfgAny["threadCount"].(float64)

		eveServer = strings.TrimSpace(eveServer)
		if eveServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng server selection is required").Err()
		}
		if strings.TrimSpace(template) == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("labpp template is required").Err()
		}
		if (op == "start" || op == "stop") && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("labpp deployment must be created before start/stop").Err()
		}

		labppAction := "e2e"
		switch op {
		case "create":
			labppAction = "upload"
		case "start":
			labppAction = "start"
		case "stop":
			labppAction = "stop"
		case "destroy":
			labppAction = "delete"
		}

		run, err = s.RunProjectLabpp(ctx, id, &ProjectLabppRunRequest{
			Message:           strings.TrimSpace(fmt.Sprintf("Skyforge labpp run (%s)", pc.claims.Username)),
			Action:            labppAction,
			EveServer:         eveServer,
			Template:          strings.TrimSpace(template),
			TemplatesRoot:     "",
			TemplateSource:    strings.TrimSpace(templateSource),
			TemplateRepo:      strings.TrimSpace(templateRepo),
			TemplatesDir:      strings.TrimSpace(templatesDir),
			TemplatesDestRoot: strings.TrimSpace(templatesDestRoot),
			LabPath:           strings.TrimSpace(labPath),
			ThreadCount:       int(threadCount),
			Deployment:        dep.Name,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown deployment type").Err()
	}

	cfgAny["lastAction"] = op
	switch op {
	case "create":
		cfgAny["infraCreated"] = true
	case "destroy":
		cfgAny["infraCreated"] = false
	}

	cfgJSON, err := toJSONMap(cfgAny)
	if err != nil {
		cfgJSON = dep.Config
	}
	updated, err := s.touchDeploymentFromRun(ctx, pc.project.ID, deploymentID, cfgJSON, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
		updated = dep
	}

	resp := &ProjectDeploymentActionResponse{ProjectID: pc.project.ID, Deployment: updated}
	if run != nil {
		resp.Run = run.Task
	}
	return resp, nil
}

type netlabAPIJob struct {
	ID     string  `json:"id"`
	State  string  `json:"state"`
	Status *string `json:"status,omitempty"`
	Error  *string `json:"error,omitempty"`
}

type netlabAPILog struct {
	Log string `json:"log"`
}

func netlabAPIDo(ctx context.Context, url string, payload any) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func netlabAPIGet(ctx context.Context, url string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

// GetProjectDeploymentInfo returns provider-specific info for a deployment.
// For Netlab deployments, this executes `netlab status` against the associated Netlab API and returns the output.
//
//encore:api auth method=GET path=/api/projects/:id/deployments/:deploymentID/info
func (s *Service) GetProjectDeploymentInfo(ctx context.Context, id, deploymentID string) (*ProjectDeploymentInfoResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	resp := &ProjectDeploymentInfoResponse{
		ProjectID:   pc.project.ID,
		Deployment:  dep,
		Provider:    dep.Type,
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}

	switch dep.Type {
	case "netlab":
		netlabServer, _ := cfgAny["netlabServer"].(string)
		netlabServer = strings.TrimSpace(netlabServer)
		if netlabServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
		}

		server, _ := resolveNetlabServer(s.cfg, netlabServer)
		if server == nil || strings.TrimSpace(server.SSHHost) == "" {
			return nil, errs.B().Code(errs.Unavailable).Msg("netlab runner is not configured").Err()
		}

		multilabID := dep.ID
		h := fnv.New32a()
		_, _ = h.Write([]byte(multilabID))
		multilabNumericID := int(h.Sum32()%199) + 1

		workspaceRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
		apiURL := strings.TrimRight(fmt.Sprintf("https://%s/netlab", strings.TrimSpace(server.SSHHost)), "/")

		payload := map[string]any{
			"action":        "status",
			"user":          strings.TrimSpace(pc.claims.Username),
			"project":       strings.TrimSpace(pc.project.Slug),
			"deployment":    strings.TrimSpace(dep.Name),
			"workspaceRoot": workspaceRoot,
			"plugin":        "multilab",
			"multilabId":    strconv.Itoa(multilabNumericID),
			"instance":      strconv.Itoa(multilabNumericID),
			"stateRoot":     strings.TrimSpace(server.StateRoot),
		}

		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		postResp, body, err := netlabAPIDo(ctx, apiURL+"/jobs", payload)
		if err != nil {
			log.Printf("netlab info: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach netlab API").Err()
		}
		if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
			return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("netlab API rejected request: %s", strings.TrimSpace(string(body)))).Err()
		}
		var job netlabAPIJob
		if err := json.Unmarshal(body, &job); err != nil || strings.TrimSpace(job.ID) == "" {
			return nil, errs.B().Code(errs.Unavailable).Msg("netlab API returned invalid response").Err()
		}

		deadline := time.Now().Add(25 * time.Second)
		for {
			getResp, getBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s", apiURL, job.ID))
			if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
				_ = json.Unmarshal(getBody, &job)
			}
			logResp, logBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s/log", apiURL, job.ID))
			if err == nil && logResp != nil && logResp.StatusCode >= 200 && logResp.StatusCode < 300 {
				var lr netlabAPILog
				if err := json.Unmarshal(logBody, &lr); err == nil {
					resp.Log = lr.Log
				}
			}

			state := strings.ToLower(strings.TrimSpace(job.State))
			if state == "" {
				state = strings.ToLower(strings.TrimSpace(derefString(job.Status)))
			}
			resp.Status = state
			if state == "success" || state == "failed" || state == "canceled" {
				break
			}
			if time.Now().After(deadline) {
				resp.Note = "netlab status is still running; try again shortly"
				break
			}
			time.Sleep(1 * time.Second)
		}

		resp.Netlab = &NetlabInfo{
			JobID:      job.ID,
			MultilabID: multilabNumericID,
			APIURL:     apiURL,
		}

		return resp, nil
	case "labpp":
		template, _ := cfgAny["template"].(string)
		template = strings.TrimSpace(template)
		eveServerName, _ := cfgAny["eveServer"].(string)
		eveServerName = strings.TrimSpace(eveServerName)
		if eveServerName == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng server selection is required").Err()
		}
		eveServer := eveServerByName(s.cfg.EveServers, eveServerName)
		if eveServer == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("unknown eve server").Err()
		}

		labPath, _ := cfgAny["labPath"].(string)
		labPath = strings.TrimSpace(labPath)
		if labPath == "" && template != "" {
			labPath = fmt.Sprintf(
				"/Users/%s/%s/%s/%s.unl",
				pc.claims.Username,
				pc.project.Slug,
				strings.TrimSpace(dep.Name),
				labppLabFilename(template),
			)
		}
		if labPath == "" {
			resp.Note = "lab path is not configured yet"
			return resp, nil
		}

		base := strings.TrimRight(strings.TrimSpace(eveServer.APIURL), "/")
		if base == "" {
			base = strings.TrimRight(strings.TrimSpace(eveServer.WebURL), "/")
		}
		if base == "" {
			resp.Note = "eve server is missing apiUrl/webUrl"
			resp.Labpp = &LabppInfo{EveServer: eveServerName, LabPath: labPath}
			return resp, nil
		}

		username := strings.TrimSpace(eveServer.Username)
		password := strings.TrimSpace(eveServer.Password)
		if username == "" || password == "" {
			resp.Note = "eve server credentials are not configured"
			resp.Labpp = &LabppInfo{EveServer: eveServerName, EveURL: base, LabPath: labPath}
			return resp, nil
		}

		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()

		jar, _ := cookiejar.New(nil)
		client := &http.Client{
			Timeout: checkCtxTimeout(checkCtx, 8*time.Second),
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: eveServer.SkipTLSVerify},
			},
		}
		if err := eveLogin(checkCtx, client, base, username, password); err != nil {
			resp.Note = "failed to login to eve-ng"
			resp.Status = "error"
			resp.Labpp = &LabppInfo{EveServer: eveServerName, EveURL: base, LabPath: labPath}
			return resp, nil
		}

		hasRunning, endpoint, err := eveLabHasRunningNodes(checkCtx, client, base, username, labPath)
		if err != nil {
			resp.Note = sanitizeError(err)
			resp.Status = "error"
		} else if hasRunning {
			resp.Status = "running"
		} else {
			resp.Status = "stopped"
		}

		resp.Labpp = &LabppInfo{EveServer: eveServerName, EveURL: base, LabPath: labPath, Endpoint: endpoint}
		return resp, nil
	default:
		resp.Note = "info is not yet supported for this deployment type"
		return resp, nil
	}
}

func checkCtxTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if ctx == nil {
		return fallback
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			return remaining
		}
	}
	return fallback
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// StartProjectDeployment starts a deployment run in Semaphore.
//
//encore:api auth method=POST path=/api/projects/:id/deployments/:deploymentID/start
func (s *Service) StartProjectDeployment(ctx context.Context, id, deploymentID string, req *ProjectDeploymentStartRequest) (*ProjectDeploymentActionResponse, error) {
	return s.runDeployment(ctx, id, deploymentID, req, "start")
}

// DestroyProjectDeployment triggers a destructive run (destroy) for a deployment.
//
//encore:api auth method=POST path=/api/projects/:id/deployments/:deploymentID/destroy
func (s *Service) DestroyProjectDeployment(ctx context.Context, id, deploymentID string) (*ProjectDeploymentActionResponse, error) {
	return s.runDeployment(ctx, id, deploymentID, &ProjectDeploymentStartRequest{Action: "destroy"}, "destroy")
}

// StopProjectDeployment attempts to stop the most recent task for this deployment.
//
//encore:api auth method=POST path=/api/projects/:id/deployments/:deploymentID/stop
func (s *Service) StopProjectDeployment(ctx context.Context, id, deploymentID string) (*ProjectDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if dep.LastTaskProjectID == nil || dep.LastTaskID == nil {
		return &ProjectDeploymentActionResponse{ProjectID: pc.project.ID, Deployment: dep}, nil
	}
	semaphoreCfg, err := semaphoreConfigForUser(s.cfg, pc.claims.Username)
	if err != nil {
		return nil, err
	}
	resp, body, err := semaphoreDo(semaphoreCfg, http.MethodPost, fmt.Sprintf("/project/%d/tasks/%d/stop", *dep.LastTaskProjectID, *dep.LastTaskID), map[string]any{})
	if err != nil {
		log.Printf("semaphore stop: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach semaphore").Err()
	}
	if resp == nil || (resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK) {
		return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("semaphore stop rejected: %s", strings.TrimSpace(string(body)))).Err()
	}
	return &ProjectDeploymentActionResponse{ProjectID: pc.project.ID, Deployment: dep}, nil
}

func (s *Service) runDeployment(ctx context.Context, id, deploymentID string, req *ProjectDeploymentStartRequest, mode string) (*ProjectDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getProjectDeployment(ctx, pc.project.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "apply"
	}
	if mode == "destroy" {
		action = "destroy"
	}

	var run *ProjectRunResponse

	switch dep.Type {
	case "tofu":
		cfg, _ := fromJSONMap(dep.Config)
		cloud, _ := cfg["cloud"].(string)
		cloud = strings.ToLower(strings.TrimSpace(cloud))
		if cloud == "" {
			cloud = "aws"
		}
		run, err = s.RunProjectTofuApply(ctx, id, &ProjectTofuApplyParams{Confirm: "true", Cloud: cloud, Action: action})
		if err != nil {
			return nil, err
		}
	case "netlab":
		cfg, _ := fromJSONMap(dep.Config)
		branch, _ := cfg["gitBranch"].(string)
		message, _ := cfg["message"].(string)
		netlabServer, _ := cfg["netlabServer"].(string)
		templateSource, _ := cfg["templateSource"].(string)
		templateRepo, _ := cfg["templateRepo"].(string)
		templatesDir, _ := cfg["templatesDir"].(string)
		template, _ := cfg["template"].(string)
		netlabAction := "up"
		cleanup := false
		if mode == "destroy" {
			netlabAction = "down"
			cleanup = true
		}
		run, err = s.RunProjectNetlab(ctx, id, &ProjectNetlabRunRequest{
			Message:          message,
			GitBranch:        branch,
			Action:           netlabAction,
			Cleanup:          cleanup,
			NetlabServer:     strings.TrimSpace(netlabServer),
			NetlabMultilabID: dep.ID,
			NetlabDeployment: dep.Name,
			TemplateSource:   strings.TrimSpace(templateSource),
			TemplateRepo:     strings.TrimSpace(templateRepo),
			TemplatesDir:     strings.TrimSpace(templatesDir),
			Template:         strings.TrimSpace(template),
		})
		if err != nil {
			return nil, err
		}
	case "labpp":
		cfg, _ := fromJSONMap(dep.Config)
		template, _ := cfg["template"].(string)
		eveServer, _ := cfg["eveServer"].(string)
		templateSource, _ := cfg["templateSource"].(string)
		templateRepo, _ := cfg["templateRepo"].(string)
		templatesDir, _ := cfg["templatesDir"].(string)
		templatesDestRoot, _ := cfg["templatesDestRoot"].(string)
		labPath, _ := cfg["labPath"].(string)
		threadCount, _ := cfg["threadCount"].(float64)

		labppAction := "e2e"
		switch mode {
		case "destroy":
			labppAction = "delete"
		case "start":
			labppAction = "e2e"
		}

		run, err = s.RunProjectLabpp(ctx, id, &ProjectLabppRunRequest{
			Message:           strings.TrimSpace(fmt.Sprintf("Skyforge labpp run (%s)", pc.claims.Username)),
			Action:            labppAction,
			EveServer:         strings.TrimSpace(eveServer),
			Template:          strings.TrimSpace(template),
			TemplatesRoot:     "",
			TemplateSource:    strings.TrimSpace(templateSource),
			TemplateRepo:      strings.TrimSpace(templateRepo),
			TemplatesDir:      strings.TrimSpace(templatesDir),
			TemplatesDestRoot: strings.TrimSpace(templatesDestRoot),
			LabPath:           strings.TrimSpace(labPath),
			ThreadCount:       int(threadCount),
			Deployment:        dep.Name,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown deployment type").Err()
	}

	updated, err := s.touchDeploymentFromRun(ctx, pc.project.ID, deploymentID, dep.Config, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
	}

	resp := &ProjectDeploymentActionResponse{ProjectID: pc.project.ID, Deployment: updated}
	if run != nil {
		resp.Run = run.Task
	}
	return resp, nil
}

func (s *Service) touchDeploymentFromRun(ctx context.Context, projectID, deploymentID string, cfg JSONMap, run *ProjectRunResponse) (*ProjectDeployment, error) {
	if s.db == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	taskProjectID := 0
	taskID := 0
	status := ""
	if run != nil {
		taskProjectID = run.ProjectID
		if task, _ := fromJSONMap(run.Task); task != nil {
			if v, ok := task["id"].(float64); ok {
				taskID = int(v)
			}
			if v, ok := task["status"].(string); ok {
				status = v
			}
		}
	}
	if cfg == nil {
		cfg = JSONMap{}
	}
	cfgBytes, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  config=$1,
  last_task_project_id=$2,
  last_task_id=$3,
  last_status=$4,
  last_started_at=now(),
  updated_at=now()
WHERE project_id=$5 AND id=$6`, cfgBytes, nullIfZeroInt(taskProjectID), nullIfZeroInt(taskID), nullIfEmpty(status), projectID, deploymentID)
	if err != nil {
		return nil, err
	}
	return s.getProjectDeployment(ctx, projectID, deploymentID)
}

func (s *Service) updateDeploymentStatus(ctx context.Context, projectID, deploymentID string, status string, finishedAt *time.Time) error {
	if s.db == nil {
		return fmt.Errorf("db unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if finishedAt != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  last_finished_at=$2,
  updated_at=now()
WHERE project_id=$3 AND id=$4`, status, *finishedAt, projectID, deploymentID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  updated_at=now()
WHERE project_id=$2 AND id=$3`, status, projectID, deploymentID)
	return err
}

func nullIfZeroInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func (s *Service) getProjectDeployment(ctx context.Context, projectID, deploymentID string) (*ProjectDeployment, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		rec               ProjectDeployment
		raw               json.RawMessage
		lastTaskProjectID sql.NullInt64
		lastTaskID        sql.NullInt64
		lastStatus        sql.NullString
		lastStarted       sql.NullTime
		lastFinished      sql.NullTime
		createdAt         time.Time
		updatedAt         time.Time
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_project_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE project_id=$1 AND id=$2`, projectID, deploymentID).Scan(
		&rec.ID,
		&rec.Name,
		&rec.Type,
		&raw,
		&rec.CreatedBy,
		&createdAt,
		&updatedAt,
		&lastTaskProjectID,
		&lastTaskID,
		&lastStatus,
		&lastStarted,
		&lastFinished,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
		}
		log.Printf("deployments get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployment").Err()
	}
	rec.ProjectID = projectID
	rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &rec.Config)
	}
	if rec.Config == nil {
		rec.Config = JSONMap{}
	}
	if lastTaskProjectID.Valid {
		v := int(lastTaskProjectID.Int64)
		rec.LastTaskProjectID = &v
	}
	if lastTaskID.Valid {
		v := int(lastTaskID.Int64)
		rec.LastTaskID = &v
	}
	if lastStatus.Valid {
		v := lastStatus.String
		rec.LastStatus = &v
	}
	if lastStarted.Valid {
		v := lastStarted.Time.UTC().Format(time.RFC3339)
		rec.LastStartedAt = &v
	}
	if lastFinished.Valid {
		v := lastFinished.Time.UTC().Format(time.RFC3339)
		rec.LastFinishedAt = &v
	}
	return &rec, nil
}

func shouldRefreshDeploymentStatus(status *string) bool {
	if status == nil {
		return true
	}
	normalized := strings.ToLower(strings.TrimSpace(*status))
	if normalized == "" {
		return true
	}
	for _, marker := range []string{"waiting", "pending", "queued", "running", "in_progress", "in-progress", "processing"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func isTerminalDeploymentStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	for _, marker := range []string{"success", "completed", "failed", "error", "canceled", "cancelled", "aborted"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func parseDeploymentTimestamp(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return &parsed
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return &parsed
	}
	return nil
}
