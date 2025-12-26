package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

var deploymentNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type ProjectDeployment struct {
	ID               string  `json:"id"`
	ProjectID         string  `json:"projectId"`
	Name             string  `json:"name"`
	Type             string  `json:"type"`
	Config           JSONMap  `json:"config"`
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
	ProjectID   string             `json:"projectId"`
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
	ProjectID   string            `json:"projectId"`
	Deployment  *ProjectDeployment `json:"deployment"`
	Run         JSONMap           `json:"run,omitempty"`
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
	case "tofu", "netlab":
		return t, nil
	default:
		return "", errs.B().Code(errs.InvalidArgument).Msg("deployment type must be tofu or netlab").Err()
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
	for rows.Next() {
		var (
			rec ProjectDeployment
			raw json.RawMessage
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
	}
	if err := rows.Err(); err != nil {
		log.Printf("deployments list rows: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployments").Err()
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
		password, ok := getCachedLDAPPassword(pc.claims.Username)
		if !ok {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("LDAP password unavailable; reauthenticate").Err()
		}
		cfg, _ := fromJSONMap(dep.Config)
		branch, _ := cfg["gitBranch"].(string)
		message, _ := cfg["message"].(string)
		run, err = s.RunProjectNetlab(ctx, id, &ProjectNetlabRunRequest{
			Message:       message,
			GitBranch:     branch,
			NetlabPassword: password,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown deployment type").Err()
	}

	updated, err := s.touchDeploymentFromRun(ctx, pc.project.ID, deploymentID, dep.Type, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
	}

	resp := &ProjectDeploymentActionResponse{ProjectID: pc.project.ID, Deployment: updated}
	if run != nil {
		resp.Run = run.Task
	}
	return resp, nil
}

func (s *Service) touchDeploymentFromRun(ctx context.Context, projectID, deploymentID, typ string, run *ProjectRunResponse) (*ProjectDeployment, error) {
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
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_task_project_id=$1,
  last_task_id=$2,
  last_status=$3,
  last_started_at=now(),
  updated_at=now()
WHERE project_id=$4 AND id=$5`, nullIfZeroInt(taskProjectID), nullIfZeroInt(taskID), nullIfEmpty(status), projectID, deploymentID)
	if err != nil {
		return nil, err
	}
	return s.getProjectDeployment(ctx, projectID, deploymentID)
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
		rec ProjectDeployment
		raw json.RawMessage
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
