package skyforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskqueue"
	"encore.app/storage"
	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

var deploymentNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type WorkspaceDeployment struct {
	ID                  string  `json:"id"`
	WorkspaceID         string  `json:"workspaceId"`
	Name                string  `json:"name"`
	Type                string  `json:"type"`
	Config              JSONMap `json:"config"`
	CreatedBy           string  `json:"createdBy"`
	CreatedAt           string  `json:"createdAt"`
	UpdatedAt           string  `json:"updatedAt"`
	LastTaskWorkspaceID *int    `json:"lastTaskWorkspaceId,omitempty"`
	LastTaskID          *int    `json:"lastTaskId,omitempty"`
	LastStatus          *string `json:"lastStatus,omitempty"`
	LastStartedAt       *string `json:"lastStartedAt,omitempty"`
	LastFinishedAt      *string `json:"lastFinishedAt,omitempty"`
	ActiveTaskID        *int    `json:"activeTaskId,omitempty"`
	ActiveTaskStatus    *string `json:"activeTaskStatus,omitempty"`
	QueueDepth          *int    `json:"queueDepth,omitempty"`
}

type WorkspaceDeploymentListResponse struct {
	WorkspaceID string                 `json:"workspaceId"`
	Deployments []*WorkspaceDeployment `json:"deployments"`
}

type WorkspaceDeploymentCreateRequest struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	Config JSONMap `json:"config,omitempty"`
}

type WorkspaceDeploymentUpdateRequest struct {
	Name   string  `json:"name,omitempty"`
	Config JSONMap `json:"config,omitempty"`
}

type WorkspaceDeploymentActionResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Deployment  *WorkspaceDeployment `json:"deployment"`
	Run         JSONMap              `json:"run,omitempty"`
}

type WorkspaceDeploymentDeleteRequest struct {
	ForwardDelete bool `query:"forward_delete" encore:"optional"`
}

type WorkspaceDeploymentInfoResponse struct {
	WorkspaceID  string               `json:"workspaceId"`
	Deployment   *WorkspaceDeployment `json:"deployment"`
	Provider     string               `json:"provider"`
	RetrievedAt  string               `json:"retrievedAt"`
	Status       string               `json:"status,omitempty"`
	Log          string               `json:"log,omitempty"`
	Note         string               `json:"note,omitempty"`
	ForwardID    string               `json:"forwardNetworkId,omitempty"`
	ForwardURL   string               `json:"forwardSnapshotUrl,omitempty"`
	Netlab       *NetlabInfo          `json:"netlab,omitempty"`
	Labpp        *LabppInfo           `json:"labpp,omitempty"`
	Containerlab *ContainerlabInfo    `json:"containerlab,omitempty"`
	Clabernetes  *ClabernetesInfo     `json:"clabernetes,omitempty"`
}

type NetlabGraphResponse struct {
	GeneratedAt string `json:"generatedAt"`
	SVG         string `json:"svg"`
	OutputPath  string `json:"outputPath,omitempty"`
}

type NetlabInfo struct {
	JobID      string `json:"jobId"`
	MultilabID int    `json:"multilabId"`
	APIURL     string `json:"apiUrl"`
}

type ClabernetesInfo struct {
	Namespace    string `json:"namespace"`
	TopologyName string `json:"topologyName"`
	LabName      string `json:"labName"`
	Ready        bool   `json:"ready,omitempty"`
	ConfigMaps   int    `json:"configMaps,omitempty"`
}

type NetlabConnectRequest struct {
	Node string   `json:"node"`
	Show []string `json:"show,omitempty"`
}

type NetlabConnectResponse struct {
	Output string `json:"output"`
}

type LabppInfo struct {
	EveServer      string `json:"eveServer"`
	EveURL         string `json:"eveUrl,omitempty"`
	LabPath        string `json:"labPath"`
	Endpoint       string `json:"endpoint,omitempty"`
	JobID          string `json:"jobId,omitempty"`
	DataSourcesCSV string `json:"dataSourcesCsv,omitempty"`
}

type LabppDataSourcesDownloadResponse struct {
	Status   string `json:"status"`
	Filename string `json:"filename"`
	FileData string `json:"fileData"`
}

type ContainerlabInfo struct {
	LabName string `json:"labName"`
	APIURL  string `json:"apiUrl"`
}

type terraformStateOutput struct {
	Value     any  `json:"value"`
	Sensitive bool `json:"sensitive"`
}

type terraformState struct {
	Outputs map[string]terraformStateOutput `json:"outputs"`
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
	case "terraform", "netlab", "netlab-c9s", "labpp", "containerlab", "clabernetes":
		return t, nil
	default:
		return "", errs.B().Code(errs.InvalidArgument).Msg("deployment type must be terraform, netlab, netlab-c9s, labpp, containerlab, or clabernetes").Err()
	}
}

// ListWorkspaceDeployments lists deployment definitions for a workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments
func (s *Service) ListWorkspaceDeployments(ctx context.Context, id string) (*WorkspaceDeploymentListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_workspace_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE workspace_id=$1
ORDER BY updated_at DESC`, pc.workspace.ID)
	if err != nil {
		log.Printf("deployments list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployments").Err()
	}
	defer rows.Close()

	out := make([]*WorkspaceDeployment, 0, 16)
	refresh := make([]*WorkspaceDeployment, 0, 4)
	for rows.Next() {
		var (
			rec                 WorkspaceDeployment
			raw                 json.RawMessage
			lastTaskWorkspaceID sql.NullInt64
			lastTaskID          sql.NullInt64
			lastStatus          sql.NullString
			lastStarted         sql.NullTime
			lastFinished        sql.NullTime
			createdAt           time.Time
			updatedAt           time.Time
		)
		if err := rows.Scan(
			&rec.ID,
			&rec.Name,
			&rec.Type,
			&raw,
			&rec.CreatedBy,
			&createdAt,
			&updatedAt,
			&lastTaskWorkspaceID,
			&lastTaskID,
			&lastStatus,
			&lastStarted,
			&lastFinished,
		); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode deployments").Err()
		}
		rec.WorkspaceID = pc.workspace.ID
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		{
			qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			summary, err := getDeploymentQueueSummary(qctx, s.db, pc.workspace.ID, rec.ID)
			cancel()
			if err == nil && summary != nil {
				if summary.ActiveTaskID > 0 {
					rec.ActiveTaskID = &summary.ActiveTaskID
				}
				if strings.TrimSpace(summary.ActiveTaskStatus) != "" {
					status := strings.TrimSpace(summary.ActiveTaskStatus)
					rec.ActiveTaskStatus = &status
				}
				rec.QueueDepth = &summary.QueueDepth
			}
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &rec.Config); err != nil {
				rec.Config = JSONMap{}
			}
		} else {
			rec.Config = JSONMap{}
		}
		if lastTaskWorkspaceID.Valid {
			v := int(lastTaskWorkspaceID.Int64)
			rec.LastTaskWorkspaceID = &v
		}
		if lastTaskID.Valid {
			v := int(lastTaskID.Int64)
			rec.LastTaskID = &v
		}
		if lastStatus.Valid {
			v := lastStatus.String
			rec.LastStatus = &v
		} else {
			v := "created"
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
		if shouldRefreshDeploymentStatus(rec.LastStatus) && rec.LastTaskID != nil {
			refresh = append(refresh, &rec)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("deployments list rows: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployments").Err()
	}

	if len(refresh) > 0 {
		for _, dep := range refresh {
			if dep.LastTaskID == nil {
				continue
			}
			task, err := getTask(ctx, s.db, *dep.LastTaskID)
			if err != nil || task == nil {
				continue
			}
			status := strings.TrimSpace(task.Status)
			if status == "" {
				continue
			}
			if dep.LastStatus != nil && strings.EqualFold(*dep.LastStatus, status) {
				continue
			}
			var finishedAt *time.Time
			if task.FinishedAt.Valid {
				finished := task.FinishedAt.Time.UTC()
				finishedAt = &finished
			} else if isTerminalDeploymentStatus(status) {
				now := time.Now().UTC()
				finishedAt = &now
			}
			if err := s.updateDeploymentStatus(ctx, pc.workspace.ID, dep.ID, status, finishedAt); err != nil {
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

	return &WorkspaceDeploymentListResponse{WorkspaceID: pc.workspace.ID, Deployments: out}, nil
}

// CreateWorkspaceDeployment creates a deployment definition for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments
func (s *Service) CreateWorkspaceDeployment(ctx context.Context, id string, req *WorkspaceDeploymentCreateRequest) (*WorkspaceDeployment, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
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
	case "terraform":
		cloud := strings.ToLower(getString("cloud"))
		if cloud == "" {
			cloud = "aws"
		}
		templateSource := strings.ToLower(getString("templateSource"))
		if templateSource == "" {
			templateSource = "workspace"
		}
		templateRepo := getString("templateRepo")
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		template := strings.Trim(getString("template"), "/")
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		if templateSource == "custom" && templateRepo == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		if templatesDir == "" {
			templatesDir = fmt.Sprintf("cloud/terraform/%s", cloud)
		}
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		templatePath := path.Join(templatesDir, template)
		if !isSafeRelativePath(templatePath) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a safe repo-relative path").Err()
		}
		cfgAny["cloud"] = cloud
		cfgAny["templateSource"] = templateSource
		if templateRepo != "" {
			cfgAny["templateRepo"] = templateRepo
		}
		cfgAny["templatesDir"] = templatesDir
		cfgAny["template"] = template
	case "netlab":
		netlabServer := strings.TrimSpace(getString("netlabServer"))
		if netlabServer == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer is required").Err()
		}
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := strings.ToLower(getString("templateSource"))
		if templateSource == "" {
			templateSource = "blueprints"
		}
		templateRepo := strings.TrimSpace(getString("templateRepo"))
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		if templateSource == "custom" && templateRepo == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		templatesDir = normalizeNetlabTemplatesDir(templateSource, templatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		cfgAny["netlabServer"] = netlabServer
		cfgAny["templateSource"] = templateSource
		if templateRepo != "" {
			cfgAny["templateRepo"] = templateRepo
		}
		cfgAny["templatesDir"] = templatesDir
		cfgAny["template"] = template
	case "labpp":
		if getString("eveServer") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("eveServer is required").Err()
		}
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		if strings.TrimSpace(getString("labPath")) == "" {
			cfgAny["labPath"] = labppLabPath(pc.claims.Username, name, template, time.Now())
		}
		// Never persist plaintext passwords in deployment config; store an encrypted
		// version instead for worker-side use.
		if pwd := strings.TrimSpace(getString("evePassword")); pwd != "" {
			if enc := encryptUserSecret(pwd); enc != "" {
				cfgAny["evePasswordEnc"] = enc
			}
			delete(cfgAny, "evePassword")
		}
	case "clabernetes":
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := strings.ToLower(getString("templateSource"))
		if templateSource == "" {
			templateSource = "workspace"
		}
		templateRepo := getString("templateRepo")
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		switch templateSource {
		case "custom":
			if templateRepo == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
			}
		case "external":
			if !pc.workspace.AllowExternalTemplateRepos {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("external template repos are disabled for this workspace").Err()
			}
			if strings.TrimSpace(templateRepo) == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("external repo is required").Err()
			}
			if externalTemplateRepoByID(&pc.workspace, templateRepo) == nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown external repo").Err()
			}
		}
		templatesDir = normalizeContainerlabTemplatesDir(templateSource, templatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		cfgAny["templateSource"] = templateSource
		if templateRepo != "" {
			cfgAny["templateRepo"] = templateRepo
		}
		cfgAny["templatesDir"] = templatesDir
		cfgAny["template"] = template
		cfgAny["labName"] = containerlabLabName(pc.workspace.Slug, name)
	case "containerlab":
		if getString("netlabServer") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer is required").Err()
		}
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := strings.ToLower(getString("templateSource"))
		if templateSource == "" {
			templateSource = "workspace"
		}
		templateRepo := getString("templateRepo")
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		switch templateSource {
		case "custom":
			if templateRepo == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
			}
		case "external":
			if !pc.workspace.AllowExternalTemplateRepos {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("external template repos are disabled for this workspace").Err()
			}
			if strings.TrimSpace(templateRepo) == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("external repo is required").Err()
			}
			if externalTemplateRepoByID(&pc.workspace, templateRepo) == nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown external repo").Err()
			}
		}
		templatesDir = normalizeContainerlabTemplatesDir(templateSource, templatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		cfgAny["templateSource"] = templateSource
		if templateRepo != "" {
			cfgAny["templateRepo"] = templateRepo
		}
		cfgAny["templatesDir"] = templatesDir
		cfgAny["template"] = template
		cfgAny["labName"] = containerlabLabName(pc.workspace.Slug, name)
	}
	cfg, _ = toJSONMap(cfgAny)
	cfgBytes, _ := json.Marshal(cfg)

	deploymentID := uuid.NewString()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	initialStatus := "created"
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_deployments (
  id, workspace_id, name, type, config, created_by, last_status
) VALUES ($1,$2,$3,$4,$5,$6,$7)`, deploymentID, pc.workspace.ID, name, typ, cfgBytes, pc.claims.Username, initialStatus)
	if err != nil {
		log.Printf("deployments insert: %v", err)
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, errs.B().Code(errs.AlreadyExists).Msg("deployment name already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create deployment").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if dep != nil && (typ == "netlab" || typ == "labpp") {
		if _, err := s.ensureForwardNetworkForDeployment(ctx, pc, dep); err != nil {
			log.Printf("forward network create: %v", err)
			_, _ = s.db.ExecContext(ctx, `DELETE FROM sf_deployments WHERE workspace_id=$1 AND id=$2`, pc.workspace.ID, deploymentID)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to create Forward network").Err()
		}
		if typ == "netlab" {
			// Kick off a `netlab create` run immediately so a subsequent start has less work to do.
			// This is best-effort: keep the deployment even if the create run fails.
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if _, err := s.RunWorkspaceDeploymentAction(ctx, id, deploymentID, &WorkspaceDeploymentOpRequest{Action: "create"}); err != nil {
				log.Printf("netlab create on deployment create: %v", err)
			}
		}
		if typ == "labpp" {
			_, err := s.RunWorkspaceDeploymentAction(ctx, id, deploymentID, &WorkspaceDeploymentOpRequest{Action: "create"})
			if err != nil {
				log.Printf("labpp create upload: %v", err)
				_, _ = s.db.ExecContext(ctx, `DELETE FROM sf_deployments WHERE workspace_id=$1 AND id=$2`, pc.workspace.ID, deploymentID)
				return nil, err
			}
		}
		return s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	}
	return dep, nil
}

// UpdateWorkspaceDeployment updates an existing deployment definition.
//
//encore:api auth method=PUT path=/api/workspaces/:id/deployments/:deploymentID
func (s *Service) UpdateWorkspaceDeployment(ctx context.Context, id, deploymentID string, req *WorkspaceDeploymentUpdateRequest) (*WorkspaceDeployment, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
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
		cfg := req.Config
		// Sanitize config updates based on existing deployment type.
		existing, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
		if err != nil {
			return nil, err
		}
		if existing != nil && existing.Type == "labpp" {
			cfgAny, _ := fromJSONMap(cfg)
			if cfgAny == nil {
				cfgAny = map[string]any{}
			}
			if rawPwd, ok := cfgAny["evePassword"].(string); ok {
				if pwd := strings.TrimSpace(rawPwd); pwd != "" {
					if enc := encryptUserSecret(pwd); enc != "" {
						cfgAny["evePasswordEnc"] = enc
					}
				}
				delete(cfgAny, "evePassword")
			}
			cfg, _ = toJSONMap(cfgAny)
		}
		cfgBytes, _ := json.Marshal(cfg)
		fields = append(fields, "config="+arg(cfgBytes))
	}
	fields = append(fields, "updated_at=now()")
	if len(fields) == 1 {
		return s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	}

	args = append(args, pc.workspace.ID, deploymentID)
	query := fmt.Sprintf("UPDATE sf_deployments SET %s WHERE workspace_id=$%d AND id=$%d", strings.Join(fields, ", "), len(args)-1, len(args))
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
	return s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
}

// DeleteWorkspaceDeployment removes a deployment definition from Skyforge.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/deployments/:deploymentID
func (s *Service) DeleteWorkspaceDeployment(ctx context.Context, id, deploymentID string, req *WorkspaceDeploymentDeleteRequest) (*WorkspaceDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	existing, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if existing.Type == "netlab" {
		cfgAny, _ := fromJSONMap(existing.Config)
		if cfgAny == nil {
			cfgAny = map[string]any{}
		}
		netlabServer, _ := cfgAny["netlabServer"].(string)
		if strings.TrimSpace(netlabServer) == "" {
			netlabServer = strings.TrimSpace(pc.workspace.NetlabServer)
		}
		if strings.TrimSpace(netlabServer) == "" {
			netlabServer = strings.TrimSpace(pc.workspace.EveServer)
		}
		if strings.TrimSpace(netlabServer) != "" {
			_, err := s.RunWorkspaceNetlab(ctx, id, &WorkspaceNetlabRunRequest{
				Message:          strings.TrimSpace(fmt.Sprintf("Skyforge netlab cleanup (%s)", pc.claims.Username)),
				Action:           "down",
				Cleanup:          true,
				NetlabServer:     netlabServer,
				NetlabMultilabID: existing.ID,
				NetlabDeployment: existing.Name,
			})
			if err != nil {
				log.Printf("deployments delete netlab cleanup (ignored): %v", err)
			}
		}
	}
	if existing.Type == "labpp" {
		_, err := s.RunWorkspaceDeploymentAction(ctx, id, deploymentID, &WorkspaceDeploymentOpRequest{Action: "destroy"})
		if err != nil {
			log.Printf("deployments delete labpp cleanup (ignored): %v", err)
		}
	}
	if existing.Type == "netlab-c9s" || existing.Type == "clabernetes" {
		_, err := s.RunWorkspaceDeploymentAction(ctx, id, deploymentID, &WorkspaceDeploymentOpRequest{Action: "destroy"})
		if err != nil {
			log.Printf("deployments delete c9s cleanup (ignored): %v", err)
		}
	}
	if req != nil && req.ForwardDelete {
		cfgAny, _ := fromJSONMap(existing.Config)
		if cfgAny == nil {
			cfgAny = map[string]any{}
		}
		if raw, ok := cfgAny[forwardNetworkIDKey]; ok {
			networkID := strings.TrimSpace(fmt.Sprintf("%v", raw))
			if networkID != "" {
				forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
				if err != nil {
					return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward config").Err()
				}
				if forwardCfg != nil {
					client, err := newForwardClient(*forwardCfg)
					if err != nil {
						return nil, errs.B().Code(errs.Unavailable).Msg("failed to init Forward client").Err()
					}
					if err := forwardDeleteNetwork(ctx, client, networkID); err != nil {
						return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward network").Err()
					}
				}
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_deployments WHERE workspace_id=$1 AND id=$2`, pc.workspace.ID, deploymentID)
	if err != nil {
		log.Printf("deployments delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete deployment").Err()
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	return &WorkspaceDeploymentActionResponse{WorkspaceID: pc.workspace.ID, Deployment: existing}, nil
}

type WorkspaceDeploymentStartRequest struct {
	Action string `json:"action,omitempty"` // used for terraform (apply/destroy)
}

type WorkspaceDeploymentOpRequest struct {
	Action string `json:"action,omitempty"` // create, start, stop, destroy, export
}

// RunWorkspaceDeploymentAction runs a deployment operation with consistent UX verbs.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/action
func (s *Service) RunWorkspaceDeploymentAction(ctx context.Context, id, deploymentID string, req *WorkspaceDeploymentOpRequest) (*WorkspaceDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
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
		req = &WorkspaceDeploymentOpRequest{}
	}

	op := strings.ToLower(strings.TrimSpace(req.Action))
	if op == "" {
		op = "start"
	}
	switch op {
	case "create", "start", "stop", "destroy", "export":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid deployment action (use create, start, stop, destroy, export)").Err()
	}

	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	envMap, err := s.mergeDeploymentEnvironment(ctx, pc.workspace.ID, cfgAny)
	if err != nil {
		return nil, err
	}
	envJSON := JSONMap{}
	if len(envMap) > 0 {
		envAny := map[string]any{}
		for k, v := range envMap {
			envAny[k] = v
		}
		if converted, err := toJSONMap(envAny); err == nil {
			envJSON = converted
		} else {
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode environment overrides").Err()
		}
	}
	infraCreated := false
	if v, ok := cfgAny["infraCreated"].(bool); ok {
		infraCreated = v
	}

	run := (*WorkspaceRunResponse)(nil)
	switch dep.Type {
	case "terraform":
		cloud, _ := cfgAny["cloud"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		cloud = strings.ToLower(strings.TrimSpace(cloud))
		if cloud == "" {
			cloud = "aws"
		}
		templateSource = strings.TrimSpace(templateSource)
		templateRepo = strings.TrimSpace(templateRepo)
		templatesDir = strings.TrimSpace(templatesDir)
		template = strings.TrimSpace(template)
		switch op {
		case "create":
			run, err = s.RunWorkspaceTerraformApply(ctx, id, &WorkspaceTerraformApplyParams{
				Confirm:        "true",
				Cloud:          cloud,
				Action:         "apply",
				TemplateSource: templateSource,
				TemplateRepo:   templateRepo,
				TemplatesDir:   templatesDir,
				Template:       template,
				DeploymentID:   dep.ID,
			})
		case "destroy":
			run, err = s.RunWorkspaceTerraformApply(ctx, id, &WorkspaceTerraformApplyParams{
				Confirm:        "true",
				Cloud:          cloud,
				Action:         "destroy",
				TemplateSource: templateSource,
				TemplateRepo:   templateRepo,
				TemplatesDir:   templatesDir,
				Template:       template,
				DeploymentID:   dep.ID,
			})
		default:
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unsupported terraform action (use create or destroy)").Err()
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
		if (op == "stop" || op == "export") && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab deployment must be created before stop/export").Err()
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
		case "export":
			netlabAction = "clab-tarball"
		case "destroy":
			netlabAction = "down"
			cleanup = true
		}

		run, err = s.RunWorkspaceNetlab(ctx, id, &WorkspaceNetlabRunRequest{
			Message:          message,
			GitBranch:        branch,
			Environment:      envJSON,
			Action:           netlabAction,
			Cleanup:          cleanup,
			NetlabServer:     netlabServer,
			NetlabMultilabID: dep.ID,
			NetlabDeployment: dep.Name,
			ClabCleanup:      false,
			TemplateSource:   strings.TrimSpace(templateSource),
			TemplateRepo:     strings.TrimSpace(templateRepo),
			TemplatesDir:     strings.TrimSpace(templatesDir),
			Template:         strings.TrimSpace(template),
		})
		if err != nil {
			return nil, err
		}
		case "netlab-c9s":
			netlabServer, _ := cfgAny["netlabServer"].(string)
			templateSource, _ := cfgAny["templateSource"].(string)
			templateRepo, _ := cfgAny["templateRepo"].(string)
			templatesDir, _ := cfgAny["templatesDir"].(string)
			template, _ := cfgAny["template"].(string)
			labName, _ := cfgAny["labName"].(string)
			k8sNamespace, _ := cfgAny["k8sNamespace"].(string)

			netlabServer = strings.TrimSpace(netlabServer)
			if strings.TrimSpace(template) == "" && op != "destroy" && op != "stop" {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab template is required").Err()
			}
		if op == "stop" && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab-c9s deployment must be created before stop").Err()
		}
		if strings.TrimSpace(labName) == "" {
			labName = containerlabLabName(pc.workspace.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
			cfgAny["k8sNamespace"] = k8sNamespace
		}
		cfgAny["topologyName"] = clabernetesTopologyName(labName)

		c9sAction := "deploy"
		switch op {
		case "create", "start":
			c9sAction = "deploy"
		case "stop", "destroy":
			c9sAction = "destroy"
		}

		run, err = s.runNetlabC9sDeploymentAction(
			ctx,
			pc,
			dep,
			envJSON,
			c9sAction,
			netlabServer,
			strings.TrimSpace(templateSource),
			strings.TrimSpace(templateRepo),
			strings.TrimSpace(templatesDir),
			strings.TrimSpace(template),
			strings.TrimSpace(labName),
			strings.TrimSpace(k8sNamespace),
		)
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
		eveUsername, _ := cfgAny["eveUsername"].(string)
		evePassword, _ := cfgAny["evePassword"].(string)
		evePasswordEnc, _ := cfgAny["evePasswordEnc"].(string)
		if strings.TrimSpace(evePassword) == "" && strings.TrimSpace(evePasswordEnc) != "" {
			if plaintext, err := decryptUserSecret(evePasswordEnc); err == nil {
				evePassword = plaintext
			}
		}

		eveServer = strings.TrimSpace(eveServer)
		if eveServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng server selection is required").Err()
		}
		if strings.TrimSpace(template) == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("labpp template is required").Err()
		}
		if op == "stop" && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("labpp deployment must be created before start/stop").Err()
		}
		labPath = strings.TrimSpace(labPath)
		if labPath == "" {
			labPath = labppLabPath(pc.claims.Username, dep.Name, template, time.Now())
		}
		labPath = labppNormalizeFolderPath(labPath)
		cfgAny["labPath"] = labPath

		labppAction := "e2e"
		switch op {
		case "create":
			labppAction = "upload"
		case "start":
			if !infraCreated {
				labppAction = "e2e"
			} else {
				labppAction = "start"
			}
		case "stop":
			labppAction = "stop"
		case "destroy":
			labppAction = "delete"
		}

		run, err = s.RunWorkspaceLabpp(ctx, id, &WorkspaceLabppRunRequest{
			Message:           strings.TrimSpace(fmt.Sprintf("Skyforge labpp run (%s)", pc.claims.Username)),
			Environment:       envJSON,
			Action:            labppAction,
			EveServer:         eveServer,
			EveUsername:       strings.TrimSpace(eveUsername),
			EvePassword:       strings.TrimSpace(evePassword),
			Template:          strings.TrimSpace(template),
			TemplatesRoot:     "",
			TemplateSource:    strings.TrimSpace(templateSource),
			TemplateRepo:      strings.TrimSpace(templateRepo),
			TemplatesDir:      strings.TrimSpace(templatesDir),
			TemplatesDestRoot: strings.TrimSpace(templatesDestRoot),
			LabPath:           labPath,
			ThreadCount:       int(threadCount),
			Deployment:        dep.Name,
			DeploymentID:      dep.ID,
		})
		if err != nil {
			return nil, err
		}
	case "containerlab":
		netlabServer, _ := cfgAny["netlabServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		labName, _ := cfgAny["labName"].(string)

		netlabServer = strings.TrimSpace(netlabServer)
		if netlabServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
		}
		if strings.TrimSpace(template) == "" && op != "destroy" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab template is required").Err()
		}
		if (op == "start" || op == "stop") && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("containerlab deployment must be created before start/stop").Err()
		}

		containerlabAction := "deploy"
		reconfigure := false
		switch op {
		case "create":
			containerlabAction = "deploy"
		case "start":
			containerlabAction = "deploy"
			reconfigure = true
		case "stop":
			containerlabAction = "destroy"
		case "destroy":
			containerlabAction = "destroy"
		}

		run, err = s.RunWorkspaceContainerlab(ctx, id, &WorkspaceContainerlabRunRequest{
			Message:        strings.TrimSpace(fmt.Sprintf("Skyforge containerlab run (%s)", pc.claims.Username)),
			Environment:    envJSON,
			Action:         containerlabAction,
			NetlabServer:   netlabServer,
			TemplateSource: strings.TrimSpace(templateSource),
			TemplateRepo:   strings.TrimSpace(templateRepo),
			TemplatesDir:   strings.TrimSpace(templatesDir),
			Template:       strings.TrimSpace(template),
			Deployment:     strings.TrimSpace(dep.Name),
			Reconfigure:    reconfigure,
		})
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(labName) == "" {
			cfgAny["labName"] = containerlabLabName(pc.workspace.Slug, dep.Name)
		}
	case "clabernetes":
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		labName, _ := cfgAny["labName"].(string)
		k8sNamespace, _ := cfgAny["k8sNamespace"].(string)

		if strings.TrimSpace(template) == "" && op != "destroy" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("clabernetes template is required").Err()
		}
		if (op == "start" || op == "stop") && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("clabernetes deployment must be created before start/stop").Err()
		}
		if strings.TrimSpace(labName) == "" {
			labName = containerlabLabName(pc.workspace.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
			cfgAny["k8sNamespace"] = k8sNamespace
		}

		clabernetesAction := "deploy"
		switch op {
		case "create", "start":
			clabernetesAction = "deploy"
		case "stop", "destroy":
			clabernetesAction = "destroy"
		}

		run, err = s.runClabernetesDeploymentAction(ctx, pc, dep, envJSON, clabernetesAction, strings.TrimSpace(templateSource), strings.TrimSpace(templateRepo), strings.TrimSpace(templatesDir), strings.TrimSpace(template), strings.TrimSpace(labName), strings.TrimSpace(k8sNamespace))
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
	updated, err := s.touchDeploymentFromRun(ctx, pc.workspace.ID, deploymentID, cfgJSON, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
		updated = dep
	}

	resp := &WorkspaceDeploymentActionResponse{WorkspaceID: pc.workspace.ID, Deployment: updated}
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

type netlabGraphAPIResponse struct {
	SVGBase64  string `json:"svgBase64"`
	OutputPath string `json:"outputPath,omitempty"`
}

func netlabAPIDo(ctx context.Context, url string, payload any, insecure bool, auth netlabAPIAuth) (*http.Response, []byte, error) {
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
	auth.apply(req)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
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

func netlabAPIGet(ctx context.Context, url string, insecure bool, auth netlabAPIAuth) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	auth.apply(req)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
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

// GetWorkspaceDeploymentInfo returns provider-specific info for a deployment.
// For Netlab deployments, this executes `netlab status` against the associated Netlab API and returns the output.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/info
func (s *Service) GetWorkspaceDeploymentInfo(ctx context.Context, id, deploymentID string) (*WorkspaceDeploymentInfoResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	resp := &WorkspaceDeploymentInfoResponse{
		WorkspaceID: pc.workspace.ID,
		Deployment:  dep,
		Provider:    dep.Type,
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
	}

	cfgAny, _ := fromJSONMap(dep.Config)
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
	if forwardNetworkID := getString(forwardNetworkIDKey); forwardNetworkID != "" {
		resp.ForwardID = forwardNetworkID
		if forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID); err == nil && forwardCfg != nil {
			baseURL := strings.TrimSpace(forwardCfg.BaseURL)
			if baseURL == "" {
				baseURL = defaultForwardBaseURL
			}
			if normalized, err := normalizeForwardBaseURL(baseURL); err == nil {
				baseURL = normalized
			}
			resp.ForwardURL = fmt.Sprintf("%s/?/networkId=%s", strings.TrimRight(baseURL, "/"), url.QueryEscape(forwardNetworkID))
		}
	}

	switch dep.Type {
	case "netlab":
		netlabServer := getString("netlabServer")
		templateSource := getString("templateSource")
		templatesDir := getString("templatesDir")
		template := getString("template")
		if netlabServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
		}

		server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, netlabServer)
		if err != nil {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
		}

		multilabID := dep.ID
		h := fnv.New32a()
		_, _ = h.Write([]byte(multilabID))
		multilabNumericID := int(h.Sum32()%199) + 1

		workspaceRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
		apiURL := strings.TrimSpace(server.APIURL)
		if apiURL == "" {
			apiURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", strings.TrimSpace(server.SSHHost)), "/")
		}
		if apiURL == "" {
			return nil, errs.B().Code(errs.Unavailable).Msg("netlab API URL is not configured").Err()
		}
		insecure := server.APIInsecure
		auth, err := s.netlabAPIAuthForUser(pc.claims.Username, *server)
		if err != nil {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
		}

		payload := map[string]any{
			"action":        "status",
			"user":          strings.TrimSpace(pc.claims.Username),
			"workspace":     strings.TrimSpace(pc.workspace.Slug),
			"deployment":    strings.TrimSpace(dep.Name),
			"workspaceRoot": workspaceRoot,
			"plugin":        "multilab",
			"multilabId":    strconv.Itoa(multilabNumericID),
			"instance":      strconv.Itoa(multilabNumericID),
			"stateRoot":     strings.TrimSpace(server.StateRoot),
		}
		if _, _, _, topologyPath := normalizeNetlabTemplateSelectionWithSource(templateSource, templatesDir, template); strings.TrimSpace(topologyPath) != "" {
			payload["topologyPath"] = strings.TrimSpace(topologyPath)
		}

		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		postResp, body, err := netlabAPIDo(ctx, apiURL+"/jobs", payload, insecure, auth)
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
			getResp, getBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s", apiURL, job.ID), insecure, auth)
			if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
				_ = json.Unmarshal(getBody, &job)
			}
			logResp, logBody, err := netlabAPIGet(ctx, fmt.Sprintf("%s/jobs/%s/log", apiURL, job.ID), insecure, auth)
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
		eveServerRef, _ := cfgAny["eveServer"].(string)
		eveServerRef = strings.TrimSpace(eveServerRef)
		if eveServerRef == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng server selection is required").Err()
		}
		resolvedEve, err := s.resolveWorkspaceEveServerConfig(ctx, pc.workspace.ID, eveServerRef)
		if err != nil {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
		}
		eveServer := &resolvedEve.Server

		labPath, _ := cfgAny["labPath"].(string)
		labPath = strings.TrimSpace(labPath)
		if labPath == "" && template != "" {
			labPath = labppLabPath(pc.claims.Username, dep.Name, template, time.Now())
		}
		labPath = labppNormalizeFolderPath(labPath)
		if labPath == "" {
			resp.Note = "lab path is not configured yet"
			return resp, nil
		}
		labFilePath := labppLabFilePath(labPath, template)

		base := strings.TrimRight(strings.TrimSpace(eveServer.APIURL), "/")
		if base == "" {
			base = strings.TrimRight(strings.TrimSpace(eveServer.WebURL), "/")
		}
		if base == "" {
			resp.Note = "eve server is missing apiUrl/webUrl"
			resp.Labpp = &LabppInfo{EveServer: eveServerRef, LabPath: labFilePath}
			return resp, nil
		}

		username := strings.TrimSpace(pc.claims.Username)
		password, ok := getCachedLDAPPassword(s.db, pc.claims.Username)
		if username == "" || !ok || strings.TrimSpace(password) == "" {
			resp.Note = "EVE password unavailable; reauthenticate to check lab status"
			resp.Labpp = &LabppInfo{EveServer: eveServerRef, EveURL: base, LabPath: labFilePath}
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
			resp.Labpp = &LabppInfo{EveServer: eveServerRef, EveURL: base, LabPath: labPath}
			return resp, nil
		}

		hasRunning, endpoint, err := eveLabHasRunningNodes(checkCtx, client, base, username, labFilePath)
		if err != nil {
			resp.Note = sanitizeError(err)
			resp.Status = "error"
		} else if hasRunning {
			resp.Status = "running"
		} else {
			resp.Status = "stopped"
		}

		labppInfo := &LabppInfo{EveServer: eveServerRef, EveURL: base, LabPath: labFilePath, Endpoint: endpoint}
		if task, err := getLatestDeploymentTask(ctx, s.db, pc.workspace.ID, dep.ID, "labpp-run"); err == nil && task != nil {
			if key := strings.TrimSpace(getJSONMapString(task.Metadata, "labppDataSourcesKey")); key != "" {
				labppInfo.DataSourcesCSV = key
			} else {
				labppInfo.DataSourcesCSV = strings.TrimSpace(getJSONMapString(task.Metadata, "labppDataSourcesCsv"))
			}
		}
		resp.Labpp = labppInfo
		return resp, nil
	case "terraform":
		stateKey := strings.TrimSpace(pc.workspace.TerraformStateKey)
		if stateKey == "" {
			resp.Note = "terraform state key is not configured"
			return resp, nil
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		stateBytes, err := getTerraformStateObject(ctx, s.cfg, "terraform-state", stateKey)
		if err != nil {
			resp.Note = "failed to load terraform state"
			return resp, nil
		}
		var state terraformState
		if err := json.Unmarshal(stateBytes, &state); err != nil {
			resp.Note = "terraform state could not be parsed"
			return resp, nil
		}
		resp.Log = formatTerraformOutputs(state.Outputs)
		return resp, nil
	case "containerlab":
		netlabServer, _ := cfgAny["netlabServer"].(string)
		netlabServer = strings.TrimSpace(netlabServer)
		if netlabServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
		}
		server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, netlabServer)
		if err != nil {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
		}
		apiURL := containerlabAPIURL(s.cfg, *server)
		if apiURL == "" {
			return nil, errs.B().Code(errs.Unavailable).Msg("containerlab api url is not configured").Err()
		}
		labName, _ := cfgAny["labName"].(string)
		labName = strings.TrimSpace(labName)
		if labName == "" {
			labName = containerlabLabName(pc.workspace.Slug, dep.Name)
		}
		resp.Containerlab = &ContainerlabInfo{LabName: labName, APIURL: apiURL}

		token, err := containerlabTokenForUser(s.cfg, pc.claims.Username)
		if err != nil {
			resp.Note = "containerlab auth is not configured"
			resp.Status = "error"
			return resp, nil
		}
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		getResp, body, err := containerlabAPIGet(checkCtx, fmt.Sprintf("%s/api/v1/labs/%s", apiURL, labName), token, containerlabSkipTLS(s.cfg, *server))
		if err != nil {
			resp.Note = "failed to reach containerlab api"
			resp.Status = "error"
			return resp, nil
		}
		if getResp.StatusCode == http.StatusNotFound {
			resp.Status = "not_found"
			resp.Note = "lab not found"
			return resp, nil
		}
		if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
			resp.Status = "error"
			resp.Note = strings.TrimSpace(string(body))
			return resp, nil
		}
		resp.Status = "ok"
		if len(body) > 0 {
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, body, "", "  "); err == nil {
				resp.Log = pretty.String()
			} else {
				resp.Log = string(body)
			}
		}
		return resp, nil
	case "clabernetes", "netlab-c9s":
		labName := strings.TrimSpace(getString("labName"))
		if labName == "" {
			labName = containerlabLabName(pc.workspace.Slug, dep.Name)
		}
		k8sNamespace := strings.TrimSpace(getString("k8sNamespace"))
		if k8sNamespace == "" {
			k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
		}
		topologyName := strings.TrimSpace(getString("topologyName"))
		if topologyName == "" {
			topologyName = clabernetesTopologyName(labName)
		}

		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		topo, status, err := kubeGetClabernetesTopology(checkCtx, k8sNamespace, topologyName)
		if err != nil {
			resp.Note = sanitizeError(err)
			resp.Status = "error"
		} else if topo == nil && status == http.StatusNotFound {
			resp.Status = "not_found"
			resp.Note = "topology not found"
		} else if topo != nil && topo.Status.TopologyReady {
			resp.Status = "ready"
		} else {
			resp.Status = "pending"
		}

		clab := &ClabernetesInfo{
			Namespace:    k8sNamespace,
			TopologyName: topologyName,
			LabName:      labName,
		}
		if topo != nil {
			clab.Ready = topo.Status.TopologyReady
		}
		if dep.Type == "netlab-c9s" {
			if n, err := kubeCountConfigMapsByLabel(checkCtx, k8sNamespace, map[string]string{
				"skyforge-c9s-topology": topologyName,
			}); err == nil {
				clab.ConfigMaps = n
			}
		}
		resp.Clabernetes = clab
		return resp, nil
	default:
		resp.Note = "info is not yet supported for this deployment type"
		return resp, nil
	}
}

// SyncWorkspaceDeploymentForward triggers a Forward Networks sync for a deployment.
// Currently supported for LabPP deployments.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/forward-sync
func (s *Service) SyncWorkspaceDeploymentForward(ctx context.Context, id, deploymentID string) (*WorkspaceDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if dep == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	if dep.Type != "labpp" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("forward sync is only supported for labpp deployments").Err()
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil {
		return nil, err
	}
	if forwardCfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("forward networks is not configured").Err()
	}
	task, err := getLatestDeploymentTask(ctx, s.db, pc.workspace.ID, dep.ID, "labpp-run")
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("no labpp run metadata found").Err()
	}
	csvPath := strings.TrimSpace(getJSONMapString(task.Metadata, "labppDataSourcesCsv"))
	csvKey := strings.TrimSpace(getJSONMapString(task.Metadata, "labppDataSourcesKey"))
	if csvPath == "" && csvKey == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("labpp data sources file not found").Err()
	}

	if csvKey != "" {
		ctxDL, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		obj := artifactObjectName(pc.workspace.ID, csvKey)
		resp, err := storage.Read(ctxDL, &storage.ReadRequest{ObjectName: obj})
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to download labpp data sources").Err()
		}
		tmp, err := os.CreateTemp("", "skyforge-labpp-data-sources-*.csv")
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to stage labpp data sources").Err()
		}
		tmpPath := tmp.Name()
		_, _ = tmp.Write(resp.Data)
		_ = tmp.Close()
		defer func() { _ = os.Remove(tmpPath) }()
		csvPath = tmpPath
	}

	syncCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.syncForwardLabppDevicesFromCSV(syncCtx, 0, pc, dep.ID, csvPath, true, nil); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg(err.Error()).Err()
	}
	return &WorkspaceDeploymentActionResponse{
		WorkspaceID: pc.workspace.ID,
		Deployment:  dep,
	}, nil
}

// DownloadLabppDataSourcesCSV returns the generated LabPP `data_sources.csv` for a deployment.
//
// The CSV is created by the LabPP runner and stored in Skyforge object storage; Skyforge serves it
// back to the user as a base64 payload for easy browser download (legacy file-backed paths are still supported).
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/labpp/data-sources.csv
func (s *Service) DownloadLabppDataSourcesCSV(ctx context.Context, id, deploymentID string) (*LabppDataSourcesDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if dep == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	if dep.Type != "labpp" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("data sources csv is only available for labpp deployments").Err()
	}
	task, err := getLatestDeploymentTask(ctx, s.db, pc.workspace.ID, dep.ID, "labpp-run")
	if err != nil {
		return nil, err
	}
	if task == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("no labpp run metadata found").Err()
	}
	csvKey := strings.TrimSpace(getJSONMapString(task.Metadata, "labppDataSourcesKey"))
	if csvKey == "" {
		return nil, errs.B().Code(errs.NotFound).Msg("labpp data sources file not available (rerun LabPP to regenerate)").Err()
	}

	obj := artifactObjectName(pc.workspace.ID, csvKey)
	resp, err := storage.Read(ctx, &storage.ReadRequest{ObjectName: obj})
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("labpp data sources file not found").Err()
	}
	data := resp.Data
	// Keep responses small and predictable; this file is expected to be tiny.
	if len(data) > 2<<20 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("csv too large").Err()
	}

	return &LabppDataSourcesDownloadResponse{
		Status:   "ok",
		Filename: "data_sources.csv",
		FileData: base64.StdEncoding.EncodeToString(data),
	}, nil
}

// NetlabConnect executes `netlab connect` on the Netlab runner host and returns its output.
//
// This is an alternative to local SSH ProxyJump when clients can't reach the lab network.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/netlab/connect
func (s *Service) NetlabConnect(ctx context.Context, id, deploymentID string, req *NetlabConnectRequest) (*NetlabConnectResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	node := strings.TrimSpace(req.Node)
	if node == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("node is required").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if dep.Type != "netlab" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("connect is only available for netlab deployments").Err()
	}

	cfgAny, _ := fromJSONMap(dep.Config)
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

	netlabServer := getString("netlabServer")
	templateSource := getString("templateSource")
	templatesDir := getString("templatesDir")
	template := getString("template")
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}
	server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, netlabServer)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	multilabID := dep.ID
	h := fnv.New32a()
	_, _ = h.Write([]byte(multilabID))
	multilabNumericID := int(h.Sum32()%199) + 1

	workspaceRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
	apiURL := strings.TrimSpace(server.APIURL)
	if apiURL == "" {
		apiURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", strings.TrimSpace(server.SSHHost)), "/")
	}
	if apiURL == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab API URL is not configured").Err()
	}
	insecure := server.APIInsecure
	auth, err := s.netlabAPIAuthForUser(pc.claims.Username, *server)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	payload := map[string]any{
		"user":          strings.TrimSpace(pc.claims.Username),
		"workspace":     strings.TrimSpace(pc.workspace.Slug),
		"deployment":    strings.TrimSpace(dep.Name),
		"workspaceRoot": workspaceRoot,
		"plugin":        "multilab",
		"multilabId":    strconv.Itoa(multilabNumericID),
		"instance":      strconv.Itoa(multilabNumericID),
		"stateRoot":     strings.TrimSpace(server.StateRoot),
		"node":          node,
	}
	if req.Show != nil {
		payload["show"] = req.Show
	}
	if _, _, _, topologyPath := normalizeNetlabTemplateSelectionWithSource(templateSource, templatesDir, template); strings.TrimSpace(topologyPath) != "" {
		payload["topologyPath"] = strings.TrimSpace(topologyPath)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	postResp, body, err := netlabAPIDo(ctx, apiURL+"/connect", payload, insecure, auth)
	if err != nil {
		log.Printf("netlab connect: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach netlab API").Err()
	}
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("netlab API rejected request: %s", strings.TrimSpace(string(body)))).Err()
	}
	var lr netlabAPILog
	if err := json.Unmarshal(body, &lr); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab API returned invalid response").Err()
	}
	return &NetlabConnectResponse{Output: lr.Log}, nil
}

// GetWorkspaceDeploymentNetlabGraph returns a rendered netlab topology graph for a deployment.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/netlab-graph
func (s *Service) GetWorkspaceDeploymentNetlabGraph(ctx context.Context, id, deploymentID string) (*NetlabGraphResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if dep.Type != "netlab" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("graph is only available for netlab deployments").Err()
	}

	cfgAny, _ := fromJSONMap(dep.Config)
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

	netlabServer := getString("netlabServer")
	templateSource := getString("templateSource")
	templatesDir := getString("templatesDir")
	template := getString("template")
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}

	server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, netlabServer)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	multilabID := dep.ID
	h := fnv.New32a()
	_, _ = h.Write([]byte(multilabID))
	multilabNumericID := int(h.Sum32()%199) + 1

	workspaceRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
	apiURL := strings.TrimSpace(server.APIURL)
	if apiURL == "" {
		apiURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", strings.TrimSpace(server.SSHHost)), "/")
	}
	if apiURL == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab API URL is not configured").Err()
	}
	insecure := server.APIInsecure
	auth, err := s.netlabAPIAuthForUser(pc.claims.Username, *server)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}
	payload := map[string]any{
		"user":          strings.TrimSpace(pc.claims.Username),
		"workspace":     strings.TrimSpace(pc.workspace.Slug),
		"deployment":    strings.TrimSpace(dep.Name),
		"workspaceRoot": workspaceRoot,
		"plugin":        "multilab",
		"multilabId":    strconv.Itoa(multilabNumericID),
		"instance":      strconv.Itoa(multilabNumericID),
		"stateRoot":     strings.TrimSpace(server.StateRoot),
	}
	if _, _, _, topologyPath := normalizeNetlabTemplateSelectionWithSource(templateSource, templatesDir, template); strings.TrimSpace(topologyPath) != "" {
		payload["topologyPath"] = strings.TrimSpace(topologyPath)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	postResp, body, err := netlabAPIDo(ctx, apiURL+"/graph", payload, insecure, auth)
	if err != nil {
		log.Printf("netlab graph: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach netlab API").Err()
	}
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg(fmt.Sprintf("netlab API rejected request: %s", strings.TrimSpace(string(body)))).Err()
	}

	var graph netlabGraphAPIResponse
	if err := json.Unmarshal(body, &graph); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab graph returned invalid response").Err()
	}
	if strings.TrimSpace(graph.SVGBase64) == "" {
		return nil, errs.B().Code(errs.Unavailable).Msg("netlab graph returned empty output").Err()
	}

	return &NetlabGraphResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SVG:         graph.SVGBase64,
		OutputPath:  graph.OutputPath,
	}, nil
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

func formatTerraformOutputs(outputs map[string]terraformStateOutput) string {
	if len(outputs) == 0 {
		return "No terraform outputs found in state."
	}
	keys := make([]string, 0, len(outputs))
	for key := range outputs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		out := outputs[key]
		value := "<unknown>"
		if out.Sensitive {
			value = "<sensitive>"
		} else if out.Value == nil {
			value = "null"
		} else if raw, err := json.Marshal(out.Value); err == nil {
			value = string(raw)
		} else {
			value = fmt.Sprint(out.Value)
		}
		lines = append(lines, fmt.Sprintf("%s = %s", key, value))
	}
	return strings.Join(lines, "\n")
}

// StartWorkspaceDeployment starts a deployment run.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/start
func (s *Service) StartWorkspaceDeployment(ctx context.Context, id, deploymentID string, req *WorkspaceDeploymentStartRequest) (*WorkspaceDeploymentActionResponse, error) {
	return s.runDeployment(ctx, id, deploymentID, req, "start")
}

// DestroyWorkspaceDeployment triggers a destructive run (destroy) for a deployment.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/destroy
func (s *Service) DestroyWorkspaceDeployment(ctx context.Context, id, deploymentID string) (*WorkspaceDeploymentActionResponse, error) {
	return s.runDeployment(ctx, id, deploymentID, &WorkspaceDeploymentStartRequest{Action: "destroy"}, "destroy")
}

// StopWorkspaceDeployment attempts to stop the most recent task for this deployment.
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments/:deploymentID/stop
func (s *Service) StopWorkspaceDeployment(ctx context.Context, id, deploymentID string) (*WorkspaceDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	var task *TaskRecord
	if active, err := getActiveDeploymentTask(ctx, s.db, pc.workspace.ID, dep.ID); err == nil && active != nil {
		task = active
	} else if dep.LastTaskID != nil {
		if rec, err := getTask(ctx, s.db, *dep.LastTaskID); err == nil {
			task = rec
		}
	}
	if task == nil {
		return &WorkspaceDeploymentActionResponse{WorkspaceID: pc.workspace.ID, Deployment: dep}, nil
	}
	if err := cancelTask(ctx, s.db, task.ID); err != nil {
		log.Printf("deployment stop: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to cancel task").Err()
	}
	_, _ = taskqueue.CancelTopic.Publish(ctx, &taskqueue.TaskCancelEvent{TaskID: task.ID})
	now := time.Now().UTC()
	if err := s.updateDeploymentStatus(ctx, pc.workspace.ID, dep.ID, "canceled", &now); err != nil {
		log.Printf("deployment stop update: %v", err)
	}
	return &WorkspaceDeploymentActionResponse{WorkspaceID: pc.workspace.ID, Deployment: dep}, nil
}

func (s *Service) runDeployment(ctx context.Context, id, deploymentID string, req *WorkspaceDeploymentStartRequest, mode string) (*WorkspaceDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	envMap, err := s.mergeDeploymentEnvironment(ctx, pc.workspace.ID, cfgAny)
	if err != nil {
		return nil, err
	}
	envJSON := JSONMap{}
	if len(envMap) > 0 {
		envAny := map[string]any{}
		for k, v := range envMap {
			envAny[k] = v
		}
		if converted, err := toJSONMap(envAny); err == nil {
			envJSON = converted
		} else {
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode environment overrides").Err()
		}
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = "apply"
	}
	if mode == "destroy" {
		action = "destroy"
	}

	var run *WorkspaceRunResponse
	cfgOut := dep.Config

	switch dep.Type {
	case "terraform":
		cloud, _ := cfgAny["cloud"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		cloud = strings.ToLower(strings.TrimSpace(cloud))
		if cloud == "" {
			cloud = "aws"
		}
		run, err = s.RunWorkspaceTerraformApply(ctx, id, &WorkspaceTerraformApplyParams{
			Confirm:        "true",
			Cloud:          cloud,
			Action:         action,
			TemplateSource: strings.TrimSpace(templateSource),
			TemplateRepo:   strings.TrimSpace(templateRepo),
			TemplatesDir:   strings.TrimSpace(templatesDir),
			Template:       strings.TrimSpace(template),
			DeploymentID:   dep.ID,
		})
		if err != nil {
			return nil, err
		}
	case "netlab":
		branch, _ := cfgAny["gitBranch"].(string)
		message, _ := cfgAny["message"].(string)
		netlabServer, _ := cfgAny["netlabServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		netlabAction := "up"
		cleanup := false
		if mode == "destroy" {
			netlabAction = "down"
			cleanup = true
		}
		run, err = s.RunWorkspaceNetlab(ctx, id, &WorkspaceNetlabRunRequest{
			Message:          message,
			GitBranch:        branch,
			Environment:      envJSON,
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
	case "netlab-c9s":
		netlabServer, _ := cfgAny["netlabServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		labName, _ := cfgAny["labName"].(string)
		k8sNamespace, _ := cfgAny["k8sNamespace"].(string)

		netlabServer = strings.TrimSpace(netlabServer)
		generatorMode := strings.ToLower(strings.TrimSpace(s.cfg.NetlabC9sGeneratorMode))
		if generatorMode == "" {
			generatorMode = "k8s"
		}
		// Skyforge is moving away from BYOS netlab runners for netlab-c9s; treat "remote" as legacy
		// and default to the in-cluster generator.
		if generatorMode == "remote" {
			generatorMode = "k8s"
		}
		if generatorMode == "remote" {
			if netlabServer == "" {
				return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
			}
		} else {
			// Cluster-native netlab-c9s mode: treat missing netlabServer as "k8s".
			if netlabServer == "" {
				netlabServer = "k8s"
				cfgAny["netlabServer"] = netlabServer
			}
		}
		if strings.TrimSpace(template) == "" && mode != "destroy" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab template is required").Err()
		}
		if strings.TrimSpace(labName) == "" {
			labName = containerlabLabName(pc.workspace.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
			cfgAny["k8sNamespace"] = k8sNamespace
		}
		cfgAny["topologyName"] = clabernetesTopologyName(labName)

		c9sAction := "deploy"
		if mode == "destroy" {
			c9sAction = "destroy"
			cfgAny["infraCreated"] = false
		} else {
			cfgAny["infraCreated"] = true
		}

		run, err = s.runNetlabC9sDeploymentAction(
			ctx,
			pc,
			dep,
			envJSON,
			c9sAction,
			netlabServer,
			strings.TrimSpace(templateSource),
			strings.TrimSpace(templateRepo),
			strings.TrimSpace(templatesDir),
			strings.TrimSpace(template),
			strings.TrimSpace(labName),
			strings.TrimSpace(k8sNamespace),
		)
		if err != nil {
			return nil, err
		}
		if next, err := toJSONMap(cfgAny); err == nil {
			cfgOut = next
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
		eveUsername, _ := cfgAny["eveUsername"].(string)
		evePassword, _ := cfgAny["evePassword"].(string)
		evePasswordEnc, _ := cfgAny["evePasswordEnc"].(string)
		if strings.TrimSpace(evePassword) == "" && strings.TrimSpace(evePasswordEnc) != "" {
			if plaintext, err := decryptUserSecret(evePasswordEnc); err == nil {
				evePassword = plaintext
			}
		}

		labppAction := "e2e"
		switch mode {
		case "destroy":
			labppAction = "delete"
		case "start":
			labppAction = "e2e"
		}

		run, err = s.RunWorkspaceLabpp(ctx, id, &WorkspaceLabppRunRequest{
			Message:           strings.TrimSpace(fmt.Sprintf("Skyforge labpp run (%s)", pc.claims.Username)),
			Environment:       envJSON,
			Action:            labppAction,
			EveServer:         strings.TrimSpace(eveServer),
			EveUsername:       strings.TrimSpace(eveUsername),
			EvePassword:       strings.TrimSpace(evePassword),
			Template:          strings.TrimSpace(template),
			TemplatesRoot:     "",
			TemplateSource:    strings.TrimSpace(templateSource),
			TemplateRepo:      strings.TrimSpace(templateRepo),
			TemplatesDir:      strings.TrimSpace(templatesDir),
			TemplatesDestRoot: strings.TrimSpace(templatesDestRoot),
			LabPath:           strings.TrimSpace(labPath),
			ThreadCount:       int(threadCount),
			Deployment:        dep.Name,
			DeploymentID:      dep.ID,
		})
		if err != nil {
			return nil, err
		}
	case "containerlab":
		netlabServer, _ := cfgAny["netlabServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		labName, _ := cfgAny["labName"].(string)
		containerlabAction := "deploy"
		reconfigure := false
		if mode == "destroy" {
			containerlabAction = "destroy"
		}
		if mode == "start" {
			reconfigure = true
		}
		run, err = s.RunWorkspaceContainerlab(ctx, id, &WorkspaceContainerlabRunRequest{
			Message:        strings.TrimSpace(fmt.Sprintf("Skyforge containerlab run (%s)", pc.claims.Username)),
			Environment:    envJSON,
			Action:         containerlabAction,
			NetlabServer:   strings.TrimSpace(netlabServer),
			TemplateSource: strings.TrimSpace(templateSource),
			TemplateRepo:   strings.TrimSpace(templateRepo),
			TemplatesDir:   strings.TrimSpace(templatesDir),
			Template:       strings.TrimSpace(template),
			Deployment:     strings.TrimSpace(dep.Name),
			Reconfigure:    reconfigure,
		})
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(labName) == "" {
			cfgAny["labName"] = containerlabLabName(pc.workspace.Slug, dep.Name)
		}
	case "clabernetes":
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		labName, _ := cfgAny["labName"].(string)
		k8sNamespace, _ := cfgAny["k8sNamespace"].(string)

		if strings.TrimSpace(template) == "" && mode != "destroy" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("clabernetes template is required").Err()
		}
		if strings.TrimSpace(labName) == "" {
			labName = containerlabLabName(pc.workspace.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
			cfgAny["k8sNamespace"] = k8sNamespace
		}

		clabernetesAction := "deploy"
		if mode == "destroy" {
			clabernetesAction = "destroy"
			cfgAny["infraCreated"] = false
		} else {
			cfgAny["infraCreated"] = true
		}

		run, err = s.runClabernetesDeploymentAction(
			ctx,
			pc,
			dep,
			envJSON,
			clabernetesAction,
			strings.TrimSpace(templateSource),
			strings.TrimSpace(templateRepo),
			strings.TrimSpace(templatesDir),
			strings.TrimSpace(template),
			strings.TrimSpace(labName),
			strings.TrimSpace(k8sNamespace),
		)
		if err != nil {
			return nil, err
		}
		if next, err := toJSONMap(cfgAny); err == nil {
			cfgOut = next
		}
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown deployment type").Err()
	}

	updated, err := s.touchDeploymentFromRun(ctx, pc.workspace.ID, deploymentID, cfgOut, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
	}

	resp := &WorkspaceDeploymentActionResponse{WorkspaceID: pc.workspace.ID, Deployment: updated}
	if run != nil {
		resp.Run = run.Task
	}
	return resp, nil
}

func (s *Service) touchDeploymentFromRun(ctx context.Context, workspaceID, deploymentID string, cfg JSONMap, run *WorkspaceRunResponse) (*WorkspaceDeployment, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	taskWorkspaceID := 0
	taskID := 0
	status := ""
	if run != nil {
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
  last_task_workspace_id=$2,
  last_task_id=$3,
  last_status=$4,
  last_started_at=now(),
  updated_at=now()
WHERE workspace_id=$5 AND id=$6`, cfgBytes, nullIfZeroInt(taskWorkspaceID), nullIfZeroInt(taskID), nullIfEmpty(status), workspaceID, deploymentID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update deployment").Err()
	}
	return s.getWorkspaceDeployment(ctx, workspaceID, deploymentID)
}

func (s *Service) updateDeploymentStatus(ctx context.Context, workspaceID, deploymentID string, status string, finishedAt *time.Time) error {
	if s == nil || s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if finishedAt != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  last_finished_at=$2,
  updated_at=now()
WHERE workspace_id=$3 AND id=$4`, status, *finishedAt, workspaceID, deploymentID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  last_status=$1,
  updated_at=now()
WHERE workspace_id=$2 AND id=$3`, status, workspaceID, deploymentID)
	return err
}

func (s *Service) getLatestDeploymentByType(ctx context.Context, workspaceID, depType string) (*WorkspaceDeployment, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var deploymentID string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM sf_deployments WHERE workspace_id=$1 AND type=$2 ORDER BY updated_at DESC LIMIT 1`, workspaceID, depType).Scan(&deploymentID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return s.getWorkspaceDeployment(ctx, workspaceID, deploymentID)
}

func nullIfZeroInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func (s *Service) getWorkspaceDeployment(ctx context.Context, workspaceID, deploymentID string) (*WorkspaceDeployment, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		rec                 WorkspaceDeployment
		raw                 json.RawMessage
		lastTaskWorkspaceID sql.NullInt64
		lastTaskID          sql.NullInt64
		lastStatus          sql.NullString
		lastStarted         sql.NullTime
		lastFinished        sql.NullTime
		createdAt           time.Time
		updatedAt           time.Time
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_workspace_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE workspace_id=$1 AND id=$2`, workspaceID, deploymentID).Scan(
		&rec.ID,
		&rec.Name,
		&rec.Type,
		&raw,
		&rec.CreatedBy,
		&createdAt,
		&updatedAt,
		&lastTaskWorkspaceID,
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
	rec.WorkspaceID = workspaceID
	rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	{
		qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		summary, err := getDeploymentQueueSummary(qctx, s.db, workspaceID, rec.ID)
		cancel()
		if err == nil && summary != nil {
			if summary.ActiveTaskID > 0 {
				rec.ActiveTaskID = &summary.ActiveTaskID
			}
			if strings.TrimSpace(summary.ActiveTaskStatus) != "" {
				status := strings.TrimSpace(summary.ActiveTaskStatus)
				rec.ActiveTaskStatus = &status
			}
			rec.QueueDepth = &summary.QueueDepth
		}
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &rec.Config)
	}
	if rec.Config == nil {
		rec.Config = JSONMap{}
	}
	if lastTaskWorkspaceID.Valid {
		v := int(lastTaskWorkspaceID.Int64)
		rec.LastTaskWorkspaceID = &v
	}
	if lastTaskID.Valid {
		v := int(lastTaskID.Int64)
		rec.LastTaskID = &v
	}
	if lastStatus.Valid {
		v := lastStatus.String
		rec.LastStatus = &v
	} else {
		v := "created"
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
