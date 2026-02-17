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
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskqueue"
	"encore.app/internal/taskstore"
	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

var deploymentNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type UserDeployment struct {
	ID               string  `json:"id"`
	OwnerUsername    string  `json:"ownerUsername"`
	Name             string  `json:"name"`
	Type             string  `json:"type"`
	Config           JSONMap `json:"config"`
	CreatedBy        string  `json:"createdBy"`
	CreatedAt        string  `json:"createdAt"`
	UpdatedAt        string  `json:"updatedAt"`
	LastTaskOwnerID  *int    `json:"lastTaskOwnerId,omitempty"`
	LastTaskID       *int    `json:"lastTaskId,omitempty"`
	LastStatus       *string `json:"lastStatus,omitempty"`
	LastStartedAt    *string `json:"lastStartedAt,omitempty"`
	LastFinishedAt   *string `json:"lastFinishedAt,omitempty"`
	ActiveTaskID     *int    `json:"activeTaskId,omitempty"`
	ActiveTaskStatus *string `json:"activeTaskStatus,omitempty"`
	QueueDepth       *int    `json:"queueDepth,omitempty"`
}

type UserDeploymentListResponse struct {
	OwnerUsername string            `json:"ownerUsername"`
	Deployments   []*UserDeployment `json:"deployments"`
}

type UserDeploymentCreateRequest struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	Config JSONMap `json:"config,omitempty"`
}

type UserDeploymentUpdateRequest struct {
	Name   string  `json:"name,omitempty"`
	Config JSONMap `json:"config,omitempty"`
}

type UserDeploymentActionResponse struct {
	OwnerUsername string          `json:"ownerUsername"`
	Deployment    *UserDeployment `json:"deployment"`
	Run           JSONMap         `json:"run,omitempty"`
}

type UserDeploymentDeleteRequest struct {
	ForwardDelete bool `query:"forward_delete" encore:"optional"`
	// Alternate casing used by some UI clients.
	ForwardDeleteCamel bool `query:"forwardDelete" encore:"optional"`
}

type UserDeploymentInfoResponse struct {
	OwnerUsername string            `json:"ownerUsername"`
	Deployment    *UserDeployment   `json:"deployment"`
	Provider      string            `json:"provider"`
	RetrievedAt   string            `json:"retrievedAt"`
	Status        string            `json:"status,omitempty"`
	Log           string            `json:"log,omitempty"`
	Note          string            `json:"note,omitempty"`
	ForwardID     string            `json:"forwardNetworkId,omitempty"`
	ForwardURL    string            `json:"forwardSnapshotUrl,omitempty"`
	Netlab        *NetlabInfo       `json:"netlab,omitempty"`
	Containerlab  *ContainerlabInfo `json:"containerlab,omitempty"`
	Clabernetes   *ClabernetesInfo  `json:"clabernetes,omitempty"`
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
	case "terraform", "netlab", "netlab-c9s", "containerlab", "clabernetes":
		return t, nil
	case "eve-ng", "eve_ng":
		return "eve_ng", nil
	default:
		return "", errs.B().Code(errs.InvalidArgument).Msg("deployment type must be terraform, netlab, netlab-c9s, eve_ng, containerlab, or clabernetes").Err()
	}
}

// ListUserDeployments lists deployment definitions for a user context.
func (s *Service) ListUserDeployments(ctx context.Context, id string) (*UserDeploymentListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_owner_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE owner_username=$1
ORDER BY updated_at DESC`, pc.context.ID)
	if err != nil {
		log.Printf("deployments list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to query deployments").Err()
	}
	defer rows.Close()

	out := make([]*UserDeployment, 0, 16)
	refresh := make([]*UserDeployment, 0, 4)
	for rows.Next() {
		var (
			rec             UserDeployment
			raw             json.RawMessage
			lastTaskOwnerID sql.NullInt64
			lastTaskID      sql.NullInt64
			lastStatus      sql.NullString
			lastStarted     sql.NullTime
			lastFinished    sql.NullTime
			createdAt       time.Time
			updatedAt       time.Time
		)
		if err := rows.Scan(
			&rec.ID,
			&rec.Name,
			&rec.Type,
			&raw,
			&rec.CreatedBy,
			&createdAt,
			&updatedAt,
			&lastTaskOwnerID,
			&lastTaskID,
			&lastStatus,
			&lastStarted,
			&lastFinished,
		); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode deployments").Err()
		}
		if normalized, err := normalizeDeploymentType(rec.Type); err == nil {
			rec.Type = normalized
		}
		rec.OwnerUsername = pc.context.ID
		rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		{
			qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			summary, err := getDeploymentQueueSummary(qctx, s.db, pc.context.ID, rec.ID)
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
		if lastTaskOwnerID.Valid {
			v := int(lastTaskOwnerID.Int64)
			rec.LastTaskOwnerID = &v
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
			if err := s.updateDeploymentStatus(ctx, pc.context.ID, dep.ID, status, finishedAt); err != nil {
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

	return &UserDeploymentListResponse{OwnerUsername: pc.context.ID, Deployments: out}, nil
}

// CreateUserDeployment creates a deployment definition for a user context.
func (s *Service) CreateUserDeployment(ctx context.Context, id string, req *UserDeploymentCreateRequest) (*UserDeployment, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	// Governance guardrails (admin-configurable).
	if policy, err := loadGovernancePolicy(ctx, s.db); err == nil {
		if err := enforceGovernanceDeploymentCreate(ctx, s.db, user.Username, policy); err != nil {
			return nil, err
		}
	} else {
		log.Printf("governance policy load failed (ignored): %v", err)
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
		templateSource := canonicalTemplateSource(getString("templateSource"), "user")
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
			switch templateSource {
			case "blueprints", "blueprint", "external", "custom":
				templatesDir = "terraform"
			default:
				templatesDir = "blueprints/terraform"
			}
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
		templateSource := canonicalTemplateSource(getString("templateSource"), "blueprints")
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
	case "netlab-c9s":
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := canonicalTemplateSource(getString("templateSource"), "blueprints")
		templateRepo := strings.TrimSpace(getString("templateRepo"))
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		if templateSource == "custom" && templateRepo == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		templatesDir = normalizeNetlabTemplatesDir(templateSource, templatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		cfgAny["templateSource"] = templateSource
		if templateRepo != "" {
			cfgAny["templateRepo"] = templateRepo
		}
		cfgAny["templatesDir"] = templatesDir
		cfgAny["template"] = template
		cfgAny["labName"] = containerlabLabName(pc.context.Slug, name)
	case "eve_ng":
		eveServer := strings.TrimSpace(getString("eveServer"))
		if eveServer == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("eveServer is required").Err()
		}
		template := strings.TrimSpace(getString("template"))
		labPath := strings.TrimSpace(getString("labPath"))
		if template == "" && labPath == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := canonicalTemplateSource(getString("templateSource"), "blueprints")
		templateRepo := strings.TrimSpace(getString("templateRepo"))
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		if templateSource == "custom" && templateRepo == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
		}
		cfgAny["eveServer"] = eveServer
		if template != "" {
			templatesDir = normalizeEveNgTemplatesDir(templateSource, templatesDir)
			if !isSafeRelativePath(templatesDir) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
			}
			cfgAny["templateSource"] = templateSource
			if templateRepo != "" {
				cfgAny["templateRepo"] = templateRepo
			}
			cfgAny["templatesDir"] = templatesDir
			cfgAny["template"] = template
		}
		if labPath != "" {
			cfgAny["labPath"] = labPath
		}
	case "clabernetes":
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := canonicalTemplateSource(getString("templateSource"), "user")
		templateRepo := getString("templateRepo")
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		switch templateSource {
		case "custom":
			if templateRepo == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
			}
		case "external":
			if strings.TrimSpace(templateRepo) == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("external repo is required").Err()
			}
			if externalTemplateRepoByIDForContext(pc, templateRepo) == nil {
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
		cfgAny["labName"] = containerlabLabName(pc.context.Slug, name)
	case "containerlab":
		if getString("netlabServer") == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer is required").Err()
		}
		template := strings.TrimSpace(getString("template"))
		if template == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
		}
		templateSource := canonicalTemplateSource(getString("templateSource"), "user")
		templateRepo := getString("templateRepo")
		templatesDir := strings.Trim(getString("templatesDir"), "/")
		switch templateSource {
		case "custom":
			if templateRepo == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("custom repo is required").Err()
			}
		case "external":
			if strings.TrimSpace(templateRepo) == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("external repo is required").Err()
			}
			if externalTemplateRepoByIDForContext(pc, templateRepo) == nil {
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
		cfgAny["labName"] = containerlabLabName(pc.context.Slug, name)
	}

	// Per-deployment Forward sync configuration (optional for all deployment types).
	//
	// UI stores these keys under the deployment config so the worker can decide
	// whether to sync post-deploy.
	if enabled, ok := cfgAny["forwardEnabled"].(bool); ok {
		cfgAny["forwardEnabled"] = enabled
	} else if v := strings.TrimSpace(getString("forwardEnabled")); v != "" {
		cfgAny["forwardEnabled"] = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	}
	if v := strings.TrimSpace(getString("forwardCollectorUsername")); v != "" {
		cfgAny["forwardCollectorUsername"] = v
	}
	cfg, _ = toJSONMap(cfgAny)
	cfgBytes, _ := json.Marshal(cfg)

	deploymentID := uuid.NewString()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	initialStatus := "created"
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_deployments (
  id, owner_id, owner_username, name, type, config, created_by, last_status
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, deploymentID, pc.context.ID, pc.context.ID, name, typ, cfgBytes, pc.claims.Username, initialStatus)
	if err != nil {
		log.Printf("deployments insert: %v", err)
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, errs.B().Code(errs.AlreadyExists).Msg("deployment name already exists").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create deployment").Err()
	}
	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	if enabled, ok := cfgAny["forwardEnabled"].(bool); ok && enabled {
		// Best-effort: create the Forward network early so the user can see it immediately
		// after creating the deployment (before any lab is started).
		metaAny := map[string]any{
			"deploymentId": deploymentID,
		}
		meta, _ := toJSONMap(metaAny)
		msg := fmt.Sprintf("Skyforge Forward init (%s)", pc.claims.Username)
		if task, err := createTaskAllowActive(ctx, s.db, pc.context.ID, &deploymentID, "forward-init", msg, pc.claims.Username, meta); err != nil {
			log.Printf("forward init enqueue: %v", err)
		} else {
			s.enqueueTask(ctx, task)
		}
	}
	if dep != nil && typ == "netlab" {
		// Kick off a `netlab create` run immediately so a subsequent start has less work to do.
		// This is best-effort: keep the deployment even if the create run fails.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if _, err := s.RunUserDeploymentAction(ctx, id, deploymentID, &UserDeploymentOpRequest{Action: "create"}); err != nil {
			log.Printf("netlab create on deployment create: %v", err)
		}
		return s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	}
	return dep, nil
}

// UpdateUserDeployment updates an existing deployment definition.
func (s *Service) UpdateUserDeployment(ctx context.Context, id, deploymentID string, req *UserDeploymentUpdateRequest) (*UserDeployment, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
		cfgBytes, _ := json.Marshal(cfg)
		fields = append(fields, "config="+arg(cfgBytes))
	}
	fields = append(fields, "updated_at=now()")
	if len(fields) == 1 {
		return s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	}

	args = append(args, pc.context.ID, deploymentID)
	query := fmt.Sprintf("UPDATE sf_deployments SET %s WHERE owner_username=$%d AND id=$%d", strings.Join(fields, ", "), len(args)-1, len(args))
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
	return s.getUserDeployment(ctx, pc.context.ID, deploymentID)
}

// DeleteUserDeployment removes a deployment definition from Skyforge.
func (s *Service) DeleteUserDeployment(ctx context.Context, id, deploymentID string, req *UserDeploymentDeleteRequest) (*UserDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	existing, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	// Guardrail: do not allow deleting a deployment while it still has queued/running tasks.
	// Otherwise background workers can observe a missing deployment row mid-run and skip
	// post-deploy behavior (Forward sync, cleanup, etc).
	{
		ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var n int
		_ = s.db.QueryRowContext(ctxReq, `SELECT count(*) FROM sf_tasks
WHERE owner_username=$1 AND deployment_id=$2 AND status IN ('queued','running')`, pc.context.ID, existing.ID).Scan(&n)
		if n > 0 {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("deployment has an active run; cancel/stop it before deleting").Err()
		}
	}

	if existing.Type == "netlab" {
		cfgAny, _ := fromJSONMap(existing.Config)
		if cfgAny == nil {
			cfgAny = map[string]any{}
		}
		netlabServer, _ := cfgAny["netlabServer"].(string)
		if strings.TrimSpace(netlabServer) == "" {
			netlabServer = strings.TrimSpace(pc.context.NetlabServer)
		}
		if strings.TrimSpace(netlabServer) != "" {
			_, err := s.RunUserNetlab(ctx, id, &UserNetlabRunRequest{
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
	if existing.Type == "netlab-c9s" || existing.Type == "clabernetes" || existing.Type == "eve_ng" {
		_, err := s.RunUserDeploymentAction(ctx, id, deploymentID, &UserDeploymentOpRequest{Action: "destroy"})
		if err != nil {
			log.Printf("deployments delete c9s cleanup (ignored): %v", err)
		}
	}
	if req != nil && (req.ForwardDelete || req.ForwardDeleteCamel) {
		cfgAny, _ := fromJSONMap(existing.Config)
		if cfgAny == nil {
			cfgAny = map[string]any{}
		}
		if raw, ok := cfgAny[forwardNetworkIDKey]; ok {
			networkID := strings.TrimSpace(fmt.Sprintf("%v", raw))
			if networkID != "" {
				collectorConfigID := strings.TrimSpace(fmt.Sprintf("%v", cfgAny["forwardCollectorId"]))
				if collectorConfigID == "" {
					if v, err := s.forwardCollectorConfigIDForUserNetwork(ctx, pc.context.ID, networkID); err == nil && v != "" {
						collectorConfigID = v
					}
				}

				candidates := []string{
					pc.claims.Username,
					strings.TrimSpace(existing.CreatedBy),
				}
				if collectorConfigID != "" {
					if ownerUsername, err := s.forwardCollectorConfigOwner(ctx, collectorConfigID); err == nil && ownerUsername != "" {
						candidates = append(candidates, ownerUsername)
					}
				}

				var forwardCfg *forwardCredentials
				resolvedUser := ""
				seenUsers := map[string]struct{}{}
				for _, candidate := range candidates {
					username := strings.ToLower(strings.TrimSpace(candidate))
					if username == "" {
						continue
					}
					if _, ok := seenUsers[username]; ok {
						continue
					}
					seenUsers[username] = struct{}{}
					cfg, err := resolveForwardCredentialsFor(
						ctx,
						s.db,
						s.cfg.SessionSecret,
						pc.context.ID,
						username,
						networkID,
						forwardCredResolveOpts{
							CollectorConfigID: collectorConfigID,
						},
					)
					if err != nil {
						log.Printf("deployments delete: Forward credential resolution failed for deployment %s (%s) user=%s: %v", existing.ID, networkID, username, err)
						continue
					}
					if cfg != nil {
						forwardCfg = cfg
						resolvedUser = username
						break
					}
				}

				if forwardCfg == nil {
					return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials are not configured (cannot delete Forward network)").Err()
				}

				client, err := newForwardClient(*forwardCfg)
				if err != nil {
					return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credentials are invalid (cannot delete Forward network)").Err()
				}
				delCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				if err := forwardDeleteNetwork(delCtx, client, networkID); err != nil {
					return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward network").Err()
				}
				log.Printf("deployments delete: Forward network cleanup succeeded for deployment %s (%s) using user=%s", existing.ID, networkID, resolvedUser)
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_deployments WHERE owner_username=$1 AND id=$2`, pc.context.ID, deploymentID)
	if err != nil {
		log.Printf("deployments delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete deployment").Err()
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("deployment not found").Err()
	}
	return &UserDeploymentActionResponse{OwnerUsername: pc.context.ID, Deployment: existing}, nil
}

func (s *Service) forwardCollectorConfigOwner(ctx context.Context, collectorConfigID string) (string, error) {
	if s.db == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	collectorConfigID = strings.TrimSpace(collectorConfigID)
	if collectorConfigID == "" {
		return "", nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var owner string
	err := s.db.QueryRowContext(ctxReq, `SELECT COALESCE(username,'') FROM sf_user_forward_collectors WHERE id=$1`, collectorConfigID).Scan(&owner)
	if err != nil {
		if err == sql.ErrNoRows || isMissingDBRelation(err) {
			return "", nil
		}
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(owner)), nil
}

func (s *Service) forwardCollectorConfigIDForUserNetwork(ctx context.Context, ownerID, networkID string) (string, error) {
	if s.db == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ownerID = strings.TrimSpace(ownerID)
	networkID = strings.TrimSpace(networkID)
	if ownerID == "" || networkID == "" {
		return "", nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var collectorConfigID string
	err := s.db.QueryRowContext(ctxReq, `SELECT COALESCE(collector_config_id,'')
FROM sf_policy_report_forward_networks
WHERE owner_username=$1 AND forward_network=$2
ORDER BY updated_at DESC
LIMIT 1`, ownerID, networkID).Scan(&collectorConfigID)
	if err != nil {
		if err == sql.ErrNoRows || isMissingDBRelation(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(collectorConfigID), nil
}

type UserDeploymentStartRequest struct {
	Action string `json:"action,omitempty"` // used for terraform (apply/destroy)
}

type UserDeploymentOpRequest struct {
	Action string `json:"action,omitempty"` // create, start, stop, destroy, export
}

// RunUserDeploymentAction runs a deployment operation with consistent UX verbs.
func (s *Service) RunUserDeploymentAction(ctx context.Context, id, deploymentID string, req *UserDeploymentOpRequest) (*UserDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
		req = &UserDeploymentOpRequest{}
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

	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	envMap, err := s.mergeDeploymentEnvironment(ctx, pc.context.ID, user.Username, cfgAny)
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

	run := (*UserRunResponse)(nil)
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
		templateSource = canonicalTemplateSource(templateSource, "user")
		templateRepo = strings.TrimSpace(templateRepo)
		templatesDir = strings.TrimSpace(templatesDir)
		template = strings.TrimSpace(template)
		switch op {
		case "create":
			run, err = s.RunUserTerraformApply(ctx, id, &UserTerraformApplyParams{
				Confirm:        "true",
				Cloud:          cloud,
				Action:         "apply",
				TemplateSource: publicTemplateSource(templateSource),
				TemplateRepo:   templateRepo,
				TemplatesDir:   templatesDir,
				Template:       template,
				DeploymentID:   dep.ID,
			})
		case "destroy":
			run, err = s.RunUserTerraformApply(ctx, id, &UserTerraformApplyParams{
				Confirm:        "true",
				Cloud:          cloud,
				Action:         "destroy",
				TemplateSource: publicTemplateSource(templateSource),
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

		run, err = s.RunUserNetlab(ctx, id, &UserNetlabRunRequest{
			Message:          message,
			GitBranch:        branch,
			Environment:      envJSON,
			Action:           netlabAction,
			Cleanup:          cleanup,
			NetlabServer:     netlabServer,
			NetlabMultilabID: dep.ID,
			NetlabDeployment: dep.Name,
			ClabCleanup:      false,
			TemplateSource:   publicTemplateSource(strings.TrimSpace(templateSource)),
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
		setOverridesAny := cfgAny["netlabSetOverrides"]

		netlabServer = strings.TrimSpace(netlabServer)
		if strings.TrimSpace(template) == "" && op != "destroy" && op != "stop" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab template is required").Err()
		}
		if op == "stop" && !infraCreated {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab-c9s deployment must be created before stop").Err()
		}
		if strings.TrimSpace(labName) == "" {
			labName = containerlabLabName(pc.context.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesOwnerNamespace(pc.context.Slug)
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

		setOverrides := []string{}
		switch vv := setOverridesAny.(type) {
		case []any:
			for _, it := range vv {
				s := strings.TrimSpace(fmt.Sprintf("%v", it))
				if s != "" {
					setOverrides = append(setOverrides, s)
				}
			}
		case []string:
			for _, it := range vv {
				s := strings.TrimSpace(it)
				if s != "" {
					setOverrides = append(setOverrides, s)
				}
			}
		case string:
			for _, ln := range strings.Split(vv, "\n") {
				s := strings.TrimSpace(ln)
				if s != "" {
					setOverrides = append(setOverrides, s)
				}
			}
		}

		run, err = s.runNetlabC9sDeploymentAction(
			ctx,
			pc,
			dep,
			envJSON,
			c9sAction,
			netlabServer,
			canonicalTemplateSource(strings.TrimSpace(templateSource), "user"),
			strings.TrimSpace(templateRepo),
			strings.TrimSpace(templatesDir),
			strings.TrimSpace(template),
			strings.TrimSpace(labName),
			strings.TrimSpace(k8sNamespace),
			setOverrides,
		)
		if err != nil {
			return nil, err
		}
	case "eve_ng":
		eveServer, _ := cfgAny["eveServer"].(string)
		templateSource, _ := cfgAny["templateSource"].(string)
		templateRepo, _ := cfgAny["templateRepo"].(string)
		templatesDir, _ := cfgAny["templatesDir"].(string)
		template, _ := cfgAny["template"].(string)
		labPath, _ := cfgAny["labPath"].(string)

		eveServer = strings.TrimSpace(eveServer)
		if eveServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng server selection is required").Err()
		}
		if strings.TrimSpace(template) == "" && op != "destroy" && op != "stop" && strings.TrimSpace(labPath) == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("eve-ng template is required").Err()
		}

		eveAction := op
		switch op {
		case "create":
			eveAction = "create"
		case "start":
			eveAction = "start"
		case "stop":
			eveAction = "stop"
		case "destroy":
			eveAction = "destroy"
		default:
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unsupported eve-ng action").Err()
		}

		run, err = s.RunUserEveNg(ctx, id, &UserEveNgRunRequest{
			Message:        strings.TrimSpace(fmt.Sprintf("Skyforge eve-ng run (%s)", pc.claims.Username)),
			Action:         eveAction,
			EveServer:      eveServer,
			TemplateSource: publicTemplateSource(strings.TrimSpace(templateSource)),
			TemplateRepo:   strings.TrimSpace(templateRepo),
			TemplatesDir:   strings.TrimSpace(templatesDir),
			Template:       strings.TrimSpace(template),
			Deployment:     strings.TrimSpace(dep.Name),
			DeploymentID:   strings.TrimSpace(dep.ID),
			LabPath:        strings.TrimSpace(labPath),
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

		run, err = s.RunUserContainerlab(ctx, id, &UserContainerlabRunRequest{
			Message:        strings.TrimSpace(fmt.Sprintf("Skyforge containerlab run (%s)", pc.claims.Username)),
			Environment:    envJSON,
			Action:         containerlabAction,
			NetlabServer:   netlabServer,
			TemplateSource: publicTemplateSource(strings.TrimSpace(templateSource)),
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
			cfgAny["labName"] = containerlabLabName(pc.context.Slug, dep.Name)
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
			labName = containerlabLabName(pc.context.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesOwnerNamespace(pc.context.Slug)
			cfgAny["k8sNamespace"] = k8sNamespace
		}

		clabernetesAction := "deploy"
		switch op {
		case "create", "start":
			clabernetesAction = "deploy"
		case "stop", "destroy":
			clabernetesAction = "destroy"
		}

		run, err = s.runClabernetesDeploymentAction(ctx, pc, dep, envJSON, clabernetesAction, canonicalTemplateSource(strings.TrimSpace(templateSource), "user"), strings.TrimSpace(templateRepo), strings.TrimSpace(templatesDir), strings.TrimSpace(template), strings.TrimSpace(labName), strings.TrimSpace(k8sNamespace))
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
	updated, err := s.touchDeploymentFromRun(ctx, pc.context.ID, deploymentID, cfgJSON, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
		updated = dep
	}

	resp := &UserDeploymentActionResponse{OwnerUsername: pc.context.ID, Deployment: updated}
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

// GetUserDeploymentInfo returns provider-specific info for a deployment.
// For Netlab deployments, this executes `netlab status` against the associated Netlab API and returns the output.
func (s *Service) GetUserDeploymentInfo(ctx context.Context, id, deploymentID string) (*UserDeploymentInfoResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}

	resp := &UserDeploymentInfoResponse{
		OwnerUsername: pc.context.ID,
		Deployment:    dep,
		Provider:      dep.Type,
		RetrievedAt:   time.Now().UTC().Format(time.RFC3339),
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
		if forwardCfg, err := s.forwardConfigForOwner(ctx, pc.context.ID); err == nil && forwardCfg != nil {
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
		templateSource := canonicalTemplateSource(getString("templateSource"), "user")
		templatesDir := getString("templatesDir")
		template := getString("template")
		if netlabServer == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
		}

		server, err := s.resolveNetlabServerConfig(ctx, pc, netlabServer)
		if err != nil {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
		}

		multilabID := dep.ID
		h := fnv.New32a()
		_, _ = h.Write([]byte(multilabID))
		multilabNumericID := int(h.Sum32()%199) + 1

		userRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
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
			"action":      "status",
			"user":        strings.TrimSpace(pc.claims.Username),
			"userContext": strings.TrimSpace(pc.context.Slug),
			"deployment":  strings.TrimSpace(dep.Name),
			"userRoot":    userRoot,
			"plugin":      "multilab",
			"multilabId":  strconv.Itoa(multilabNumericID),
			"instance":    strconv.Itoa(multilabNumericID),
			"stateRoot":   strings.TrimSpace(server.StateRoot),
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
	case "terraform":
		stateKey := strings.TrimSpace(pc.context.TerraformStateKey)
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
		server, err := s.resolveContainerlabServerConfig(ctx, pc, netlabServer)
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
			labName = containerlabLabName(pc.context.Slug, dep.Name)
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
			labName = containerlabLabName(pc.context.Slug, dep.Name)
		}
		k8sNamespace := strings.TrimSpace(getString("k8sNamespace"))
		if k8sNamespace == "" {
			k8sNamespace = clabernetesOwnerNamespace(pc.context.Slug)
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

// NetlabConnect executes `netlab connect` on the Netlab runner host and returns its output.
//
// This is an alternative to local SSH ProxyJump when clients can't reach the lab network.
func (s *Service) NetlabConnect(ctx context.Context, id, deploymentID string, req *NetlabConnectRequest) (*NetlabConnectResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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

	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
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
	templateSource := canonicalTemplateSource(getString("templateSource"), "user")
	templatesDir := getString("templatesDir")
	template := getString("template")
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}
	server, err := s.resolveNetlabServerConfig(ctx, pc, netlabServer)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	multilabID := dep.ID
	h := fnv.New32a()
	_, _ = h.Write([]byte(multilabID))
	multilabNumericID := int(h.Sum32()%199) + 1

	userRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
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
		"user":        strings.TrimSpace(pc.claims.Username),
		"userContext": strings.TrimSpace(pc.context.Slug),
		"deployment":  strings.TrimSpace(dep.Name),
		"userRoot":    userRoot,
		"plugin":      "multilab",
		"multilabId":  strconv.Itoa(multilabNumericID),
		"instance":    strconv.Itoa(multilabNumericID),
		"stateRoot":   strings.TrimSpace(server.StateRoot),
		"node":        node,
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

// GetUserDeploymentNetlabGraph returns a rendered netlab topology graph for a deployment.
func (s *Service) GetUserDeploymentNetlabGraph(ctx context.Context, id, deploymentID string) (*NetlabGraphResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
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
	templateSource := canonicalTemplateSource(getString("templateSource"), "user")
	templatesDir := getString("templatesDir")
	template := getString("template")
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}

	server, err := s.resolveNetlabServerConfig(ctx, pc, netlabServer)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	multilabID := dep.ID
	h := fnv.New32a()
	_, _ = h.Write([]byte(multilabID))
	multilabNumericID := int(h.Sum32()%199) + 1

	userRoot := fmt.Sprintf("/home/%s/netlab", pc.claims.Username)
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
		"user":        strings.TrimSpace(pc.claims.Username),
		"userContext": strings.TrimSpace(pc.context.Slug),
		"deployment":  strings.TrimSpace(dep.Name),
		"userRoot":    userRoot,
		"plugin":      "multilab",
		"multilabId":  strconv.Itoa(multilabNumericID),
		"instance":    strconv.Itoa(multilabNumericID),
		"stateRoot":   strings.TrimSpace(server.StateRoot),
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

// StartUserDeployment starts a deployment run.
func (s *Service) StartUserDeployment(ctx context.Context, id, deploymentID string, req *UserDeploymentStartRequest) (*UserDeploymentActionResponse, error) {
	return s.runDeployment(ctx, id, deploymentID, req, "start")
}

// DestroyUserDeployment triggers a destructive run (destroy) for a deployment.
func (s *Service) DestroyUserDeployment(ctx context.Context, id, deploymentID string) (*UserDeploymentActionResponse, error) {
	return s.runDeployment(ctx, id, deploymentID, &UserDeploymentStartRequest{Action: "destroy"}, "destroy")
}

// StopUserDeployment attempts to stop the most recent task for this deployment.
func (s *Service) StopUserDeployment(ctx context.Context, id, deploymentID string) (*UserDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	var task *TaskRecord
	if active, err := getActiveDeploymentTask(ctx, s.db, pc.context.ID, dep.ID); err == nil && active != nil {
		task = active
	} else if dep.LastTaskID != nil {
		if rec, err := getTask(ctx, s.db, *dep.LastTaskID); err == nil {
			task = rec
		}
	}
	if task == nil {
		return &UserDeploymentActionResponse{OwnerUsername: pc.context.ID, Deployment: dep}, nil
	}
	if err := cancelTask(ctx, s.db, task.ID); err != nil {
		log.Printf("deployment stop: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to cancel task").Err()
	}
	_, _ = taskqueue.CancelTopic.Publish(ctx, &taskqueue.TaskCancelEvent{TaskID: task.ID})
	now := time.Now().UTC()
	if err := s.updateDeploymentStatus(ctx, pc.context.ID, dep.ID, "canceled", &now); err != nil {
		log.Printf("deployment stop update: %v", err)
	}
	return &UserDeploymentActionResponse{OwnerUsername: pc.context.ID, Deployment: dep}, nil
}

func (s *Service) runDeployment(ctx context.Context, id, deploymentID string, req *UserDeploymentStartRequest, mode string) (*UserDeploymentActionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	envMap, err := s.mergeDeploymentEnvironment(ctx, pc.context.ID, user.Username, cfgAny)
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

	var run *UserRunResponse
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
		run, err = s.RunUserTerraformApply(ctx, id, &UserTerraformApplyParams{
			Confirm:        "true",
			Cloud:          cloud,
			Action:         action,
			TemplateSource: publicTemplateSource(strings.TrimSpace(templateSource)),
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
		run, err = s.RunUserNetlab(ctx, id, &UserNetlabRunRequest{
			Message:          message,
			GitBranch:        branch,
			Environment:      envJSON,
			Action:           netlabAction,
			Cleanup:          cleanup,
			NetlabServer:     strings.TrimSpace(netlabServer),
			NetlabMultilabID: dep.ID,
			NetlabDeployment: dep.Name,
			TemplateSource:   publicTemplateSource(strings.TrimSpace(templateSource)),
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
		setOverridesAny := cfgAny["netlabSetOverrides"]

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
			labName = containerlabLabName(pc.context.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesOwnerNamespace(pc.context.Slug)
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

		setOverrides := []string{}
		switch vv := setOverridesAny.(type) {
		case []any:
			for _, it := range vv {
				s := strings.TrimSpace(fmt.Sprintf("%v", it))
				if s != "" {
					setOverrides = append(setOverrides, s)
				}
			}
		case []string:
			for _, it := range vv {
				s := strings.TrimSpace(it)
				if s != "" {
					setOverrides = append(setOverrides, s)
				}
			}
		case string:
			for _, ln := range strings.Split(vv, "\n") {
				s := strings.TrimSpace(ln)
				if s != "" {
					setOverrides = append(setOverrides, s)
				}
			}
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
			setOverrides,
		)
		if err != nil {
			return nil, err
		}
		if next, err := toJSONMap(cfgAny); err == nil {
			cfgOut = next
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
		run, err = s.RunUserContainerlab(ctx, id, &UserContainerlabRunRequest{
			Message:        strings.TrimSpace(fmt.Sprintf("Skyforge containerlab run (%s)", pc.claims.Username)),
			Environment:    envJSON,
			Action:         containerlabAction,
			NetlabServer:   strings.TrimSpace(netlabServer),
			TemplateSource: publicTemplateSource(strings.TrimSpace(templateSource)),
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
			cfgAny["labName"] = containerlabLabName(pc.context.Slug, dep.Name)
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
			labName = containerlabLabName(pc.context.Slug, dep.Name)
			cfgAny["labName"] = labName
		}
		if strings.TrimSpace(k8sNamespace) == "" {
			k8sNamespace = clabernetesOwnerNamespace(pc.context.Slug)
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

	updated, err := s.touchDeploymentFromRun(ctx, pc.context.ID, deploymentID, cfgOut, run)
	if err != nil {
		log.Printf("deployments touch: %v", err)
	}

	resp := &UserDeploymentActionResponse{OwnerUsername: pc.context.ID, Deployment: updated}
	if run != nil {
		resp.Run = run.Task
	}
	return resp, nil
}

func (s *Service) touchDeploymentFromRun(ctx context.Context, ownerID, deploymentID string, cfg JSONMap, run *UserRunResponse) (*UserDeployment, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	taskOwnerID := 0
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
  last_task_owner_id=$2,
  last_task_id=$3,
  last_status=$4,
  last_started_at=now(),
  updated_at=now()
WHERE owner_username=$5 AND id=$6`, cfgBytes, nullIfZeroInt(taskOwnerID), nullIfZeroInt(taskID), nullIfEmpty(status), ownerID, deploymentID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update deployment").Err()
	}
	return s.getUserDeployment(ctx, ownerID, deploymentID)
}

func (s *Service) updateDeploymentStatus(ctx context.Context, ownerID, deploymentID string, status string, finishedAt *time.Time) error {
	return taskstore.UpdateDeploymentStatus(ctx, s.db, ownerID, deploymentID, status, finishedAt)
}

func (s *Service) getLatestDeploymentByType(ctx context.Context, ownerID, depType string) (*UserDeployment, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var deploymentID string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM sf_deployments WHERE owner_username=$1 AND type=$2 ORDER BY updated_at DESC LIMIT 1`, ownerID, depType).Scan(&deploymentID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return s.getUserDeployment(ctx, ownerID, deploymentID)
}

func nullIfZeroInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func (s *Service) getUserDeployment(ctx context.Context, ownerID, deploymentID string) (*UserDeployment, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		rec             UserDeployment
		raw             json.RawMessage
		lastTaskOwnerID sql.NullInt64
		lastTaskID      sql.NullInt64
		lastStatus      sql.NullString
		lastStarted     sql.NullTime
		lastFinished    sql.NullTime
		createdAt       time.Time
		updatedAt       time.Time
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, name, type, config, created_by, created_at, updated_at,
  last_task_owner_id, last_task_id, last_status, last_started_at, last_finished_at
FROM sf_deployments
WHERE owner_username=$1 AND id=$2`, ownerID, deploymentID).Scan(
		&rec.ID,
		&rec.Name,
		&rec.Type,
		&raw,
		&rec.CreatedBy,
		&createdAt,
		&updatedAt,
		&lastTaskOwnerID,
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
	if normalized, err := normalizeDeploymentType(rec.Type); err == nil {
		rec.Type = normalized
	}
	rec.OwnerUsername = ownerID
	rec.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	rec.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	{
		qctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		summary, err := getDeploymentQueueSummary(qctx, s.db, ownerID, rec.ID)
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
	if lastTaskOwnerID.Valid {
		v := int(lastTaskOwnerID.Int64)
		rec.LastTaskOwnerID = &v
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
