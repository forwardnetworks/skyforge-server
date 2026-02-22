package taskengine

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errWorkspaceNotFound = errors.New("workspace not found")

func (e *Engine) loadWorkspaceByKey(ctx context.Context, key string) (*Workspace, error) {
	db, err := e.requireDB()
	if err != nil {
		return nil, err
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("workspace id is required")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var (
		id, slug, name, createdBy, giteaOwner, giteaRepo  string
		defaultBranch, blueprint, netlabServer, eveServer sql.NullString
		terraformStateKey, awsRegion                      sql.NullString
		allowExternalTemplateRepos                        bool
		externalTemplateReposJSON                         []byte
	)
	row := db.QueryRowContext(ctxReq, `SELECT id, slug, name, created_by, COALESCE(default_branch,''), COALESCE(blueprint,''), COALESCE(netlab_server,''), COALESCE(eve_server,''),
  allow_external_template_repos, COALESCE(external_template_repos,'[]'::jsonb), gitea_owner, gitea_repo, COALESCE(terraform_state_key,''), COALESCE(aws_region,'')
FROM sf_workspaces
WHERE id=$1 OR slug=$1
LIMIT 1`, key)
	if err := row.Scan(&id, &slug, &name, &createdBy, &defaultBranch, &blueprint, &netlabServer, &eveServer, &allowExternalTemplateRepos, &externalTemplateReposJSON, &giteaOwner, &giteaRepo, &terraformStateKey, &awsRegion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errWorkspaceNotFound
		}
		return nil, err
	}

	external := parseExternalTemplateRepos(externalTemplateReposJSON)
	w := &Workspace{
		ID:                         id,
		Slug:                       slug,
		Name:                       name,
		CreatedBy:                  createdBy,
		DefaultBranch:              strings.TrimSpace(defaultBranch.String),
		Blueprint:                  strings.TrimSpace(blueprint.String),
		NetlabServer:               strings.TrimSpace(netlabServer.String),
		EveServer:                  strings.TrimSpace(eveServer.String),
		AllowExternalTemplateRepos: allowExternalTemplateRepos,
		ExternalTemplateRepos:      external,
		GiteaOwner:                 giteaOwner,
		GiteaRepo:                  giteaRepo,
		TerraformStateKey:          strings.TrimSpace(terraformStateKey.String),
		AWSRegion:                  strings.TrimSpace(awsRegion.String),
	}
	return w, nil
}

func parseWorkspaceServerRef(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	const prefix = "ws:"
	if after, ok := strings.CutPrefix(value, prefix); ok {
		id := strings.TrimSpace(after)
		if id == "" {
			return "", false
		}
		return id, true
	}
	return "", false
}

func (e *Engine) resolveWorkspaceNetlabServer(ctx context.Context, workspaceID, serverRef string) (*NetlabServerConfig, error) {
	db, err := e.requireDB()
	if err != nil {
		return nil, err
	}
	workspaceID = strings.TrimSpace(workspaceID)
	serverRef = strings.TrimSpace(serverRef)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id required")
	}
	if serverRef == "" {
		return nil, fmt.Errorf("netlab server is required (configure a Netlab server in workspace settings)")
	}
	serverID, ok := parseWorkspaceServerRef(serverRef)
	if !ok {
		return nil, fmt.Errorf("netlab server must be a workspace server reference (ws:...)")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var rec netlabServerRecord
	var tokenEnc sql.NullString
	err = db.QueryRowContext(ctxReq, `SELECT id, project_id, name, api_url, api_insecure, COALESCE(api_token,''), created_at, updated_at
FROM sf_project_netlab_servers WHERE project_id=$1 AND id=$2`, workspaceID, serverID).Scan(
		&rec.ID, &rec.WorkspaceID, &rec.Name, &rec.APIURL, &rec.APIInsecure, &tokenEnc, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("workspace netlab server not found")
		}
		return nil, err
	}
	token := strings.TrimSpace(tokenEnc.String)
	if token != "" {
		if decrypted, err := e.box.decrypt(token); err == nil {
			token = strings.TrimSpace(decrypted)
		}
	}
	cfg := NetlabServerConfig{
		Name:        strings.TrimSpace(rec.Name),
		APIURL:      strings.TrimSpace(rec.APIURL),
		APIInsecure: rec.APIInsecure,
		APIToken:    token,
	}
	cfg = normalizeNetlabServer(cfg, e.cfg.Netlab)
	return &cfg, nil
}

func (e *Engine) loadDeployment(ctx context.Context, workspaceID, deploymentID string) (*WorkspaceDeployment, error) {
	db, err := e.requireDB()
	if err != nil {
		return nil, err
	}
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	if workspaceID == "" || deploymentID == "" {
		return nil, nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var dep WorkspaceDeployment
	var cfgBytes []byte
	err = db.QueryRowContext(ctxReq, `SELECT id, username, name, type, config
FROM sf_deployments WHERE username=$1 AND id=$2`, workspaceID, deploymentID).Scan(&dep.ID, &dep.WorkspaceID, &dep.Name, &dep.Type, &cfgBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if len(cfgBytes) > 0 {
		_ = json.Unmarshal(cfgBytes, &dep.Config)
	}
	return &dep, nil
}
