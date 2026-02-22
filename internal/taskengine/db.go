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

var errUserScopeNotFound = errors.New("user scope not found")

func (e *Engine) loadUserScopeByKey(ctx context.Context, key string) (*UserScope, error) {
	db, err := e.requireDB()
	if err != nil {
		return nil, err
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("user id is required")
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
FROM sf_user_scopes
WHERE id=$1 OR slug=$1
LIMIT 1`, key)
	if err := row.Scan(&id, &slug, &name, &createdBy, &defaultBranch, &blueprint, &netlabServer, &eveServer, &allowExternalTemplateRepos, &externalTemplateReposJSON, &giteaOwner, &giteaRepo, &terraformStateKey, &awsRegion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errUserScopeNotFound
		}
		return nil, err
	}

	external := parseExternalTemplateRepos(externalTemplateReposJSON)
	w := &UserScope{
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

func parseUserScopeServerRef(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	const prefix = "user:"
	if after, ok := strings.CutPrefix(value, prefix); ok {
		id := strings.TrimSpace(after)
		if id == "" {
			return "", false
		}
		return id, true
	}
	return "", false
}

func (e *Engine) resolveUserScopeNetlabServer(ctx context.Context, userScopeID, serverRef string) (*NetlabServerConfig, error) {
	db, err := e.requireDB()
	if err != nil {
		return nil, err
	}
	userScopeID = strings.TrimSpace(userScopeID)
	serverRef = strings.TrimSpace(serverRef)
	if userScopeID == "" {
		return nil, fmt.Errorf("user id required")
	}
	if serverRef == "" {
		return nil, fmt.Errorf("netlab server is required (configure a Netlab server in user settings)")
	}
	serverID, ok := parseUserScopeServerRef(serverRef)
	if !ok {
		return nil, fmt.Errorf("netlab server must be a user server reference (user:...)")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var rec netlabServerRecord
	var tokenEnc sql.NullString
	err = db.QueryRowContext(ctxReq, `SELECT id, username, name, api_url, api_insecure, COALESCE(api_token,''), created_at, updated_at
FROM sf_user_netlab_servers WHERE username=$1 AND id=$2`, userScopeID, serverID).Scan(
		&rec.ID, &rec.UserScopeID, &rec.Name, &rec.APIURL, &rec.APIInsecure, &tokenEnc, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user netlab server not found")
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

func (e *Engine) loadDeployment(ctx context.Context, userScopeID, deploymentID string) (*UserScopeDeployment, error) {
	db, err := e.requireDB()
	if err != nil {
		return nil, err
	}
	userScopeID = strings.TrimSpace(userScopeID)
	deploymentID = strings.TrimSpace(deploymentID)
	if userScopeID == "" || deploymentID == "" {
		return nil, nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var dep UserScopeDeployment
	var cfgBytes []byte
	err = db.QueryRowContext(ctxReq, `SELECT id, username, name, type, config
FROM sf_deployments WHERE username=$1 AND id=$2`, userScopeID, deploymentID).Scan(&dep.ID, &dep.UserScopeID, &dep.Name, &dep.Type, &cfgBytes)
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
