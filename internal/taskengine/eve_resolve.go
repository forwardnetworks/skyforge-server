package taskengine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
)

type EveServerConfig = skyforgecore.EveServerConfig

type workspaceEveResolved struct {
	Server          EveServerConfig
	SSHKey          string
	SkipTLSOverride bool
}

type workspaceEveServer struct {
	ID            string
	WorkspaceID   string
	Name          string
	APIURL        string
	WebURL        string
	SkipTLSVerify bool
	SSHHost       string
	SSHUser       string
	SSHKey        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func normalizeEveServer(s EveServerConfig, fallback skyforgecore.LabsConfig) EveServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.APIURL = strings.TrimSpace(s.APIURL)
	s.WebURL = strings.TrimSpace(s.WebURL)
	s.Username = strings.TrimSpace(s.Username)
	s.Password = strings.TrimSpace(s.Password)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.LabsPath = strings.TrimSpace(s.LabsPath)
	s.TmpPath = strings.TrimSpace(s.TmpPath)
	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.EveSSHUser)
	}
	if s.LabsPath == "" {
		s.LabsPath = strings.TrimSpace(fallback.EveLabsPath)
	}
	if s.TmpPath == "" {
		s.TmpPath = strings.TrimSpace(fallback.EveTmpPath)
	}
	if s.WebURL == "" {
		s.WebURL = s.APIURL
	}
	if s.SSHHost == "" {
		if raw := strings.TrimSpace(s.APIURL); raw != "" {
			if u, err := url.Parse(raw); err == nil && u != nil && u.Hostname() != "" {
				s.SSHHost = strings.TrimSpace(u.Hostname())
			}
		}
	}
	return s
}

func (e *Engine) resolveWorkspaceEveServerConfig(ctx context.Context, workspaceID string, serverRef string) (*workspaceEveResolved, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id required")
	}
	serverRef = strings.TrimSpace(serverRef)
	if serverRef == "" {
		return nil, fmt.Errorf("eve server is required (configure an EVE server in workspace settings)")
	}
	serverID, ok := parseWorkspaceServerRef(serverRef)
	if !ok {
		return nil, fmt.Errorf("eve server must be a workspace server reference (ws:...)")
	}

	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rec, err := e.getWorkspaceEveServerByID(ctxReq, workspaceID, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to load workspace EVE server")
	}
	if rec == nil {
		return nil, fmt.Errorf("workspace EVE server not found")
	}
	eveServer := EveServerConfig{
		Name:          strings.TrimSpace(rec.Name),
		APIURL:        strings.TrimSpace(rec.APIURL),
		WebURL:        strings.TrimSpace(rec.WebURL),
		SkipTLSVerify: rec.SkipTLSVerify,
		SSHHost:       strings.TrimSpace(rec.SSHHost),
		SSHUser:       strings.TrimSpace(rec.SSHUser),
	}
	eveServer = normalizeEveServer(eveServer, e.cfg.Labs)
	key := strings.TrimSpace(rec.SSHKey)

	return &workspaceEveResolved{
		Server:          eveServer,
		SSHKey:          key,
		SkipTLSOverride: eveServer.SkipTLSVerify,
	}, nil
}

func (e *Engine) getWorkspaceEveServerByID(ctx context.Context, workspaceID, id string) (*workspaceEveServer, error) {
	if e == nil || e.db == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	id = strings.TrimSpace(id)
	if workspaceID == "" || id == "" {
		return nil, nil
	}
	var rec workspaceEveServer
	var webURL, sshHost, sshUser, sshKeyEnc string
	err := e.db.QueryRowContext(ctx, `SELECT id, project_id, name, api_url, COALESCE(web_url,''), skip_tls_verify,
  COALESCE(ssh_host,''), COALESCE(ssh_user,''), COALESCE(ssh_key,''), created_at, updated_at
FROM sf_project_eve_servers WHERE project_id=$1 AND id=$2`, workspaceID, id).Scan(
		&rec.ID, &rec.WorkspaceID, &rec.Name, &rec.APIURL, &webURL, &rec.SkipTLSVerify,
		&sshHost, &sshUser, &sshKeyEnc, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rec.Name = strings.TrimSpace(rec.Name)
	rec.APIURL = strings.TrimSpace(rec.APIURL)
	rec.WebURL = strings.TrimSpace(webURL)
	rec.SSHHost = strings.TrimSpace(sshHost)
	rec.SSHUser = strings.TrimSpace(sshUser)

	sshKey := strings.TrimSpace(sshKeyEnc)
	if sshKey != "" && e.box != nil {
		if decrypted, err := e.box.decrypt(sshKey); err == nil {
			sshKey = strings.TrimSpace(decrypted)
		}
	}
	rec.SSHKey = sshKey
	return &rec, nil
}
