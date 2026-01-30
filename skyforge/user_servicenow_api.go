package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserServiceNowConfigResponse struct {
	Configured            bool   `json:"configured"`
	InstanceURL           string `json:"instanceUrl,omitempty"`
	AdminUsername         string `json:"adminUsername,omitempty"`
	HasAdminPassword      bool   `json:"hasAdminPassword"`
	ForwardCollectorID    string `json:"forwardCollectorConfigId,omitempty"`
	ForwardUsername       string `json:"forwardUsername,omitempty"` // custom username (if using custom creds)
	HasForwardPassword    bool   `json:"hasForwardPassword"`        // true if a custom password is stored
	UpdatedAt             string `json:"updatedAt,omitempty"`
	LastInstallStatus     string `json:"lastInstallStatus,omitempty"`
	LastInstallError      string `json:"lastInstallError,omitempty"`
	LastInstallStartedAt  string `json:"lastInstallStartedAt,omitempty"`
	LastInstallFinishedAt string `json:"lastInstallFinishedAt,omitempty"`
}

type PutUserServiceNowConfigRequest struct {
	InstanceURL      string `json:"instanceUrl"`
	AdminUsername    string `json:"adminUsername"`
	AdminPassword    string `json:"adminPassword"`
	ForwardCollectorConfigID string `json:"forwardCollectorConfigId"`
	ForwardUsername          string `json:"forwardUsername"`
	ForwardPassword          string `json:"forwardPassword"`
}

type InstallUserServiceNowDemoResponse struct {
	Installed bool   `json:"installed"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
}

type ServiceNowPDIStatusResponse struct {
	Status     string `json:"status"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Detail     string `json:"detail,omitempty"`
	CheckedAt  string `json:"checkedAt,omitempty"`
}

type WakeServiceNowPDIResponse struct {
	Status     string `json:"status"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Detail     string `json:"detail,omitempty"`
	CheckedAt  string `json:"checkedAt,omitempty"`
}

const defaultServiceNowForwardBaseURL = "https://fwd.app/api"

// GetUserServiceNowConfig returns the current user's ServiceNow demo integration settings.
//
//encore:api auth method=GET path=/api/user/integrations/servicenow
func (s *Service) GetUserServiceNowConfig(ctx context.Context) (*UserServiceNowConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserServiceNowConfig(ctx, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("servicenow get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load ServiceNow config").Err()
	}
	if rec == nil {
		return &UserServiceNowConfigResponse{
			Configured:         false,
			HasAdminPassword:   false,
			ForwardCollectorID: "",
			HasForwardPassword: false,
		}, nil
	}
	return rec.toAPI(), nil
}

// GetUserServiceNowPDIStatus checks whether the user's ServiceNow PDI is awake (or likely sleeping).
//
//encore:api auth method=GET path=/api/user/integrations/servicenow/pdiStatus
func (s *Service) GetUserServiceNowPDIStatus(ctx context.Context) (*ServiceNowPDIStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)

	ctxCfg, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cfg, err := getUserServiceNowConfig(ctxCfg, s.db, box, user.Username)
	if err != nil || cfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ServiceNow not configured").Err()
	}

	ctxCheck, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	status, httpStatus, detail := checkServiceNowPDI(ctxCheck, cfg.InstanceURL, cfg.AdminUsername, cfg.AdminPassword)
	return &ServiceNowPDIStatusResponse{
		Status:     status,
		HTTPStatus: httpStatus,
		Detail:     detail,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// WakeServiceNowPDI attempts to wake the user's ServiceNow PDI and waits briefly for it to become responsive.
//
//encore:api auth method=POST path=/api/user/integrations/servicenow/wake
func (s *Service) WakeServiceNowPDI(ctx context.Context) (*WakeServiceNowPDIResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)

	ctxCfg, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cfg, err := getUserServiceNowConfig(ctxCfg, s.db, box, user.Username)
	if err != nil || cfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ServiceNow not configured").Err()
	}

	ctxWake, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()

	_ = triggerServiceNowPDIWake(ctxWake, cfg.InstanceURL)

	deadline := time.Now().Add(60 * time.Second)
	lastStatus := "waking"
	lastCode := 0
	lastDetail := ""
	for time.Now().Before(deadline) {
		st, code, detail := checkServiceNowPDI(ctxWake, cfg.InstanceURL, cfg.AdminUsername, cfg.AdminPassword)
		lastStatus, lastCode, lastDetail = st, code, detail
		if st == "awake" {
			return &WakeServiceNowPDIResponse{
				Status:     "awake",
				HTTPStatus: code,
				Detail:     detail,
				CheckedAt:  time.Now().UTC().Format(time.RFC3339),
			}, nil
		}
		select {
		case <-ctxWake.Done():
			return &WakeServiceNowPDIResponse{
				Status:     lastStatus,
				HTTPStatus: lastCode,
				Detail:     lastDetail,
				CheckedAt:  time.Now().UTC().Format(time.RFC3339),
			}, nil
		case <-time.After(10 * time.Second):
		}
	}

	return &WakeServiceNowPDIResponse{
		Status:     lastStatus,
		HTTPStatus: lastCode,
		Detail:     lastDetail,
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// PutUserServiceNowConfig stores the current user's ServiceNow demo integration settings.
//
//encore:api auth method=PUT path=/api/user/integrations/servicenow
func (s *Service) PutUserServiceNowConfig(ctx context.Context, req *PutUserServiceNowConfigRequest) (*UserServiceNowConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	instanceURL, err := normalizeServiceNowInstanceURL(req.InstanceURL)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid ServiceNow instance URL").Err()
	}
	adminUser := strings.TrimSpace(req.AdminUsername)
	adminPass := strings.TrimSpace(req.AdminPassword)
	forwardCollectorConfigID := strings.TrimSpace(req.ForwardCollectorConfigID)
	fwdUser := strings.TrimSpace(req.ForwardUsername)
	fwdPass := strings.TrimSpace(req.ForwardPassword)

	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current, err := getUserServiceNowConfig(ctx, s.db, box, user.Username)
	if err != nil {
		log.Printf("servicenow get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load ServiceNow config").Err()
	}

	if adminUser == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("adminUsername is required").Err()
	}
	if adminPass == "" && current != nil {
		adminPass = current.AdminPassword
	}
	if adminPass == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("adminPassword is required").Err()
	}
	if forwardCollectorConfigID == "" {
		// Custom Forward creds required when no collector config is selected.
		if fwdUser == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("forwardUsername is required").Err()
		}
		if fwdPass == "" && current != nil {
			fwdPass = current.ForwardPassword
		}
		if fwdPass == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("forwardPassword is required").Err()
		}
	} else {
		// If using collector creds, allow clearing custom creds (but keep stored password unless explicitly overwritten).
		if fwdPass == "" && current != nil {
			fwdPass = current.ForwardPassword
		}
	}

	cfg := userServiceNowConfig{
		Username:               user.Username,
		InstanceURL:            instanceURL,
		AdminUsername:          adminUser,
		AdminPassword:          adminPass,
		ForwardBaseURL:         defaultServiceNowForwardBaseURL,
		ForwardCollectorConfigID: forwardCollectorConfigID,
		ForwardUsername:        fwdUser,
		ForwardPassword:        fwdPass,
	}
	if err := putUserServiceNowConfig(ctx, s.db, box, cfg); err != nil {
		log.Printf("servicenow put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store ServiceNow config").Err()
	}

	ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	stored, _ := getUserServiceNowConfig(ctx, s.db, box, user.Username)
	if stored == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to reload ServiceNow config").Err()
	}
	return stored.toAPI(), nil
}

type ConfigureForwardServiceNowTicketingResponse struct {
	Configured bool   `json:"configured"`
	Message    string `json:"message,omitempty"`
}

// ConfigureForwardServiceNowTicketing configures Forward SaaS to auto-create/update incidents in ServiceNow.
//
// This does not configure ServiceNow CMDB integration (that is per-network and handled elsewhere).
//
//encore:api auth method=POST path=/api/user/integrations/servicenow/configureForwardTicketing
func (s *Service) ConfigureForwardServiceNowTicketing(ctx context.Context) (*ConfigureForwardServiceNowTicketingResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxCfg, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg, err := getUserServiceNowConfig(ctxCfg, s.db, box, user.Username)
	if err != nil || cfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ServiceNow not configured").Err()
	}

	fwdUser, fwdPass, err := resolveForwardCredsForServiceNow(ctxCfg, s.db, box, user.Username, cfg.ForwardCollectorConfigID, cfg.ForwardUsername, cfg.ForwardPassword)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	// Best-effort: clear any existing integration before applying the desired configuration.
	if err := deleteForwardServiceNowIntegration(ctx, fwdUser, fwdPass); err != nil {
		// Ignore not-found; treat everything else as failure so users see the cause.
		if !errors.Is(err, errForwardIntegrationNotConfigured) {
			return &ConfigureForwardServiceNowTicketingResponse{Configured: false, Message: err.Error()}, nil
		}
	}

	if err := patchForwardServiceNowIntegration(ctx, fwdUser, fwdPass, cfg.InstanceURL, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		return &ConfigureForwardServiceNowTicketingResponse{Configured: false, Message: err.Error()}, nil
	}
	return &ConfigureForwardServiceNowTicketingResponse{Configured: true, Message: "configured"}, nil
}

// InstallUserServiceNowDemo installs/configures the ServiceNow Connectivity Ticket demo into the user's ServiceNow instance.
//
//encore:api auth method=POST path=/api/user/integrations/servicenow/install
func (s *Service) InstallUserServiceNowDemo(ctx context.Context) (*InstallUserServiceNowDemoResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)

	ctxCfg, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cfg, err := getUserServiceNowConfig(ctxCfg, s.db, box, user.Username)
	if err != nil || cfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ServiceNow not configured").Err()
	}

	fwdUser, fwdPass, err := resolveForwardCredsForServiceNow(ctxCfg, s.db, box, user.Username, cfg.ForwardCollectorConfigID, cfg.ForwardUsername, cfg.ForwardPassword)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
	}

	startedAt := time.Now().UTC()
	_ = updateUserServiceNowInstallStatus(ctx, s.db, user.Username, "running", "", &startedAt, nil)

	assets := loadServiceNowDemoAssets()
	installer := newServiceNowInstaller(serviceNowInstallerConfig{
		InstanceURL:     cfg.InstanceURL,
		AdminUsername:   cfg.AdminUsername,
		AdminPassword:   cfg.AdminPassword,
		ForwardBaseURL:  cfg.ForwardBaseURL,
		ForwardUsername: fwdUser,
		ForwardPassword: fwdPass,
		Assets:          assets,
	})

	if err := installer.Install(ctx); err != nil {
		finishedAt := time.Now().UTC()
		_ = updateUserServiceNowInstallStatus(ctx, s.db, user.Username, "error", err.Error(), &startedAt, &finishedAt)
		return &InstallUserServiceNowDemoResponse{
			Installed: false,
			Status:    "error",
			Message:   err.Error(),
		}, nil
	}

	finishedAt := time.Now().UTC()
	_ = updateUserServiceNowInstallStatus(ctx, s.db, user.Username, "installed", "", &startedAt, &finishedAt)
	return &InstallUserServiceNowDemoResponse{
		Installed: true,
		Status:    "installed",
		Message:   "installed",
	}, nil
}

func normalizeServiceNowInstanceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("instanceUrl is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" {
		u, err = url.Parse("https://" + raw)
		if err != nil {
			return "", err
		}
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("unsupported scheme")
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	out := strings.TrimRight(u.String(), "/")
	// Basic sanity check: must be a host with dot.
	parsed, err := url.Parse(out)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid host")
	}
	return out, nil
}

type userServiceNowConfig struct {
	Username              string
	InstanceURL           string
	AdminUsername         string
	AdminPassword         string
	ForwardBaseURL        string
	ForwardCollectorConfigID string
	ForwardUsername       string
	ForwardPassword       string
	LastInstallStatus     string
	LastInstallError      string
	LastInstallStartedAt  time.Time
	LastInstallFinishedAt time.Time
	UpdatedAt             time.Time
	DecryptionFailed      bool
}

func (c *userServiceNowConfig) toAPI() *UserServiceNowConfigResponse {
	if c == nil {
		return &UserServiceNowConfigResponse{Configured: false}
	}
	updatedAt := ""
	if !c.UpdatedAt.IsZero() {
		updatedAt = c.UpdatedAt.UTC().Format(time.RFC3339)
	}
	startedAt := ""
	if !c.LastInstallStartedAt.IsZero() {
		startedAt = c.LastInstallStartedAt.UTC().Format(time.RFC3339)
	}
	finishedAt := ""
	if !c.LastInstallFinishedAt.IsZero() {
		finishedAt = c.LastInstallFinishedAt.UTC().Format(time.RFC3339)
	}
	configured := c.InstanceURL != "" && c.AdminUsername != "" && c.AdminPassword != "" &&
		(c.ForwardCollectorConfigID != "" || (c.ForwardUsername != "" && c.ForwardPassword != ""))
	return &UserServiceNowConfigResponse{
		Configured:            configured,
		InstanceURL:           c.InstanceURL,
		AdminUsername:         c.AdminUsername,
		HasAdminPassword:      c.AdminPassword != "",
		ForwardCollectorID:    c.ForwardCollectorConfigID,
		ForwardUsername:       c.ForwardUsername,
		HasForwardPassword:    c.ForwardPassword != "",
		UpdatedAt:             updatedAt,
		LastInstallStatus:     c.LastInstallStatus,
		LastInstallError:      c.LastInstallError,
		LastInstallStartedAt:  startedAt,
		LastInstallFinishedAt: finishedAt,
	}
}

func getUserServiceNowConfig(ctx context.Context, db *sql.DB, box *secretBox, username string) (*userServiceNowConfig, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	row := db.QueryRowContext(ctx, `SELECT instance_url, admin_username, admin_password,
  forward_base_url, forward_collector_config_id, forward_username, forward_password,
  COALESCE(last_install_status, ''), COALESCE(last_install_error, ''),
  COALESCE(last_install_started_at, 'epoch'::timestamptz),
  COALESCE(last_install_finished_at, 'epoch'::timestamptz),
  updated_at
FROM sf_user_servicenow_configs WHERE username=$1`, username)
	var instanceURL, adminUser, adminPass, fwdBase, fwdCollectorID, fwdUser, fwdPass string
	var status, installErr string
	var startedAt, finishedAt, updatedAt time.Time
	if err := row.Scan(&instanceURL, &adminUser, &adminPass, &fwdBase, &fwdCollectorID, &fwdUser, &fwdPass, &status, &installErr, &startedAt, &finishedAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}

	rec := &userServiceNowConfig{
		Username:          username,
		LastInstallStatus: strings.TrimSpace(status),
		LastInstallError:  strings.TrimSpace(installErr),
		UpdatedAt:         updatedAt,
	}
	if startedAt.Unix() > 0 {
		rec.LastInstallStartedAt = startedAt
	}
	if finishedAt.Unix() > 0 {
		rec.LastInstallFinishedAt = finishedAt
	}

	dec := func(cipher string) (string, bool) {
		if strings.TrimSpace(cipher) == "" {
			return "", false
		}
		if box == nil {
			return "", true
		}
		plain, err := box.decrypt(cipher)
		if err != nil {
			return "", true
		}
		return strings.TrimSpace(plain), false
	}
	var failed bool
	if v, bad := dec(instanceURL); bad {
		failed = true
	} else {
		rec.InstanceURL = v
	}
	if v, bad := dec(adminUser); bad {
		failed = true
	} else {
		rec.AdminUsername = v
	}
	if v, bad := dec(adminPass); bad {
		failed = true
	} else {
		rec.AdminPassword = v
	}
	if v, bad := dec(fwdBase); bad {
		failed = true
	} else {
		rec.ForwardBaseURL = v
	}
	if v, bad := dec(fwdCollectorID); bad {
		failed = true
	} else {
		rec.ForwardCollectorConfigID = v
	}
	if v, bad := dec(fwdUser); bad {
		failed = true
	} else {
		rec.ForwardUsername = v
	}
	if v, bad := dec(fwdPass); bad {
		failed = true
	} else {
		rec.ForwardPassword = v
	}
	if failed {
		rec.DecryptionFailed = true
		rec.InstanceURL = ""
		rec.AdminUsername = ""
		rec.AdminPassword = ""
		rec.ForwardBaseURL = ""
		rec.ForwardCollectorConfigID = ""
		rec.ForwardUsername = ""
		rec.ForwardPassword = ""
	}
	if strings.TrimSpace(rec.ForwardBaseURL) == "" {
		rec.ForwardBaseURL = defaultServiceNowForwardBaseURL
	}
	return rec, nil
}

func putUserServiceNowConfig(ctx context.Context, db *sql.DB, box *secretBox, cfg userServiceNowConfig) error {
	if strings.TrimSpace(cfg.Username) == "" {
		return fmt.Errorf("username is required")
	}
	if box == nil {
		return fmt.Errorf("secret box unavailable")
	}
	enc := func(v string) (string, error) {
		return box.encrypt(strings.TrimSpace(v))
	}
	instanceURL, err := enc(cfg.InstanceURL)
	if err != nil {
		return err
	}
	adminUser, err := enc(cfg.AdminUsername)
	if err != nil {
		return err
	}
	adminPass, err := enc(cfg.AdminPassword)
	if err != nil {
		return err
	}
	fwdBase, err := enc(cfg.ForwardBaseURL)
	if err != nil {
		return err
	}
	fwdCollectorID, err := enc(cfg.ForwardCollectorConfigID)
	if err != nil {
		return err
	}
	fwdUser, err := enc(cfg.ForwardUsername)
	if err != nil {
		return err
	}
	fwdPass, err := enc(cfg.ForwardPassword)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `INSERT INTO sf_user_servicenow_configs (
  username, instance_url, admin_username, admin_password,
  forward_base_url, forward_collector_config_id, forward_username, forward_password,
  updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
ON CONFLICT (username) DO UPDATE SET
  instance_url=EXCLUDED.instance_url,
  admin_username=EXCLUDED.admin_username,
  admin_password=EXCLUDED.admin_password,
  forward_base_url=EXCLUDED.forward_base_url,
  forward_collector_config_id=EXCLUDED.forward_collector_config_id,
  forward_username=EXCLUDED.forward_username,
  forward_password=EXCLUDED.forward_password,
  updated_at=now()`,
		cfg.Username, instanceURL, adminUser, adminPass, fwdBase, fwdCollectorID, fwdUser, fwdPass,
	)
	return err
}

func updateUserServiceNowInstallStatus(ctx context.Context, db *sql.DB, username, status, installErr string, startedAt, finishedAt *time.Time) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	setStarted := sql.NullTime{}
	if startedAt != nil {
		setStarted = sql.NullTime{Valid: true, Time: *startedAt}
	}
	setFinished := sql.NullTime{}
	if finishedAt != nil {
		setFinished = sql.NullTime{Valid: true, Time: *finishedAt}
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_user_servicenow_configs
SET last_install_status=$2,
  last_install_error=$3,
  last_install_started_at=COALESCE($4, last_install_started_at),
  last_install_finished_at=COALESCE($5, last_install_finished_at),
  updated_at=now()
WHERE username=$1`, username, status, installErr, nullTimeOrNil(setStarted), nullTimeOrNil(setFinished))
	return err
}

func nullTimeOrNil(nt sql.NullTime) any {
	if nt.Valid {
		return nt.Time
	}
	return nil
}
