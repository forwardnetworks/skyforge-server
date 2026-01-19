package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type APIHealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
	DB     string `json:"db,omitempty"`
	Redis  string `json:"redis,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GetAPIHealth returns a summary of database health.
//
//encore:api public method=GET path=/api/health
func (s *Service) GetAPIHealth(ctx context.Context) (*APIHealthResponse, error) {
	if s.db != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		if err := s.db.PingContext(pingCtx); err != nil {
			return nil, errs.B().
				Code(errs.Unavailable).
				Msg("database unavailable").
				Meta("db", "down").
				Meta("error", sanitizeError(err)).
				Err()
		}
	}
	return &APIHealthResponse{
		Status: "ok",
		Time:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type LDAPHealthResponse struct {
	Status   string `json:"status"`
	URL      string `json:"url"`
	StartTLS bool   `json:"starttls"`
	Time     string `json:"time"`
}

// GetLDAPHealth checks LDAP connectivity.
//
//encore:api public method=GET path=/api/health/ldap
func (s *Service) GetLDAPHealth(ctx context.Context) (*LDAPHealthResponse, error) {
	if strings.TrimSpace(s.cfg.LDAP.URL) == "" || strings.TrimSpace(s.cfg.LDAP.BindTemplate) == "" {
		return &LDAPHealthResponse{
			Status:   "disabled",
			URL:      "",
			StartTLS: false,
			Time:     time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := checkLDAPConnectivity(checkCtx, s.cfg.LDAP); err != nil {
		return nil, errs.B().
			Code(errs.Unavailable).
			Msg("ldap unavailable").
			Meta("error", sanitizeError(err)).
			Err()
	}
	return &LDAPHealthResponse{
		Status:   "ok",
		URL:      s.cfg.LDAP.URL,
		StartTLS: s.cfg.LDAP.UseStartTLS,
		Time:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}
