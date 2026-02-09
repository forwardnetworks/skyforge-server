package skyforge

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

func (s *Service) mcpGetOrRotateWebhookToken(ctx context.Context, username string, rotate bool) (string, error) {
	if s == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	if s.db == nil || s.box == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if rotate {
		token, err := generateOpaqueToken(16)
		if err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to generate token").Err()
		}
		if err := s.putWebhookToken(ctx, username, token); err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to store token").Err()
		}
		b, _ := json.Marshal(map[string]any{
			"token":         token,
			"ingestBaseUrl": strings.TrimRight(s.cfg.PublicURL, "/") + "/hooks/" + token,
			"updatedAt":     time.Now().UTC().Format(time.RFC3339),
		})
		return string(b), nil
	}
	rec, err := s.getWebhookToken(ctx, username)
	if err != nil {
		return "", errs.B().Code(errs.Internal).Msg("failed to load webhook token").Err()
	}
	if rec == nil || strings.TrimSpace(rec.Token) == "" {
		token, err := generateOpaqueToken(16)
		if err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to generate token").Err()
		}
		if err := s.putWebhookToken(ctx, username, token); err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to store token").Err()
		}
		rec = &webhookTokenRecord{Token: token, UpdatedAt: time.Now().UTC()}
	}
	b, _ := json.Marshal(map[string]any{
		"token":         rec.Token,
		"ingestBaseUrl": strings.TrimRight(s.cfg.PublicURL, "/") + "/hooks/" + rec.Token,
		"updatedAt":     rec.UpdatedAt.UTC().Format(time.RFC3339),
	})
	return string(b), nil
}

func (s *Service) mcpGetOrRotateSnmpToken(ctx context.Context, username string, rotate bool) (string, error) {
	if s == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}
	if s.db == nil || s.box == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	host := strings.TrimSpace(s.cfg.PublicURL)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")

	if rotate {
		comm, err := generateCommunity(username)
		if err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to generate community").Err()
		}
		if err := s.putSnmpTrapToken(ctx, username, comm); err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to store community").Err()
		}
		b, _ := json.Marshal(map[string]any{
			"community":    comm,
			"listenHost":   host,
			"listenPort":   162,
			"updatedAtUtc": time.Now().UTC().Format(time.RFC3339),
		})
		return string(b), nil
	}
	rec, err := s.getSnmpTrapToken(ctx, username)
	if err != nil {
		return "", errs.B().Code(errs.Internal).Msg("failed to load snmp token").Err()
	}
	if rec == nil || strings.TrimSpace(rec.Community) == "" {
		comm, err := generateCommunity(username)
		if err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to generate community").Err()
		}
		if err := s.putSnmpTrapToken(ctx, username, comm); err != nil {
			return "", errs.B().Code(errs.Internal).Msg("failed to store community").Err()
		}
		rec = &snmpTrapTokenRecord{Community: comm, UpdatedAt: time.Now().UTC()}
	}
	b, _ := json.Marshal(map[string]any{
		"community":    rec.Community,
		"listenHost":   host,
		"listenPort":   162,
		"updatedAtUtc": rec.UpdatedAt.UTC().Format(time.RFC3339),
	})
	return string(b), nil
}
