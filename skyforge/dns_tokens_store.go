package skyforge

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type dnsTokenRecord struct {
	Token     string
	Zone      string
	UpdatedAt time.Time
}

func (s *Service) getDNSToken(ctx context.Context, username string) (*dnsTokenRecord, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		tokenEnc  string
		zone      string
		updatedAt time.Time
	)
	err := s.db.QueryRowContext(ctx, `SELECT token, zone, updated_at FROM sf_dns_tokens WHERE username=$1`, username).Scan(&tokenEnc, &zone, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	token, err := s.box.decrypt(tokenEnc)
	if err != nil {
		return nil, err
	}
	return &dnsTokenRecord{Token: strings.TrimSpace(token), Zone: strings.TrimSpace(zone), UpdatedAt: updatedAt}, nil
}

func (s *Service) putDNSToken(ctx context.Context, username, token, zone string) error {
	if s.db == nil {
		return errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if s.box == nil {
		return errs.B().Code(errs.Unavailable).Msg("encryption unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	token = strings.TrimSpace(token)
	zone = strings.TrimSpace(zone)
	if username == "" || token == "" || zone == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("username, token, and zone are required").Err()
	}

	enc, err := s.box.encrypt(token)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sf_dns_tokens (username, token, zone, updated_at)
VALUES ($1,$2,$3,now())
ON CONFLICT (username) DO UPDATE SET token=excluded.token, zone=excluded.zone, updated_at=now()`, username, enc, zone)
	return err
}
