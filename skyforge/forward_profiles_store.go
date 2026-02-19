package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	forwardProfileSaaSName   = "__settings_saas"
	forwardProfileOnPremName = "__settings_onprem"
	forwardProfileUserPrefix = "__profile__:"
)

type userForwardProfile struct {
	ID            string
	Name          string
	BaseURL       string
	SkipTLSVerify bool
	Username      string
	HasPassword   bool
	UpdatedAt     time.Time
}

func isHiddenForwardCollectorConfigName(name string) bool {
	name = strings.TrimSpace(name)
	return name == forwardProfileSaaSName || name == forwardProfileOnPremName || strings.HasPrefix(name, forwardProfileUserPrefix)
}

func forwardProfileRecordName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return forwardProfileUserPrefix + name
}

func forwardProfileDisplayName(recordName string) string {
	recordName = strings.TrimSpace(recordName)
	if !strings.HasPrefix(recordName, forwardProfileUserPrefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(recordName, forwardProfileUserPrefix))
}

func getUserForwardProfileByName(ctx context.Context, db *sql.DB, box *secretBox, username, name string) (*userForwardProfile, error) {
	if db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	username = strings.TrimSpace(username)
	name = strings.TrimSpace(name)
	if username == "" || name == "" {
		return nil, nil
	}

	rows, err := listUserForwardCollectorConfigRows(ctx, db, box, username)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if strings.TrimSpace(r.Name) != name {
			continue
		}
		baseURL := strings.TrimSpace(r.BaseURL)
		if baseURL == "" {
			baseURL = defaultForwardBaseURL
		}
		return &userForwardProfile{
			ID:            strings.TrimSpace(r.ID),
			Name:          name,
			BaseURL:       baseURL,
			SkipTLSVerify: r.SkipTLSVerify,
			Username:      strings.TrimSpace(r.ForwardUsername),
			HasPassword:   strings.TrimSpace(r.ForwardPassword) != "",
			UpdatedAt:     r.UpdatedAt,
		}, nil
	}
	return nil, nil
}

func upsertUserForwardProfile(ctx context.Context, db *sql.DB, box *secretBox, username, name, baseURL string, skipTLSVerify bool, forwardUsername, forwardPassword string) (*userForwardProfile, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	username = strings.TrimSpace(username)
	name = strings.TrimSpace(name)
	baseURL = strings.TrimSpace(baseURL)
	forwardUsername = strings.TrimSpace(forwardUsername)
	forwardPassword = strings.TrimSpace(forwardPassword)
	if username == "" || name == "" {
		return nil, fmt.Errorf("username and profile name are required")
	}
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	if forwardUsername == "" {
		return nil, fmt.Errorf("forward username is required")
	}

	existing, err := getUserForwardProfileByName(ctx, db, box, username, name)
	if err != nil {
		return nil, err
	}
	if forwardPassword == "" && existing != nil && existing.HasPassword {
		// Keep the existing secret unless caller provided a replacement.
		var passEnc sql.NullString
		if err := db.QueryRowContext(ctx, `
SELECT forward_password
FROM sf_user_forward_collectors
WHERE username=$1 AND name=$2
`, username, name).Scan(&passEnc); err == nil && strings.TrimSpace(passEnc.String) != "" {
			if plain, decErr := box.decrypt(passEnc.String); decErr == nil {
				forwardPassword = strings.TrimSpace(plain)
			}
		}
	}
	if forwardPassword == "" {
		return nil, fmt.Errorf("forward password is required")
	}

	encBaseURL, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return nil, err
	}
	encUser, err := encryptIfPlain(box, forwardUsername)
	if err != nil {
		return nil, err
	}
	encPass, err := encryptIfPlain(box, forwardPassword)
	if err != nil {
		return nil, err
	}

	id := uuid.NewString()
	if existing != nil && strings.TrimSpace(existing.ID) != "" {
		id = strings.TrimSpace(existing.ID)
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO sf_user_forward_collectors (
  id, username, name,
  base_url, skip_tls_verify, forward_username, forward_password,
  collector_id, collector_username, authorization_key,
  created_at, updated_at, is_default
) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,NULL,now(),now(),false)
ON CONFLICT (username, name) DO UPDATE SET
  base_url=excluded.base_url,
  skip_tls_verify=excluded.skip_tls_verify,
  forward_username=excluded.forward_username,
  forward_password=excluded.forward_password,
  collector_id=NULL,
  collector_username=NULL,
  authorization_key=NULL,
  is_default=false,
  updated_at=now()
`, id, username, name, encBaseURL, skipTLSVerify, encUser, encPass)
	if err != nil {
		return nil, err
	}
	return getUserForwardProfileByName(ctx, db, box, username, name)
}

func deleteUserForwardProfileByName(ctx context.Context, db *sql.DB, username, name string) error {
	if db == nil {
		return fmt.Errorf("database unavailable")
	}
	username = strings.TrimSpace(username)
	name = strings.TrimSpace(name)
	if username == "" || name == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_user_forward_collectors WHERE username=$1 AND name=$2`, username, name)
	return err
}

func listUserForwardCredentialProfiles(ctx context.Context, db *sql.DB, box *secretBox, username string) ([]userForwardProfile, error) {
	rows, err := listUserForwardCollectorConfigRows(ctx, db, box, username)
	if err != nil {
		return nil, err
	}
	out := make([]userForwardProfile, 0, len(rows))
	for _, r := range rows {
		display := forwardProfileDisplayName(r.Name)
		if display == "" {
			continue
		}
		baseURL := strings.TrimSpace(r.BaseURL)
		if baseURL == "" {
			baseURL = defaultForwardBaseURL
		}
		out = append(out, userForwardProfile{
			ID:            strings.TrimSpace(r.ID),
			Name:          display,
			BaseURL:       baseURL,
			SkipTLSVerify: r.SkipTLSVerify,
			Username:      strings.TrimSpace(r.ForwardUsername),
			HasPassword:   strings.TrimSpace(r.ForwardPassword) != "",
			UpdatedAt:     r.UpdatedAt,
		})
	}
	return out, nil
}
