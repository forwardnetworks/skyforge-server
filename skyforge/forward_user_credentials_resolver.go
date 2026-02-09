package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// preferredUserForwardCollectorConfigID returns the collector config id to use as the user's
// default Forward credentials source.
//
// Priority:
// 1) sf_user_settings.default_forward_collector_config_id
// 2) sf_user_forward_collectors where is_default=true
func preferredUserForwardCollectorConfigID(ctx context.Context, db *sql.DB, username string) (string, error) {
	if db == nil {
		return "", nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", nil
	}

	ctxReq, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Preferred: explicit default in sf_user_settings.
	var explicit sql.NullString
	if err := db.QueryRowContext(ctxReq, `SELECT default_forward_collector_config_id FROM sf_user_settings WHERE user_id=$1`, username).Scan(&explicit); err == nil {
		if v := strings.TrimSpace(explicit.String); v != "" {
			return v, nil
		}
	} else if err != nil {
		if !errors.Is(err, sql.ErrNoRows) && !isMissingDBRelation(err) {
			return "", err
		}
	}

	// Fallback: whichever collector is marked default.
	var id sql.NullString
	if err := db.QueryRowContext(ctxReq, `SELECT id FROM sf_user_forward_collectors WHERE username=$1 AND COALESCE(is_default,false)=true ORDER BY updated_at DESC LIMIT 1`, username).Scan(&id); err == nil {
		return strings.TrimSpace(id.String), nil
	} else if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return "", nil
		}
		return "", err
	}
	return "", nil
}

func forwardConfigForUserPreferredCollector(ctx context.Context, db *sql.DB, sessionSecret string, username string) (*forwardCredentials, error) {
	if db == nil {
		return nil, nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, nil
	}
	cfgID, err := preferredUserForwardCollectorConfigID(ctx, db, username)
	if err != nil || strings.TrimSpace(cfgID) == "" {
		return nil, err
	}

	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// sf_user_forward_collectors stores encrypted values (base_url, forward_username, forward_password, etc).
	var baseURLEnc, fwdUserEnc, fwdPassEnc string
	var collectorUserEnc, authKeyEnc string
	var skipTLSVerify bool
	err = db.QueryRowContext(ctxReq, `SELECT base_url, COALESCE(skip_tls_verify, false),
  forward_username, forward_password,
  COALESCE(collector_username, ''), COALESCE(authorization_key, '')
FROM sf_user_forward_collectors
WHERE username=$1 AND id=$2`, username, cfgID).Scan(
		&baseURLEnc, &skipTLSVerify, &fwdUserEnc, &fwdPassEnc, &collectorUserEnc, &authKeyEnc,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}

	box := newSecretBox(sessionSecret)
	baseURL, err := box.decrypt(baseURLEnc)
	if err != nil {
		return nil, nil
	}
	fwdUser, err := box.decrypt(fwdUserEnc)
	if err != nil {
		return nil, nil
	}
	fwdPass, err := box.decrypt(fwdPassEnc)
	if err != nil {
		return nil, nil
	}
	collectorUser, _ := box.decrypt(collectorUserEnc)
	authKey, _ := box.decrypt(authKeyEnc)

	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	fwdUser = strings.TrimSpace(fwdUser)
	fwdPass = strings.TrimSpace(fwdPass)
	if fwdUser == "" || fwdPass == "" {
		return nil, nil
	}

	collectorUser = strings.TrimSpace(collectorUser)
	authKey = strings.TrimSpace(authKey)
	if collectorUser == "" && authKey != "" {
		if before, _, ok := strings.Cut(authKey, ":"); ok {
			collectorUser = strings.TrimSpace(before)
		}
	}

	return &forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: skipTLSVerify,
		Username:      fwdUser,
		Password:      fwdPass,
		CollectorUser: collectorUser,
	}, nil
}
