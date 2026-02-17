package skyforge

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type forwardCredResolveOpts struct {
	// ExplicitCredentialID optionally forces use of a specific saved Forward credential set.
	// For MCP, this is supplied via X-Forward-Credential-Id on the Forward-scoped endpoint.
	ExplicitCredentialID string

	// CollectorConfigID optionally pins which user collector config to use (deployment-specific).
	CollectorConfigID string
}

func resolveForwardCredentialsFor(ctx context.Context, db *sql.DB, sessionSecret string, userContextID, username, forwardNetworkID string, opts forwardCredResolveOpts) (*forwardCredentials, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	userContextID = strings.TrimSpace(userContextID)
	username = strings.ToLower(strings.TrimSpace(username))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	opts.ExplicitCredentialID = strings.TrimSpace(opts.ExplicitCredentialID)
	opts.CollectorConfigID = strings.TrimSpace(opts.CollectorConfigID)

	box := newSecretBox(sessionSecret)

	// 1) Explicit override (MCP).
	if opts.ExplicitCredentialID != "" {
		ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if username != "" {
			if set, err := getUserForwardCredentialSet(ctxReq, db, box, username, opts.ExplicitCredentialID); err == nil && set != nil {
				cfg := set.toForwardClientCreds()
				if strings.TrimSpace(cfg.BaseURL) == "" {
					cfg.BaseURL = defaultForwardBaseURL
				}
				if strings.TrimSpace(cfg.Username) == "" || strings.TrimSpace(cfg.Password) == "" {
					return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credential set is missing username/password").Err()
				}
				return &cfg, nil
			}
		}
		if userContextID != "" {
			if set, err := getWorkspaceForwardCredentialSet(ctxReq, db, box, userContextID, opts.ExplicitCredentialID); err == nil && set != nil {
				cfg := set.toForwardClientCreds()
				if strings.TrimSpace(cfg.BaseURL) == "" {
					cfg.BaseURL = defaultForwardBaseURL
				}
				if strings.TrimSpace(cfg.Username) == "" || strings.TrimSpace(cfg.Password) == "" {
					return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward credential set is missing username/password").Err()
				}
				return &cfg, nil
			}
		}
		return nil, errs.B().Code(errs.PermissionDenied).Msg("Forward credential set not accessible").Err()
	}

	// 2) Policy Reports per-user per-network credentials (if configured).
	if userContextID != "" && username != "" && forwardNetworkID != "" {
		ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if pr, err := getPolicyReportForwardCreds(ctxReq, db, box, userContextID, username, forwardNetworkID); err == nil && pr != nil {
			cfg := forwardCredentials{
				BaseURL:       pr.BaseURL,
				SkipTLSVerify: pr.SkipTLSVerify,
				Username:      pr.Username,
				Password:      pr.Password,
			}
			if strings.TrimSpace(cfg.BaseURL) == "" {
				cfg.BaseURL = defaultForwardBaseURL
			}
			if strings.TrimSpace(cfg.Username) != "" && strings.TrimSpace(cfg.Password) != "" {
				return &cfg, nil
			}
		}
	}

	// 3) User collector config pin (deployment-specific).
	if username != "" && opts.CollectorConfigID != "" {
		ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cfg, err := forwardConfigForUserCollectorConfigID(ctxReq, db, sessionSecret, username, opts.CollectorConfigID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
		if cfg != nil && strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.Username) != "" && strings.TrimSpace(cfg.Password) != "" {
			return cfg, nil
		}
	}

	// 4) User default collector config (preferred) -> legacy per-user credentials fallback.
	if username != "" {
		ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cfg, err := forwardConfigForUser(ctxReq, db, sessionSecret, username)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
		if cfg != nil && strings.TrimSpace(cfg.BaseURL) != "" && strings.TrimSpace(cfg.Username) != "" && strings.TrimSpace(cfg.Password) != "" {
			return cfg, nil
		}
	}

	// 5) Legacy user-context-level Forward credentials.
	if userContextID != "" {
		ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cfg, err := getUserContextForwardCredentials(ctxReq, db, box, userContextID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
		if cfg != nil {
			if strings.TrimSpace(cfg.BaseURL) == "" {
				cfg.BaseURL = defaultForwardBaseURL
			}
			if strings.TrimSpace(cfg.Username) != "" && strings.TrimSpace(cfg.Password) != "" {
				return cfg, nil
			}
		}
	}

	return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user/network").Err()
}

func forwardConfigForUser(ctx context.Context, db *sql.DB, sessionSecret string, username string) (*forwardCredentials, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil, nil
	}

	// Preferred: per-user default Forward collector config (sf_user_forward_collectors).
	if cfg, err := forwardConfigForUserPreferredCollector(ctx, db, sessionSecret, username); err == nil && cfg != nil {
		return cfg, nil
	} else if err != nil {
		return nil, err
	}

	// Fallback: explicit default Forward credential set in sf_user_settings.
	{
		ctxReq, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		var credID sql.NullString
		if err := db.QueryRowContext(ctxReq, `
SELECT COALESCE(default_forward_credential_id,'')
  FROM sf_user_settings
 WHERE user_id=$1
`, username).Scan(&credID); err == nil {
			id := strings.TrimSpace(credID.String)
			if id != "" {
				box := newSecretBox(sessionSecret)
				ctxReq2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
				defer cancel2()
				if set, err := getUserForwardCredentialSet(ctxReq2, db, box, username, id); err == nil && set != nil {
					baseURL := strings.TrimSpace(set.BaseURL)
					if baseURL == "" {
						baseURL = defaultForwardBaseURL
					}
					if strings.TrimSpace(set.Username) == "" || strings.TrimSpace(set.Password) == "" {
						return nil, nil
					}
					return &forwardCredentials{
						BaseURL:       baseURL,
						SkipTLSVerify: set.SkipTLSVerify,
						Username:      strings.TrimSpace(set.Username),
						Password:      strings.TrimSpace(set.Password),
						CollectorUser: strings.TrimSpace(set.CollectorUsername),
					}, nil
				}
			}
		}
	}
	return nil, nil
}

func forwardConfigForUserCollectorConfigID(ctx context.Context, db *sql.DB, sessionSecret string, username, collectorConfigID string) (*forwardCredentials, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	username = strings.ToLower(strings.TrimSpace(username))
	collectorConfigID = strings.TrimSpace(collectorConfigID)
	if username == "" || collectorConfigID == "" {
		return nil, nil
	}
	// Reuse existing Service helper implementation via a minimal query path:
	// this keeps the credential-set-aware logic in one place.
	//
	// Note: we intentionally call the package-level helper in forward_sync.go by replicating
	// the logic that queries sf_user_forward_collectors and then (if present) loads sf_credentials.
	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var credID sql.NullString
	var baseURLEnc, fwdUserEnc, fwdPassEnc string
	var collectorUserEnc, authKeyEnc string
	var skipTLSVerify bool
	err := db.QueryRowContext(ctxReq, `SELECT COALESCE(credential_id,''),
  COALESCE(base_url,''), COALESCE(skip_tls_verify, false),
  forward_username, forward_password,
  COALESCE(collector_username, ''), COALESCE(authorization_key, '')
FROM sf_user_forward_collectors
WHERE username=$1 AND id=$2`, username, collectorConfigID).Scan(
		&credID, &baseURLEnc, &skipTLSVerify, &fwdUserEnc, &fwdPassEnc, &collectorUserEnc, &authKeyEnc,
	)
	if err != nil {
		if err == sql.ErrNoRows || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}

	box := newSecretBox(sessionSecret)
	if strings.TrimSpace(credID.String) != "" {
		if set, err := getUserForwardCredentialSet(ctxReq, db, box, username, strings.TrimSpace(credID.String)); err == nil && set != nil {
			baseURL := strings.TrimSpace(set.BaseURL)
			if baseURL == "" {
				baseURL = defaultForwardBaseURL
			}
			if strings.TrimSpace(set.Username) == "" || strings.TrimSpace(set.Password) == "" {
				return nil, nil
			}
			return &forwardCredentials{
				BaseURL:       baseURL,
				SkipTLSVerify: set.SkipTLSVerify,
				Username:      strings.TrimSpace(set.Username),
				Password:      strings.TrimSpace(set.Password),
				CollectorUser: strings.TrimSpace(set.CollectorUsername),
			}, nil
		}
		return nil, nil
	}

	// Backward-compat: per-row encrypted values.
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
