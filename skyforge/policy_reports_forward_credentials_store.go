package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

type policyReportForwardCreds struct {
	BaseURL       string
	SkipTLSVerify bool
	Username      string
	Password      string
	UpdatedAt     time.Time
}

func getPolicyReportForwardCreds(ctx context.Context, db *sql.DB, box *secretBox, userContextID, username, forwardNetworkID string) (*policyReportForwardCreds, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	userContextID = strings.TrimSpace(userContextID)
	username = strings.ToLower(strings.TrimSpace(username))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if userContextID == "" || username == "" || forwardNetworkID == "" {
		return nil, fmt.Errorf("invalid input")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var credID sql.NullString
	var baseEnc, userEnc, passEnc sql.NullString
	var skipTLS sql.NullBool
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
SELECT COALESCE(credential_id, ''),
       base_url_enc, forward_username_enc, forward_password_enc,
       COALESCE(skip_tls_verify, false),
       updated_at
  FROM sf_policy_report_forward_network_credentials
 WHERE workspace_id=$1 AND username=$2 AND forward_network_id=$3
`, userContextID, username, forwardNetworkID).Scan(&credID, &baseEnc, &userEnc, &passEnc, &skipTLS, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}

	// Preferred: referenced credential set.
	if strings.TrimSpace(credID.String) != "" {
		set, err := getUserForwardCredentialSet(ctx, db, box, username, strings.TrimSpace(credID.String))
		if err != nil {
			return nil, err
		}
		if set == nil {
			return nil, nil
		}
		out := &policyReportForwardCreds{
			BaseURL:       strings.TrimSpace(set.BaseURL),
			SkipTLSVerify: set.SkipTLSVerify,
			Username:      strings.TrimSpace(set.Username),
			Password:      strings.TrimSpace(set.Password),
		}
		if updatedAt.Valid {
			out.UpdatedAt = updatedAt.Time
		} else if !set.UpdatedAt.IsZero() {
			out.UpdatedAt = set.UpdatedAt
		}
		if out.Username == "" || out.Password == "" {
			return nil, nil
		}
		return out, nil
	}

	baseURL, err := box.decrypt(baseEnc.String)
	if err != nil {
		log.Printf("policy reports forward decrypt base_url (%s/%s): %v", username, forwardNetworkID, err)
		return nil, nil
	}
	fwdUser, err := box.decrypt(userEnc.String)
	if err != nil {
		log.Printf("policy reports forward decrypt username (%s/%s): %v", username, forwardNetworkID, err)
		return nil, nil
	}
	fwdPass, err := box.decrypt(passEnc.String)
	if err != nil {
		log.Printf("policy reports forward decrypt password (%s/%s): %v", username, forwardNetworkID, err)
		return nil, nil
	}

	out := &policyReportForwardCreds{
		BaseURL:       strings.TrimSpace(baseURL),
		SkipTLSVerify: skipTLS.Valid && skipTLS.Bool,
		Username:      strings.TrimSpace(fwdUser),
		Password:      strings.TrimSpace(fwdPass),
	}
	if updatedAt.Valid {
		out.UpdatedAt = updatedAt.Time
	}
	if out.Username == "" || out.Password == "" {
		return nil, nil
	}
	return out, nil
}

func putPolicyReportForwardCreds(ctx context.Context, db *sql.DB, box *secretBox, userContextID, actor, forwardNetworkID string, req PolicyReportPutForwardCredentialsRequest) (*policyReportForwardCreds, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	userContextID = strings.TrimSpace(userContextID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if userContextID == "" || actor == "" || forwardNetworkID == "" {
		return nil, fmt.Errorf("invalid input")
	}

	credID := strings.TrimSpace(req.CredentialID)
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	fwdUser := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)

	ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Resolve existing mapping (if any) for "keep existing password" and for in-place updates.
	var existingCredID sql.NullString
	_ = db.QueryRowContext(ctxReq, `
SELECT COALESCE(credential_id,'')
  FROM sf_policy_report_forward_network_credentials
 WHERE workspace_id=$1 AND username=$2 AND forward_network_id=$3
`, userContextID, actor, forwardNetworkID).Scan(&existingCredID)

	// If the caller didn't specify a credential set, we manage a dedicated set per mapping.
	managedSet := strings.TrimSpace(credID) == ""
	if managedSet {
		if strings.TrimSpace(existingCredID.String) != "" {
			credID = strings.TrimSpace(existingCredID.String)
		} else {
			credID = uuid.NewString()
		}
	}

	// If selecting an existing set explicitly, validate ownership and load values.
	if !managedSet {
		set, err := getUserForwardCredentialSet(ctxReq, db, box, actor, credID)
		if err != nil {
			return nil, err
		}
		if set == nil {
			return nil, fmt.Errorf("credential set not found")
		}
		// For status/audit, reflect the selected set.
		baseURL = set.BaseURL
		fwdUser = set.Username
		password = set.Password
		if strings.TrimSpace(fwdUser) == "" || strings.TrimSpace(password) == "" {
			return nil, fmt.Errorf("credential set is missing username/password")
		}
	}

	// Managed set: create/update the credential set from request fields.
	if managedSet {
		if fwdUser == "" {
			return nil, fmt.Errorf("username is required")
		}

		// Allow empty password to mean "keep existing" (from the existing credential set if present).
		if password == "" && strings.TrimSpace(existingCredID.String) != "" {
			if set, _ := getUserForwardCredentialSet(ctxReq, db, box, actor, strings.TrimSpace(existingCredID.String)); set != nil && strings.TrimSpace(set.Password) != "" {
				password = set.Password
			}
		}
		if password == "" {
			return nil, fmt.Errorf("password is required")
		}

		tx, err := db.BeginTx(ctxReq, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }()

		if err := upsertUserForwardCredentialSetBasic(ctxReq, tx, box, credID, actor, fmt.Sprintf("policy-reports %s", forwardNetworkID), forwardCredentials{
			BaseURL:       baseURL,
			SkipTLSVerify: req.SkipTLSVerify,
			Username:      fwdUser,
			Password:      password,
		}); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	_, err := db.ExecContext(ctxReq, `
INSERT INTO sf_policy_report_forward_network_credentials (
  workspace_id, username, forward_network_id,
  base_url_enc, forward_username_enc, forward_password_enc,
  skip_tls_verify, credential_id, updated_at
) VALUES ($1,$2,$3,NULL,NULL,NULL,$4,$5,now())
ON CONFLICT (workspace_id, username, forward_network_id) DO UPDATE SET
  skip_tls_verify=excluded.skip_tls_verify,
  credential_id=excluded.credential_id,
  updated_at=now()
`, userContextID, actor, forwardNetworkID, req.SkipTLSVerify, credID)
	if err != nil {
		return nil, err
	}

	out := &policyReportForwardCreds{
		BaseURL:       baseURL,
		SkipTLSVerify: req.SkipTLSVerify,
		Username:      fwdUser,
		Password:      password,
	}
	_ = db.QueryRowContext(ctxReq, `
SELECT updated_at
  FROM sf_policy_report_forward_network_credentials
 WHERE workspace_id=$1 AND username=$2 AND forward_network_id=$3
`, userContextID, actor, forwardNetworkID).Scan(&out.UpdatedAt)
	return out, nil
}

func deletePolicyReportForwardCreds(ctx context.Context, db *sql.DB, userContextID, username, forwardNetworkID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	userContextID = strings.TrimSpace(userContextID)
	username = strings.ToLower(strings.TrimSpace(username))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if userContextID == "" || username == "" || forwardNetworkID == "" {
		return fmt.Errorf("invalid input")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_forward_network_credentials
 WHERE workspace_id=$1 AND username=$2 AND forward_network_id=$3
`, userContextID, username, forwardNetworkID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
