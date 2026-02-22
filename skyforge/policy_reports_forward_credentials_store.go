package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

type policyReportForwardCreds struct {
	BaseURL       string
	SkipTLSVerify bool
	Username      string
	Password      string
	UpdatedAt     time.Time
}

func getPolicyReportForwardCreds(ctx context.Context, db *sql.DB, box *secretBox, workspaceID, username, forwardNetworkID string) (*policyReportForwardCreds, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	username = strings.ToLower(strings.TrimSpace(username))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || username == "" || forwardNetworkID == "" {
		return nil, fmt.Errorf("invalid input")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var baseEnc, userEnc, passEnc sql.NullString
	var skipTLS sql.NullBool
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
SELECT base_url_enc, forward_username_enc, forward_password_enc,
       COALESCE(skip_tls_verify, false),
       updated_at
  FROM sf_policy_report_forward_network_credentials
 WHERE user_id=$1 AND username=$2 AND forward_network_id=$3
`, workspaceID, username, forwardNetworkID).Scan(&baseEnc, &userEnc, &passEnc, &skipTLS, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
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

func putPolicyReportForwardCreds(ctx context.Context, db *sql.DB, box *secretBox, workspaceID, actor, forwardNetworkID string, req PolicyReportPutForwardCredentialsRequest) (*policyReportForwardCreds, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || actor == "" || forwardNetworkID == "" {
		return nil, fmt.Errorf("invalid input")
	}

	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	fwdUser := strings.TrimSpace(req.Username)
	if fwdUser == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Allow empty password to mean "keep existing".
	password := strings.TrimSpace(req.Password)
	if password == "" {
		existing, _ := getPolicyReportForwardCreds(ctx, db, box, workspaceID, actor, forwardNetworkID)
		if existing == nil || strings.TrimSpace(existing.Password) == "" {
			return nil, fmt.Errorf("password is required")
		}
		password = existing.Password
	}

	encBase, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return nil, err
	}
	encUser, err := encryptIfPlain(box, fwdUser)
	if err != nil {
		return nil, err
	}
	encPass, err := encryptIfPlain(box, password)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx, `
INSERT INTO sf_policy_report_forward_network_credentials (
  user_id, username, forward_network_id,
  base_url_enc, forward_username_enc, forward_password_enc,
  skip_tls_verify, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,now())
ON CONFLICT (user_id, username, forward_network_id) DO UPDATE SET
  base_url_enc=excluded.base_url_enc,
  forward_username_enc=excluded.forward_username_enc,
  forward_password_enc=excluded.forward_password_enc,
  skip_tls_verify=excluded.skip_tls_verify,
  updated_at=now()
`, workspaceID, actor, forwardNetworkID, encBase, encUser, encPass, req.SkipTLSVerify)
	if err != nil {
		return nil, err
	}

	out := &policyReportForwardCreds{
		BaseURL:       baseURL,
		SkipTLSVerify: req.SkipTLSVerify,
		Username:      fwdUser,
		Password:      password,
	}
	_ = db.QueryRowContext(ctx, `
SELECT updated_at
  FROM sf_policy_report_forward_network_credentials
 WHERE user_id=$1 AND username=$2 AND forward_network_id=$3
`, workspaceID, actor, forwardNetworkID).Scan(&out.UpdatedAt)
	return out, nil
}

func deletePolicyReportForwardCreds(ctx context.Context, db *sql.DB, workspaceID, username, forwardNetworkID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	username = strings.ToLower(strings.TrimSpace(username))
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if workspaceID == "" || username == "" || forwardNetworkID == "" {
		return fmt.Errorf("invalid input")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	res, err := db.ExecContext(ctx, `
DELETE FROM sf_policy_report_forward_network_credentials
 WHERE user_id=$1 AND username=$2 AND forward_network_id=$3
`, workspaceID, username, forwardNetworkID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

