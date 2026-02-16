package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"encore.dev/beta/errs"
)

type ForwardCredentialSetSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	BaseURL       string `json:"baseUrl,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username,omitempty"`
	HasPassword   bool   `json:"hasPassword"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

type ListForwardCredentialSetsResponse struct {
	CredentialSets []ForwardCredentialSetSummary `json:"credentialSets"`
}

type CreateForwardCredentialSetRequest struct {
	Name          string `json:"name"`
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

type UpdateForwardCredentialSetRequest struct {
	Name          string `json:"name"`
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	Password      string `json:"password,omitempty"` // empty means "keep existing"
}

type DeleteForwardCredentialSetResponse struct {
	Deleted bool `json:"deleted"`
}

// ListUserForwardCredentialSets lists Forward credential sets owned by the current user.
//
//encore:api auth method=GET path=/api/forward/credential-sets
func (s *Service) ListUserForwardCredentialSets(ctx context.Context) (*ListForwardCredentialSetsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)
	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctxReq, `
SELECT id, name,
       COALESCE(base_url_enc, ''), COALESCE(skip_tls_verify, false),
       COALESCE(forward_username_enc, ''), COALESCE(forward_password_enc, ''),
       updated_at
  FROM sf_credentials
 WHERE provider='forward' AND owner_username=$1 AND owner_username IS NULL
 ORDER BY updated_at DESC, name ASC
`, user.Username)
	if err != nil {
		if isMissingDBRelation(err) {
			return &ListForwardCredentialSetsResponse{CredentialSets: []ForwardCredentialSetSummary{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list credential sets").Err()
	}
	defer rows.Close()

	out := []ForwardCredentialSetSummary{}
	for rows.Next() {
		var (
			id, name string
			baseEnc  sql.NullString
			skipTLS  sql.NullBool
			userEnc  sql.NullString
			passEnc  sql.NullString
			updated  sql.NullTime
		)
		if err := rows.Scan(&id, &name, &baseEnc, &skipTLS, &userEnc, &passEnc, &updated); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to list credential sets").Err()
		}
		baseURL, _ := decryptNullStringOrEmpty(box, baseEnc)
		fwdUser, _ := decryptNullStringOrEmpty(box, userEnc)
		hasPass := strings.TrimSpace(passEnc.String) != ""
		updatedAt := ""
		if updated.Valid {
			updatedAt = updated.Time.UTC().Format(time.RFC3339)
		}
		out = append(out, ForwardCredentialSetSummary{
			ID:            strings.TrimSpace(id),
			Name:          strings.TrimSpace(name),
			BaseURL:       strings.TrimSpace(baseURL),
			SkipTLSVerify: skipTLS.Valid && skipTLS.Bool,
			Username:      strings.TrimSpace(fwdUser),
			HasPassword:   hasPass,
			UpdatedAt:     updatedAt,
		})
	}
	return &ListForwardCredentialSetsResponse{CredentialSets: out}, nil
}

// CreateUserForwardCredentialSet creates a Forward credential set owned by the current user.
//
//encore:api auth method=POST path=/api/forward/credential-sets
func (s *Service) CreateUserForwardCredentialSet(ctx context.Context, req *CreateForwardCredentialSetRequest) (*ForwardCredentialSetSummary, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	fwdUser := strings.TrimSpace(req.Username)
	fwdPass := strings.TrimSpace(req.Password)
	if fwdUser == "" || fwdPass == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username and password are required").Err()
	}

	// Quick auth check.
	{
		ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		client, err := newForwardClient(forwardCredentials{
			BaseURL:       baseURL,
			SkipTLSVerify: req.SkipTLSVerify,
			Username:      fwdUser,
			Password:      fwdPass,
		})
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
		}
		if _, err := forwardListCollectors(ctx2, client); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden") {
				return nil, errs.B().Code(errs.Unauthenticated).Msg("Forward authentication failed").Err()
			}
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to reach Forward").Err()
		}
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	id := uuid.NewString()
	tx, err := s.db.BeginTx(ctxReq, nil)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save credential set").Err()
	}
	defer func() { _ = tx.Rollback() }()

	if err := insertUserForwardCredentialSet(ctxReq, tx, box, id, user.Username, name, forwardCredentials{
		BaseURL:       baseURL,
		SkipTLSVerify: req.SkipTLSVerify,
		Username:      fwdUser,
		Password:      fwdPass,
	}, "", "", ""); err != nil {
		log.Printf("forward credential set create: %v", err)
		if isMissingDBRelation(err) {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("database migrations are pending (missing sf_credentials table)").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save credential set").Err()
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save credential set").Err()
	}

	return &ForwardCredentialSetSummary{
		ID:            id,
		Name:          name,
		BaseURL:       baseURL,
		SkipTLSVerify: req.SkipTLSVerify,
		Username:      fwdUser,
		HasPassword:   true,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// UpdateUserForwardCredentialSet updates a Forward credential set owned by the current user.
//
//encore:api auth method=PUT path=/api/forward/credential-sets/:id
func (s *Service) UpdateUserForwardCredentialSet(ctx context.Context, id string, req *UpdateForwardCredentialSetRequest) (*ForwardCredentialSetSummary, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" || req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid input").Err()
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL == "" {
		baseURL = defaultForwardBaseURL
	}
	fwdUser := strings.TrimSpace(req.Username)
	if fwdUser == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("username is required").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	existing, err := getUserForwardCredentialSet(ctxReq, s.db, box, user.Username, id)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load credential set").Err()
	}
	if existing == nil {
		return nil, errs.B().Code(errs.NotFound).Msg("credential set not found").Err()
	}
	password := strings.TrimSpace(req.Password)
	if password == "" {
		password = existing.Password
	}
	if strings.TrimSpace(password) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("password is required").Err()
	}

	// Quick auth check.
	{
		ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		client, err := newForwardClient(forwardCredentials{
			BaseURL:       baseURL,
			SkipTLSVerify: req.SkipTLSVerify,
			Username:      fwdUser,
			Password:      password,
		})
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
		}
		if _, err := forwardListCollectors(ctx2, client); err != nil {
			return nil, errs.B().Code(errs.Unauthenticated).Msg("Forward authentication failed").Err()
		}
	}

	encBase, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to encrypt credential set").Err()
	}
	encUser, err := encryptIfPlain(box, fwdUser)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to encrypt credential set").Err()
	}
	encPass, err := encryptIfPlain(box, password)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to encrypt credential set").Err()
	}

	res, err := s.db.ExecContext(ctxReq, `
UPDATE sf_credentials
   SET name=$1,
       base_url_enc=$2,
       skip_tls_verify=$3,
       forward_username_enc=$4,
       forward_password_enc=$5,
       updated_at=now()
 WHERE id=$6 AND provider='forward' AND owner_username=$7 AND owner_username IS NULL
`, name, encBase, req.SkipTLSVerify, encUser, encPass, id, user.Username)
	if err != nil {
		log.Printf("forward credential set update: %v", err)
		if isMissingDBRelation(err) {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("database migrations are pending (missing sf_credentials table)").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update credential set").Err()
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("credential set not found").Err()
	}

	return &ForwardCredentialSetSummary{
		ID:            id,
		Name:          name,
		BaseURL:       baseURL,
		SkipTLSVerify: req.SkipTLSVerify,
		Username:      fwdUser,
		HasPassword:   true,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DeleteUserForwardCredentialSet deletes a Forward credential set owned by the current user.
// Deletion is blocked if the credential set is referenced elsewhere.
//
//encore:api auth method=DELETE path=/api/forward/credential-sets/:id
func (s *Service) DeleteUserForwardCredentialSet(ctx context.Context, id string) (*DeleteForwardCredentialSetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("id is required").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Block delete if referenced.
	var refs int
	if err := s.db.QueryRowContext(ctxReq, `
SELECT
  (SELECT COUNT(*) FROM sf_user_forward_collectors WHERE credential_id=$1) +
  (SELECT COUNT(*) FROM sf_policy_report_forward_network_credentials WHERE credential_id=$1) +
  (SELECT COUNT(*) FROM sf_owner_forward_credentials WHERE credential_id=$1)
`, id).Scan(&refs); err == nil && refs > 0 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("credential set is in use").Err()
	}

	res, err := s.db.ExecContext(ctxReq, `
DELETE FROM sf_credentials
 WHERE id=$1 AND provider='forward' AND owner_username=$2 AND owner_username IS NULL
`, id, user.Username)
	if err != nil {
		if isMissingDBRelation(err) {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("database migrations are pending (missing sf_credentials table)").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete credential set").Err()
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return &DeleteForwardCredentialSetResponse{Deleted: false}, nil
	}
	return &DeleteForwardCredentialSetResponse{Deleted: true}, nil
}

func (s *Service) forwardCredentialSetNameForCollectorConfig(collectorConfigName string) string {
	n := strings.TrimSpace(collectorConfigName)
	if n == "" {
		return "collector"
	}
	return n
}

func (s *Service) forwardCredentialSetNameForPolicyReports(forwardNetworkID string) string {
	fid := strings.TrimSpace(forwardNetworkID)
	if fid == "" {
		return "policy-reports"
	}
	return fmt.Sprintf("policy-reports %s", fid)
}
