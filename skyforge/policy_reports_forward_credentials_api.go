package skyforge

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"encore.dev/beta/errs"
)

// GetUserContextPolicyReportForwardNetworkCredentials returns the current user's credentials status for a Forward network.
//
//encore:api auth method=GET path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/credentials
func (s *Service) GetUserContextPolicyReportForwardNetworkCredentials(ctx context.Context, id string, forwardNetworkId string) (*PolicyReportForwardCredentialsStatus, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	rec, err := getPolicyReportForwardCreds(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userContext.ID, pc.claims.Username, forwardNetworkId)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load credentials").Err()
	}
	if rec == nil {
		return &PolicyReportForwardCredentialsStatus{Configured: false}, nil
	}
	return &PolicyReportForwardCredentialsStatus{
		Configured:    true,
		BaseURL:       rec.BaseURL,
		SkipTLSVerify: rec.SkipTLSVerify,
		Username:      rec.Username,
		HasPassword:   rec.Password != "",
		UpdatedAt:     rec.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// PutUserContextPolicyReportForwardNetworkCredentials upserts the current user's credentials for a Forward network.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/credentials
func (s *Service) PutUserContextPolicyReportForwardNetworkCredentials(ctx context.Context, id string, forwardNetworkId string, req *PolicyReportPutForwardCredentialsRequest) (*PolicyReportForwardCredentialsStatus, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserContextEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	out, err := putPolicyReportForwardCreds(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userContext.ID, pc.claims.Username, forwardNetworkId, *req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.userContext.ID, pc.claims.Username, "policy_reports.forward_credentials.put", map[string]any{
		"forwardNetworkId": forwardNetworkId,
		"baseUrl":          out.BaseURL,
		"skipTlsVerify":    out.SkipTLSVerify,
		"username":         out.Username,
	})
	return &PolicyReportForwardCredentialsStatus{
		Configured:    true,
		BaseURL:       out.BaseURL,
		SkipTLSVerify: out.SkipTLSVerify,
		Username:      out.Username,
		HasPassword:   out.Password != "",
		UpdatedAt:     out.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// DeleteUserContextPolicyReportForwardNetworkCredentials clears the current user's credentials for a Forward network.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/credentials
func (s *Service) DeleteUserContextPolicyReportForwardNetworkCredentials(ctx context.Context, id string, forwardNetworkId string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserContextEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}

	if err := deletePolicyReportForwardCreds(ctx, s.db, pc.userContext.ID, pc.claims.Username, forwardNetworkId); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errs.B().Code(errs.Unavailable).Msg("request canceled").Err()
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("credentials not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete credentials").Err()
	}
	policyReportAudit(ctx, s.db, pc.userContext.ID, pc.claims.Username, "policy_reports.forward_credentials.delete", map[string]any{
		"forwardNetworkId": forwardNetworkId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
