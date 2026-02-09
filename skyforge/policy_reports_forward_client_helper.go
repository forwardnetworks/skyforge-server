package skyforge

import (
	"context"
	"database/sql"
	"strings"

	"encore.dev/beta/errs"
)

// policyReportsForwardClientFor mirrors (*Service).policyReportsForwardClient but can be used
// from cron jobs and other non-request contexts.
func policyReportsForwardClientFor(ctx context.Context, db *sql.DB, sessionSecret string, workspaceID, username, forwardNetworkID string) (*forwardClient, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	box := newSecretBox(sessionSecret)

	// Preferred: per-user per-network credentials (Policy Reports specific).
	if strings.TrimSpace(username) != "" && strings.TrimSpace(forwardNetworkID) != "" {
		if pr, err := getPolicyReportForwardCreds(ctx, db, box, workspaceID, username, forwardNetworkID); err == nil && pr != nil {
			return newForwardClient(forwardCredentials{
				BaseURL:       pr.BaseURL,
				SkipTLSVerify: pr.SkipTLSVerify,
				Username:      pr.Username,
				Password:      pr.Password,
			})
		}
	}

	// Fallback: legacy per-user Forward credentials.
	if strings.TrimSpace(username) != "" {
		// Prefer the user's default collector config if present.
		if cfg, err := forwardConfigForUserPreferredCollector(ctx, db, sessionSecret, strings.ToLower(strings.TrimSpace(username))); err == nil && cfg != nil {
			return newForwardClient(*cfg)
		}

		// Legacy fallback.
		if urec, err := getUserForwardCredentials(ctx, db, box, strings.ToLower(strings.TrimSpace(username))); err == nil && urec != nil {
			return newForwardClient(forwardCredentials{
				BaseURL:       urec.BaseURL,
				SkipTLSVerify: urec.SkipTLSVerify,
				Username:      urec.ForwardUsername,
				Password:      urec.ForwardPassword,
			})
		}
	}

	// Final fallback: workspace-level Forward credentials.
	rec, err := getWorkspaceForwardCredentials(ctx, db, box, workspaceID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
	}
	if rec == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user/network or workspace").Err()
	}
	client, err := newForwardClient(*rec)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return client, nil
}
