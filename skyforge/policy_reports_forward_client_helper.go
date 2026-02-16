package skyforge

import (
	"context"
	"database/sql"

	"encore.dev/beta/errs"
)

// policyReportsForwardClientFor mirrors (*Service).policyReportsForwardClient but can be used
// from cron jobs and other non-request contexts.
func policyReportsForwardClientFor(ctx context.Context, db *sql.DB, sessionSecret string, ownerID, username, forwardNetworkID string) (*forwardClient, error) {
	rec, err := resolveForwardCredentialsFor(ctx, db, sessionSecret, ownerID, username, forwardNetworkID, forwardCredResolveOpts{})
	if err != nil {
		return nil, err
	}
	client, err := newForwardClient(*rec)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return client, nil
}
