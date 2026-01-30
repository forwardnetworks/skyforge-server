package skyforge

import (
	"context"
	"database/sql"

	"encore.dev/beta/errs"
)

func enforceGovernanceDeploymentCreate(ctx context.Context, db *sql.DB, username string, policy GovernancePolicy) error {
	if db == nil {
		return nil
	}
	if policy.MaxDeploymentsPerUser <= 0 {
		return nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_deployments WHERE created_by=$1`, username).Scan(&count); err != nil {
		return errs.B().Code(errs.Unavailable).Msg("failed to evaluate governance policy").Err()
	}
	if count >= policy.MaxDeploymentsPerUser {
		return errs.B().Code(errs.FailedPrecondition).Msg("governance limit reached: too many deployments for user").Err()
	}
	return nil
}

func enforceGovernanceCollectorCreate(ctx context.Context, db *sql.DB, username string, policy GovernancePolicy) error {
	if db == nil {
		return nil
	}
	if policy.MaxCollectorsPerUser <= 0 {
		return nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_user_forward_collectors WHERE username=$1`, username).Scan(&count); err != nil {
		if isMissingDBRelation(err) {
			return nil
		}
		return errs.B().Code(errs.Unavailable).Msg("failed to evaluate governance policy").Err()
	}
	if count >= policy.MaxCollectorsPerUser {
		return errs.B().Code(errs.FailedPrecondition).Msg("governance limit reached: too many collectors for user").Err()
	}
	return nil
}
