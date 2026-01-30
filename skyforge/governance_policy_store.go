package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"encore.dev/rlog"
)

const governancePolicySettingKey = "governance_policy"

// GovernancePolicy is a lightweight guardrail layer (admin-configurable).
//
// All limits are optional. A value of 0 means "unlimited/disabled".
type GovernancePolicy struct {
	// MaxDeploymentsPerUser caps the number of deployment definitions a user can create across all workspaces.
	MaxDeploymentsPerUser int `json:"maxDeploymentsPerUser"`

	// MaxCollectorsPerUser caps the number of in-cluster Forward collectors a user can create.
	MaxCollectorsPerUser int `json:"maxCollectorsPerUser"`
}

func defaultGovernancePolicy() GovernancePolicy {
	return GovernancePolicy{
		MaxDeploymentsPerUser: 0,
		MaxCollectorsPerUser:  0,
	}
}

func normalizeGovernancePolicy(p GovernancePolicy) GovernancePolicy {
	if p.MaxDeploymentsPerUser < 0 {
		p.MaxDeploymentsPerUser = 0
	}
	if p.MaxCollectorsPerUser < 0 {
		p.MaxCollectorsPerUser = 0
	}
	return p
}

func loadGovernancePolicy(ctx context.Context, db *sql.DB) (GovernancePolicy, error) {
	if db == nil {
		return defaultGovernancePolicy(), nil
	}
	raw, ok, err := getSetting(ctx, db, governancePolicySettingKey)
	if err != nil {
		return defaultGovernancePolicy(), err
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultGovernancePolicy(), nil
	}

	var p GovernancePolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		rlog.Warn("governance policy parse failed; using defaults", "err", err)
		return defaultGovernancePolicy(), nil
	}
	return normalizeGovernancePolicy(p), nil
}

func saveGovernancePolicy(ctx context.Context, db *sql.DB, p GovernancePolicy) error {
	p = normalizeGovernancePolicy(p)
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return upsertSetting(ctx, db, governancePolicySettingKey, string(b))
}
