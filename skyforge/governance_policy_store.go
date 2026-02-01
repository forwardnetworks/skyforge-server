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

	// AllowUserByosNetlabServers controls whether non-admin users may use user-scoped Netlab BYOS servers (user:... refs).
	AllowUserByosNetlabServers bool `json:"allowUserByosNetlabServers"`

	// AllowUserByosContainerlabServers controls whether non-admin users may use user-scoped Containerlab BYOS servers (user:... refs).
	AllowUserByosContainerlabServers bool `json:"allowUserByosContainerlabServers"`

	// AllowUserExternalTemplateRepos controls whether non-admin users may use template source = external (user-scoped external repos).
	AllowUserExternalTemplateRepos bool `json:"allowUserExternalTemplateRepos"`

	// AllowCustomTemplateRepos controls whether non-admin users may use template source = custom.
	// This is distinct from "external" because "custom" can reference arbitrary repos and is therefore riskier.
	AllowCustomTemplateRepos bool `json:"allowCustomTemplateRepos"`
}

func defaultGovernancePolicy() GovernancePolicy {
	return GovernancePolicy{
		MaxDeploymentsPerUser: 0,
		MaxCollectorsPerUser:  0,
		AllowUserByosNetlabServers:       true,
		AllowUserByosContainerlabServers: true,
		AllowUserExternalTemplateRepos:   true,
		AllowCustomTemplateRepos:         true,
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
	applyGovernancePolicyBackfillDefaults(raw, &p)
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

// applyGovernancePolicyBackfillDefaults ensures newly-added fields get sane defaults
// when older stored policy JSON does not include them.
//
// For booleans, Go's json unmarshaler uses false for "missing", so we need to
// distinguish "unset" vs "explicitly false". We do that by checking for key
// presence in the raw JSON.
func applyGovernancePolicyBackfillDefaults(raw string, p *GovernancePolicy) {
	if p == nil || strings.TrimSpace(raw) == "" {
		return
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return
	}
	if _, ok := keys["allowUserByosNetlabServers"]; !ok {
		p.AllowUserByosNetlabServers = true
	}
	if _, ok := keys["allowUserByosContainerlabServers"]; !ok {
		p.AllowUserByosContainerlabServers = true
	}
	if _, ok := keys["allowUserExternalTemplateRepos"]; !ok {
		p.AllowUserExternalTemplateRepos = true
	}
	if _, ok := keys["allowCustomTemplateRepos"]; !ok {
		p.AllowCustomTemplateRepos = true
	}
}
