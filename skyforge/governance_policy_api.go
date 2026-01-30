package skyforge

import (
	"context"
	"time"

	"encore.dev/beta/errs"
)

type AdminGovernancePolicyResponse struct {
	Policy      GovernancePolicy `json:"policy"`
	RetrievedAt string           `json:"retrievedAt"`
}

// GetGovernancePolicy returns the current governance policy (admin only).
//
//encore:api auth method=GET path=/api/admin/governance/policy tag:admin
func (s *Service) GetGovernancePolicy(ctx context.Context) (*AdminGovernancePolicyResponse, error) {
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	p, err := loadGovernancePolicy(ctx, s.db)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load governance policy").Err()
	}
	return &AdminGovernancePolicyResponse{
		Policy:      p,
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

type UpdateGovernancePolicyRequest struct {
	Policy GovernancePolicy `json:"policy"`
}

type UpdateGovernancePolicyResponse struct {
	Status    string           `json:"status"`
	Policy    GovernancePolicy `json:"policy"`
	UpdatedAt string           `json:"updatedAt"`
}

// UpdateGovernancePolicy updates the governance policy (admin only).
//
//encore:api auth method=PUT path=/api/admin/governance/policy tag:admin
func (s *Service) UpdateGovernancePolicy(ctx context.Context, req *UpdateGovernancePolicyRequest) (*UpdateGovernancePolicyResponse, error) {
	admin, err := requireAdmin()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	p := normalizeGovernancePolicy(req.Policy)
	if err := saveGovernancePolicy(ctx, s.db, p); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save governance policy").Err()
	}
	writeAuditEvent(ctx, s.db, admin.Username, true, "", "admin.governance.policy.update", "", "")
	now := time.Now().UTC().Format(time.RFC3339)
	return &UpdateGovernancePolicyResponse{
		Status:    "ok",
		Policy:    p,
		UpdatedAt: now,
	}, nil
}
