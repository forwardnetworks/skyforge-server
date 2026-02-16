package skyforge

import (
	"context"
	"database/sql"
	"errors"

	"encore.dev/beta/errs"
)

// CreateUserPolicyReportForwardNetwork stores a Forward network id for Policy Reports.
func (s *Service) CreateUserPolicyReportForwardNetwork(ctx context.Context, id string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	out, err := createPolicyReportForwardNetwork(ctx, s.db, pc.context.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.forward_network.create", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetwork,
		"name":             out.Name,
	})
	return out, nil
}

// ListUserPolicyReportForwardNetworks lists saved Forward networks for Policy Reports.
func (s *Service) ListUserPolicyReportForwardNetworks(ctx context.Context, id string) (*PolicyReportListForwardNetworksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	out, err := listPolicyReportForwardNetworks(ctx, s.db, pc.context.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListForwardNetworksResponse{Networks: []PolicyReportForwardNetwork{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list networks").Err()
	}
	return &PolicyReportListForwardNetworksResponse{Networks: out}, nil
}

// DeleteUserPolicyReportForwardNetwork deletes a saved Forward network (by uuid id or by forwardNetworkId).
func (s *Service) DeleteUserPolicyReportForwardNetwork(ctx context.Context, id string, networkRef string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if err := deletePolicyReportForwardNetwork(ctx, s.db, pc.context.ID, networkRef); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errs.B().Code(errs.Unavailable).Msg("request canceled").Err()
		}
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("network not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete network").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.forward_network.delete", map[string]any{
		"networkRef": networkRef,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
