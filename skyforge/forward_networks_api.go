package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

// Forward Networks (workspace scoped)
//
// This is a generic wrapper around the saved Forward networks table that was
// originally added for Policy Reports. Capacity tooling also uses these
// user-managed networks.

// CreateWorkspaceForwardNetwork stores a Forward network id for a workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/forward-networks
func (s *Service) CreateWorkspaceForwardNetwork(ctx context.Context, id string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireWorkspaceEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	out, err := createPolicyReportForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return out, nil
}

// ListWorkspaceForwardNetworks lists saved Forward networks for a workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks
func (s *Service) ListWorkspaceForwardNetworks(ctx context.Context, id string) (*PolicyReportListForwardNetworksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	out, err := listPolicyReportForwardNetworks(ctx, s.db, pc.workspace.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListForwardNetworksResponse{Networks: []PolicyReportForwardNetwork{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list networks").Err()
	}
	return &PolicyReportListForwardNetworksResponse{Networks: out}, nil
}

// DeleteWorkspaceForwardNetwork deletes a saved Forward network (by uuid id or by forwardNetworkId).
//
//encore:api auth method=DELETE path=/api/workspaces/:id/forward-networks/:networkRef
func (s *Service) DeleteWorkspaceForwardNetwork(ctx context.Context, id string, networkRef string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireWorkspaceEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if err := deletePolicyReportForwardNetwork(ctx, s.db, pc.workspace.ID, networkRef); err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportDecisionResponse{Ok: true}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete network").Err()
	}
	return &PolicyReportDecisionResponse{Ok: true}, nil
}

