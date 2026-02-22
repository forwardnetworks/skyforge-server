package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

// Forward Networks (user-scope scoped)
//
// This is a generic wrapper around the saved Forward networks table that was
// originally added for Policy Reports. Capacity tooling also uses these
// user-managed networks.

// CreateUserScopeForwardNetwork stores a Forward network id for a user scope.
//
//encore:api auth method=POST path=/api/users/:id/forward-networks
func (s *Service) CreateUserScopeForwardNetwork(ctx context.Context, id string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserScopeEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	out, err := createPolicyReportForwardNetwork(ctx, s.db, pc.userScope.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return out, nil
}

// ListUserScopeForwardNetworks lists saved Forward networks for a user scope.
//
//encore:api auth method=GET path=/api/users/:id/forward-networks
func (s *Service) ListUserScopeForwardNetworks(ctx context.Context, id string) (*PolicyReportListForwardNetworksResponse, error) {
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
	out, err := listPolicyReportForwardNetworks(ctx, s.db, pc.userScope.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListForwardNetworksResponse{Networks: []PolicyReportForwardNetwork{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list networks").Err()
	}
	return &PolicyReportListForwardNetworksResponse{Networks: out}, nil
}

// DeleteUserScopeForwardNetwork deletes a saved Forward network (by uuid id or by forwardNetworkId).
//
//encore:api auth method=DELETE path=/api/users/:id/forward-networks/:networkRef
func (s *Service) DeleteUserScopeForwardNetwork(ctx context.Context, id string, networkRef string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if err := requireUserScopeEditor(pc); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if err := deletePolicyReportForwardNetwork(ctx, s.db, pc.userScope.ID, networkRef); err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportDecisionResponse{Ok: true}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete network").Err()
	}
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
