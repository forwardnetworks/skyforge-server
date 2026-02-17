package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

// Forward Networks (user-context scoped)
//
// This is a generic wrapper around the saved Forward networks table that was
// originally added for Policy Reports. Capacity tooling also uses these
// user-managed networks.

// ---- User-scoped Forward Networks ----

// CreateUserForwardNetwork stores a Forward network id for the current user (not tied to a user context).
//
//encore:api auth method=POST path=/api/forward-networks
func (s *Service) CreateUserForwardNetwork(ctx context.Context, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	out, err := upsertUserPolicyReportForwardNetwork(ctx, s.db, user.Username, user.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return out, nil
}

// ListUserForwardNetworks lists saved Forward networks for the current user.
//
//encore:api auth method=GET path=/api/forward-networks
func (s *Service) ListUserForwardNetworks(ctx context.Context) (*PolicyReportListForwardNetworksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	out, err := listUserPolicyReportForwardNetworks(ctx, s.db, user.Username)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListForwardNetworksResponse{Networks: []PolicyReportForwardNetwork{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list networks").Err()
	}
	return &PolicyReportListForwardNetworksResponse{Networks: out}, nil
}

// DeleteUserForwardNetwork deletes a saved Forward network (by uuid id or by forwardNetworkId).
//
//encore:api auth method=DELETE path=/api/forward-networks/:networkRef
func (s *Service) DeleteUserForwardNetwork(ctx context.Context, networkRef string) (*PolicyReportDecisionResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("db not configured").Err()
	}
	if err := deleteUserPolicyReportForwardNetwork(ctx, s.db, user.Username, networkRef); err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportDecisionResponse{Ok: true}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete network").Err()
	}
	return &PolicyReportDecisionResponse{Ok: true}, nil
}

// CreateFwdNetwork stores a Forward network id for the current user.
//
//encore:api auth method=POST path=/api/fwd/networks
func (s *Service) CreateFwdNetwork(ctx context.Context, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
	return s.CreateUserForwardNetwork(ctx, req)
}

// ListFwdNetworks lists saved Forward networks for the current user.
//
//encore:api auth method=GET path=/api/fwd/networks
func (s *Service) ListFwdNetworks(ctx context.Context) (*PolicyReportListForwardNetworksResponse, error) {
	return s.ListUserForwardNetworks(ctx)
}

// DeleteFwdNetwork deletes a saved Forward network.
//
//encore:api auth method=DELETE path=/api/fwd/networks/:networkRef
func (s *Service) DeleteFwdNetwork(ctx context.Context, networkRef string) (*PolicyReportDecisionResponse, error) {
	return s.DeleteUserForwardNetwork(ctx, networkRef)
}

// ---- UserContext-scoped Forward Networks ----

// CreateUserContextForwardNetwork stores a Forward network id for a user context.
func (s *Service) CreateUserContextForwardNetwork(ctx context.Context, id string, req *PolicyReportCreateForwardNetworkRequest) (*PolicyReportForwardNetwork, error) {
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
	out, err := createPolicyReportForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	return out, nil
}

// ListUserContextForwardNetworks lists saved Forward networks for a user context.
func (s *Service) ListUserContextForwardNetworks(ctx context.Context, id string) (*PolicyReportListForwardNetworksResponse, error) {
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
	out, err := listPolicyReportForwardNetworks(ctx, s.db, pc.userContext.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListForwardNetworksResponse{Networks: []PolicyReportForwardNetwork{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list networks").Err()
	}
	return &PolicyReportListForwardNetworksResponse{Networks: out}, nil
}

// DeleteUserContextForwardNetwork deletes a saved Forward network (by uuid id or by forwardNetworkId).
func (s *Service) DeleteUserContextForwardNetwork(ctx context.Context, id string, networkRef string) (*PolicyReportDecisionResponse, error) {
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
	if err := deletePolicyReportForwardNetwork(ctx, s.db, pc.userContext.ID, networkRef); err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportDecisionResponse{Ok: true}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete network").Err()
	}
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
