package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

// Forward Networks persistence
//
// This is a generic wrapper around the saved Forward networks table that was
// originally added for Policy Reports. Capacity tooling also uses these
// user-managed networks.

// ---- User-owned Forward Networks ----

// CreateUserForwardNetwork stores a Forward network id for the current user.
//
//encore:api auth method=POST path=/api/fwd
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
//encore:api auth method=GET path=/api/fwd
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
//encore:api auth method=DELETE path=/api/fwd/:networkRef
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
