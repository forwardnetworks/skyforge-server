package skyforge

import (
	"context"
	"database/sql"
	"errors"

	"encore.dev/beta/errs"
)

// CreateUserContextPolicyReportZone creates a zone (CIDR set) for a Forward network.
//
//encore:api auth method=POST path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/zones
func (s *Service) CreateUserContextPolicyReportZone(ctx context.Context, id string, forwardNetworkId string, req *PolicyReportCreateZoneRequest) (*PolicyReportZone, error) {
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

	out, err := createPolicyReportZone(ctx, s.db, pc.claims.Username, pc.userContext.ID, pc.claims.Username, forwardNetworkId, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.userContext.ID, pc.claims.Username, "policy_reports.zone.create", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetworkID,
		"name":             out.Name,
	})
	return out, nil
}

// ListUserContextPolicyReportZones lists zones (CIDR sets) for a Forward network.
//
//encore:api auth method=GET path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/zones
func (s *Service) ListUserContextPolicyReportZones(ctx context.Context, id string, forwardNetworkId string) (*PolicyReportListZonesResponse, error) {
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

	zones, err := listPolicyReportZones(ctx, s.db, pc.claims.Username, pc.userContext.ID, forwardNetworkId)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListZonesResponse{Zones: []PolicyReportZone{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list zones").Err()
	}
	return &PolicyReportListZonesResponse{Zones: zones}, nil
}

// UpdateUserContextPolicyReportZone updates a zone (CIDR set).
//
//encore:api auth method=PUT path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/zones/:zoneId
func (s *Service) UpdateUserContextPolicyReportZone(ctx context.Context, id string, forwardNetworkId string, zoneId string, req *PolicyReportUpdateZoneRequest) (*PolicyReportZone, error) {
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

	out, err := updatePolicyReportZone(ctx, s.db, pc.claims.Username, pc.userContext.ID, forwardNetworkId, zoneId, req)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("zone not found").Err()
		}
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.userContext.ID, pc.claims.Username, "policy_reports.zone.update", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetworkID,
		"name":             out.Name,
	})
	return out, nil
}

// DeleteUserContextPolicyReportZone deletes a zone.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/policy-reports/networks/:forwardNetworkId/zones/:zoneId
func (s *Service) DeleteUserContextPolicyReportZone(ctx context.Context, id string, forwardNetworkId string, zoneId string) (*PolicyReportDecisionResponse, error) {
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
	if err := deletePolicyReportZone(ctx, s.db, pc.claims.Username, pc.userContext.ID, forwardNetworkId, zoneId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("zone not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete zone").Err()
	}
	policyReportAudit(ctx, s.db, pc.userContext.ID, pc.claims.Username, "policy_reports.zone.delete", map[string]any{
		"id":               zoneId,
		"forwardNetworkId": forwardNetworkId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
