package skyforge

import (
	"context"
	"database/sql"
	"errors"

	"encore.dev/beta/errs"
)

// CreateUserPolicyReportZone creates a zone (CIDR set) for a Forward network.
func (s *Service) CreateUserPolicyReportZone(ctx context.Context, id string, forwardNetworkId string, req *PolicyReportCreateZoneRequest) (*PolicyReportZone, error) {
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

	out, err := createPolicyReportZone(ctx, s.db, pc.context.ID, pc.claims.Username, forwardNetworkId, req)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.zone.create", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetworkID,
		"name":             out.Name,
	})
	return out, nil
}

// ListUserPolicyReportZones lists zones (CIDR sets) for a Forward network.
func (s *Service) ListUserPolicyReportZones(ctx context.Context, id string, forwardNetworkId string) (*PolicyReportListZonesResponse, error) {
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

	zones, err := listPolicyReportZones(ctx, s.db, pc.context.ID, forwardNetworkId)
	if err != nil {
		if isMissingDBRelation(err) {
			return &PolicyReportListZonesResponse{Zones: []PolicyReportZone{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list zones").Err()
	}
	return &PolicyReportListZonesResponse{Zones: zones}, nil
}

// UpdateUserPolicyReportZone updates a zone (CIDR set).
func (s *Service) UpdateUserPolicyReportZone(ctx context.Context, id string, forwardNetworkId string, zoneId string, req *PolicyReportUpdateZoneRequest) (*PolicyReportZone, error) {
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

	out, err := updatePolicyReportZone(ctx, s.db, pc.context.ID, forwardNetworkId, zoneId, req)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("zone not found").Err()
		}
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.zone.update", map[string]any{
		"id":               out.ID,
		"forwardNetworkId": out.ForwardNetworkID,
		"name":             out.Name,
	})
	return out, nil
}

// DeleteUserPolicyReportZone deletes a zone.
func (s *Service) DeleteUserPolicyReportZone(ctx context.Context, id string, forwardNetworkId string, zoneId string) (*PolicyReportDecisionResponse, error) {
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
	if err := deletePolicyReportZone(ctx, s.db, pc.context.ID, forwardNetworkId, zoneId); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.B().Code(errs.NotFound).Msg("zone not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete zone").Err()
	}
	policyReportAudit(ctx, s.db, pc.context.ID, pc.claims.Username, "policy_reports.zone.delete", map[string]any{
		"id":               zoneId,
		"forwardNetworkId": forwardNetworkId,
	})
	return &PolicyReportDecisionResponse{Ok: true}, nil
}
