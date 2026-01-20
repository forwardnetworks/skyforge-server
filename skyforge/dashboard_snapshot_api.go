package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

// DashboardSnapshot returns the latest dashboard snapshot.
//
// This is a non-streaming companion to `/api/dashboard/events` used by the UI
// to quickly populate state (and during SSE reconnects).
//
//encore:api auth method=GET path=/api/dashboard/snapshot
func (s *Service) DashboardSnapshot(ctx context.Context) (*dashboardSnapshot, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	claims := claimsFromAuthUser(user)
	if claims == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("unauthorized").Err()
	}
	snap, err := loadDashboardSnapshot(ctx, s, claims)
	if err != nil {
		return nil, err
	}
	return snap, nil
}
