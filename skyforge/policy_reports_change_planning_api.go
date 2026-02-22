package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

// SimulateWorkspacePolicyReportChangePlanning simulates a rule change against a set of flows (no config push).
//
// This endpoint is intentionally stubbed for now. Earlier iterations depended on
// fast-changing NQE output shapes and would become brittle quickly.
func (s *Service) SimulateWorkspacePolicyReportChangePlanning(ctx context.Context, id string, req *PolicyReportChangePlanningRequest) (*PolicyReportChangePlanningResponse, error) {
	_ = s
	_ = ctx
	_ = id
	_ = req
	return nil, errs.B().Code(errs.Unimplemented).Msg("change planning is not implemented yet").Err()
}
