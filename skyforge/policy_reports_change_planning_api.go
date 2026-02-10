package skyforge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"encore.dev/beta/errs"
)

// SimulateWorkspacePolicyReportChangePlanning simulates a rule change against a set of flows (no config push).
//
//encore:api auth method=POST path=/api/workspaces/:id/policy-reports/change-planning/simulate
func (s *Service) SimulateWorkspacePolicyReportChangePlanning(ctx context.Context, id string, req *PolicyReportChangePlanningRequest) (*PolicyReportChangePlanningResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}
	networkID := strings.TrimSpace(req.NetworkID)
	if networkID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("networkId is required").Err()
	}
	if len(req.Flows) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("flows are required").Err()
	}
	if len(req.Flows) > 500 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("too many flows (max 500)").Err()
	}

	op := strings.ToUpper(strings.TrimSpace(req.Change.Op))
	if op == "" {
		op = "ADD"
	}
	switch op {
	case "ADD", "REMOVE", "MODIFY":
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unsupported change op").Err()
	}
	if req.Change.Rule.Index < 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("rule index must be >= 0").Err()
	}

	// Load embedded NQE for flow-to-rules.
	checkID := "acl-flow-to-rules.nqe"
	queryText, err := policyReportsReadNQE(checkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("embedded check missing").Meta("checkId", checkID).Err()
	}

	client, err := s.policyReportsForwardClient(ctx, pc.workspace.ID, pc.claims.Username, networkID)
	if err != nil {
		return nil, err
	}

	snapshotID := strings.TrimSpace(req.SnapshotID)
	deviceFilter := strings.TrimSpace(req.DeviceName)

	totalFlows := 0
	totalDevices := map[string]bool{}
	changedCount := 0
	var impacts []PolicyReportFlowImpact

	for _, f := range req.Flows {
		flow, err := normalizePolicyReportFlowTuple(f)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		totalFlows++

		// Execute NQE flow-to-rules for this flow, then group by device and simulate the change locally.
		params := map[string]any{
			"srcIp":                  flow.SrcIP,
			"dstIp":                  flow.DstIP,
			"ipProto":                flow.IPProto,
			"dstPort":                flow.DstPort,
			"firewallsOnly":          req.FirewallsOnly,
			"includeImplicitDefault": req.IncludeImplicitDefault,
		}

		query := url.Values{}
		query.Set("networkId", networkID)
		if snapshotID != "" {
			query.Set("snapshotId", snapshotID)
		}
		payload := map[string]any{
			"query":      queryText,
			"parameters": params,
			// Keep query bounded; this is a demo endpoint and flow-to-rules can explode for any-any flows.
			"queryOptions": map[string]any{"maxNumItems": 5000, "maxSeconds": 30},
		}

		resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/nqe", query, payload)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
		}

		nqeOut, err := policyReportsNormalizeNQEResponseForCheck(checkID, body)
		if err != nil || nqeOut == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("invalid Forward response").Err()
		}

		var items []policyReportsFlowToRulesItem
		if err := json.Unmarshal(nqeOut.Results, &items); err != nil {
			// If we cannot decode, return a clear upstream body snippet.
			return nil, errs.B().Code(errs.Unavailable).Msg("unexpected NQE result shape").Meta("upstream", strings.TrimSpace(string(nqeOut.Results))).Err()
		}

		// Group matches by device.
		byDevice := map[string][]policyReportsFlowToRulesItem{}
		for _, it := range items {
			dev := strings.TrimSpace(it.Device)
			if dev == "" {
				continue
			}
			if deviceFilter != "" && !strings.EqualFold(deviceFilter, dev) {
				continue
			}
			byDevice[dev] = append(byDevice[dev], it)
		}

		// If the user specified a deviceName filter, always emit an impact for it
		// even if there are no matching rules (so ADD/MODIFY can still show effect).
		if deviceFilter != "" {
			if _, ok := byDevice[deviceFilter]; !ok {
				byDevice[deviceFilter] = nil
			}
		}

		// Stable ordering for response UX.
		devices := make([]string, 0, len(byDevice))
		for d := range byDevice {
			devices = append(devices, d)
		}
		sort.Strings(devices)

		for _, dev := range devices {
			matches := byDevice[dev]
			sort.Slice(matches, func(i, j int) bool { return matches[i].RuleIndex < matches[j].RuleIndex })

			before := policyReportsFirstMatchDecision(matches)
			after, reason := policyReportsSimulateAfterDecision(flow, matches, req.Change)

			impact := PolicyReportFlowImpact{
				Device:         dev,
				Flow:           flow,
				BeforeDecision: before.Decision,
				AfterDecision:  after.Decision,
				BeforeRule:     before.Rule,
				AfterRule:      after.Rule,
				BeforeIndex:    before.Index,
				AfterIndex:     after.Index,
				Changed:        policyReportsDecisionChanged(before, after),
				Reason:         reason,
			}

			totalDevices[dev] = true
			if impact.Changed {
				changedCount++
			}
			impacts = append(impacts, impact)
		}
	}

	return &PolicyReportChangePlanningResponse{
		TotalFlows:   totalFlows,
		TotalDevices: len(totalDevices),
		ChangedCount: changedCount,
		Impacts:      impacts,
	}, nil
}
