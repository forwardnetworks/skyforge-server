package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type AssuranceStudioEvaluatePhases struct {
	Routing  *bool `json:"routing,omitempty"`
	Capacity *bool `json:"capacity,omitempty"`
	Security *bool `json:"security,omitempty"`
}

type AssuranceStudioRoutingOptions struct {
	ThresholdUtil *float64 `json:"thresholdUtil,omitempty"` // default 0.8

	Forward     *AssuranceTrafficForwardOptions     `json:"forward,omitempty"`
	Enforcement *AssuranceTrafficEnforcementOptions `json:"enforcement,omitempty"`

	IncludeHops bool `json:"includeHops,omitempty"`
	IncludeACL  bool `json:"includeAcl,omitempty"`
	ProjectLoad bool `json:"projectLoad,omitempty"`
}

type AssuranceStudioCapacityOptions struct {
	IncludeHops  bool  `json:"includeHops,omitempty"`
	PerfFallback *bool `json:"perfFallback,omitempty"` // default true

	// Demo parity: show "what to upgrade" without additional Forward calls by reusing preloaded rollups/inventory.
	IncludeUpgradeCandidates *bool `json:"includeUpgradeCandidates,omitempty"` // default true
}

type AssuranceStudioSecurityOptions struct {
	RequireEnforcement *bool `json:"requireEnforcement,omitempty"`

	// If true, request a return path candidate from Forward so we can evaluate return enforcement/symmetry.
	IncludeReturnPath bool `json:"includeReturnPath,omitempty"`

	RequireSymmetricDelivery *bool `json:"requireSymmetricDelivery,omitempty"`
	RequireReturnEnforcement *bool `json:"requireReturnEnforcement,omitempty"`

	EnforcementDeviceTypes     []string `json:"enforcementDeviceTypes,omitempty"`
	EnforcementDeviceNameParts []string `json:"enforcementDeviceNameParts,omitempty"`
	EnforcementTagParts        []string `json:"enforcementTagParts,omitempty"`

	Intent                  string `json:"intent,omitempty"`
	MaxCandidates           int    `json:"maxCandidates,omitempty"`
	MaxResults              int    `json:"maxResults,omitempty"`
	MaxReturnPathResults    int    `json:"maxReturnPathResults,omitempty"`
	MaxSeconds              int    `json:"maxSeconds,omitempty"`
	MaxOverallSeconds       int    `json:"maxOverallSeconds,omitempty"`
	IncludeTags             *bool  `json:"includeTags,omitempty"`
	IncludeNetworkFunctions *bool  `json:"includeNetworkFunctions,omitempty"`
}

type AssuranceStudioEvaluateRequest struct {
	SnapshotID string `json:"snapshotId,omitempty"`
	// Optional baseline snapshot for routing regression comparisons. If set (and routing is enabled),
	// the backend will run a second Forward paths-bulk against this snapshot and compute a diff.
	BaselineSnapshotID string                   `json:"baselineSnapshotId,omitempty"`
	Window             string                   `json:"window,omitempty"` // 24h|7d|30d
	Demands            []AssuranceTrafficDemand `json:"demands"`

	Phases   *AssuranceStudioEvaluatePhases  `json:"phases,omitempty"`
	Routing  *AssuranceStudioRoutingOptions  `json:"routing,omitempty"`
	Capacity *AssuranceStudioCapacityOptions `json:"capacity,omitempty"`
	Security *AssuranceStudioSecurityOptions `json:"security,omitempty"`
}

type AssuranceStudioRoutingDiffSummary struct {
	TotalDemands int `json:"totalDemands"`
	Changed      int `json:"changed"`

	DeliveryRegression  int `json:"deliveryRegression"`
	DeliveryImprovement int `json:"deliveryImprovement"`
	PathChanged         int `json:"pathChanged"`
	EnforcementChanged  int `json:"enforcementChanged"`
	BottleneckChanged   int `json:"bottleneckChanged"`
	ErrorChanged        int `json:"errorChanged"`
}

type AssuranceStudioRoutingDiffItem struct {
	Index  int                    `json:"index"`
	Demand AssuranceTrafficDemand `json:"demand"`

	Changed bool     `json:"changed"`
	Reasons []string `json:"reasons,omitempty"`

	BaselineForwardingOutcome string `json:"baselineForwardingOutcome,omitempty"`
	CompareForwardingOutcome  string `json:"compareForwardingOutcome,omitempty"`
	BaselineEnforced          *bool  `json:"baselineEnforced,omitempty"`
	CompareEnforced           *bool  `json:"compareEnforced,omitempty"`
	BaselineQueryURL          string `json:"baselineQueryUrl,omitempty"`
	CompareQueryURL           string `json:"compareQueryUrl,omitempty"`
}

type AssuranceStudioRoutingDiffResponse struct {
	BaselineSnapshotID string                            `json:"baselineSnapshotId,omitempty"`
	CompareSnapshotID  string                            `json:"compareSnapshotId,omitempty"`
	Summary            AssuranceStudioRoutingDiffSummary `json:"summary"`
	Items              []AssuranceStudioRoutingDiffItem  `json:"items"`
}

type AssuranceStudioEvaluateResponse struct {
	OwnerUsername    string `json:"ownerUsername"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`

	SnapshotID         string `json:"snapshotId,omitempty"`
	BaselineSnapshotID string `json:"baselineSnapshotId,omitempty"`
	Window             string `json:"window"`

	Routing                   *AssuranceTrafficEvaluateResponse                `json:"routing,omitempty"`
	RoutingBaseline           *AssuranceTrafficEvaluateResponse                `json:"routingBaseline,omitempty"`
	RoutingDiff               *AssuranceStudioRoutingDiffResponse              `json:"routingDiff,omitempty"`
	Capacity                  *ForwardNetworkCapacityPathBottlenecksResponse   `json:"capacity,omitempty"`
	CapacityUpgradeCandidates *ForwardNetworkCapacityUpgradeCandidatesResponse `json:"capacityUpgradeCandidates,omitempty"`
	Security                  *PolicyReportNQEResponse                         `json:"security,omitempty"`

	Errors map[string]string `json:"errors,omitempty"`
	Meta   JSONMap           `json:"meta,omitempty"`
}

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func (s *Service) assuranceStudioForwardClient(ctx context.Context, ownerID, username, forwardNetworkID, collectorConfigID string) (*forwardClient, error) {
	if s == nil || s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	username = strings.TrimSpace(username)
	ownerID = strings.TrimSpace(ownerID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	collectorConfigID = strings.TrimSpace(collectorConfigID)
	if username == "" {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("unauthenticated").Err()
	}

	box := newSecretBox(s.cfg.SessionSecret)

	// Preferred: per-user per-network override creds (reuses Policy Reports credentials table).
	if forwardNetworkID != "" {
		if pr, err := getPolicyReportForwardCreds(ctx, s.db, box, ownerID, username, forwardNetworkID); err == nil && pr != nil {
			return newForwardClient(forwardCredentials{
				BaseURL:       pr.BaseURL,
				SkipTLSVerify: pr.SkipTLSVerify,
				Username:      pr.Username,
				Password:      pr.Password,
			})
		}
	}

	// Next: collector-config specific credentials (for in-cluster collectors).
	var fwdCfg *forwardCredentials
	var err error
	if collectorConfigID != "" {
		fwdCfg, err = s.forwardConfigForUserCollectorConfigID(ctx, username, collectorConfigID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
	}
	// Next: user-level credentials.
	if fwdCfg == nil {
		fwdCfg, err = s.forwardConfigForUser(ctx, username)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
	}
	// Final: scope-level Forward credentials.
	if fwdCfg == nil {
		fwdCfg, err = s.forwardConfigForOwner(ctx, ownerID)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to load Forward credentials").Err()
		}
	}
	if fwdCfg == nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward is not configured for this user/network or user context").Err()
	}
	client, err := newForwardClient(*fwdCfg)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}
	return client, nil
}

type assuranceStudioPreload struct {
	asOf    time.Time
	rollups []CapacityRollupRow
	ifaces  []CapacityInterfaceInventoryRow
}

func callForwardPathsBulk(
	ctx context.Context,
	client *forwardClient,
	forwardNetworkID string,
	snapshotID string,
	payload *fwdPathSearchBulkRequestFull,
) ([]fwdPathSearchResponseFull, string, error) {
	qv := url.Values{}
	if v := strings.TrimSpace(snapshotID); v != "" {
		qv.Set("snapshotId", v)
	}
	rawPath := forwardAPIPathFor(client, "/networks/"+url.PathEscape(forwardNetworkID)+"/paths-bulk")
	resp, body, err := client.doJSON(ctx, http.MethodPost, rawPath, qv, payload)
	if err != nil {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, strings.TrimSpace(string(body)), errs.B().Code(errs.Unavailable).Msg("Forward paths failed").Err()
	}
	var fwdOut []fwdPathSearchResponseFull
	if err := json.Unmarshal(body, &fwdOut); err != nil {
		return nil, "", errs.B().Code(errs.Unavailable).Msg("failed to decode Forward paths response").Err()
	}
	return fwdOut, "", nil
}

func routingRec(it *AssuranceTrafficEvalItem) *AssuranceTrafficCandidate {
	if it == nil {
		return nil
	}
	if len(it.Candidates) == 0 {
		return nil
	}
	idx := it.Recommended
	if idx < 0 || idx >= len(it.Candidates) {
		idx = 0
	}
	return &it.Candidates[idx]
}

func hopSig(h prFwdPathHop) string {
	return strings.TrimSpace(h.DeviceName) + "|" + strings.TrimSpace(h.IngressInterface) + ">" + strings.TrimSpace(h.EgressInterface)
}

func sameHopList(a, b []prFwdPathHop) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if hopSig(a[i]) != hopSig(b[i]) {
			return false
		}
	}
	return true
}

func routingDiff(baseline, compare *AssuranceTrafficEvaluateResponse) *AssuranceStudioRoutingDiffResponse {
	if baseline == nil || compare == nil {
		return nil
	}
	n := len(compare.Items)
	if len(baseline.Items) < n {
		n = len(baseline.Items)
	}

	items := make([]AssuranceStudioRoutingDiffItem, 0, n)
	sum := AssuranceStudioRoutingDiffSummary{TotalDemands: n}

	for i := 0; i < n; i++ {
		bi := baseline.Items[i]
		ci := compare.Items[i]
		out := AssuranceStudioRoutingDiffItem{
			Index:            i,
			Demand:           ci.Demand,
			Changed:          false,
			BaselineQueryURL: strings.TrimSpace(bi.QueryURL),
			CompareQueryURL:  strings.TrimSpace(ci.QueryURL),
		}

		reasons := []string{}
		brec := routingRec(&bi)
		crec := routingRec(&ci)

		if brec != nil {
			out.BaselineForwardingOutcome = strings.TrimSpace(brec.ForwardingOutcome)
			v := brec.Enforced
			out.BaselineEnforced = &v
		}
		if crec != nil {
			out.CompareForwardingOutcome = strings.TrimSpace(crec.ForwardingOutcome)
			v := crec.Enforced
			out.CompareEnforced = &v
		}

		// Delivery change.
		bDel := brec != nil && strings.TrimSpace(brec.ForwardingOutcome) == "DELIVERED"
		cDel := crec != nil && strings.TrimSpace(crec.ForwardingOutcome) == "DELIVERED"
		if bDel != cDel {
			if bDel && !cDel {
				reasons = append(reasons, "delivery_regression")
				sum.DeliveryRegression++
			} else {
				reasons = append(reasons, "delivery_improvement")
				sum.DeliveryImprovement++
			}
		}

		// Error/timeout/no candidates.
		if strings.TrimSpace(bi.Error) != strings.TrimSpace(ci.Error) || bi.TimedOut != ci.TimedOut {
			reasons = append(reasons, "error_changed")
			sum.ErrorChanged++
		}

		// Path changed (only if we have hop lists on both).
		if brec != nil && crec != nil && len(brec.Hops) > 0 && len(crec.Hops) > 0 {
			if !sameHopList(brec.Hops, crec.Hops) {
				reasons = append(reasons, "path_changed")
				sum.PathChanged++
			}
		}

		// Enforcement change.
		if brec != nil && crec != nil && brec.Enforced != crec.Enforced {
			reasons = append(reasons, "enforcement_changed")
			sum.EnforcementChanged++
		}

		// Bottleneck change (only if both present).
		if brec != nil && crec != nil && brec.Bottleneck != nil && crec.Bottleneck != nil {
			if strings.TrimSpace(brec.Bottleneck.DeviceName) != strings.TrimSpace(crec.Bottleneck.DeviceName) ||
				strings.TrimSpace(brec.Bottleneck.InterfaceName) != strings.TrimSpace(crec.Bottleneck.InterfaceName) ||
				strings.TrimSpace(brec.Bottleneck.Direction) != strings.TrimSpace(crec.Bottleneck.Direction) {
				reasons = append(reasons, "bottleneck_changed")
				sum.BottleneckChanged++
			} else if brec.Bottleneck.HeadroomGbps != nil && crec.Bottleneck.HeadroomGbps != nil {
				if math.Abs(*brec.Bottleneck.HeadroomGbps-*crec.Bottleneck.HeadroomGbps) >= 0.25 {
					reasons = append(reasons, "bottleneck_changed")
					sum.BottleneckChanged++
				}
			}
		}

		// Dedup reasons.
		if len(reasons) > 0 {
			seen := map[string]bool{}
			uniq := make([]string, 0, len(reasons))
			for _, r := range reasons {
				if seen[r] {
					continue
				}
				seen[r] = true
				uniq = append(uniq, r)
			}
			reasons = uniq
		}

		out.Reasons = reasons
		out.Changed = len(reasons) > 0
		if out.Changed {
			sum.Changed++
		}
		items = append(items, out)
	}

	return &AssuranceStudioRoutingDiffResponse{
		BaselineSnapshotID: strings.TrimSpace(baseline.SnapshotID),
		CompareSnapshotID:  strings.TrimSpace(compare.SnapshotID),
		Summary:            sum,
		Items:              items,
	}
}

func assuranceStudioEvaluateWithClient(
	ctx context.Context,
	client *forwardClient,
	ownerID, networkRef, forwardNetworkID string,
	req *AssuranceStudioEvaluateRequest,
	pre assuranceStudioPreload,
) (*AssuranceStudioEvaluateResponse, error) {
	if client == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward client unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	// Defaults.
	window := strings.TrimSpace(req.Window)
	if window == "" {
		window = "7d"
	}
	if window != "24h" && window != "7d" && window != "30d" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid window").Err()
	}
	windowDays := 7
	if window == "24h" {
		windowDays = 1
	} else if window == "30d" {
		windowDays = 30
	}

	if len(req.Demands) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("demands required").Err()
	}
	if len(req.Demands) > 200 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("too many demands (max 200)").Err()
	}

	phRouting := true
	phCapacity := true
	phSecurity := false
	if req.Phases != nil {
		phRouting = boolOr(req.Phases.Routing, phRouting)
		phCapacity = boolOr(req.Phases.Capacity, phCapacity)
		phSecurity = boolOr(req.Phases.Security, phSecurity)
	}

	// Build shared Forward paths-bulk payload.
	queries := make([]fwdPathSearchQuery, 0, len(req.Demands))
	for i, d := range req.Demands {
		dst := strings.TrimSpace(d.DstIP)
		if dst == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("missing dstIp at demands[" + fmt.Sprintf("%d", i) + "]").Err()
		}
		queries = append(queries, fwdPathSearchQuery{
			From:    strings.TrimSpace(d.From),
			SrcIP:   strings.TrimSpace(d.SrcIP),
			DstIP:   dst,
			IPProto: d.IPProto,
			SrcPort: strings.TrimSpace(d.SrcPort),
			DstPort: strings.TrimSpace(d.DstPort),
		})
	}

	includeTags := true
	includeNF := false
	// Match the routing endpoint default: request multiple candidates so we can recommend/compare.
	maxResults := 1
	if phRouting {
		maxResults = 3
	}
	maxCandidates := 5000
	maxSeconds := 30
	maxOverall := 300
	intent := "PREFER_DELIVERED"
	maxReturn := 0

	// Routing knobs.
	if phRouting && req.Routing != nil {
		if req.Routing.Forward != nil {
			if v := strings.TrimSpace(req.Routing.Forward.Intent); v != "" {
				intent = v
			}
			if req.Routing.Forward.MaxCandidates > 0 && req.Routing.Forward.MaxCandidates <= 10000 {
				maxCandidates = req.Routing.Forward.MaxCandidates
			}
			if req.Routing.Forward.MaxResults > 0 && req.Routing.Forward.MaxResults <= maxCandidates {
				if req.Routing.Forward.MaxResults > maxResults {
					maxResults = req.Routing.Forward.MaxResults
				}
			} else if maxResults < 3 {
				maxResults = 3
			}
			if req.Routing.Forward.MaxSeconds > 0 && req.Routing.Forward.MaxSeconds <= 300 {
				maxSeconds = req.Routing.Forward.MaxSeconds
			}
			if req.Routing.Forward.MaxOverallSeconds > 0 && req.Routing.Forward.MaxOverallSeconds <= 7200 {
				maxOverall = req.Routing.Forward.MaxOverallSeconds
			}
			if req.Routing.Forward.IncludeTags != nil {
				includeTags = *req.Routing.Forward.IncludeTags
			}
			if req.Routing.Forward.IncludeNetworkFunctions != nil {
				includeNF = *req.Routing.Forward.IncludeNetworkFunctions
			}
		} else if maxResults < 3 {
			maxResults = 3
		}
		if req.Routing.IncludeACL {
			includeNF = true
		}
	}

	// Security knobs (union with routing).
	if phSecurity && req.Security != nil {
		if v := strings.TrimSpace(req.Security.Intent); v != "" {
			intent = v
		}
		if req.Security.MaxCandidates > 0 && req.Security.MaxCandidates <= 10000 {
			if req.Security.MaxCandidates > maxCandidates {
				maxCandidates = req.Security.MaxCandidates
			}
		}
		if req.Security.MaxResults > 0 && req.Security.MaxResults <= maxCandidates {
			if req.Security.MaxResults > maxResults {
				maxResults = req.Security.MaxResults
			}
		}
		if req.Security.MaxSeconds > 0 && req.Security.MaxSeconds <= 300 {
			if req.Security.MaxSeconds > maxSeconds {
				maxSeconds = req.Security.MaxSeconds
			}
		}
		if req.Security.MaxOverallSeconds > 0 && req.Security.MaxOverallSeconds <= 600 {
			if req.Security.MaxOverallSeconds > maxOverall {
				maxOverall = req.Security.MaxOverallSeconds
			}
		}
		if req.Security.IncludeTags != nil {
			includeTags = *req.Security.IncludeTags
		}
		if req.Security.IncludeNetworkFunctions != nil && *req.Security.IncludeNetworkFunctions {
			includeNF = true
		}
		if req.Security.IncludeReturnPath || (req.Security.RequireSymmetricDelivery != nil && *req.Security.RequireSymmetricDelivery) || (req.Security.RequireReturnEnforcement != nil && *req.Security.RequireReturnEnforcement) {
			maxReturn = req.Security.MaxReturnPathResults
			if maxReturn <= 0 || maxReturn > 10000 {
				maxReturn = 1
			}
		}
	}

	payload := &fwdPathSearchBulkRequestFull{
		Queries:                 queries,
		Intent:                  intent,
		MaxCandidates:           maxCandidates,
		MaxResults:              maxResults,
		MaxReturnPathResults:    maxReturn,
		MaxSeconds:              maxSeconds,
		MaxOverallSeconds:       maxOverall,
		IncludeTags:             includeTags,
		IncludeNetworkFunctions: includeNF,
	}

	fwdOut, upstream, err := callForwardPathsBulk(ctx, client, forwardNetworkID, strings.TrimSpace(req.SnapshotID), payload)
	if err != nil {
		if strings.TrimSpace(upstream) != "" {
			return nil, errs.B().Code(errs.Unavailable).Msg("Forward paths failed").Meta("upstream", upstream).Err()
		}
		return nil, err
	}

	out := &AssuranceStudioEvaluateResponse{
		OwnerUsername:      ownerID,
		NetworkRef:         networkRef,
		ForwardNetworkID:   forwardNetworkID,
		SnapshotID:         strings.TrimSpace(req.SnapshotID),
		BaselineSnapshotID: strings.TrimSpace(req.BaselineSnapshotID),
		Window:             window,
		Errors:             map[string]string{},
		Meta:               JSONMap{},
	}
	out.Meta["pathsBulkCalls"] = json.RawMessage([]byte("1"))

	// Precompute joins for capacity/routing overlays if needed.
	join := capacityPathsJoin{}
	utilByNorm := map[utilNormKey]ifaceUtilStats{}
	if phRouting || phCapacity {
		join = buildCapacityPathsJoin(window, pre.rollups, pre.ifaces)
		utilByNorm = buildTrafficUtilByNorm(window, pre.rollups, pre.ifaces)
	}

	// Routing
	if phRouting {
		rt := &AssuranceTrafficEvaluateRequest{
			SnapshotID: strings.TrimSpace(req.SnapshotID),
			Window:     window,
			Demands:    req.Demands,
		}
		if req.Routing != nil {
			rt.ThresholdUtil = req.Routing.ThresholdUtil
			rt.Forward = req.Routing.Forward
			rt.Enforcement = req.Routing.Enforcement
			rt.IncludeHops = req.Routing.IncludeHops
			rt.IncludeACL = req.Routing.IncludeACL
			rt.ProjectLoad = req.Routing.ProjectLoad
		}

		thr := 0.8
		if rt.ThresholdUtil != nil {
			thr = *rt.ThresholdUtil
		}
		if thr <= 0 || thr > 1.0 {
			out.Errors["routing"] = "invalid thresholdUtil"
		} else {
			requireEnf := true
			if rt.Enforcement != nil && rt.Enforcement.RequireEnforcement != nil {
				requireEnf = *rt.Enforcement.RequireEnforcement
			}
			nameParts := []string{}
			tagParts := []string{}
			if rt.Enforcement != nil {
				nameParts = normalizeParts(rt.Enforcement.DeviceNameParts)
				tagParts = normalizeParts(rt.Enforcement.TagParts)
			}
			var matcher assuranceEnforcementMatcher
			if rt.Enforcement != nil {
				matcher, _ = assuranceLoadEnforcementMatcherWithClient(
					ctx,
					client,
					forwardNetworkID,
					strings.TrimSpace(rt.SnapshotID),
					rt.Enforcement.DeviceTypes,
					rt.Enforcement.DeviceNameParts,
					rt.Enforcement.TagParts,
				)
			} else {
				matcher, _ = assuranceLoadEnforcementMatcherWithClient(
					ctx,
					client,
					forwardNetworkID,
					strings.TrimSpace(rt.SnapshotID),
					nil,
					nil,
					nil,
				)
			}

			out.Routing = assuranceTrafficEvaluateFromFwdOut(
				ownerID,
				networkRef,
				forwardNetworkID,
				rt,
				window,
				thr,
				requireEnf,
				matcher,
				nameParts,
				tagParts,
				includeTags,
				includeNF,
				pre.asOf,
				utilByNorm,
				fwdOut,
			)
		}
	}

	// Routing regression vs baseline (optional): second Forward call against BaselineSnapshotID.
	// Demo-focused: computes routing diffs only (capacity/security remain on the compare snapshot).
	if phRouting && out.Routing != nil {
		baselineSnap := strings.TrimSpace(req.BaselineSnapshotID)
		compareSnap := strings.TrimSpace(req.SnapshotID)
		if baselineSnap != "" && baselineSnap != compareSnap {
			// Routing-only Forward knobs (avoid security return-path / NF inflation).
			intentRt := "PREFER_DELIVERED"
			maxCandidatesRt := 5000
			maxResultsRt := 3
			maxSecondsRt := 30
			maxOverallRt := 300
			includeTagsRt := true
			includeNFRt := false
			if req.Routing != nil && req.Routing.Forward != nil {
				if v := strings.TrimSpace(req.Routing.Forward.Intent); v != "" {
					intentRt = v
				}
				if req.Routing.Forward.MaxCandidates > 0 && req.Routing.Forward.MaxCandidates <= 10000 {
					maxCandidatesRt = req.Routing.Forward.MaxCandidates
				}
				if req.Routing.Forward.MaxResults > 0 && req.Routing.Forward.MaxResults <= maxCandidatesRt {
					maxResultsRt = req.Routing.Forward.MaxResults
				}
				if req.Routing.Forward.MaxSeconds > 0 && req.Routing.Forward.MaxSeconds <= 300 {
					maxSecondsRt = req.Routing.Forward.MaxSeconds
				}
				if req.Routing.Forward.MaxOverallSeconds > 0 && req.Routing.Forward.MaxOverallSeconds <= 7200 {
					maxOverallRt = req.Routing.Forward.MaxOverallSeconds
				}
				if req.Routing.Forward.IncludeTags != nil {
					includeTagsRt = *req.Routing.Forward.IncludeTags
				}
				if req.Routing.Forward.IncludeNetworkFunctions != nil {
					includeNFRt = *req.Routing.Forward.IncludeNetworkFunctions
				}
			}
			if req.Routing != nil && req.Routing.IncludeACL {
				includeNFRt = true
			}

			payloadRt := &fwdPathSearchBulkRequestFull{
				Queries:                 queries,
				Intent:                  intentRt,
				MaxCandidates:           maxCandidatesRt,
				MaxResults:              maxResultsRt,
				MaxReturnPathResults:    0,
				MaxSeconds:              maxSecondsRt,
				MaxOverallSeconds:       maxOverallRt,
				IncludeTags:             includeTagsRt,
				IncludeNetworkFunctions: includeNFRt,
			}

			fwdBase, upstream, err := callForwardPathsBulk(ctx, client, forwardNetworkID, baselineSnap, payloadRt)
			if err != nil {
				out.Errors["routingBaseline"] = err.Error()
				if strings.TrimSpace(upstream) != "" {
					out.Meta["routingBaselineUpstream"] = json.RawMessage(strconvQuote(upstream))
				}
			} else {
				rtBase := &AssuranceTrafficEvaluateRequest{
					SnapshotID: baselineSnap,
					Window:     window,
					Demands:    req.Demands,
				}
				if req.Routing != nil {
					rtBase.ThresholdUtil = req.Routing.ThresholdUtil
					rtBase.Forward = req.Routing.Forward
					rtBase.Enforcement = req.Routing.Enforcement
					rtBase.IncludeHops = req.Routing.IncludeHops
					rtBase.IncludeACL = req.Routing.IncludeACL
					rtBase.ProjectLoad = req.Routing.ProjectLoad
				}

				thr := 0.8
				if rtBase.ThresholdUtil != nil {
					thr = *rtBase.ThresholdUtil
				}
				requireEnf := true
				if rtBase.Enforcement != nil && rtBase.Enforcement.RequireEnforcement != nil {
					requireEnf = *rtBase.Enforcement.RequireEnforcement
				}
				nameParts := []string{}
				tagParts := []string{}
				if rtBase.Enforcement != nil {
					nameParts = normalizeParts(rtBase.Enforcement.DeviceNameParts)
					tagParts = normalizeParts(rtBase.Enforcement.TagParts)
				}
				var matcher assuranceEnforcementMatcher
				if rtBase.Enforcement != nil {
					matcher, _ = assuranceLoadEnforcementMatcherWithClient(
						ctx,
						client,
						forwardNetworkID,
						strings.TrimSpace(rtBase.SnapshotID),
						rtBase.Enforcement.DeviceTypes,
						rtBase.Enforcement.DeviceNameParts,
						rtBase.Enforcement.TagParts,
					)
				} else {
					matcher, _ = assuranceLoadEnforcementMatcherWithClient(
						ctx,
						client,
						forwardNetworkID,
						strings.TrimSpace(rtBase.SnapshotID),
						nil,
						nil,
						nil,
					)
				}

				out.RoutingBaseline = assuranceTrafficEvaluateFromFwdOut(
					ownerID,
					networkRef,
					forwardNetworkID,
					rtBase,
					window,
					thr,
					requireEnf,
					matcher,
					nameParts,
					tagParts,
					includeTagsRt,
					includeNFRt,
					pre.asOf,
					utilByNorm,
					fwdBase,
				)
				out.BaselineSnapshotID = baselineSnap
				out.RoutingDiff = routingDiff(out.RoutingBaseline, out.Routing)
				out.Meta["pathsBulkCalls"] = json.RawMessage([]byte("2"))
			}
		}
	}

	// Capacity
	if phCapacity {
		capReq := &ForwardNetworkCapacityPathBottlenecksRequest{
			Window:      window,
			SnapshotID:  strings.TrimSpace(req.SnapshotID),
			IncludeHops: false,
			Queries:     make([]CapacityPathSearchQuery, 0, len(req.Demands)),
		}
		perfFallback := true
		includeUpgrades := true
		if req.Capacity != nil {
			capReq.IncludeHops = req.Capacity.IncludeHops
			if req.Capacity.PerfFallback != nil {
				perfFallback = *req.Capacity.PerfFallback
			}
			if req.Capacity.IncludeUpgradeCandidates != nil {
				includeUpgrades = *req.Capacity.IncludeUpgradeCandidates
			}
		}
		for _, d := range req.Demands {
			capReq.Queries = append(capReq.Queries, CapacityPathSearchQuery{
				From:    strings.TrimSpace(d.From),
				SrcIP:   strings.TrimSpace(d.SrcIP),
				DstIP:   strings.TrimSpace(d.DstIP),
				IPProto: d.IPProto,
				SrcPort: strings.TrimSpace(d.SrcPort),
				DstPort: strings.TrimSpace(d.DstPort),
			})
		}
		resp, err := capacityPathBottlenecksFromFwdOut(ctx, client, ownerID, networkRef, forwardNetworkID, window, windowDays, capReq, join, pre.asOf, fwdOut, perfFallback)
		if err != nil {
			out.Errors["capacity"] = err.Error()
		} else {
			out.Capacity = resp
		}

		if includeUpgrades {
			items := capacityUpgradeCandidatesFromRollups(window, pre.rollups, pre.ifaces)
			up := &ForwardNetworkCapacityUpgradeCandidatesResponse{
				OwnerUsername:    ownerID,
				NetworkRef:       networkRef,
				ForwardNetworkID: forwardNetworkID,
				Items:            items,
			}
			if !pre.asOf.IsZero() {
				up.AsOf = pre.asOf.UTC().Format(time.RFC3339)
			}
			out.CapacityUpgradeCandidates = up
		}
	}

	// Security
	if phSecurity {
		secReq := &PolicyReportPathsEnforcementBypassRequest{
			ForwardNetworkID:        strings.TrimSpace(forwardNetworkID),
			SnapshotID:              strings.TrimSpace(req.SnapshotID),
			Queries:                 nil, // set below
			Intent:                  intent,
			MaxCandidates:           maxCandidates,
			MaxResults:              maxResults,
			MaxReturnPathResults:    maxReturn,
			MaxSeconds:              maxSeconds,
			MaxOverallSeconds:       maxOverall,
			IncludeTags:             &includeTags,
			IncludeNetworkFunctions: func() *bool { v := includeNF; return &v }(),
		}
		if req.Security != nil {
			secReq.RequireEnforcement = req.Security.RequireEnforcement
			secReq.RequireSymmetricDelivery = req.Security.RequireSymmetricDelivery
			secReq.RequireReturnEnforcement = req.Security.RequireReturnEnforcement
			secReq.EnforcementDeviceTypes = req.Security.EnforcementDeviceTypes
			secReq.EnforcementDeviceNameParts = req.Security.EnforcementDeviceNameParts
			secReq.EnforcementTagParts = req.Security.EnforcementTagParts
			if v := strings.TrimSpace(req.Security.Intent); v != "" {
				secReq.Intent = v
			}
			if req.Security.MaxCandidates > 0 {
				secReq.MaxCandidates = req.Security.MaxCandidates
			}
			if req.Security.MaxResults > 0 {
				secReq.MaxResults = req.Security.MaxResults
			}
			if req.Security.MaxSeconds > 0 {
				secReq.MaxSeconds = req.Security.MaxSeconds
			}
			if req.Security.MaxOverallSeconds > 0 {
				secReq.MaxOverallSeconds = req.Security.MaxOverallSeconds
			}
			if req.Security.MaxReturnPathResults > 0 {
				secReq.MaxReturnPathResults = req.Security.MaxReturnPathResults
			}
			if req.Security.IncludeTags != nil {
				secReq.IncludeTags = req.Security.IncludeTags
			}
			if req.Security.IncludeNetworkFunctions != nil {
				secReq.IncludeNetworkFunctions = req.Security.IncludeNetworkFunctions
			}
		}
		kept := make([]PolicyReportPathQuery, 0, len(req.Demands))
		for _, d := range req.Demands {
			q := PolicyReportPathQuery{
				From:    strings.TrimSpace(d.From),
				SrcIP:   strings.TrimSpace(d.SrcIP),
				DstIP:   strings.TrimSpace(d.DstIP),
				IPProto: d.IPProto,
				SrcPort: strings.TrimSpace(d.SrcPort),
				DstPort: strings.TrimSpace(d.DstPort),
			}
			if strings.TrimSpace(q.DstIP) == "" {
				continue
			}
			kept = append(kept, q)
		}
		secReq.Queries = kept
		matcher, _ := assuranceLoadEnforcementMatcherWithClient(
			ctx,
			client,
			forwardNetworkID,
			strings.TrimSpace(secReq.SnapshotID),
			secReq.EnforcementDeviceTypes,
			secReq.EnforcementDeviceNameParts,
			secReq.EnforcementTagParts,
		)
		resp, _, err := policyReportsPathsEnforcementBypassEvalFromFwdOut(secReq, kept, fwdOut, matcher)
		if err != nil {
			out.Errors["security"] = err.Error()
		} else {
			out.Security = resp
		}
	}

	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	return out, nil
}

func strconvQuote(s string) string {
	// JSON-quote a string for storing inside JSONMap as json.RawMessage.
	// Best-effort: if marshal fails (shouldn't), fall back to an empty JSON string.
	b, err := json.Marshal(s)
	if err != nil {
		return "\"\""
	}
	return string(b)
}

// PostUserForwardNetworkAssuranceStudioEvaluate runs the Assurance Studio "shared backend" evaluation.
// It performs a single Forward paths-bulk call and then projects results into routing/capacity/security views.
func (s *Service) PostUserForwardNetworkAssuranceStudioEvaluate(ctx context.Context, id, networkRef string, req *AssuranceStudioEvaluateRequest) (*AssuranceStudioEvaluateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.context.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	client, err := s.assuranceStudioForwardClient(ctx, pc.context.ID, pc.claims.Username, net.ForwardNetworkID, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}

	pre := assuranceStudioPreload{}
	needCap := true
	needRouting := true
	needAny := needCap || needRouting
	if req.Phases != nil {
		needRouting = boolOr(req.Phases.Routing, true)
		needCap = boolOr(req.Phases.Capacity, true)
		needAny = needRouting || needCap
	}
	if needAny {
		asOf, rollups, rollErr := loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.context.ID, net.ForwardNetworkID)
		if rollErr == nil {
			pre.asOf = asOf
			pre.rollups = rollups
		} else {
			pre.rollups = []CapacityRollupRow{}
		}
		_, _, _, ifaces, _, _, _, _, invErr := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.context.ID, net.ForwardNetworkID)
		if invErr == nil {
			pre.ifaces = ifaces
		} else {
			pre.ifaces = []CapacityInterfaceInventoryRow{}
		}
	}

	return assuranceStudioEvaluateWithClient(ctx, client, pc.context.ID, net.ID, net.ForwardNetworkID, req, pre)
}
