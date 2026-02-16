package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"github.com/google/uuid"

	"encore.app/internal/trafficassets"
)

type utilNormKey struct {
	dev string
	ifn string // normalized
	dir string // "ingress" | "egress"
}

func buildTrafficUtilByNorm(window string, rollups []CapacityRollupRow, ifaces []CapacityInterfaceInventoryRow) map[utilNormKey]ifaceUtilStats {
	ifaceSpeed := map[string]int{} // dev|iface -> speedMbps
	for _, r := range ifaces {
		dev := strings.TrimSpace(r.DeviceName)
		ifn := strings.TrimSpace(r.InterfaceName)
		if dev == "" || ifn == "" {
			continue
		}
		if r.SpeedMbps != nil && *r.SpeedMbps > 0 {
			ifaceSpeed[dev+"|"+ifn] = *r.SpeedMbps
		}
	}

	out := map[utilNormKey]ifaceUtilStats{}
	for _, r := range rollups {
		if r.ObjectType != "interface" {
			continue
		}
		if strings.TrimSpace(r.Window) != window {
			continue
		}
		if r.Metric != "util_ingress" && r.Metric != "util_egress" {
			continue
		}
		dev := strings.TrimSpace(getJSONMapString(r.Details, "deviceName"))
		ifn := strings.TrimSpace(getJSONMapString(r.Details, "interfaceName"))
		dir := ""
		if r.Metric == "util_ingress" {
			dir = "ingress"
		} else {
			dir = "egress"
		}
		if dev == "" || ifn == "" {
			continue
		}
		nn := normalizeIfaceName(ifn)
		if nn == "" {
			continue
		}
		k := utilNormKey{dev: dev, ifn: nn, dir: dir}
		st := ifaceUtilStats{}
		if r.P95 != nil {
			v := *r.P95
			st.p95 = &v
		}
		if r.Max != nil {
			v := *r.Max
			st.max = &v
		}
		if r.Threshold != nil {
			v := *r.Threshold
			st.threshold = &v
		}
		if sp, ok := ifaceSpeed[dev+"|"+ifn]; ok {
			st.speedMbps = sp
		}
		out[k] = st
	}
	return out
}

// ---- Assurance Studio: Traffic Scenarios (Forward Paths + NQE + Capacity/Security overlays) ----

type AssuranceTrafficSeedRequest struct {
	SnapshotID string `json:"snapshotId,omitempty"`

	// Filters applied to the NQE-discovered device endpoints.
	// For mode=mesh: TagParts/NameParts/DeviceTypes are applied to a single endpoint set.
	// For mode=cross: Src* filters build the source set, Dst* filters build the destination set.
	TagParts    []string `json:"tagParts,omitempty"`
	NameParts   []string `json:"nameParts,omitempty"`
	DeviceTypes []string `json:"deviceTypes,omitempty"`

	SrcTagParts    []string `json:"srcTagParts,omitempty"`
	SrcNameParts   []string `json:"srcNameParts,omitempty"`
	SrcDeviceTypes []string `json:"srcDeviceTypes,omitempty"`

	DstTagParts    []string `json:"dstTagParts,omitempty"`
	DstNameParts   []string `json:"dstNameParts,omitempty"`
	DstDeviceTypes []string `json:"dstDeviceTypes,omitempty"`

	IncludeGroups *bool `json:"includeGroups,omitempty"` // if true, tagParts also match groupNames (default true)

	// Limits.
	MaxDevices int `json:"maxDevices,omitempty"` // default 30
	MaxDemands int `json:"maxDemands,omitempty"` // default 200

	// How to build demands.
	Mode string `json:"mode,omitempty"` // "mesh" (default) | "cross"
}

type AssuranceTrafficEndpoint struct {
	DeviceName string   `json:"deviceName"`
	DeviceType string   `json:"deviceType,omitempty"`
	MgmtIP     string   `json:"mgmtIp"`
	TagNames   []string `json:"tagNames,omitempty"`
	GroupNames []string `json:"groupNames,omitempty"`
}

type AssuranceTrafficDemand struct {
	From          string   `json:"from,omitempty"`
	SrcIP         string   `json:"srcIp,omitempty"`
	DstIP         string   `json:"dstIp"`
	IPProto       *int     `json:"ipProto,omitempty"`
	SrcPort       string   `json:"srcPort,omitempty"`
	DstPort       string   `json:"dstPort,omitempty"`
	BandwidthGbps *float64 `json:"bandwidthGbps,omitempty"`
	Label         string   `json:"label,omitempty"`
}

type AssuranceTrafficSeedResponse struct {
	OwnerUsername    string `json:"ownerUsername"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	SnapshotID       string `json:"snapshotId,omitempty"`

	Endpoints    []AssuranceTrafficEndpoint `json:"endpoints"`
	SrcEndpoints []AssuranceTrafficEndpoint `json:"srcEndpoints,omitempty"`
	DstEndpoints []AssuranceTrafficEndpoint `json:"dstEndpoints,omitempty"`
	Demands      []AssuranceTrafficDemand   `json:"demands"`
}

type fwdNqeRunResult struct {
	Items         json.RawMessage `json:"items"`
	SnapshotID    string          `json:"snapshotId"`
	TotalNumItems int             `json:"totalNumItems"`
}

type trafficSeedEndpointRow struct {
	DeviceName string   `json:"deviceName"`
	DeviceType string   `json:"deviceType"`
	TagNames   []string `json:"tagNames"`
	GroupNames []string `json:"groupNames"`
	MgmtIP     string   `json:"mgmtIp"`
}

// PostUserForwardNetworkAssuranceTrafficSeeds discovers seed endpoints via NQE and produces a starter demand set.
func (s *Service) PostUserForwardNetworkAssuranceTrafficSeeds(ctx context.Context, id, networkRef string, req *AssuranceTrafficSeedRequest) (*AssuranceTrafficSeedResponse, error) {
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

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.context.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	if req == nil {
		req = &AssuranceTrafficSeedRequest{}
	}

	maxDevices := req.MaxDevices
	if maxDevices <= 0 || maxDevices > 500 {
		maxDevices = 30
	}
	maxDemands := req.MaxDemands
	if maxDemands <= 0 || maxDemands > 5000 {
		maxDemands = 200
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "mesh"
	}
	if mode != "mesh" && mode != "cross" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid mode").Err()
	}
	includeGroups := true
	if req.IncludeGroups != nil {
		includeGroups = *req.IncludeGroups
	}

	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}

	queryText, err := trafficassets.ReadQuery("traffic-seed-endpoints.nqe")
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load seed query").Err()
	}

	tagParts := normalizeParts(req.TagParts)
	nameParts := normalizeParts(req.NameParts)
	devTypes := normalizeParts(req.DeviceTypes)

	srcTagParts := normalizeParts(req.SrcTagParts)
	srcNameParts := normalizeParts(req.SrcNameParts)
	srcDevTypes := normalizeParts(req.SrcDeviceTypes)

	dstTagParts := normalizeParts(req.DstTagParts)
	dstNameParts := normalizeParts(req.DstNameParts)
	dstDevTypes := normalizeParts(req.DstDeviceTypes)

	runSeed := func(tagParts, nameParts, devTypes []string) ([]trafficSeedEndpointRow, string, error) {
		qv := url.Values{}
		qv.Set("networkId", net.ForwardNetworkID)
		if v := strings.TrimSpace(req.SnapshotID); v != "" {
			qv.Set("snapshotId", v)
		}
		payload := map[string]any{
			"query": queryText,
			"parameters": map[string]any{
				"tagParts":      tagParts,
				"nameParts":     nameParts,
				"deviceTypes":   devTypes,
				"includeGroups": includeGroups,
			},
		}

		rawPath := forwardAPIPathFor(client, "/nqe")
		resp, body, err := client.doJSON(ctx, http.MethodPost, rawPath, qv, payload)
		if err != nil {
			return nil, "", errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, "", errs.B().Code(errs.Unavailable).Msg("Forward NQE failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
		}

		var nqeOut fwdNqeRunResult
		if err := json.Unmarshal(body, &nqeOut); err != nil {
			return nil, "", errs.B().Code(errs.Unavailable).Msg("failed to decode Forward NQE response").Err()
		}

		rows := []trafficSeedEndpointRow{}
		if err := json.Unmarshal(nqeOut.Items, &rows); err != nil {
			return nil, "", errs.B().Code(errs.Unavailable).Msg("failed to decode seed items").Err()
		}
		return rows, strings.TrimSpace(nqeOut.SnapshotID), nil
	}

	toEndpoint := func(r trafficSeedEndpointRow) AssuranceTrafficEndpoint {
		return AssuranceTrafficEndpoint{
			DeviceName: strings.TrimSpace(r.DeviceName),
			DeviceType: strings.TrimSpace(r.DeviceType),
			MgmtIP:     strings.TrimSpace(r.MgmtIP),
			TagNames:   r.TagNames,
			GroupNames: r.GroupNames,
		}
	}

	var snapshotOut string
	endpoints := []AssuranceTrafficEndpoint{}
	srcEndpoints := []AssuranceTrafficEndpoint{}
	dstEndpoints := []AssuranceTrafficEndpoint{}

	switch mode {
	case "mesh":
		rows, snap, err := runSeed(tagParts, nameParts, devTypes)
		if err != nil {
			return nil, err
		}
		snapshotOut = snap
		endpoints = make([]AssuranceTrafficEndpoint, 0, len(rows))
		seen := map[string]bool{}
		for _, r := range rows {
			ep := toEndpoint(r)
			k := strings.ToLower(strings.TrimSpace(ep.DeviceName))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			endpoints = append(endpoints, ep)
		}
		// Mesh mode: src==dst set. The portal reads `endpoints` for counts in mesh mode.
		srcEndpoints = endpoints
		dstEndpoints = endpoints
	case "cross":
		srcRows, snap1, err := runSeed(srcTagParts, srcNameParts, srcDevTypes)
		if err != nil {
			return nil, err
		}
		dstRows, snap2, err := runSeed(dstTagParts, dstNameParts, dstDevTypes)
		if err != nil {
			return nil, err
		}
		if snap1 != "" {
			snapshotOut = snap1
		} else {
			snapshotOut = snap2
		}

		seenSrc := map[string]bool{}
		for _, r := range srcRows {
			ep := toEndpoint(r)
			k := strings.ToLower(strings.TrimSpace(ep.DeviceName))
			if k == "" || seenSrc[k] {
				continue
			}
			seenSrc[k] = true
			srcEndpoints = append(srcEndpoints, ep)
		}
		seenDst := map[string]bool{}
		for _, r := range dstRows {
			ep := toEndpoint(r)
			k := strings.ToLower(strings.TrimSpace(ep.DeviceName))
			if k == "" || seenDst[k] {
				continue
			}
			seenDst[k] = true
			dstEndpoints = append(dstEndpoints, ep)
		}

		// Return the union as a convenience (not required by the current portal flow).
		seen := map[string]bool{}
		for _, ep := range append(srcEndpoints, dstEndpoints...) {
			k := strings.ToLower(strings.TrimSpace(ep.DeviceName))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			endpoints = append(endpoints, ep)
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return strings.ToLower(endpoints[i].DeviceName) < strings.ToLower(endpoints[j].DeviceName)
	})
	sort.Slice(srcEndpoints, func(i, j int) bool {
		return strings.ToLower(srcEndpoints[i].DeviceName) < strings.ToLower(srcEndpoints[j].DeviceName)
	})
	sort.Slice(dstEndpoints, func(i, j int) bool {
		return strings.ToLower(dstEndpoints[i].DeviceName) < strings.ToLower(dstEndpoints[j].DeviceName)
	})

	if len(srcEndpoints) > maxDevices {
		srcEndpoints = srcEndpoints[:maxDevices]
	}
	if len(dstEndpoints) > maxDevices {
		dstEndpoints = dstEndpoints[:maxDevices]
	}

	// Ensure the primary endpoint list reflects the effective endpoint sets used
	// for demand generation (keeps mesh-mode UI semantics intuitive).
	if mode == "mesh" {
		endpoints = srcEndpoints
	} else {
		seen := map[string]bool{}
		union := make([]AssuranceTrafficEndpoint, 0, len(srcEndpoints)+len(dstEndpoints))
		for _, ep := range append(srcEndpoints, dstEndpoints...) {
			k := strings.ToLower(strings.TrimSpace(ep.DeviceName))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			union = append(union, ep)
		}
		sort.Slice(union, func(i, j int) bool {
			return strings.ToLower(union[i].DeviceName) < strings.ToLower(union[j].DeviceName)
		})
		endpoints = union
	}

	demands := []AssuranceTrafficDemand{}
	for _, src := range srcEndpoints {
		for _, dst := range dstEndpoints {
			if src.DeviceName == "" || dst.DeviceName == "" {
				continue
			}
			if src.DeviceName == dst.DeviceName {
				continue
			}
			d := AssuranceTrafficDemand{
				From:  src.DeviceName,
				SrcIP: src.MgmtIP,
				DstIP: dst.MgmtIP,
				Label: src.DeviceName + " -> " + dst.DeviceName,
			}
			demands = append(demands, d)
			if len(demands) >= maxDemands {
				break
			}
		}
		if len(demands) >= maxDemands {
			break
		}
	}

	snapOut := strings.TrimSpace(req.SnapshotID)
	if snapOut == "" {
		snapOut = snapshotOut
	}

	return &AssuranceTrafficSeedResponse{
		OwnerUsername:    pc.context.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		SnapshotID:       snapOut,
		Endpoints:        endpoints,
		SrcEndpoints:     srcEndpoints,
		DstEndpoints:     dstEndpoints,
		Demands:          demands,
	}, nil
}

type AssuranceTrafficEvaluateRequest struct {
	SnapshotID string `json:"snapshotId,omitempty"`
	Window     string `json:"window,omitempty"` // 24h|7d|30d

	ThresholdUtil *float64 `json:"thresholdUtil,omitempty"` // default 0.8

	Forward     *AssuranceTrafficForwardOptions     `json:"forward,omitempty"`
	Enforcement *AssuranceTrafficEnforcementOptions `json:"enforcement,omitempty"`
	Demands     []AssuranceTrafficDemand            `json:"demands"`
	IncludeHops bool                                `json:"includeHops,omitempty"` // include compact hop lists in response
	IncludeACL  bool                                `json:"includeAcl,omitempty"`  // if true, also asks Forward for networkFunctions and returns ACL info (slower)
	ProjectLoad bool                                `json:"projectLoad,omitempty"` // if true, includes projected utilization numbers per bottleneck
}

type AssuranceTrafficForwardOptions struct {
	Intent                  string `json:"intent,omitempty"`
	MaxCandidates           int    `json:"maxCandidates,omitempty"`
	MaxResults              int    `json:"maxResults,omitempty"`
	MaxSeconds              int    `json:"maxSeconds,omitempty"`
	MaxOverallSeconds       int    `json:"maxOverallSeconds,omitempty"`
	IncludeTags             *bool  `json:"includeTags,omitempty"`
	IncludeNetworkFunctions *bool  `json:"includeNetworkFunctions,omitempty"`
}

type AssuranceTrafficEnforcementOptions struct {
	RequireEnforcement *bool    `json:"requireEnforcement,omitempty"` // default true
	DeviceTypes        []string `json:"deviceTypes,omitempty"`
	DeviceNameParts    []string `json:"deviceNameParts,omitempty"`
	TagParts           []string `json:"tagParts,omitempty"`
}

type AssuranceTrafficBottleneck struct {
	DeviceName    string `json:"deviceName"`
	InterfaceName string `json:"interfaceName"`
	Direction     string `json:"direction"`

	SpeedMbps *int     `json:"speedMbps,omitempty"`
	P95Util   *float64 `json:"p95Util,omitempty"`
	MaxUtil   *float64 `json:"maxUtil,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`

	HeadroomGbps     *float64 `json:"headroomGbps,omitempty"`
	ProjectedUtil    *float64 `json:"projectedUtil,omitempty"`
	CrossesThreshold *bool    `json:"crossesThreshold,omitempty"`
}

type AssuranceTrafficCandidate struct {
	Index             int    `json:"index"`
	ForwardingOutcome string `json:"forwardingOutcome,omitempty"`
	SecurityOutcome   string `json:"securityOutcome,omitempty"`
	Enforced          bool   `json:"enforced"`
	TimedOut          bool   `json:"timedOut,omitempty"`

	Bottleneck *AssuranceTrafficBottleneck `json:"bottleneck,omitempty"`
	Hops       []prFwdPathHop              `json:"hops,omitempty"`
}

type AssuranceTrafficInterfaceImpact struct {
	DeviceName    string `json:"deviceName"`
	InterfaceName string `json:"interfaceName"`
	Direction     string `json:"direction"`

	SpeedMbps        *int     `json:"speedMbps,omitempty"`
	BaseP95Util      *float64 `json:"baseP95Util,omitempty"`
	AddedGbps        *float64 `json:"addedGbps,omitempty"`
	ProjectedUtil    *float64 `json:"projectedUtil,omitempty"`
	CrossesThreshold *bool    `json:"crossesThreshold,omitempty"`
}

type AssuranceTrafficEvalItem struct {
	Index  int                    `json:"index"`
	Demand AssuranceTrafficDemand `json:"demand"`

	TimedOut  bool   `json:"timedOut,omitempty"`
	TotalHits *int   `json:"totalHits,omitempty"`
	QueryURL  string `json:"queryUrl,omitempty"`

	Recommended int                         `json:"recommended"`
	Candidates  []AssuranceTrafficCandidate `json:"candidates"`

	Error string `json:"error,omitempty"`
}

type AssuranceTrafficEvaluateSummary struct {
	TotalDemands       int `json:"totalDemands"`
	Delivered          int `json:"delivered"`
	NotDelivered       int `json:"notDelivered"`
	TimedOut           int `json:"timedOut"`
	MissingEnforcement int `json:"missingEnforcement"`
	CrossesThreshold   int `json:"crossesThreshold"`
}

type AssuranceTrafficEvaluateResponse struct {
	OwnerUsername    string  `json:"ownerUsername"`
	NetworkRef       string  `json:"networkRef"`
	ForwardNetworkID string  `json:"forwardNetworkId"`
	SnapshotID       string  `json:"snapshotId,omitempty"`
	Window           string  `json:"window"`
	ThresholdUtil    float64 `json:"thresholdUtil"`

	AsOf string `json:"asOf,omitempty"` // from capacity rollups

	Summary AssuranceTrafficEvaluateSummary `json:"summary"`
	Items   []AssuranceTrafficEvalItem      `json:"items"`

	InterfaceImpacts []AssuranceTrafficInterfaceImpact `json:"interfaceImpacts,omitempty"`
}

// PostUserForwardNetworkAssuranceTrafficEvaluate evaluates demands by calling Forward paths-bulk and overlaying
// capacity/security constraints. This is a demo-first "rank + explain" view (no prediction/simulation).
func (s *Service) PostUserForwardNetworkAssuranceTrafficEvaluate(ctx context.Context, id, networkRef string, req *AssuranceTrafficEvaluateRequest) (*AssuranceTrafficEvaluateResponse, error) {
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
	if len(req.Demands) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("demands required").Err()
	}
	if len(req.Demands) > 200 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("too many demands (max 200)").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.context.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}

	window := strings.TrimSpace(req.Window)
	if window == "" {
		window = "7d"
	}
	if window != "24h" && window != "7d" && window != "30d" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid window").Err()
	}

	threshold := 0.8
	if req.ThresholdUtil != nil {
		threshold = *req.ThresholdUtil
	}
	if threshold <= 0 || threshold > 1.0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid thresholdUtil").Err()
	}

	// Enforcement config.
	requireEnf := true
	if req.Enforcement != nil && req.Enforcement.RequireEnforcement != nil {
		requireEnf = *req.Enforcement.RequireEnforcement
	}
	nameParts := []string{}
	tagParts := []string{}
	if req.Enforcement != nil {
		nameParts = normalizeParts(req.Enforcement.DeviceNameParts)
		tagParts = normalizeParts(req.Enforcement.TagParts)
	}
	var matcher assuranceEnforcementMatcher
	if req.Enforcement != nil {
		matcher, _ = assuranceLoadEnforcementMatcherWithClient(
			ctx,
			client,
			net.ForwardNetworkID,
			strings.TrimSpace(req.SnapshotID),
			req.Enforcement.DeviceTypes,
			req.Enforcement.DeviceNameParts,
			req.Enforcement.TagParts,
		)
	} else {
		matcher, _ = assuranceLoadEnforcementMatcherWithClient(
			ctx,
			client,
			net.ForwardNetworkID,
			strings.TrimSpace(req.SnapshotID),
			nil,
			nil,
			nil,
		)
	}

	// Forward knobs.
	intent := "PREFER_DELIVERED"
	maxCandidates := 5000
	maxResults := 3
	maxSeconds := 30
	maxOverall := 300
	includeTags := true
	includeNF := false
	if req.Forward != nil {
		if v := strings.TrimSpace(req.Forward.Intent); v != "" {
			intent = v
		}
		if req.Forward.MaxCandidates > 0 && req.Forward.MaxCandidates <= 10000 {
			maxCandidates = req.Forward.MaxCandidates
		}
		if req.Forward.MaxResults > 0 && req.Forward.MaxResults <= maxCandidates {
			maxResults = req.Forward.MaxResults
		}
		if req.Forward.MaxSeconds > 0 && req.Forward.MaxSeconds <= 300 {
			maxSeconds = req.Forward.MaxSeconds
		}
		if req.Forward.MaxOverallSeconds > 0 && req.Forward.MaxOverallSeconds <= 7200 {
			maxOverall = req.Forward.MaxOverallSeconds
		}
		if req.Forward.IncludeTags != nil {
			includeTags = *req.Forward.IncludeTags
		}
		if req.Forward.IncludeNetworkFunctions != nil {
			includeNF = *req.Forward.IncludeNetworkFunctions
		}
	}
	if req.IncludeACL {
		includeNF = true
	}

	// Capacity rollups/inventory.
	asOfTS, rollups, rollErr := loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.context.ID, net.ForwardNetworkID)
	if rollErr != nil {
		rollups = []CapacityRollupRow{}
	}
	_, _, _, ifaces, _, _, _, _, invErr := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.context.ID, net.ForwardNetworkID)
	if invErr != nil {
		ifaces = []CapacityInterfaceInventoryRow{}
	}
	utilByNorm := buildTrafficUtilByNorm(window, rollups, ifaces)

	// Call Forward paths-bulk.
	payload := &fwdPathSearchBulkRequestFull{
		Queries:                 make([]fwdPathSearchQuery, 0, len(req.Demands)),
		Intent:                  intent,
		MaxCandidates:           maxCandidates,
		MaxResults:              maxResults,
		MaxReturnPathResults:    0,
		MaxSeconds:              maxSeconds,
		MaxOverallSeconds:       maxOverall,
		IncludeTags:             includeTags,
		IncludeNetworkFunctions: includeNF,
	}
	for i, d := range req.Demands {
		dst := strings.TrimSpace(d.DstIP)
		if dst == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("missing dstIp at demands[" + strconv.Itoa(i) + "]").Err()
		}
		payload.Queries = append(payload.Queries, fwdPathSearchQuery{
			From:    strings.TrimSpace(d.From),
			SrcIP:   strings.TrimSpace(d.SrcIP),
			DstIP:   dst,
			IPProto: d.IPProto,
			SrcPort: strings.TrimSpace(d.SrcPort),
			DstPort: strings.TrimSpace(d.DstPort),
		})
	}

	qv := url.Values{}
	if v := strings.TrimSpace(req.SnapshotID); v != "" {
		qv.Set("snapshotId", v)
	}
	rawPath := forwardAPIPathFor(client, "/networks/"+url.PathEscape(net.ForwardNetworkID)+"/paths-bulk")
	resp, body, err := client.doJSON(ctx, http.MethodPost, rawPath, qv, payload)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward paths failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}

	var fwdOut []fwdPathSearchResponseFull
	if err := json.Unmarshal(body, &fwdOut); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode Forward paths response").Err()
	}
	out := assuranceTrafficEvaluateFromFwdOut(
		pc.context.ID,
		net.ID,
		net.ForwardNetworkID,
		req,
		window,
		threshold,
		requireEnf,
		matcher,
		nameParts,
		tagParts,
		includeTags,
		includeNF,
		asOfTS,
		utilByNorm,
		fwdOut,
	)
	return out, nil
}

func assuranceTrafficEvaluateFromFwdOut(
	ownerID string,
	networkRef string,
	forwardNetworkID string,
	req *AssuranceTrafficEvaluateRequest,
	window string,
	threshold float64,
	requireEnf bool,
	matcher assuranceEnforcementMatcher,
	nameParts []string,
	tagParts []string,
	includeTags bool,
	includeNF bool,
	asOfTS time.Time,
	utilByNorm map[utilNormKey]ifaceUtilStats,
	fwdOut []fwdPathSearchResponseFull,
) *AssuranceTrafficEvaluateResponse {
	items := make([]AssuranceTrafficEvalItem, 0, len(req.Demands))
	sum := AssuranceTrafficEvaluateSummary{TotalDemands: len(req.Demands)}

	for i, d := range req.Demands {
		it := AssuranceTrafficEvalItem{Index: i, Demand: d, Recommended: 0, Candidates: []AssuranceTrafficCandidate{}}
		if i >= len(fwdOut) {
			it.Error = "missing response from Forward"
			items = append(items, it)
			sum.NotDelivered++
			continue
		}
		r := fwdOut[i]
		it.TimedOut = r.TimedOut
		it.QueryURL = strings.TrimSpace(r.QueryURL)
		th := r.Info.TotalHits
		it.TotalHits = &th
		if r.TimedOut {
			it.Error = "timed out"
			items = append(items, it)
			sum.TimedOut++
			continue
		}
		if len(r.Info.Paths) == 0 {
			it.Error = "no path candidates returned"
			items = append(items, it)
			sum.NotDelivered++
			continue
		}

		// Build candidates.
		for pi, p := range r.Info.Paths {
			cand := AssuranceTrafficCandidate{
				Index:             pi,
				ForwardingOutcome: strings.TrimSpace(p.ForwardingOutcome),
				SecurityOutcome:   strings.TrimSpace(p.SecurityOutcome),
				Enforced:          false,
			}

			enfHops := 0
			for _, h := range p.Hops {
				if hopIsEnforcement(h, matcher, nameParts, tagParts) {
					enfHops++
				}
			}
			cand.Enforced = enfHops > 0

			// Capacity bottleneck.
			var best *AssuranceTrafficBottleneck
			for _, h := range p.Hops {
				dev := strings.TrimSpace(h.DeviceName)
				if dev == "" {
					continue
				}

				// Consider both ingress and egress interfaces.
				pairs := []struct {
					dir string
					ifn string
				}{
					{dir: "ingress", ifn: strings.TrimSpace(h.IngressInterface)},
					{dir: "egress", ifn: strings.TrimSpace(h.EgressInterface)},
				}
				for _, pair := range pairs {
					if pair.ifn == "" {
						continue
					}
					nn := normalizeIfaceName(pair.ifn)
					if nn == "" {
						continue
					}
					k := utilNormKey{dev: dev, ifn: nn, dir: pair.dir}
					st, ok := utilByNorm[k]
					if !ok {
						continue
					}
					if st.speedMbps <= 0 {
						continue
					}

					speedGbps := float64(st.speedMbps) / 1000.0
					var p95util *float64
					if st.p95 != nil {
						v := *st.p95
						p95util = &v
					}
					var headroom *float64
					if p95util != nil {
						v := (threshold - *p95util) * speedGbps
						if v < 0 {
							v = 0
						}
						headroom = &v
					}

					bn := &AssuranceTrafficBottleneck{
						DeviceName:    dev,
						InterfaceName: pair.ifn,
						Direction:     pair.dir,
					}
					sp := st.speedMbps
					bn.SpeedMbps = &sp
					bn.Threshold = &threshold
					if st.p95 != nil {
						v := *st.p95
						bn.P95Util = &v
					}
					if st.max != nil {
						v := *st.max
						bn.MaxUtil = &v
					}
					if headroom != nil {
						bn.HeadroomGbps = headroom
					}

					// Optional projection.
					if req.ProjectLoad && d.BandwidthGbps != nil && *d.BandwidthGbps > 0 && speedGbps > 0 {
						proj := 0.0
						if bn.P95Util != nil {
							proj = *bn.P95Util + (*d.BandwidthGbps / speedGbps)
						}
						bn.ProjectedUtil = &proj
						cross := proj > threshold
						bn.CrossesThreshold = &cross
					}

					// Select the tightest bottleneck: minimum headroom.
					if best == nil {
						best = bn
						continue
					}
					// Compare headroom if present; else keep existing.
					if bn.HeadroomGbps != nil && best.HeadroomGbps != nil {
						if *bn.HeadroomGbps < *best.HeadroomGbps {
							best = bn
						}
					} else if bn.HeadroomGbps != nil && best.HeadroomGbps == nil {
						best = bn
					}
				}
			}
			if best != nil {
				cand.Bottleneck = best
			}

			if req.IncludeHops {
				hopsOut := make([]prFwdPathHop, 0, len(p.Hops))
				for _, h := range p.Hops {
					ho := prFwdPathHop{
						DeviceName:       strings.TrimSpace(h.DeviceName),
						DisplayName:      strings.TrimSpace(h.DisplayName),
						DeviceType:       strings.TrimSpace(h.DeviceType),
						IngressInterface: strings.TrimSpace(h.IngressInterface),
						EgressInterface:  strings.TrimSpace(h.EgressInterface),
					}
					if includeTags {
						ho.Tags = h.Tags
					}
					if includeNF && len(h.NetworkFunctions.ACL) > 0 {
						ho.NetworkFunctions = h.NetworkFunctions
					}
					hopsOut = append(hopsOut, ho)
				}
				cand.Hops = hopsOut
			}

			it.Candidates = append(it.Candidates, cand)
		}

		// Recommend.
		rec := recommendCandidateIndex(it.Candidates, requireEnf, threshold)
		it.Recommended = rec

		// Update summary based on the recommended candidate.
		recCand := it.Candidates[rec]
		if strings.TrimSpace(recCand.ForwardingOutcome) == "DELIVERED" {
			sum.Delivered++
		} else {
			sum.NotDelivered++
		}
		if requireEnf && !recCand.Enforced {
			sum.MissingEnforcement++
		}
		if recCand.Bottleneck != nil && recCand.Bottleneck.CrossesThreshold != nil && *recCand.Bottleneck.CrossesThreshold {
			sum.CrossesThreshold++
		}

		items = append(items, it)
	}

	out := &AssuranceTrafficEvaluateResponse{
		OwnerUsername:    ownerID,
		NetworkRef:       networkRef,
		ForwardNetworkID: forwardNetworkID,
		SnapshotID:       strings.TrimSpace(req.SnapshotID),
		Window:           window,
		ThresholdUtil:    threshold,
		Summary:          sum,
		Items:            items,
	}
	if !asOfTS.IsZero() {
		out.AsOf = asOfTS.UTC().Format(time.RFC3339)
	}

	// Aggregate interface impacts (demo-friendly overlay).
	// NOTE: requires IncludeHops=true because we don't currently persist hop lists server-side.
	if req.ProjectLoad {
		type impactKey struct {
			dev string
			ifn string // normalized
			dir string
		}
		addGbps := map[impactKey]float64{}
		baseP95 := map[impactKey]*float64{}
		speed := map[impactKey]int{}

		for _, it := range items {
			if it.Error != "" || it.TimedOut {
				continue
			}
			if it.Recommended < 0 || it.Recommended >= len(it.Candidates) {
				continue
			}
			bw := 0.0
			if it.Demand.BandwidthGbps != nil && *it.Demand.BandwidthGbps > 0 {
				bw = *it.Demand.BandwidthGbps
			}
			if bw <= 0 {
				continue
			}
			rec := it.Candidates[it.Recommended]
			if len(rec.Hops) == 0 {
				continue
			}
			for _, ho := range rec.Hops {
				dev := strings.TrimSpace(ho.DeviceName)
				if dev == "" {
					continue
				}
				for _, pair := range []struct {
					dir string
					ifn string
				}{
					{dir: "ingress", ifn: strings.TrimSpace(ho.IngressInterface)},
					{dir: "egress", ifn: strings.TrimSpace(ho.EgressInterface)},
				} {
					if pair.ifn == "" {
						continue
					}
					nn := normalizeIfaceName(pair.ifn)
					if nn == "" {
						continue
					}
					k := impactKey{dev: dev, ifn: nn, dir: pair.dir}
					addGbps[k] += bw

					if st, ok := utilByNorm[utilNormKey{dev: dev, ifn: nn, dir: pair.dir}]; ok {
						if st.p95 != nil {
							v := *st.p95
							baseP95[k] = &v
						}
						if st.speedMbps > 0 {
							speed[k] = st.speedMbps
						}
					}
				}
			}
		}

		impacts := make([]AssuranceTrafficInterfaceImpact, 0, len(addGbps))
		for k, added := range addGbps {
			added := added
			imp := AssuranceTrafficInterfaceImpact{
				DeviceName:    k.dev,
				InterfaceName: k.ifn,
				Direction:     k.dir,
				AddedGbps:     &added,
			}
			if sp, ok := speed[k]; ok && sp > 0 {
				sp := sp
				imp.SpeedMbps = &sp
			}
			if p95, ok := baseP95[k]; ok && p95 != nil {
				imp.BaseP95Util = p95
				if imp.SpeedMbps != nil && *imp.SpeedMbps > 0 {
					speedGbps := float64(*imp.SpeedMbps) / 1000.0
					proj := *p95 + (added / speedGbps)
					imp.ProjectedUtil = &proj
					cross := proj > threshold
					imp.CrossesThreshold = &cross
				}
			}
			impacts = append(impacts, imp)
		}
		sort.Slice(impacts, func(i, j int) bool {
			a := 0.0
			b := 0.0
			if impacts[i].ProjectedUtil != nil {
				a = *impacts[i].ProjectedUtil
			} else if impacts[i].AddedGbps != nil {
				a = *impacts[i].AddedGbps
			}
			if impacts[j].ProjectedUtil != nil {
				b = *impacts[j].ProjectedUtil
			} else if impacts[j].AddedGbps != nil {
				b = *impacts[j].AddedGbps
			}
			if a != b {
				return a > b
			}
			if impacts[i].DeviceName != impacts[j].DeviceName {
				return impacts[i].DeviceName < impacts[j].DeviceName
			}
			if impacts[i].InterfaceName != impacts[j].InterfaceName {
				return impacts[i].InterfaceName < impacts[j].InterfaceName
			}
			return impacts[i].Direction < impacts[j].Direction
		})
		if len(impacts) > 200 {
			impacts = impacts[:200]
		}
		out.InterfaceImpacts = impacts
	}

	return out
}

func recommendCandidateIndex(cands []AssuranceTrafficCandidate, requireEnf bool, threshold float64) int {
	if len(cands) == 0 {
		return 0
	}
	best := 0
	for i := 1; i < len(cands); i++ {
		if candidateBetter(cands[i], cands[best], requireEnf, threshold) {
			best = i
		}
	}
	return best
}

func candidateBetter(a, b AssuranceTrafficCandidate, requireEnf bool, threshold float64) bool {
	adel := strings.TrimSpace(a.ForwardingOutcome) == "DELIVERED"
	bdel := strings.TrimSpace(b.ForwardingOutcome) == "DELIVERED"
	if adel != bdel {
		return adel
	}
	if requireEnf && a.Enforced != b.Enforced {
		return a.Enforced
	}

	// Prefer candidates that do not cross threshold (when projection is present).
	across := false
	bcross := false
	if a.Bottleneck != nil && a.Bottleneck.CrossesThreshold != nil {
		across = *a.Bottleneck.CrossesThreshold
	}
	if b.Bottleneck != nil && b.Bottleneck.CrossesThreshold != nil {
		bcross = *b.Bottleneck.CrossesThreshold
	}
	if across != bcross {
		return !across
	}

	// Prefer more headroom.
	aH := -1.0
	bH := -1.0
	if a.Bottleneck != nil && a.Bottleneck.HeadroomGbps != nil {
		aH = *a.Bottleneck.HeadroomGbps
	}
	if b.Bottleneck != nil && b.Bottleneck.HeadroomGbps != nil {
		bH = *b.Bottleneck.HeadroomGbps
	}
	if aH != bH {
		return aH > bH
	}

	// Tie-breaker: fewer hops if we have them.
	if len(a.Hops) != len(b.Hops) {
		if len(a.Hops) == 0 || len(b.Hops) == 0 {
			return len(a.Hops) > len(b.Hops) // if one has hops and the other doesn't, prefer the one with detail
		}
		return len(a.Hops) < len(b.Hops)
	}
	return false
}

// Unused right now, but reserved for future session/run storage.
var _ = uuid.Nil
var _ = sql.ErrNoRows
