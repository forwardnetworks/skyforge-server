package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

// ---- Forward paths (capacity-only) ----

type CapacityPathSearchQuery struct {
	From        string `json:"from,omitempty"`
	SrcIP       string `json:"srcIp,omitempty"`
	DstIP       string `json:"dstIp"`
	IPProto     *int   `json:"ipProto,omitempty"`
	SrcPort     string `json:"srcPort,omitempty"`
	DstPort     string `json:"dstPort,omitempty"`
	IcmpType    *int   `json:"icmpType,omitempty"`
	Fin         *int   `json:"fin,omitempty"`
	Syn         *int   `json:"syn,omitempty"`
	Rst         *int   `json:"rst,omitempty"`
	Psh         *int   `json:"psh,omitempty"`
	Ack         *int   `json:"ack,omitempty"`
	Urg         *int   `json:"urg,omitempty"`
	AppID       string `json:"appId,omitempty"`
	UserID      string `json:"userId,omitempty"`
	UserGroupID string `json:"userGroupId,omitempty"`
	URL         string `json:"url,omitempty"`
}

type ForwardNetworkCapacityPathBottlenecksRequest struct {
	Window string `json:"window"`

	// Optional Forward snapshot to compute the path against. If omitted, Forward uses the latest processed snapshot.
	SnapshotID string `json:"snapshotId,omitempty"`

	// If true, includes a minimal hop list in the response. Default false to keep this view capacity-focused.
	IncludeHops bool `json:"includeHops,omitempty"`

	Queries []CapacityPathSearchQuery `json:"queries"`
}

type ForwardNetworkCapacityPathHop struct {
	DeviceName       string `json:"deviceName,omitempty"`
	IngressInterface string `json:"ingressInterface,omitempty"`
	EgressInterface  string `json:"egressInterface,omitempty"`
}

type ForwardNetworkCapacityPathBottleneck struct {
	DeviceName    string `json:"deviceName"`
	InterfaceName string `json:"interfaceName"`
	Direction     string `json:"direction"`

	// Source of the bottleneck stats (capacity-only).
	Source string `json:"source,omitempty"` // rollup | perf_fallback

	SpeedMbps *int     `json:"speedMbps,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`
	P95Util   *float64 `json:"p95Util,omitempty"`
	MaxUtil   *float64 `json:"maxUtil,omitempty"`
	P95Gbps   *float64 `json:"p95Gbps,omitempty"`
	MaxGbps   *float64 `json:"maxGbps,omitempty"`
	// Headroom at the selected threshold (e.g. 0.85) for the chosen util value.
	HeadroomGbps *float64 `json:"headroomGbps,omitempty"`
	HeadroomUtil *float64 `json:"headroomUtil,omitempty"`

	ForecastCrossingTS *string `json:"forecastCrossingTs,omitempty"`
}

type ForwardNetworkCapacityPathBottleneckItem struct {
	Index int                     `json:"index"`
	Query CapacityPathSearchQuery `json:"query"`

	TimedOut  bool `json:"timedOut,omitempty"`
	TotalHits *int `json:"totalHits,omitempty"`

	// Forward application URL for deeper interactive analysis (intentionally delegated to Forward UI).
	ForwardQueryURL string `json:"forwardQueryUrl,omitempty"`

	ForwardingOutcome string `json:"forwardingOutcome,omitempty"`
	SecurityOutcome   string `json:"securityOutcome,omitempty"`

	Bottleneck *ForwardNetworkCapacityPathBottleneck `json:"bottleneck,omitempty"`
	Hops       []ForwardNetworkCapacityPathHop       `json:"hops,omitempty"`

	// Diagnostics for partial-coverage environments (helps explain "unknown" results).
	UnmatchedHopInterfacesSample []string `json:"unmatchedHopInterfacesSample,omitempty"`

	Notes []CapacityNote `json:"notes,omitempty"`
	Error string         `json:"error,omitempty"`
}

type CapacityNote struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ForwardNetworkCapacityPathBottlenecksCoverage struct {
	HopInterfaceKeys int  `json:"hopInterfaceKeys"`
	RollupMatched    int  `json:"rollupMatched"`
	PerfFallbackUsed int  `json:"perfFallbackUsed"`
	Unknown          int  `json:"unknown"`
	Truncated        bool `json:"truncated,omitempty"`

	UnmatchedHopInterfacesSample []string `json:"unmatchedHopInterfacesSample,omitempty"`
}

type ForwardNetworkCapacityPathBottlenecksResponse struct {
	WorkspaceID      string `json:"workspaceId"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	AsOf             string `json:"asOf,omitempty"`
	Window           string `json:"window"`
	SnapshotID       string `json:"snapshotId,omitempty"`

	Coverage *ForwardNetworkCapacityPathBottlenecksCoverage `json:"coverage,omitempty"`
	Items    []ForwardNetworkCapacityPathBottleneckItem     `json:"items"`
}

type fwdPathSearchBulkRequest struct {
	Queries []CapacityPathSearchQuery `json:"queries"`

	Intent        string `json:"intent,omitempty"`
	MaxCandidates int    `json:"maxCandidates,omitempty"`
	MaxResults    int    `json:"maxResults,omitempty"`
	// Do not omit 0; we want to avoid any extra return-path computation by default.
	MaxReturnPathResults    int  `json:"maxReturnPathResults"`
	MaxSeconds              int  `json:"maxSeconds,omitempty"`
	MaxOverallSeconds       int  `json:"maxOverallSeconds,omitempty"`
	IncludeTags             bool `json:"includeTags,omitempty"`
	IncludeNetworkFunctions bool `json:"includeNetworkFunctions,omitempty"`
}

type capFwdPathSearchResponse struct {
	Info     capFwdPathInfo `json:"info"`
	TimedOut bool           `json:"timedOut"`
	QueryURL string         `json:"queryUrl,omitempty"`
}

type capFwdPathInfo struct {
	Paths     []capFwdPath `json:"paths"`
	TotalHits int          `json:"totalHits"`
}

type capFwdPath struct {
	ForwardingOutcome string          `json:"forwardingOutcome"`
	SecurityOutcome   string          `json:"securityOutcome"`
	Hops              []capFwdPathHop `json:"hops"`
}

type capFwdPathHop struct {
	DeviceName       string `json:"deviceName"`
	IngressInterface string `json:"ingressInterface"`
	EgressInterface  string `json:"egressInterface"`
}

type ifaceUtilKey struct {
	dev string
	ifn string
	dir string
}

type ifaceUtilStats struct {
	p95       *float64
	max       *float64
	forecast  *string
	threshold *float64
	speedMbps int
}

type fwdPerfDataPoint struct {
	Instant string  `json:"instant"`
	Value   float64 `json:"value"`
}

type fwdPerfIfaceWithDir struct {
	DeviceName    string `json:"deviceName"`
	InterfaceName string `json:"interfaceName"`
	Direction     string `json:"direction"`
}

type fwdPerfIfaceHistory struct {
	InterfaceWithDirection fwdPerfIfaceWithDir `json:"interfaceWithDirection"`
	Data                   []fwdPerfDataPoint  `json:"data"`
}

type fwdPerfIfaceHistoryResponse struct {
	Metrics []fwdPerfIfaceHistory `json:"metrics"`
}

type capacityPathsJoin struct {
	// member iface -> aggregate iface name (port-channel/bundle/etc). Key: dev|iface (dev lowercased).
	memberToAgg map[string]string
	// Speed lookup. Key: dev|iface (dev lowercased, iface exact or normalized).
	ifaceSpeed map[string]int
	// Util rollups lookup. Keys: (dev lowercased, iface exact/normalized, dir INGRESS|EGRESS).
	utilByKey     map[ifaceUtilKey]ifaceUtilStats
	utilByNormKey map[ifaceUtilKey]ifaceUtilStats
}

func buildCapacityPathsJoin(window string, rollups []CapacityRollupRow, ifaces []CapacityInterfaceInventoryRow) capacityPathsJoin {
	// LAG membership: member iface -> aggregate iface name. Used to join hop interfaces to rollups that
	// exist only at the aggregate layer (port-channel) without duplicating Forward workflows.
	memberToAgg := map[string]string{} // dev|member -> aggregate interfaceName

	ifaceSpeed := map[string]int{} // dev|iface -> speedMbps
	for _, r := range ifaces {
		dev := strings.ToLower(strings.TrimSpace(r.DeviceName))
		ifn := strings.TrimSpace(r.InterfaceName)
		if dev == "" || ifn == "" {
			continue
		}
		if r.AggregateID != nil {
			agg := strings.TrimSpace(*r.AggregateID)
			if agg != "" {
				memberToAgg[dev+"|"+ifn] = agg
				if nn := normalizeIfaceName(ifn); nn != "" {
					memberToAgg[dev+"|"+nn] = agg
				}
			}
		}
		if r.SpeedMbps != nil && *r.SpeedMbps > 0 {
			ifaceSpeed[dev+"|"+ifn] = *r.SpeedMbps
			if nn := normalizeIfaceName(ifn); nn != "" {
				ifaceSpeed[dev+"|"+nn] = *r.SpeedMbps
			}
		}
	}
	// Best-effort aggregate speed: if aggregate has no speed, sum member speeds.
	for _, r := range ifaces {
		dev := strings.ToLower(strings.TrimSpace(r.DeviceName))
		ifn := strings.TrimSpace(r.InterfaceName)
		if dev == "" || ifn == "" {
			continue
		}
		if strings.TrimSpace(r.InterfaceType) != "IF_AGGREGATE" {
			continue
		}
		if r.SpeedMbps != nil && *r.SpeedMbps > 0 {
			continue
		}
		memberNames := r.AggregationMemberNames
		if len(memberNames) == 0 {
			memberNames = r.AggregationConfiguredMemberNames
		}
		sum := 0
		for _, m := range memberNames {
			mm := strings.TrimSpace(m)
			if mm == "" {
				continue
			}
			if v, ok := ifaceSpeed[dev+"|"+mm]; ok && v > 0 {
				sum += v
				continue
			}
			if nn := normalizeIfaceName(mm); nn != "" {
				if v, ok := ifaceSpeed[dev+"|"+nn]; ok && v > 0 {
					sum += v
				}
			}
		}
		if sum > 0 {
			ifaceSpeed[dev+"|"+ifn] = sum
			if nn := normalizeIfaceName(ifn); nn != "" {
				ifaceSpeed[dev+"|"+nn] = sum
			}
		}
	}

	utilByKey := map[ifaceUtilKey]ifaceUtilStats{}     // exact interfaceName
	utilByNormKey := map[ifaceUtilKey]ifaceUtilStats{} // normalized interfaceName
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
		dir := strings.TrimSpace(getJSONMapString(r.Details, "direction"))
		if dev == "" || ifn == "" {
			parts := strings.Split(r.ObjectID, ":")
			if len(parts) >= 2 {
				dev = strings.TrimSpace(parts[0])
				ifn = strings.TrimSpace(parts[1])
			}
			if len(parts) >= 3 && dir == "" {
				dir = strings.TrimSpace(parts[2])
			}
		}
		if dev == "" || ifn == "" {
			continue
		}
		dev = strings.ToLower(dev)
		dir = normDir(dir, r.Metric)

		speedMbps := getJSONMapInt(r.Details, "speedMbps")
		if speedMbps <= 0 {
			if v, ok := ifaceSpeed[dev+"|"+ifn]; ok {
				speedMbps = v
			}
		}
		st := ifaceUtilStats{
			p95:       r.P95,
			max:       r.Max,
			forecast:  r.ForecastCrossingTS,
			threshold: r.Threshold,
			speedMbps: speedMbps,
		}
		utilByKey[ifaceUtilKey{dev: dev, ifn: ifn, dir: dir}] = st
		if nn := normalizeIfaceName(ifn); nn != "" {
			k := ifaceUtilKey{dev: dev, ifn: nn, dir: dir}
			if _, ok := utilByNormKey[k]; !ok {
				utilByNormKey[k] = st
			}
		}
	}

	return capacityPathsJoin{
		memberToAgg:   memberToAgg,
		ifaceSpeed:    ifaceSpeed,
		utilByKey:     utilByKey,
		utilByNormKey: utilByNormKey,
	}
}

func normalizeIfaceName(name string) string {
	// Keep separators that matter for interface identity (/, ., -).
	s := strings.TrimSpace(name)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "")

	// Normalize common vendor prefix variants. Prefer short canonical prefixes so
	// "GigabitEthernet0/0" and "Gi0/0" match.
	repl := []struct{ from, to string }{
		// Aggregates / bundles.
		{"port-channel", "po"},
		{"portchannel", "po"},
		{"bundle-ether", "be"},
		{"bundleether", "be"},

		// Common IOS/NX-OS long forms.
		{"gigabitethernet", "gi"},
		{"tengigabitethernet", "te"},
		{"twentyfivegigabitethernet", "twe"},
		{"fortygigabitethernet", "fo"},
		{"hundredgigabitethernet", "hu"},

		// Shorthand variants seen in the wild.
		{"tengige", "te"},
		{"twentyfivegige", "twe"},
		{"fortygige", "fo"},
		{"hundredgige", "hu"},
		{"twohundredgige", "twohu"},
		{"fourhundredgige", "fourhu"},

		// Mgmt variants.
		{"managementethernet", "mgmt"},
		{"mgmtethernet", "mgmt"},
		{"management", "mgmt"},

		// Generic.
		{"fastethernet", "fa"},
		{"ethernet", "eth"},
		{"loopback", "lo"},
		{"vlan", "vl"},
	}
	for _, r := range repl {
		if strings.HasPrefix(s, r.from) {
			s = r.to + strings.TrimPrefix(s, r.from)
			break
		}
	}
	// Common vendor quirk: some sources use ".0" unit suffix for the base interface.
	// Keep other units (e.g. ".100") intact.
	if strings.HasSuffix(s, ".0") {
		s = strings.TrimSuffix(s, ".0")
	}
	return s
}

func finiteFloats(points []fwdPerfDataPoint) []float64 {
	out := make([]float64, 0, len(points))
	for _, p := range points {
		if math.IsNaN(p.Value) || math.IsInf(p.Value, 0) {
			continue
		}
		out = append(out, p.Value)
	}
	return out
}

func quantile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	cp := append([]float64(nil), values...)
	sort.Float64s(cp)
	if q <= 0 {
		return cp[0]
	}
	if q >= 1 {
		return cp[len(cp)-1]
	}
	pos := q * float64(len(cp)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return cp[lo]
	}
	frac := pos - float64(lo)
	return cp[lo]*(1-frac) + cp[hi]*frac
}

func maxFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func snapshotIDFromForwardQueryURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return ""
	}
	if sid := strings.TrimSpace(u.Query().Get("snapshotId")); sid != "" {
		return sid
	}
	// Some apps encode query params in the URL fragment.
	frag := strings.TrimSpace(u.Fragment)
	if frag == "" {
		return ""
	}
	if i := strings.Index(frag, "?"); i >= 0 {
		frag = frag[i+1:]
	}
	q, err := url.ParseQuery(frag)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(q.Get("snapshotId"))
}

// PostWorkspaceForwardNetworkCapacityPathBottlenecks uses Forward's /paths-bulk API and projects results into a capacity-only
// "bottleneck interface" view by joining the computed path hops to Skyforge's stored capacity rollups.
//
// This intentionally does not replicate Forward path analysis UI/workflows. It is meant for capacity planning showcase and
// "art of the possible" analysis (e.g., batch pastes of candidate flows).
//
//encore:api auth method=POST path=/api/workspaces/:id/forward-networks/:networkRef/capacity/path-bottlenecks
func (s *Service) PostWorkspaceForwardNetworkCapacityPathBottlenecks(ctx context.Context, id, networkRef string, req *ForwardNetworkCapacityPathBottlenecksRequest) (*ForwardNetworkCapacityPathBottlenecksResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

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
	if len(req.Queries) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("queries required").Err()
	}
	if len(req.Queries) > 100 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("too many queries (max 100)").Err()
	}
	for i, q := range req.Queries {
		if strings.TrimSpace(q.DstIP) == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(fmt.Sprintf("queries[%d].dstIp is required", i)).Err()
		}
	}

	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}

	// Load rollups and inventory up front so we can do a single join for all queries.
	asOf, rollups, err := loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load capacity rollups").Err()
	}
	_, _, _, ifaces, _, _, _, _, invErr := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID)
	if invErr != nil {
		ifaces = []CapacityInterfaceInventoryRow{}
	}
	join := buildCapacityPathsJoin(window, rollups, ifaces)

	// Build Forward bulk request with guardrails: keep this endpoint capacity-only and avoid
	// duplicating Forward path analysis knobs.
	payload := &fwdPathSearchBulkRequestFull{
		Queries:                 make([]fwdPathSearchQuery, 0, len(req.Queries)),
		Intent:                  "PREFER_DELIVERED",
		MaxCandidates:           5000,
		MaxResults:              1,
		MaxReturnPathResults:    0,
		MaxSeconds:              30,
		MaxOverallSeconds:       300,
		IncludeTags:             false,
		IncludeNetworkFunctions: false,
	}
	for _, q := range req.Queries {
		payload.Queries = append(payload.Queries, fwdPathSearchQuery{
			From:    strings.TrimSpace(q.From),
			SrcIP:   strings.TrimSpace(q.SrcIP),
			DstIP:   strings.TrimSpace(q.DstIP),
			IPProto: q.IPProto,
			SrcPort: strings.TrimSpace(q.SrcPort),
			DstPort: strings.TrimSpace(q.DstPort),
		})
	}

	query := url.Values{}
	if v := strings.TrimSpace(req.SnapshotID); v != "" {
		query.Set("snapshotId", v)
	}

	rawPath := forwardAPIPathFor(client, "/networks/"+url.PathEscape(net.ForwardNetworkID)+"/paths-bulk")
	resp, body, err := client.doJSON(ctx, http.MethodPost, rawPath, query, payload)
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

	return capacityPathBottlenecksFromFwdOut(ctx, client, pc.workspace.ID, net.ID, net.ForwardNetworkID, window, windowDays, req, join, asOf, fwdOut, true)
}

func capacityPathBottlenecksFromFwdOut(
	ctx context.Context,
	client *forwardClient,
	workspaceID string,
	networkRef string,
	forwardNetworkID string,
	window string,
	windowDays int,
	req *ForwardNetworkCapacityPathBottlenecksRequest,
	join capacityPathsJoin,
	asOf time.Time,
	fwdOut []fwdPathSearchResponseFull,
	perfFallbackEnabled bool,
) (*ForwardNetworkCapacityPathBottlenecksResponse, error) {
	if client == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("Forward client unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	memberToAgg := join.memberToAgg
	ifaceSpeed := join.ifaceSpeed
	utilByKey := join.utilByKey
	utilByNormKey := join.utilByNormKey

	// Perf fallback: for hop interfaces that have no matching utilization rollup, pull Forward perf history
	// and compute p95/max locally (bounded). This helps demos and partial-coverage environments.
	const maxFallbackInterfaces = 200

	allHopKeys := map[ifaceUtilKey]struct{}{}
	rollupMatched := map[ifaceUtilKey]struct{}{}
	missingSet := map[ifaceUtilKey]struct{}{}
	missingOrder := make([]ifaceUtilKey, 0, 64)

	hasRollup := func(devKey, ifnOut, dir string) bool {
		if _, ok := utilByKey[ifaceUtilKey{dev: devKey, ifn: ifnOut, dir: dir}]; ok {
			return true
		}
		if nn := normalizeIfaceName(ifnOut); nn != "" {
			if _, ok := utilByNormKey[ifaceUtilKey{dev: devKey, ifn: nn, dir: dir}]; ok {
				return true
			}
		}
		// If this is a LAG member, allow matching rollups that exist only on the aggregate interface.
		agg := ""
		if v, ok := memberToAgg[devKey+"|"+ifnOut]; ok {
			agg = strings.TrimSpace(v)
		} else if nn := normalizeIfaceName(ifnOut); nn != "" {
			if v, ok := memberToAgg[devKey+"|"+nn]; ok {
				agg = strings.TrimSpace(v)
			}
		}
		if agg != "" {
			if _, ok := utilByKey[ifaceUtilKey{dev: devKey, ifn: agg, dir: dir}]; ok {
				return true
			}
			if nn := normalizeIfaceName(agg); nn != "" {
				if _, ok := utilByNormKey[ifaceUtilKey{dev: devKey, ifn: nn, dir: dir}]; ok {
					return true
				}
			}
		}
		return false
	}

	for _, r := range fwdOut {
		if len(r.Info.Paths) == 0 {
			continue
		}
		p := r.Info.Paths[0]
		for _, h := range p.Hops {
			devKey := strings.ToLower(strings.TrimSpace(h.DeviceName))
			if devKey == "" {
				continue
			}
			if in := strings.TrimSpace(h.IngressInterface); in != "" {
				k := ifaceUtilKey{dev: devKey, ifn: in, dir: "INGRESS"}
				allHopKeys[k] = struct{}{}
				if hasRollup(devKey, in, "INGRESS") {
					rollupMatched[k] = struct{}{}
				} else if _, ok := missingSet[k]; !ok {
					missingSet[k] = struct{}{}
					missingOrder = append(missingOrder, k)
				}
			}
			if outIf := strings.TrimSpace(h.EgressInterface); outIf != "" {
				k := ifaceUtilKey{dev: devKey, ifn: outIf, dir: "EGRESS"}
				allHopKeys[k] = struct{}{}
				if hasRollup(devKey, outIf, "EGRESS") {
					rollupMatched[k] = struct{}{}
				} else if _, ok := missingSet[k]; !ok {
					missingSet[k] = struct{}{}
					missingOrder = append(missingOrder, k)
				}
			}
		}
	}

	truncated := false
	if len(missingOrder) > maxFallbackInterfaces {
		truncated = true
		missingOrder = missingOrder[:maxFallbackInterfaces]
	}

	fallbackMatched := map[ifaceUtilKey]struct{}{}
	utilFallbackByKey := map[ifaceUtilKey]ifaceUtilStats{}
	if perfFallbackEnabled && len(missingOrder) > 0 {
		ifacesReq := make([]CapacityInterfaceWithDirection, 0, len(missingOrder))
		for _, k := range missingOrder {
			ifacesReq = append(ifacesReq, CapacityInterfaceWithDirection{
				DeviceName:    k.dev,
				InterfaceName: k.ifn,
				Direction:     k.dir,
			})
		}

		perfQuery := url.Values{}
		perfQuery.Set("type", "UTILIZATION")
		perfQuery.Set("days", fmt.Sprintf("%d", windowDays))
		perfQuery.Set("maxSamples", "400")

		perfPath := forwardAPIPathFor(client, "/networks/"+url.PathEscape(strings.TrimSpace(forwardNetworkID))+"/interface-metrics-history")
		perfPayload := &fwdInterfaceMetricsHistoryPayload{Interfaces: ifacesReq}
		perfResp, perfBody, perfErr := client.doJSON(ctx, http.MethodPost, perfPath, perfQuery, perfPayload)
		if perfErr == nil && perfResp.StatusCode >= 200 && perfResp.StatusCode < 300 {
			var decoded fwdPerfIfaceHistoryResponse
			if jsonErr := json.Unmarshal(perfBody, &decoded); jsonErr == nil {
				for _, m := range decoded.Metrics {
					devKey := strings.ToLower(strings.TrimSpace(m.InterfaceWithDirection.DeviceName))
					ifnOut := strings.TrimSpace(m.InterfaceWithDirection.InterfaceName)
					dir := strings.ToUpper(strings.TrimSpace(m.InterfaceWithDirection.Direction))
					if devKey == "" || ifnOut == "" || (dir != "INGRESS" && dir != "EGRESS") {
						continue
					}
					vals := finiteFloats(m.Data)
					if len(vals) == 0 {
						continue
					}
					p95v := quantile(vals, 0.95)
					maxv := maxFloat(vals)

					speed := 0
					if v, ok := ifaceSpeed[devKey+"|"+ifnOut]; ok {
						speed = v
					} else if nn := normalizeIfaceName(ifnOut); nn != "" {
						if v, ok := ifaceSpeed[devKey+"|"+nn]; ok {
							speed = v
						}
					}
					p95p := p95v
					maxp := maxv
					k := ifaceUtilKey{dev: devKey, ifn: ifnOut, dir: dir}
					utilFallbackByKey[k] = ifaceUtilStats{
						p95:       &p95p,
						max:       &maxp,
						forecast:  nil,
						threshold: nil,
						speedMbps: speed,
					}
					fallbackMatched[k] = struct{}{}
				}
			}
		}
	}

	unknown := map[ifaceUtilKey]struct{}{}
	for k := range allHopKeys {
		if _, ok := rollupMatched[k]; ok {
			continue
		}
		if _, ok := fallbackMatched[k]; ok {
			continue
		}
		unknown[k] = struct{}{}
	}

	asOfStr := ""
	if !asOf.IsZero() {
		asOfStr = asOf.UTC().Format(time.RFC3339)
	}

	items := make([]ForwardNetworkCapacityPathBottleneckItem, 0, len(req.Queries))
	for i := 0; i < len(req.Queries); i++ {
		it := ForwardNetworkCapacityPathBottleneckItem{
			Index: i,
			Query: req.Queries[i],
		}
		if i >= len(fwdOut) {
			it.Error = "missing response from Forward"
			items = append(items, it)
			continue
		}

		r := fwdOut[i]
		it.TimedOut = r.TimedOut
		it.ForwardQueryURL = strings.TrimSpace(r.QueryURL)
		th := r.Info.TotalHits
		it.TotalHits = &th
		if r.TimedOut {
			it.Error = "timed out"
			items = append(items, it)
			continue
		}
		if len(r.Info.Paths) == 0 {
			it.Error = "no path candidates returned"
			items = append(items, it)
			continue
		}

		p := r.Info.Paths[0]
		it.ForwardingOutcome = strings.TrimSpace(p.ForwardingOutcome)
		it.SecurityOutcome = strings.TrimSpace(p.SecurityOutcome)

		// Forward hop list (optional).
		if req.IncludeHops {
			hops := make([]ForwardNetworkCapacityPathHop, 0, len(p.Hops))
			for _, h := range p.Hops {
				hops = append(hops, ForwardNetworkCapacityPathHop{
					DeviceName:       strings.TrimSpace(h.DeviceName),
					IngressInterface: strings.TrimSpace(h.IngressInterface),
					EgressInterface:  strings.TrimSpace(h.EgressInterface),
				})
			}
			it.Hops = hops
		}

		// Join to rollups / perf fallback.
		best := (*ForwardNetworkCapacityPathBottleneck)(nil)
		itemUnknown := false
		notes := []CapacityNote{}

		unmatched := []string{}
		for _, h := range p.Hops {
			devKey := strings.ToLower(strings.TrimSpace(h.DeviceName))
			if devKey == "" {
				continue
			}

			pairs := []struct {
				dir string
				ifn string
			}{
				{dir: "INGRESS", ifn: strings.TrimSpace(h.IngressInterface)},
				{dir: "EGRESS", ifn: strings.TrimSpace(h.EgressInterface)},
			}
			for _, pair := range pairs {
				if pair.ifn == "" {
					continue
				}

				// Select best available stats for this hop interface+dir.
				st, src := ifaceUtilStats{}, ""
				k := ifaceUtilKey{dev: devKey, ifn: pair.ifn, dir: pair.dir}
				if v, ok := utilByKey[k]; ok {
					st = v
					src = "rollup"
				} else if nn := normalizeIfaceName(pair.ifn); nn != "" {
					if v, ok := utilByNormKey[ifaceUtilKey{dev: devKey, ifn: nn, dir: pair.dir}]; ok {
						st = v
						src = "rollup"
					}
				}
				if src == "" {
					// LAG member mapping.
					agg := ""
					if v, ok := memberToAgg[devKey+"|"+pair.ifn]; ok {
						agg = strings.TrimSpace(v)
					} else if nn := normalizeIfaceName(pair.ifn); nn != "" {
						if v, ok := memberToAgg[devKey+"|"+nn]; ok {
							agg = strings.TrimSpace(v)
						}
					}
					if agg != "" {
						if v, ok := utilByKey[ifaceUtilKey{dev: devKey, ifn: agg, dir: pair.dir}]; ok {
							st = v
							src = "rollup"
						} else if nn := normalizeIfaceName(agg); nn != "" {
							if v, ok := utilByNormKey[ifaceUtilKey{dev: devKey, ifn: nn, dir: pair.dir}]; ok {
								st = v
								src = "rollup"
							}
						}
					}
				}

				// On-demand perf fallback (bounded).
				if src == "" {
					if v, ok := utilFallbackByKey[k]; ok {
						st = v
						src = "perf_fallback"
					} else if nn := normalizeIfaceName(pair.ifn); nn != "" {
						if v, ok := utilFallbackByKey[ifaceUtilKey{dev: devKey, ifn: nn, dir: pair.dir}]; ok {
							st = v
							src = "perf_fallback"
						}
					}
				}

				if src == "" {
					itemUnknown = true
					if len(unmatched) < 20 {
						unmatched = append(unmatched, devKey+"|"+pair.ifn+"|"+pair.dir)
					}
					continue
				}

				// Require speed for Gbps conversion/headroom.
				if st.speedMbps <= 0 {
					// Best-effort speed: fall back to inventory lookup.
					if v, ok := ifaceSpeed[devKey+"|"+pair.ifn]; ok {
						st.speedMbps = v
					} else if nn := normalizeIfaceName(pair.ifn); nn != "" {
						if v, ok := ifaceSpeed[devKey+"|"+nn]; ok {
							st.speedMbps = v
						}
					}
				}

				// Convert to bottleneck candidate.
				bn := &ForwardNetworkCapacityPathBottleneck{
					DeviceName:    strings.TrimSpace(h.DeviceName),
					InterfaceName: pair.ifn,
					Direction:     strings.ToLower(pair.dir),
					Source:        src,
				}
				if st.speedMbps > 0 {
					sp := st.speedMbps
					bn.SpeedMbps = &sp
				}
				if st.threshold != nil {
					v := *st.threshold
					bn.Threshold = &v
				}
				if st.p95 != nil {
					v := *st.p95
					bn.P95Util = &v
				}
				if st.max != nil {
					v := *st.max
					bn.MaxUtil = &v
				}
				if st.forecast != nil && strings.TrimSpace(*st.forecast) != "" {
					v := strings.TrimSpace(*st.forecast)
					bn.ForecastCrossingTS = &v
				}

				// Derived: Gbps + headroom.
				if bn.SpeedMbps != nil && *bn.SpeedMbps > 0 {
					speedGbps := float64(*bn.SpeedMbps) / 1000.0
					if bn.P95Util != nil {
						p95g := *bn.P95Util * speedGbps
						bn.P95Gbps = &p95g
					}
					if bn.MaxUtil != nil {
						mg := *bn.MaxUtil * speedGbps
						bn.MaxGbps = &mg
					}
					if bn.Threshold != nil && bn.P95Util != nil {
						hg := (*bn.Threshold - *bn.P95Util) * speedGbps
						if hg < 0 {
							hg = 0
						}
						bn.HeadroomGbps = &hg
						hu := *bn.Threshold - *bn.P95Util
						if hu < 0 {
							hu = 0
						}
						bn.HeadroomUtil = &hu
					}
				}

				// Select worst bottleneck: least headroom Gbps (or highest util when headroom absent).
				if best == nil {
					best = bn
					continue
				}
				a := -1.0
				b := -1.0
				if bn.HeadroomGbps != nil {
					a = *bn.HeadroomGbps
				}
				if best.HeadroomGbps != nil {
					b = *best.HeadroomGbps
				}
				if a >= 0 && b >= 0 {
					if a < b {
						best = bn
					}
					continue
				}
				au := -1.0
				bu := -1.0
				if bn.P95Util != nil {
					au = *bn.P95Util
				}
				if best.P95Util != nil {
					bu = *best.P95Util
				}
				if au > bu {
					best = bn
				}
			}
		}

		if len(unmatched) > 0 {
			it.UnmatchedHopInterfacesSample = unmatched
		}

		if itemUnknown {
			notes = append(notes, CapacityNote{
				Code:    "PARTIAL_COVERAGE",
				Message: "Some hop interfaces had no matching rollups. This can happen due to routing/topology changes or missing collectors.",
			})
			if perfFallbackEnabled && truncated {
				notes = append(notes, CapacityNote{
					Code:    "FALLBACK_TRUNCATED",
					Message: "On-demand perf fallback was truncated for this batch; some hop interfaces may be missing stats.",
				})
			}
		}

		it.Bottleneck = best
		if it.Bottleneck == nil {
			it.Error = "no utilization stats matched any hop interfaces (run Refresh to compute rollups, or ensure perf is available)"
			notes = append(notes, CapacityNote{
				Code:    "STATS_MISSING",
				Message: "No utilization rollups or perf fallback stats matched hop interfaces.",
			})
		} else if it.Bottleneck.SpeedMbps == nil {
			notes = append(notes, CapacityNote{
				Code:    "SPEED_MISSING",
				Message: "Missing speed metadata for bottleneck interface; showing utilization headroom only.",
			})
		}
		it.Notes = notes
		items = append(items, it)
	}

	// Coverage diagnostics (best-effort; helps customers understand why some flows are unknown).
	sample := make([]string, 0, 20)
	if len(unknown) > 0 {
		all := make([]string, 0, len(unknown))
		for k := range unknown {
			all = append(all, k.dev+"|"+k.ifn+"|"+k.dir)
		}
		sort.Strings(all)
		if len(all) > 20 {
			all = all[:20]
		}
		sample = append(sample, all...)
	}
	coverage := &ForwardNetworkCapacityPathBottlenecksCoverage{
		HopInterfaceKeys:             len(allHopKeys),
		RollupMatched:                len(rollupMatched),
		PerfFallbackUsed:             len(fallbackMatched),
		Unknown:                      len(unknown),
		Truncated:                    perfFallbackEnabled && truncated,
		UnmatchedHopInterfacesSample: sample,
	}

	out := &ForwardNetworkCapacityPathBottlenecksResponse{
		WorkspaceID:      workspaceID,
		NetworkRef:       networkRef,
		ForwardNetworkID: forwardNetworkID,
		AsOf:             asOfStr,
		Window:           window,
		SnapshotID:       strings.TrimSpace(req.SnapshotID),
		Coverage:         coverage,
		Items:            items,
	}
	if out.SnapshotID == "" {
		// Best-effort: infer snapshotId from Forward's queryUrl (if present), otherwise omit.
		for _, r := range fwdOut {
			if sid := snapshotIDFromForwardQueryURL(r.QueryURL); sid != "" {
				out.SnapshotID = sid
				break
			}
		}
	}
	return out, nil
}
