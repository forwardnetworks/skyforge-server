package skyforge

import (
	"context"
	"math"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type capacityDirStats struct {
	dir       string
	p95       float64
	max       float64
	forecast  *string
	speedMbps int
}

type capacityAggStats struct {
	dev string
	ifn string
	ing *capacityDirStats
	egr *capacityDirStats
}

type ForwardNetworkCapacityUpgradeCandidatesQuery struct {
	Window string `query:"window" encore:"optional"`
}

type ForwardNetworkCapacityUpgradeCandidate struct {
	ObjectType string   `json:"objectType"`
	Device     string   `json:"device"`
	Name       string   `json:"name"`
	Members    []string `json:"members,omitempty"`

	SpeedMbps          int     `json:"speedMbps"`
	WorstDirection     string  `json:"worstDirection"`
	P95Util            float64 `json:"p95Util"`
	MaxUtil            float64 `json:"maxUtil"`
	P95Gbps            float64 `json:"p95Gbps"`
	MaxGbps            float64 `json:"maxGbps"`
	ForecastCrossingTS *string `json:"forecastCrossingTs,omitempty"`

	RequiredSpeedMbps    *int   `json:"requiredSpeedMbps,omitempty"`
	RecommendedSpeedMbps *int   `json:"recommendedSpeedMbps,omitempty"`
	Reason               string `json:"reason,omitempty"`

	// For LAGs: highlight worst-member imbalance.
	WorstMemberMaxUtil *float64 `json:"worstMemberMaxUtil,omitempty"`
}

type ForwardNetworkCapacityUpgradeCandidatesResponse struct {
	OwnerUsername    string `json:"ownerUsername"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	AsOf             string `json:"asOf,omitempty"`

	Items []ForwardNetworkCapacityUpgradeCandidate `json:"items"`
}

// capacityUpgradeCandidatesFromRollups is the core computation used by both the Capacity UI endpoint
// and Assurance Studio (which reuses preloaded rollups/inventory).
func capacityUpgradeCandidatesFromRollups(window string, rollups []CapacityRollupRow, ifaces []CapacityInterfaceInventoryRow) []ForwardNetworkCapacityUpgradeCandidate {
	// Speed + LAG metadata index from inventory.
	type ifaceMeta struct {
		speedMbps     int
		aggregateId   string
		configMembers []string
		members       []string
	}
	ifaceByKey := map[string]ifaceMeta{} // dev|iface
	for _, r := range ifaces {
		dev := strings.TrimSpace(r.DeviceName)
		ifn := strings.TrimSpace(r.InterfaceName)
		if dev == "" || ifn == "" {
			continue
		}
		speed := 0
		if r.SpeedMbps != nil && *r.SpeedMbps > 0 {
			speed = *r.SpeedMbps
		}
		ifaceByKey[dev+"|"+ifn] = ifaceMeta{
			speedMbps:     speed,
			aggregateId:   strings.TrimSpace(ptrToString(r.AggregateID)),
			configMembers: trimAndFilter(r.AggregationConfiguredMemberNames),
			members:       trimAndFilter(r.AggregationMemberNames),
		}
	}

	// Extract interface utilization rollups for the chosen window and collapse ingress+egress into one row per (dev,iface).
	statsByKey := map[string]*capacityAggStats{}

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
			// Fallback: parse object id (device:iface:dir).
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
		k := dev + "|" + ifn
		a := statsByKey[k]
		if a == nil {
			a = &capacityAggStats{dev: dev, ifn: ifn}
			statsByKey[k] = a
		}
		speedMbps := getJSONMapInt(r.Details, "speedMbps")
		if speedMbps <= 0 {
			if m, ok := ifaceByKey[k]; ok && m.speedMbps > 0 {
				speedMbps = m.speedMbps
			}
		}

		ds := &capacityDirStats{
			dir:       normDir(dir, r.Metric),
			p95:       nullFloatToZero(r.P95),
			max:       nullFloatToZero(r.Max),
			forecast:  r.ForecastCrossingTS,
			speedMbps: speedMbps,
		}
		if r.Metric == "util_ingress" {
			a.ing = ds
		} else {
			a.egr = ds
		}
	}

	// Build candidate set for non-LAG interfaces (and for LAGs separately).
	// Map device|aggregateName -> member keys.
	lagMembers := map[string][]string{}
	for k, meta := range ifaceByKey {
		if meta.aggregateId == "" {
			continue
		}
		lagKey := strings.TrimSpace(strings.SplitN(k, "|", 2)[0]) + "|" + meta.aggregateId
		lagMembers[lagKey] = append(lagMembers[lagKey], k)
	}
	for k, meta := range ifaceByKey {
		dev, ifn := splitDevIfaceKey(k)
		if dev == "" || ifn == "" {
			continue
		}
		memberNames := meta.configMembers
		if len(memberNames) == 0 {
			memberNames = meta.members
		}
		if len(memberNames) == 0 {
			continue
		}
		lagKey := dev + "|" + ifn
		for _, mn := range memberNames {
			mk := dev + "|" + strings.TrimSpace(mn)
			lagMembers[lagKey] = append(lagMembers[lagKey], mk)
		}
	}
	for k := range lagMembers {
		lagMembers[k] = uniqSorted(lagMembers[k])
	}

	items := []ForwardNetworkCapacityUpgradeCandidate{}
	seenMember := map[string]struct{}{}

	// LAG candidates.
	for lagKey, memberKeys := range lagMembers {
		dev, lagIf := splitDevIfaceKey(lagKey)
		if dev == "" || lagIf == "" || len(memberKeys) == 0 {
			continue
		}

		type mrow struct {
			ifn       string
			worstDir  string
			p95       float64
			max       float64
			p95Gbps   float64
			maxGbps   float64
			speedMbps int
			forecast  *string
		}
		mrows := []mrow{}
		totalSpeedMbps := 0
		totalP95Gbps := 0.0
		totalMaxGbps := 0.0
		worstMemberMax := -1.0
		soonestForecast := (*string)(nil)

		for _, mk := range memberKeys {
			md, mif := splitDevIfaceKey(mk)
			if md == "" || mif == "" {
				continue
			}
			a := statsByKey[md+"|"+mif]
			s := pickWorstDir(a)
			if s == nil || s.speedMbps <= 0 {
				continue
			}
			speedGbps := float64(s.speedMbps) / 1000.0
			p95Gbps := speedGbps * s.p95
			maxGbps := speedGbps * s.max
			mrows = append(mrows, mrow{
				ifn:       mif,
				worstDir:  s.dir,
				p95:       s.p95,
				max:       s.max,
				p95Gbps:   p95Gbps,
				maxGbps:   maxGbps,
				speedMbps: s.speedMbps,
				forecast:  s.forecast,
			})
			totalSpeedMbps += s.speedMbps
			totalP95Gbps += p95Gbps
			totalMaxGbps += maxGbps
			if s.max > worstMemberMax {
				worstMemberMax = s.max
			}
			if s.forecast != nil && strings.TrimSpace(*s.forecast) != "" {
				if soonestForecast == nil || strings.TrimSpace(*s.forecast) < strings.TrimSpace(*soonestForecast) {
					v := strings.TrimSpace(*s.forecast)
					soonestForecast = &v
				}
			}
			seenMember[md+"|"+mif] = struct{}{}
		}

		if len(mrows) == 0 || totalSpeedMbps <= 0 {
			continue
		}

		sort.Slice(mrows, func(i, j int) bool { return mrows[i].max > mrows[j].max })
		memberNames := []string{}
		for _, r := range mrows {
			memberNames = append(memberNames, r.ifn)
		}

		// Pick worst direction for the LAG using aggregate throughput.
		worstDir := "EGRESS"
		if len(mrows) > 0 {
			worstDir = mrows[0].worstDir
		}

		den := float64(totalSpeedMbps) / 1000.0
		item := ForwardNetworkCapacityUpgradeCandidate{
			ObjectType:     "lag",
			Device:         dev,
			Name:           lagIf,
			Members:        memberNames,
			SpeedMbps:      totalSpeedMbps,
			WorstDirection: worstDir,
			P95Util: func() float64 {
				if den <= 0 {
					return 0
				}
				return totalP95Gbps / den
			}(),
			MaxUtil: func() float64 {
				if den <= 0 {
					return 0
				}
				return totalMaxGbps / den
			}(),
			P95Gbps:            totalP95Gbps,
			MaxGbps:            totalMaxGbps,
			ForecastCrossingTS: soonestForecast,
		}
		if worstMemberMax >= 0 {
			v := worstMemberMax
			item.WorstMemberMaxUtil = &v
		}
		applyUpgradeHeuristic(&item)
		items = append(items, item)
	}

	// Non-LAG interface candidates (skip members that were surfaced in LAG rows).
	for _, a := range statsByKey {
		dev := a.dev
		ifn := a.ifn
		if dev == "" || ifn == "" {
			continue
		}
		if _, ok := seenMember[dev+"|"+ifn]; ok {
			continue
		}
		s := pickWorstDir(a)
		if s == nil || s.speedMbps <= 0 {
			continue
		}
		speedGbps := float64(s.speedMbps) / 1000.0
		p95Gbps := speedGbps * s.p95
		maxGbps := speedGbps * s.max
		item := ForwardNetworkCapacityUpgradeCandidate{
			ObjectType:         "iface",
			Device:             dev,
			Name:               ifn,
			SpeedMbps:          s.speedMbps,
			WorstDirection:     s.dir,
			P95Util:            s.p95,
			MaxUtil:            s.max,
			P95Gbps:            p95Gbps,
			MaxGbps:            maxGbps,
			ForecastCrossingTS: s.forecast,
		}
		applyUpgradeHeuristic(&item)
		items = append(items, item)
	}

	// Only return "interesting" candidates; keep it a tight showcase list.
	keep := []ForwardNetworkCapacityUpgradeCandidate{}
	for _, it := range items {
		if it.MaxUtil >= 0.85 || it.P95Util >= 0.85 || it.ForecastCrossingTS != nil || it.RecommendedSpeedMbps != nil || it.WorstMemberMaxUtil != nil {
			keep = append(keep, it)
		}
	}
	sort.Slice(keep, func(i, j int) bool {
		if keep[i].RecommendedSpeedMbps != nil && keep[j].RecommendedSpeedMbps == nil {
			return true
		}
		if keep[i].RecommendedSpeedMbps == nil && keep[j].RecommendedSpeedMbps != nil {
			return false
		}
		if keep[i].MaxUtil == keep[j].MaxUtil {
			if keep[i].Device == keep[j].Device {
				return keep[i].Name < keep[j].Name
			}
			return keep[i].Device < keep[j].Device
		}
		return keep[i].MaxUtil > keep[j].MaxUtil
	})
	return keep
}

// GetUserForwardNetworkCapacityUpgradeCandidates proposes "what to upgrade" based on rollups + inventory.
//
// This is intentionally a showcase/heuristic view (not a replacement for full NPM alerting/workflows).
func (s *Service) GetUserForwardNetworkCapacityUpgradeCandidates(ctx context.Context, id, networkRef string, q *ForwardNetworkCapacityUpgradeCandidatesQuery) (*ForwardNetworkCapacityUpgradeCandidatesResponse, error) {
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

	window := "7d"
	if q != nil && strings.TrimSpace(q.Window) != "" {
		window = strings.TrimSpace(q.Window)
	}

	asOf, rollups, err := loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.context.ID, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load rollups").Err()
	}
	_, _, _, ifaces, _, _, _, _, invErr := loadLatestCapacityInventoryForForwardNetwork(ctx, s.db, pc.context.ID, net.ForwardNetworkID)
	if invErr != nil {
		// Best-effort; we can still return interface candidates that have speed in rollup details.
		ifaces = []CapacityInterfaceInventoryRow{}
	}

	keep := capacityUpgradeCandidatesFromRollups(window, rollups, ifaces)

	out := &ForwardNetworkCapacityUpgradeCandidatesResponse{
		OwnerUsername:    pc.context.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Items:            keep,
	}
	if !asOf.IsZero() {
		out.AsOf = asOf.UTC().Format(time.RFC3339)
	}
	return out, nil
}

func pickWorstDir(a *capacityAggStats) *capacityDirStats {
	if a == nil {
		return nil
	}
	// Prefer the direction with higher max; tie-breaker by p95.
	cands := []*capacityDirStats{}
	if a.ing != nil {
		cands = append(cands, a.ing)
	}
	if a.egr != nil {
		cands = append(cands, a.egr)
	}
	if len(cands) == 0 {
		return nil
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.max > best.max || (c.max == best.max && c.p95 > best.p95) {
			best = c
		}
	}
	return best
}

func applyUpgradeHeuristic(it *ForwardNetworkCapacityUpgradeCandidate) {
	if it == nil || it.SpeedMbps <= 0 {
		return
	}
	const target = 0.85

	required := 0
	reason := ""
	if it.MaxUtil >= target {
		required = int(math.Ceil(float64(it.SpeedMbps) * (it.MaxUtil / target)))
		reason = "HOT_MAX"
	} else if it.P95Util >= target {
		required = int(math.Ceil(float64(it.SpeedMbps) * (it.P95Util / target)))
		reason = "HOT_P95"
	} else if it.ForecastCrossingTS != nil && strings.TrimSpace(*it.ForecastCrossingTS) != "" {
		// No utilization threshold crossed yet, but forecast says it will.
		required = int(math.Ceil(float64(it.SpeedMbps) * (math.Max(it.P95Util, it.MaxUtil) / target)))
		if required <= 0 {
			required = it.SpeedMbps
		}
		reason = "FORECAST"
	}
	if required <= it.SpeedMbps {
		// No upgrade needed.
		it.Reason = reason
		return
	}

	rec := nextStandardSpeedMbps(required)
	it.Reason = reason
	it.RequiredSpeedMbps = &required
	if rec > it.SpeedMbps {
		it.RecommendedSpeedMbps = &rec
	}
}

func nextStandardSpeedMbps(min int) int {
	// Keep the list small and common.
	steps := []int{
		100, 1000, 2500, 5000,
		10000, 25000, 40000, 50000,
		100000, 200000, 400000,
	}
	for _, s := range steps {
		if s >= min {
			return s
		}
	}
	// If we exceed the table, just round up to nearest 100G.
	return int(math.Ceil(float64(min)/100000.0)) * 100000
}

func nullFloatToZero(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func normDir(dir, metric string) string {
	d := strings.ToUpper(strings.TrimSpace(dir))
	if d != "" {
		return d
	}
	if metric == "util_ingress" {
		return "INGRESS"
	}
	if metric == "util_egress" {
		return "EGRESS"
	}
	return ""
}

func splitDevIfaceKey(k string) (dev, ifn string) {
	parts := strings.SplitN(k, "|", 2)
	if len(parts) >= 1 {
		dev = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		ifn = strings.TrimSpace(parts[1])
	}
	return dev, ifn
}

func uniqSorted(keys []string) []string {
	m := map[string]struct{}{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		m[k] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func trimAndFilter(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
