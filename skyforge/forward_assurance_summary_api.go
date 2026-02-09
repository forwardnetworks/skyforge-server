package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

// NOTE: This file intentionally mirrors the contract exposed by the meta-repo
// `components/server` assurance summary endpoint so "competitive demo" UIs can
// consume a stable API even if their backend doesn't use the forward import
// storage pipeline.

type ForwardAssuranceHistoryParams struct {
	Limit string `query:"limit" encore:"optional"`
}

type ForwardAssuranceSummaryResponse struct {
	WorkspaceID      string `json:"workspaceId"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	GeneratedAt      string `json:"generatedAt"`

	Snapshot         ForwardAssuranceSnapshotTile         `json:"snapshot"`
	CollectionHealth ForwardAssuranceCollectionHealthTile `json:"collectionHealth"`
	IndexingHealth   ForwardAssuranceIndexingHealthTile   `json:"indexingHealth"`
	Vulnerabilities  ForwardAssuranceVulnerabilitiesTile  `json:"vulnerabilities"`
	Capacity         ForwardAssuranceCapacityTile         `json:"capacity"`
	LiveSignals      ForwardAssuranceLiveSignalsTile      `json:"liveSignals"`

	Evidence ForwardAssuranceEvidence `json:"evidence"`
	Warnings []string                 `json:"warnings,omitempty"`
	Missing  []string                 `json:"missing,omitempty"`
}

type ForwardAssuranceSnapshotTile struct {
	SnapshotID         string `json:"snapshotId"`
	ProcessedAt        string `json:"processedAt,omitempty"`
	State              string `json:"state,omitempty"`
	AgeSeconds         int64  `json:"ageSeconds,omitempty"`
	SourceImportItemID int64  `json:"sourceImportItemId,omitempty"`
}

type ForwardAssuranceCollectionHealthTile struct {
	NumSuccessfulDevices          *int   `json:"numSuccessfulDevices,omitempty"`
	NumCollectionFailureDevices   *int   `json:"numCollectionFailureDevices,omitempty"`
	NumProcessingFailureDevices   *int   `json:"numProcessingFailureDevices,omitempty"`
	NumSuccessfulEndpoints        *int   `json:"numSuccessfulEndpoints,omitempty"`
	NumCollectionFailureEndpoints *int   `json:"numCollectionFailureEndpoints,omitempty"`
	NumProcessingFailureEndpoints *int   `json:"numProcessingFailureEndpoints,omitempty"`
	CollectionDurationMs          *int64 `json:"collectionDurationMs,omitempty"`
	ProcessingDurationMs          *int64 `json:"processingDurationMs,omitempty"`
	TopFailureReasons             []ForwardAssuranceFailureReason `json:"topFailureReasons,omitempty"`
	SourceImportItemID            int64                           `json:"sourceImportItemId,omitempty"`
}

type ForwardAssuranceFailureReason struct {
	Kind  string `json:"kind"`
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type ForwardAssuranceIndexingHealthTile struct {
	PathSearchIndexingStatus string `json:"pathSearchIndexingStatus,omitempty"`
	SearchIndexingStatus     string `json:"searchIndexingStatus,omitempty"`
	L2IndexingStatus         string `json:"l2IndexingStatus,omitempty"`
	HostComputationStatus    string `json:"hostComputationStatus,omitempty"`
	IPLocationIndexingStatus string `json:"ipLocationIndexingStatus,omitempty"`
	Overall                  string `json:"overall"`
	SourceImportItemID       int64  `json:"sourceImportItemId,omitempty"`
}

type ForwardAssuranceVulnerabilitiesTile struct {
	Total              *int           `json:"total,omitempty"`
	Offset             *int           `json:"offset,omitempty"`
	LimitUsed          int            `json:"limitUsed"`
	BySeverity         map[string]int `json:"bySeverity,omitempty"`
	KnownExploitCount  *int           `json:"knownExploitCount,omitempty"`
	IndexCreatedAt     string         `json:"indexCreatedAt,omitempty"`
	Partial            bool           `json:"partial"`
	SourceImportItemID int64          `json:"sourceImportItemId,omitempty"`
}

type ForwardAssuranceCapacityTile struct {
	AsOf          string   `json:"asOf,omitempty"`
	Stale         bool     `json:"stale"`
	HotInterfaces int      `json:"hotInterfaces"`
	MaxUtilMax    *float64 `json:"maxUtilMax,omitempty"`
	Source        string   `json:"source"`
}

type ForwardAssuranceLiveSignalsTile struct {
	WindowMinutes int `json:"windowMinutes"`
	Syslog        ForwardAssuranceLiveSyslog `json:"syslog"`
	SnmpTraps     ForwardAssuranceLiveCount  `json:"snmpTraps"`
	Webhooks      ForwardAssuranceLiveCount  `json:"webhooks"`
}

type ForwardAssuranceLiveSyslog struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
}

type ForwardAssuranceLiveCount struct {
	Total int `json:"total"`
}

type ForwardAssuranceEvidence struct {
	// Kept for API compatibility. This backend computes summary directly from
	// live Forward calls, so there may be no import items.
	ImportItemIDsByKind map[string]int64 `json:"importItemIdsByKind,omitempty"`
	ImportID            string           `json:"importId,omitempty"`
}

type ForwardAssuranceHistoryItem struct {
	ID          int64                         `json:"id"`
	GeneratedAt string                        `json:"generatedAt"`
	SnapshotID  string                        `json:"snapshotId,omitempty"`
	Summary     ForwardAssuranceSummaryResponse `json:"summary"`
}

type ForwardAssuranceHistoryResponse struct {
	Items []ForwardAssuranceHistoryItem `json:"items"`
}

type forwardSnapshotInfo struct {
	ID          string `json:"id"`
	ProcessedAt string `json:"processedAt,omitempty"`
	State       string `json:"state,omitempty"`
}

type forwardSnapshotMetrics struct {
	SnapshotId string `json:"snapshotId,omitempty"`

	NumSuccessfulDevices          *int `json:"numSuccessfulDevices,omitempty"`
	NumCollectionFailureDevices   *int `json:"numCollectionFailureDevices,omitempty"`
	NumProcessingFailureDevices   *int `json:"numProcessingFailureDevices,omitempty"`
	NumSuccessfulEndpoints        *int `json:"numSuccessfulEndpoints,omitempty"`
	NumCollectionFailureEndpoints *int `json:"numCollectionFailureEndpoints,omitempty"`
	NumProcessingFailureEndpoints *int `json:"numProcessingFailureEndpoints,omitempty"`

	CollectionDuration int64 `json:"collectionDuration,omitempty"`
	ProcessingDuration int64 `json:"processingDuration,omitempty"`

	PathSearchIndexingStatus string `json:"pathSearchIndexingStatus,omitempty"`
	SearchIndexingStatus     string `json:"searchIndexingStatus,omitempty"`
	L2IndexingStatus         string `json:"l2IndexingStatus,omitempty"`
	HostComputationStatus    string `json:"hostComputationStatus,omitempty"`
	IPLocationIndexingStatus string `json:"ipLocationIndexingStatus,omitempty"`

	DeviceCollectionFailures   map[string]int `json:"deviceCollectionFailures,omitempty"`
	DeviceProcessingFailures   map[string]int `json:"deviceProcessingFailures,omitempty"`
	EndpointCollectionFailures map[string]int `json:"endpointCollectionFailures,omitempty"`
	EndpointProcessingFailures map[string]int `json:"endpointProcessingFailures,omitempty"`
}

type forwardVulnerability struct {
	Severity           string `json:"severity,omitempty"`
	KnownExploitSource string `json:"knownExploitSource,omitempty"`
}

type forwardVulnerabilityAnalysis struct {
	Vulnerabilities []forwardVulnerability `json:"vulnerabilities,omitempty"`
	Offset          int                    `json:"offset,omitempty"`
	Total           int                    `json:"total,omitempty"`
	IndexCreatedAt  string                 `json:"indexCreatedAt,omitempty"`
}

func parseJSONBytesInto(b []byte, dst any) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 {
		return fmt.Errorf("empty json")
	}
	return json.Unmarshal(b, dst)
}

func forwardGETJSON(ctx context.Context, client *forwardClient, path string, query url.Values) ([]byte, error) {
	resp, body, err := client.doJSON(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("forward %s failed: %s", path, msg)
	}
	return body, nil
}

func parseForwardSnapshotIDFromLatestProcessed(body []byte) string {
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err == nil {
		for _, k := range []string{"id", "snapshotId", "snapshotID"} {
			if v, ok := obj[k]; ok {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	var s string
	if err := json.Unmarshal(body, &s); err == nil && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	return ""
}

func normalizeForwardStatus(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func computeIndexingOverall(statuses ...string) string {
	haveAny := false
	warn := false
	for _, raw := range statuses {
		s := normalizeForwardStatus(raw)
		if s == "" {
			continue
		}
		haveAny = true
		switch s {
		case "SUCCESS", "OK":
			// ok
		default:
			warn = true
		}
	}
	if !haveAny {
		return "unknown"
	}
	if warn {
		return "warn"
	}
	return "ok"
}

func topFailureReasons(m map[string]int, kind string, out *[]ForwardAssuranceFailureReason) {
	if len(m) == 0 {
		return
	}
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		k = strings.TrimSpace(k)
		if k == "" || v <= 0 {
			continue
		}
		arr = append(arr, kv{k: k, v: v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v == arr[j].v {
			return arr[i].k < arr[j].k
		}
		return arr[i].v > arr[j].v
	})
	for i := 0; i < len(arr) && i < 5; i++ {
		*out = append(*out, ForwardAssuranceFailureReason{
			Kind:  kind,
			Key:   arr[i].k,
			Count: arr[i].v,
		})
	}
}

func computeForwardAssuranceSummaryFromLive(now time.Time, workspaceID, networkRef, forwardNetworkID string, snapshot forwardSnapshotInfo, haveSnapshot bool, metrics forwardSnapshotMetrics, haveMetrics bool, vuln forwardVulnerabilityAnalysis, haveVuln bool, capAsOf time.Time, capRollups []CapacityRollupRow, capErr error) ForwardAssuranceSummaryResponse {
	now = now.UTC()
	out := ForwardAssuranceSummaryResponse{
		WorkspaceID:      workspaceID,
		NetworkRef:       networkRef,
		ForwardNetworkID: forwardNetworkID,
		GeneratedAt:      now.Format(time.RFC3339Nano),
		Snapshot:         ForwardAssuranceSnapshotTile{},
		CollectionHealth: ForwardAssuranceCollectionHealthTile{},
		IndexingHealth:   ForwardAssuranceIndexingHealthTile{Overall: "unknown"},
		Vulnerabilities:  ForwardAssuranceVulnerabilitiesTile{LimitUsed: 1000},
		Capacity: ForwardAssuranceCapacityTile{
			Stale:  true,
			Source: "none",
		},
		LiveSignals: ForwardAssuranceLiveSignalsTile{
			WindowMinutes: 60,
			Syslog:        ForwardAssuranceLiveSyslog{},
			SnmpTraps:     ForwardAssuranceLiveCount{},
			Webhooks:      ForwardAssuranceLiveCount{},
		},
		Evidence: ForwardAssuranceEvidence{
			ImportItemIDsByKind: map[string]int64{},
		},
		Missing:  []string{},
		Warnings: []string{},
	}

	// Snapshot info.
	if haveSnapshot {
		out.Snapshot.SnapshotID = strings.TrimSpace(snapshot.ID)
		out.Snapshot.ProcessedAt = strings.TrimSpace(snapshot.ProcessedAt)
		out.Snapshot.State = strings.TrimSpace(snapshot.State)
		if out.Snapshot.ProcessedAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, out.Snapshot.ProcessedAt); err == nil {
				out.Snapshot.AgeSeconds = int64(now.Sub(t.UTC()).Seconds())
			} else if t, err := time.Parse(time.RFC3339, out.Snapshot.ProcessedAt); err == nil {
				out.Snapshot.AgeSeconds = int64(now.Sub(t.UTC()).Seconds())
			}
		}
	}

	// Snapshot metrics.
	if haveMetrics {
		out.CollectionHealth.NumSuccessfulDevices = metrics.NumSuccessfulDevices
		out.CollectionHealth.NumCollectionFailureDevices = metrics.NumCollectionFailureDevices
		out.CollectionHealth.NumProcessingFailureDevices = metrics.NumProcessingFailureDevices
		out.CollectionHealth.NumSuccessfulEndpoints = metrics.NumSuccessfulEndpoints
		out.CollectionHealth.NumCollectionFailureEndpoints = metrics.NumCollectionFailureEndpoints
		out.CollectionHealth.NumProcessingFailureEndpoints = metrics.NumProcessingFailureEndpoints
		if metrics.CollectionDuration > 0 {
			v := metrics.CollectionDuration
			out.CollectionHealth.CollectionDurationMs = &v
		}
		if metrics.ProcessingDuration > 0 {
			v := metrics.ProcessingDuration
			out.CollectionHealth.ProcessingDurationMs = &v
		}
		fail := []ForwardAssuranceFailureReason{}
		topFailureReasons(metrics.DeviceCollectionFailures, "deviceCollectionFailures", &fail)
		topFailureReasons(metrics.DeviceProcessingFailures, "deviceProcessingFailures", &fail)
		topFailureReasons(metrics.EndpointCollectionFailures, "endpointCollectionFailures", &fail)
		topFailureReasons(metrics.EndpointProcessingFailures, "endpointProcessingFailures", &fail)
		out.CollectionHealth.TopFailureReasons = fail

		out.IndexingHealth.PathSearchIndexingStatus = strings.TrimSpace(metrics.PathSearchIndexingStatus)
		out.IndexingHealth.SearchIndexingStatus = strings.TrimSpace(metrics.SearchIndexingStatus)
		out.IndexingHealth.L2IndexingStatus = strings.TrimSpace(metrics.L2IndexingStatus)
		out.IndexingHealth.HostComputationStatus = strings.TrimSpace(metrics.HostComputationStatus)
		out.IndexingHealth.IPLocationIndexingStatus = strings.TrimSpace(metrics.IPLocationIndexingStatus)
		out.IndexingHealth.Overall = computeIndexingOverall(
			out.IndexingHealth.PathSearchIndexingStatus,
			out.IndexingHealth.SearchIndexingStatus,
			out.IndexingHealth.L2IndexingStatus,
			out.IndexingHealth.HostComputationStatus,
			out.IndexingHealth.IPLocationIndexingStatus,
		)
	}

	// Vulnerabilities.
	if haveVuln {
		if vuln.Total >= 0 {
			v := vuln.Total
			out.Vulnerabilities.Total = &v
		}
		if vuln.Offset >= 0 {
			v := vuln.Offset
			out.Vulnerabilities.Offset = &v
		}
		out.Vulnerabilities.IndexCreatedAt = strings.TrimSpace(vuln.IndexCreatedAt)
		bySev := map[string]int{}
		known := 0
		for _, v := range vuln.Vulnerabilities {
			sev := strings.ToUpper(strings.TrimSpace(v.Severity))
			if sev == "" {
				sev = "UNKNOWN"
			}
			bySev[sev]++
			if strings.TrimSpace(v.KnownExploitSource) != "" {
				known++
			}
		}
		if len(bySev) > 0 {
			out.Vulnerabilities.BySeverity = bySev
		}
		kc := known
		out.Vulnerabilities.KnownExploitCount = &kc

		// Partial paging heuristic.
		total := vuln.Total
		offset := vuln.Offset
		pageLen := len(vuln.Vulnerabilities)
		if total > 0 && offset >= 0 && pageLen >= 0 && total > offset+pageLen {
			out.Vulnerabilities.Partial = true
		}
	}

	// Capacity cache.
	if capErr != nil {
		out.Warnings = append(out.Warnings, "capacity cache unavailable")
	} else if !capAsOf.IsZero() {
		out.Capacity.AsOf = capAsOf.UTC().Format(time.RFC3339)
		out.Capacity.Stale = now.Sub(capAsOf.UTC()) > 2*time.Hour
		out.Capacity.Source = "cache"

		hot := 0
		var maxUtil *float64
		for _, r := range capRollups {
			if strings.ToLower(strings.TrimSpace(r.ObjectType)) != "interface" {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Metric)), "util_") {
				continue
			}
			if r.Max == nil {
				continue
			}
			if *r.Max >= 0.85 {
				hot++
			}
			if maxUtil == nil || *r.Max > *maxUtil {
				v := *r.Max
				maxUtil = &v
			}
		}
		out.Capacity.HotInterfaces = hot
		out.Capacity.MaxUtilMax = maxUtil
	} else {
		out.Capacity.Source = "none"
		out.Capacity.Stale = true
	}

	// Missing kinds.
	if !haveSnapshot {
		out.Missing = append(out.Missing, "snapshot-latest")
	}
	if !haveMetrics {
		out.Missing = append(out.Missing, "snapshot-metrics")
	}
	if !haveVuln {
		out.Missing = append(out.Missing, "vulnerabilities")
	}

	return out
}

func saveForwardAssuranceSummary(ctx context.Context, db *sql.DB, sum ForwardAssuranceSummaryResponse) error {
	if db == nil {
		return fmt.Errorf("db unavailable")
	}
	ctxQ, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	b, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctxQ, `
INSERT INTO sf_forward_assurance_summaries (
  workspace_id, forward_network_id, network_ref, snapshot_id, generated_at, summary_json
) VALUES ($1,$2,$3,$4,now(),$5::jsonb)
`, strings.TrimSpace(sum.WorkspaceID), strings.TrimSpace(sum.ForwardNetworkID), strings.TrimSpace(sum.NetworkRef), strings.TrimSpace(sum.Snapshot.SnapshotID), string(b))
	return err
}

func parseOptionalLimit(raw string, def, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func (s *Service) countLiveSignals(ctx context.Context, username string, windowMinutes int) (ForwardAssuranceLiveSignalsTile, []string) {
	username = strings.TrimSpace(username)
	if windowMinutes <= 0 {
		windowMinutes = 60
	}
	out := ForwardAssuranceLiveSignalsTile{
		WindowMinutes: windowMinutes,
		Syslog:        ForwardAssuranceLiveSyslog{},
		SnmpTraps:     ForwardAssuranceLiveCount{},
		Webhooks:      ForwardAssuranceLiveCount{},
	}
	warnings := []string{}
	if s == nil || s.db == nil || username == "" {
		return out, warnings
	}
	cutoff := time.Now().UTC().Add(-time.Duration(windowMinutes) * time.Minute)

	// Syslog: count only events mapped to the current user via routes (same semantics as inbox).
	{
		ctxQ, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var total, critical int
		err := s.db.QueryRowContext(ctxQ, `
SELECT
  COUNT(*)::int AS total,
  SUM(CASE WHEN e.severity IS NOT NULL AND e.severity <= 3 THEN 1 ELSE 0 END)::int AS critical
FROM sf_syslog_events e
LEFT JOIN LATERAL (
  SELECT owner_username
  FROM sf_syslog_routes
  WHERE e.source_ip <<= source_cidr
  ORDER BY masklen(source_cidr) DESC
  LIMIT 1
) r ON TRUE
WHERE r.owner_username = $1 AND e.received_at >= $2
`, username, cutoff).Scan(&total, &critical)
		if err != nil {
			if isMissingDBRelation(err) {
				warnings = append(warnings, "syslog unavailable")
			} else {
				warnings = append(warnings, "syslog count failed")
			}
		} else {
			out.Syslog.Total = total
			out.Syslog.Critical = critical
		}
	}

	{
		ctxQ, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var total int
		err := s.db.QueryRowContext(ctxQ, `
SELECT COUNT(*)::int FROM sf_snmp_trap_events
WHERE username=$1 AND received_at >= $2
`, username, cutoff).Scan(&total)
		if err != nil {
			if isMissingDBRelation(err) {
				warnings = append(warnings, "snmp unavailable")
			} else {
				warnings = append(warnings, "snmp count failed")
			}
		} else {
			out.SnmpTraps.Total = total
		}
	}

	{
		ctxQ, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var total int
		err := s.db.QueryRowContext(ctxQ, `
SELECT COUNT(*)::int FROM sf_webhook_events
WHERE username=$1 AND received_at >= $2
`, username, cutoff).Scan(&total)
		if err != nil {
			if isMissingDBRelation(err) {
				warnings = append(warnings, "webhooks unavailable")
			} else {
				warnings = append(warnings, "webhooks count failed")
			}
		} else {
			out.Webhooks.Total = total
		}
	}
	return out, warnings
}

type forwardAssuranceLiveInputs struct {
	snapshotBody []byte
	metricsBody  []byte
	vulnBody     []byte
	snapshotID   string
}

func fetchForwardAssuranceLiveInputs(ctx context.Context, client *forwardClient, forwardNetworkID string) (forwardAssuranceLiveInputs, error) {
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if client == nil || forwardNetworkID == "" {
		return forwardAssuranceLiveInputs{}, fmt.Errorf("invalid forward client")
	}

	// Latest processed snapshot.
	ctxSnap, cancelSnap := context.WithTimeout(ctx, 30*time.Second)
	defer cancelSnap()
	snapBody, err := forwardGETJSON(ctxSnap, client, fmt.Sprintf("/api/networks/%s/snapshots/latestProcessed", url.PathEscape(forwardNetworkID)), nil)
	if err != nil {
		return forwardAssuranceLiveInputs{}, err
	}
	snapshotID := parseForwardSnapshotIDFromLatestProcessed(snapBody)
	if snapshotID == "" {
		return forwardAssuranceLiveInputs{}, fmt.Errorf("failed to detect snapshot id")
	}

	// Metrics.
	ctxMet, cancelMet := context.WithTimeout(ctx, 60*time.Second)
	defer cancelMet()
	metricsBody, err := forwardGETJSON(ctxMet, client, fmt.Sprintf("/api/snapshots/%s/metrics", url.PathEscape(snapshotID)), nil)
	if err != nil {
		return forwardAssuranceLiveInputs{}, err
	}

	// Vulnerabilities.
	ctxV, cancelV := context.WithTimeout(ctx, 60*time.Second)
	defer cancelV()
	qs := url.Values{}
	qs.Set("offset", "0")
	qs.Set("limit", "1000")
	qs.Set("snapshotId", snapshotID)
	vulnBody, err := forwardGETJSON(ctxV, client, fmt.Sprintf("/api/networks/%s/vulnerabilities", url.PathEscape(forwardNetworkID)), qs)
	if err != nil {
		return forwardAssuranceLiveInputs{}, err
	}

	return forwardAssuranceLiveInputs{
		snapshotBody: snapBody,
		metricsBody:  metricsBody,
		vulnBody:     vulnBody,
		snapshotID:   snapshotID,
	}, nil
}

// GetWorkspaceForwardNetworkAssuranceSummary returns a demo-oriented assurance summary computed from live Forward calls.
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/assurance/summary
func (s *Service) GetWorkspaceForwardNetworkAssuranceSummary(ctx context.Context, id, networkRef string) (*ForwardAssuranceSummaryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if !s.cfg.Features.ForwardEnabled {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward Networks integrations are disabled").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, networkRef)
	if err != nil {
		return nil, err
	}

	client, err := s.capacityForwardClientForUserNetwork(ctx, pc.claims.Username, net.CollectorConfigID)
	if err != nil {
		return nil, err
	}
	inputs, err := fetchForwardAssuranceLiveInputs(ctx, client, net.ForwardNetworkID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to fetch Forward assurance inputs").Err()
	}

	var snap forwardSnapshotInfo
	haveSnap := parseJSONBytesInto(inputs.snapshotBody, &snap) == nil
	// Some Forward deployments may return a minimal payload (or parsing may fail
	// due to unexpected extra fields). We still treat snapshot id as "present"
	// because downstream tiles only require the id for correlation.
	if strings.TrimSpace(snap.ID) == "" && inputs.snapshotID != "" {
		snap.ID = inputs.snapshotID
		haveSnap = true
	}

	var met forwardSnapshotMetrics
	haveMet := parseJSONBytesInto(inputs.metricsBody, &met) == nil

	var vul forwardVulnerabilityAnalysis
	haveVul := parseJSONBytesInto(inputs.vulnBody, &vul) == nil

	// Capacity cache.
	var capAsOf time.Time
	var capRows []CapacityRollupRow
	var capErr error
	capAsOf, capRows, capErr = loadLatestCapacityRollupsForForwardNetwork(ctx, s.db, pc.workspace.ID, net.ForwardNetworkID)

	sum := computeForwardAssuranceSummaryFromLive(time.Now(), pc.workspace.ID, net.ID, net.ForwardNetworkID, snap, haveSnap, met, haveMet, vul, haveVul, capAsOf, capRows, capErr)
	sum.LiveSignals, sum.Warnings = s.countLiveSignals(ctx, pc.claims.Username, 60)
	return &sum, nil
}

// RefreshWorkspaceForwardNetworkAssurance recomputes the live summary, stores it in history (best-effort), and returns it.
//
//encore:api auth method=POST path=/api/workspaces/:id/forward-networks/:networkRef/assurance/refresh
func (s *Service) RefreshWorkspaceForwardNetworkAssurance(ctx context.Context, id, networkRef string) (*ForwardAssuranceSummaryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	sum, err := s.GetWorkspaceForwardNetworkAssuranceSummary(ctx, id, networkRef)
	if err != nil {
		return nil, err
	}

	if s.db != nil {
		if err := saveForwardAssuranceSummary(ctx, s.db, *sum); err != nil && !isMissingDBRelation(err) {
			rlog.Error("failed to save forward assurance summary", "error", err)
		}
	}

	// Best-effort: index to Elastic (category=assurance).
	s.indexElasticAsync(pc.claims.Username, "assurance", time.Now().UTC(), map[string]any{
		"generated_at":      sum.GeneratedAt,
		"workspace_id":      sum.WorkspaceID,
		"network_ref":       sum.NetworkRef,
		"forward_network_id": sum.ForwardNetworkID,
		"snapshot_id":       sum.Snapshot.SnapshotID,
		"summary":           sum,
	})

	return sum, nil
}

// ListWorkspaceForwardNetworkAssuranceSummaryHistory returns recent stored summaries (if enabled via migrations).
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/assurance/summary/history
func (s *Service) ListWorkspaceForwardNetworkAssuranceSummaryHistory(ctx context.Context, id, networkRef string, params *ForwardAssuranceHistoryParams) (*ForwardAssuranceHistoryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return &ForwardAssuranceHistoryResponse{Items: []ForwardAssuranceHistoryItem{}}, nil
	}
	if !s.cfg.Features.ForwardEnabled {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("Forward Networks integrations are disabled").Err()
	}
	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, networkRef)
	if err != nil {
		return nil, err
	}

	limit := parseOptionalLimit("", 20, 200)
	if params != nil {
		limit = parseOptionalLimit(params.Limit, 20, 200)
	}

	ctxQ, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctxQ, `
SELECT id, generated_at, COALESCE(snapshot_id,''), summary_json::text
FROM sf_forward_assurance_summaries
WHERE workspace_id=$1 AND forward_network_id=$2 AND network_ref=$3
ORDER BY generated_at DESC, id DESC
LIMIT $4
`, pc.workspace.ID, net.ForwardNetworkID, net.ID, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return &ForwardAssuranceHistoryResponse{Items: []ForwardAssuranceHistoryItem{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load assurance history").Err()
	}
	defer rows.Close()

	items := []ForwardAssuranceHistoryItem{}
	for rows.Next() {
		var id int64
		var generatedAt time.Time
		var snapshotID string
		var raw string
		if err := rows.Scan(&id, &generatedAt, &snapshotID, &raw); err != nil {
			continue
		}
		var sum ForwardAssuranceSummaryResponse
		if err := parseJSONBytesInto([]byte(raw), &sum); err != nil {
			continue
		}
		items = append(items, ForwardAssuranceHistoryItem{
			ID:          id,
			GeneratedAt: generatedAt.UTC().Format(time.RFC3339Nano),
			SnapshotID:  strings.TrimSpace(snapshotID),
			Summary:     sum,
		})
	}
	return &ForwardAssuranceHistoryResponse{Items: items}, nil
}
