package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type NodeMetricSnapshot struct {
	Node      string                     `json:"node"`
	UpdatedAt string                     `json:"updatedAt"`
	CPUActive *float64                   `json:"cpuActive,omitempty"`
	MemUsed   *float64                   `json:"memUsed,omitempty"`
	DiskUsed  *float64                   `json:"diskUsed,omitempty"`
	Raw       map[string]json.RawMessage `json:"raw,omitempty"`
}

type NodeMetricsResponse struct {
	Nodes []NodeMetricSnapshot `json:"nodes"`
}

// ListNodeMetrics returns a lightweight, live view of node metrics (admin only).
//
// Data is a short-lived snapshot stored in Redis by Telegraf.
//
//encore:api auth method=GET path=/api/admin/node-metrics tag:admin
func (s *Service) ListNodeMetrics(ctx context.Context) (*NodeMetricsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin || user.SelectedRole != "ADMIN" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("admin required").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	rows, err := listRecentNodeMetricSnapshots(ctxReq, s.db, 2*time.Minute, 2000)
	cancel()
	if err != nil && err != sql.ErrConnDone {
		return nil, errs.B().Code(errs.Internal).Msg("failed to query node metrics").Err()
	}
	nodesByName := map[string]*NodeMetricSnapshot{}
	for _, row := range rows {
		node := strings.TrimSpace(row.Node)
		if node == "" {
			continue
		}
		snap := nodesByName[node]
		if snap == nil {
			snap = &NodeMetricSnapshot{Node: node, Raw: map[string]json.RawMessage{}}
			nodesByName[node] = snap
		}
		if snap.UpdatedAt == "" || row.UpdatedAt.After(mustParseTime(snap.UpdatedAt)) {
			snap.UpdatedAt = row.UpdatedAt.UTC().Format(time.RFC3339Nano)
		}
		raw := strings.TrimSpace(row.RawJSON)
		if raw == "" {
			continue
		}
		switch strings.TrimSpace(row.Metric) {
		case "cpu":
			snap.CPUActive = extractFloatField(raw, "usage_active")
			snap.Raw["cpu"] = json.RawMessage(raw)
		case "mem":
			snap.MemUsed = extractFloatField(raw, "used_percent")
			snap.Raw["mem"] = json.RawMessage(raw)
		case "disk":
			snap.DiskUsed = extractFloatField(raw, "used_percent")
			snap.Raw["disk"] = json.RawMessage(raw)
		default:
			snap.Raw[row.Metric] = json.RawMessage(raw)
		}
	}
	nodes := make([]NodeMetricSnapshot, 0, len(nodesByName))
	for _, snap := range nodesByName {
		nodes = append(nodes, *snap)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Node < nodes[j].Node })
	return &NodeMetricsResponse{Nodes: nodes}, nil
}

func extractFloatField(raw string, field string) *float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var metric IngestTelegrafMetricParams
	if err := json.Unmarshal([]byte(raw), &metric); err != nil {
		return nil
	}
	v, ok := metric.Fields[field]
	if !ok || len(v) == 0 {
		return nil
	}
	// Try number first.
	var f float64
	if err := json.Unmarshal(v, &f); err == nil {
		return &f
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return &f
		}
	}
	return nil
}

func mustParseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(v))
	return t
}
