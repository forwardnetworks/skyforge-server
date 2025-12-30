package skyforge

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type NodeMetricSnapshot struct {
	Node      string  `json:"node"`
	UpdatedAt string  `json:"updatedAt"`
	CPUActive *float64 `json:"cpuActive,omitempty"`
	MemUsed   *float64 `json:"memUsed,omitempty"`
	DiskUsed  *float64 `json:"diskUsed,omitempty"`
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
	if redisClient == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("redis unavailable").Err()
	}

	prefix := strings.TrimSpace(s.cfg.Redis.KeyPrefix)
	if prefix == "" {
		prefix = "skyforge"
	}
	pattern := prefix + ":node-metrics:*"

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var cursor uint64
	keys := make([]string, 0, 64)
	for {
		out, next, err := redisClient.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to scan node metrics").Err()
		}
		keys = append(keys, out...)
		cursor = next
		if cursor == 0 || len(keys) > 200 {
			break
		}
	}

	nodes := make([]NodeMetricSnapshot, 0, len(keys))
	for _, key := range keys {
		node := strings.TrimPrefix(key, prefix+":node-metrics:")
		h, err := redisClient.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}
		if len(h) == 0 {
			continue
		}

		snap := NodeMetricSnapshot{Node: node, UpdatedAt: strings.TrimSpace(h["__updated_at"]), Raw: map[string]json.RawMessage{}}

		// Parse a few well-known metrics if present.
		if raw := h["m:cpu"]; raw != "" {
			snap.CPUActive = extractFloatField(raw, "usage_active")
			snap.Raw["cpu"] = json.RawMessage(raw)
		}
		if raw := h["m:mem"]; raw != "" {
			snap.MemUsed = extractFloatField(raw, "used_percent")
			snap.Raw["mem"] = json.RawMessage(raw)
		}
		if raw := h["m:disk"]; raw != "" {
			snap.DiskUsed = extractFloatField(raw, "used_percent")
			snap.Raw["disk"] = json.RawMessage(raw)
		}

		nodes = append(nodes, snap)
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

