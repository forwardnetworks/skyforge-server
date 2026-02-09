package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"encore.dev/beta/errs"
)

func forwardMCPToolCatalog() []mcpTool {
	anyArgs := map[string]any{"type": "object", "additionalProperties": true}
	return []mcpTool{
		{Name: "list_networks", Description: "List Forward networks.", InputSchema: map[string]any{"type": "object", "additionalProperties": false}},
		{Name: "create_network", Description: "Create a Forward network (write).", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}, "required": []string{"name"}, "additionalProperties": false}},
		{Name: "update_network", Description: "Update a Forward network (write).", InputSchema: anyArgs},
		{Name: "search_paths", Description: "Single path search.", InputSchema: anyArgs},
		{Name: "search_paths_bulk", Description: "Bulk path search.", InputSchema: anyArgs},
		{Name: "analyze_network_prefixes", Description: "Analyze connectivity between prefixes (stub).", InputSchema: anyArgs},
		{Name: "run_nqe_query_by_id", Description: "Run an NQE query by queryId.", InputSchema: anyArgs},
		{Name: "list_nqe_queries", Description: "List available NQE queries.", InputSchema: anyArgs},
		{Name: "get_device_basic_info", Description: "Get device inventory info (via NQE query library).", InputSchema: anyArgs},
		{Name: "get_device_hardware", Description: "Get device hardware info (via NQE query library).", InputSchema: anyArgs},
		{Name: "get_hardware_support", Description: "Get hardware support/EoL info (via NQE query library).", InputSchema: anyArgs},
		{Name: "get_os_support", Description: "Get OS support/EoL info (via NQE query library).", InputSchema: anyArgs},
		{Name: "search_configs", Description: "Search configs (via NQE query library).", InputSchema: anyArgs},
		{Name: "get_config_diff", Description: "Diff configs between snapshots (via NQE query library).", InputSchema: anyArgs},
		{Name: "list_devices", Description: "List devices.", InputSchema: anyArgs},
		{Name: "get_device_locations", Description: "Get device location mapping.", InputSchema: anyArgs},
		{Name: "list_snapshots", Description: "List snapshots.", InputSchema: anyArgs},
		{Name: "get_latest_snapshot", Description: "Get latest processed snapshot.", InputSchema: anyArgs},
		{Name: "delete_snapshot", Description: "Delete a snapshot (write).", InputSchema: anyArgs},
		{Name: "list_locations", Description: "List locations.", InputSchema: anyArgs},
		{Name: "create_location", Description: "Create a location (write).", InputSchema: anyArgs},
		{Name: "update_location", Description: "Update a location (write).", InputSchema: anyArgs},
		{Name: "delete_location", Description: "Delete a location (write).", InputSchema: anyArgs},
		{Name: "create_locations_bulk", Description: "Create locations in bulk (write).", InputSchema: anyArgs},
		{Name: "update_device_locations", Description: "Update device locations mapping (write).", InputSchema: anyArgs},
		{Name: "get_default_settings", Description: "Get default settings (stub).", InputSchema: anyArgs},
		{Name: "set_default_network", Description: "Set default network (stub).", InputSchema: anyArgs},
		{Name: "get_cache_stats", Description: "Get cache stats (stub).", InputSchema: anyArgs},
		{Name: "suggest_similar_queries", Description: "Suggest similar queries (stub).", InputSchema: anyArgs},
		{Name: "clear_cache", Description: "Clear cache (stub).", InputSchema: anyArgs},
		{Name: "search_nqe_queries", Description: "Search NQE queries (stub).", InputSchema: anyArgs},
		{Name: "initialize_query_index", Description: "Initialize query index (stub).", InputSchema: anyArgs},
		{Name: "hydrate_database", Description: "Hydrate database (stub).", InputSchema: anyArgs},
		{Name: "refresh_query_index", Description: "Refresh query index (stub).", InputSchema: anyArgs},
		{Name: "get_database_status", Description: "Get database status (stub).", InputSchema: anyArgs},
		{Name: "create_entity", Description: "Create memory entity (stub).", InputSchema: anyArgs},
		{Name: "create_relation", Description: "Create memory relation (stub).", InputSchema: anyArgs},
		{Name: "add_observation", Description: "Add memory observation (stub).", InputSchema: anyArgs},
		{Name: "search_entities", Description: "Search memory entities (stub).", InputSchema: anyArgs},
		{Name: "get_entity", Description: "Get memory entity (stub).", InputSchema: anyArgs},
		{Name: "get_relations", Description: "Get relations (stub).", InputSchema: anyArgs},
		{Name: "get_observations", Description: "Get observations (stub).", InputSchema: anyArgs},
		{Name: "delete_entity", Description: "Delete entity (stub).", InputSchema: anyArgs},
		{Name: "delete_relation", Description: "Delete relation (stub).", InputSchema: anyArgs},
		{Name: "delete_observation", Description: "Delete observation (stub).", InputSchema: anyArgs},
		{Name: "get_memory_stats", Description: "Get memory stats (stub).", InputSchema: anyArgs},
		{Name: "get_query_analytics", Description: "Get query analytics (stub).", InputSchema: anyArgs},
		{Name: "list_instance_ids", Description: "List instance IDs (stub).", InputSchema: anyArgs},
		{Name: "get_nqe_result_chunks", Description: "Get cached NQE result chunks (stub).", InputSchema: anyArgs},
		{Name: "get_nqe_result_summary", Description: "Get NQE result summary (stub).", InputSchema: anyArgs},
		{Name: "analyze_nqe_result_sql", Description: "Analyze NQE result via SQL (stub).", InputSchema: anyArgs},
		{Name: "build_bloom_filter", Description: "Build bloom filter (stub).", InputSchema: anyArgs},
		{Name: "search_bloom_filter", Description: "Search bloom filter (stub).", InputSchema: anyArgs},
		{Name: "get_bloom_filter_stats", Description: "Bloom filter stats (stub).", InputSchema: anyArgs},
	}
}

func (s *Service) mcpForwardToolsCall(ctx context.Context, user *AuthUser, workspaceID, forwardNetworkID, name string, args map[string]any) (string, error) {
	if user == nil {
		return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
	}
	explicitCredID, _ := ctx.Value(ctxKeyMCPForwardCredentialID).(string)
	explicitCredID = strings.TrimSpace(explicitCredID)

	rec, err := resolveForwardCredentialsFor(ctx, s.db, s.cfg.SessionSecret, workspaceID, user.Username, forwardNetworkID, forwardCredResolveOpts{
		ExplicitCredentialID: explicitCredID,
	})
	if err != nil {
		return "", err
	}
	client, err := newForwardClient(*rec)
	if err != nil {
		return "", errs.B().Code(errs.InvalidArgument).Msg("invalid Forward config").Err()
	}

	networkID := strings.TrimSpace(getStringArg(args, "network_id"))
	if networkID == "" {
		networkID = forwardNetworkID
	}
	snapshotID := strings.TrimSpace(getStringArg(args, "snapshot_id"))

	allowWrites := s.cfg.MCP.ForwardAllowWrites
	requireWrite := func() error {
		if !allowWrites {
			return errs.B().Code(errs.PermissionDenied).Msg("Forward writes are disabled on this Skyforge instance").Err()
		}
		return nil
	}

	switch name {
	case "list_networks":
		resp, body, err := client.doJSON(ctx, http.MethodGet, "/api/networks", nil, nil)
		return forwardBodyOrErr(resp, body, err)
	case "create_network":
		if err := requireWrite(); err != nil {
			return "", err
		}
		n := strings.TrimSpace(getStringArg(args, "name"))
		if n == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
		}
		q := url.Values{}
		q.Set("name", n)
		resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/networks", q, nil)
		return forwardBodyOrErr(resp, body, err)
	case "update_network":
		if err := requireWrite(); err != nil {
			return "", err
		}
		id := strings.TrimSpace(getStringArg(args, "network_id"))
		if id == "" {
			id = forwardNetworkID
		}
		if id == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		// Pass through any fields; Forward supports PATCH with a JSON object.
		payload := map[string]any{}
		for k, v := range args {
			if k == "network_id" {
				continue
			}
			payload[k] = v
		}
		path := "/api/networks/" + url.PathEscape(id)
		resp, body, err := client.doJSON(ctx, http.MethodPatch, path, nil, payload)
		return forwardBodyOrErr(resp, body, err)
	case "search_paths":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		dst := strings.TrimSpace(getStringArg(args, "dst_ip"))
		if dst == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("dst_ip is required").Err()
		}
		q := url.Values{}
		q.Set("dstIp", dst)
		if v := strings.TrimSpace(getStringArg(args, "from")); v != "" {
			q.Set("from", v)
		}
		if v := strings.TrimSpace(getStringArg(args, "src_ip")); v != "" {
			q.Set("srcIp", v)
		}
		if v := strings.TrimSpace(getStringArg(args, "intent")); v != "" {
			q.Set("intent", v)
		}
		if v, ok := getIntArg(args, "ip_proto"); ok {
			q.Set("ipProto", strconv.Itoa(v))
		}
		if v := strings.TrimSpace(getStringArg(args, "src_port")); v != "" {
			q.Set("srcPort", v)
		}
		if v := strings.TrimSpace(getStringArg(args, "dst_port")); v != "" {
			q.Set("dstPort", v)
		}
		if v, ok := getBoolArg(args, "include_network_functions"); ok && v {
			q.Set("includeNetworkFunctions", "true")
		}
		if v, ok := getIntArg(args, "max_candidates"); ok && v > 0 {
			q.Set("maxCandidates", strconv.Itoa(v))
		}
		if v, ok := getIntArg(args, "max_results"); ok && v > 0 {
			q.Set("maxResults", strconv.Itoa(v))
		}
		if v, ok := getIntArg(args, "max_return_path_results"); ok && v > 0 {
			q.Set("maxReturnPathResults", strconv.Itoa(v))
		}
		if v, ok := getIntArg(args, "max_seconds"); ok && v > 0 {
			q.Set("maxSeconds", strconv.Itoa(v))
		}
		if snapshotID != "" {
			q.Set("snapshotId", snapshotID)
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/paths"
		resp, body, err := client.doJSON(ctx, http.MethodGet, path, q, nil)
		return forwardBodyOrErr(resp, body, err)
	case "search_paths_bulk":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		payload := map[string]any{}
		if v, ok := args["queries"]; ok {
			payload["queries"] = v
		} else if v, ok := args["Queries"]; ok { // tolerate misc casing
			payload["queries"] = v
		} else {
			return "", errs.B().Code(errs.InvalidArgument).Msg("queries is required").Err()
		}
		q := url.Values{}
		if snapshotID != "" && snapshotID != "latest" {
			q.Set("snapshotId", snapshotID)
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/paths-bulk"
		resp, body, err := client.doJSON(ctx, http.MethodPost, path, q, payload)
		return forwardBodyOrErr(resp, body, err)
	case "run_nqe_query_by_id":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		queryID := strings.TrimSpace(getStringArg(args, "query_id"))
		if queryID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("query_id is required").Err()
		}
		q := url.Values{}
		q.Set("networkId", networkID)
		if snapshotID != "" && snapshotID != "latest" {
			q.Set("snapshotId", snapshotID)
		}
		payload := map[string]any{"queryId": queryID}
		if p, ok := args["parameters"].(map[string]any); ok && len(p) > 0 {
			payload["parameters"] = p
		}
		if o, ok := args["options"].(map[string]any); ok && len(o) > 0 {
			payload["queryOptions"] = o
		}
		resp, body, err := client.doJSON(ctx, http.MethodPost, "/api/nqe", q, payload)
		return forwardBodyOrErr(resp, body, err)
	case "list_nqe_queries":
		// Prefer the newer repo-backed endpoints, but allow an optional dir filter.
		dir := strings.TrimSpace(getStringArg(args, "dir"))
		if dir == "" {
			dir = strings.TrimSpace(getStringArg(args, "directory"))
		}
		if dir != "" {
			q := url.Values{}
			q.Set("dir", dir)
			resp, body, err := client.doJSON(ctx, http.MethodGet, "/api/nqe/queries", q, nil)
			return forwardBodyOrErr(resp, body, err)
		}
		resp1, body1, err1 := client.doJSON(ctx, http.MethodGet, "/api/nqe/repos/fwd/commits/head/queries", nil, nil)
		out1, e1 := forwardBodyOrErr(resp1, body1, err1)
		resp2, body2, err2 := client.doJSON(ctx, http.MethodGet, "/api/nqe/repos/org/commits/head/queries", nil, nil)
		out2, e2 := forwardBodyOrErr(resp2, body2, err2)
		if e1 != nil && e2 != nil {
			return "", e1
		}
		merged := map[string]any{
			"fwd": json.RawMessage([]byte(out1)),
			"org": json.RawMessage([]byte(out2)),
		}
		b, _ := json.Marshal(merged)
		return string(b), nil
	case "get_device_basic_info":
		return s.mcpForwardToolsCall(ctx, user, workspaceID, forwardNetworkID, "run_nqe_query_by_id", withArgs(args, map[string]any{"query_id": "FQ_ac651cb2901b067fe7dbfb511613ab44776d8029"}))
	case "get_device_hardware":
		return s.mcpForwardToolsCall(ctx, user, workspaceID, forwardNetworkID, "run_nqe_query_by_id", withArgs(args, map[string]any{"query_id": "FQ_7ec4a8148b48a91271f342c512b2af1cdb276744"}))
	case "get_hardware_support":
		return s.mcpForwardToolsCall(ctx, user, workspaceID, forwardNetworkID, "run_nqe_query_by_id", withArgs(args, map[string]any{"query_id": "FQ_f0984b777b940b4376ed3ec4317ad47437426e7c"}))
	case "get_os_support":
		return s.mcpForwardToolsCall(ctx, user, workspaceID, forwardNetworkID, "run_nqe_query_by_id", withArgs(args, map[string]any{"query_id": "FQ_fc33d9fd70ba19a18455b0e4d26ca8420003d9cc"}))
	case "search_configs":
		// Forward's library query expects parameter searchPattern.
		search := strings.TrimSpace(getStringArg(args, "search_term"))
		if search == "" {
			search = strings.TrimSpace(getStringArg(args, "searchPattern"))
		}
		if search == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("search_term is required").Err()
		}
		a2 := withArgs(args, map[string]any{
			"query_id": "FQ_e636c47826ad7144f09eaf6bc14dfb0b560e7cc9",
			"parameters": map[string]any{
				"searchPattern": search,
			},
		})
		return s.mcpForwardToolsCall(ctx, user, workspaceID, forwardNetworkID, "run_nqe_query_by_id", a2)
	case "get_config_diff":
		after := strings.TrimSpace(getStringArg(args, "after_snapshot"))
		before := strings.TrimSpace(getStringArg(args, "before_snapshot"))
		if before == "" {
			before = snapshotID
		}
		params := map[string]any{}
		if after != "" {
			params["compareSnapshotId"] = after
		}
		a2 := withArgs(args, map[string]any{
			"snapshot_id": before,
			"query_id":    "FQ_51f090cbea069b4049eb283716ab3bbb3f578aea",
			"parameters":  params,
		})
		return s.mcpForwardToolsCall(ctx, user, workspaceID, forwardNetworkID, "run_nqe_query_by_id", a2)
	case "list_devices":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		q := url.Values{}
		if snapshotID != "" && snapshotID != "latest" {
			q.Set("snapshotId", snapshotID)
		}
		if v, ok := getIntArg(args, "offset"); ok && v > 0 {
			q.Set("offset", strconv.Itoa(v))
		}
		if v, ok := getIntArg(args, "limit"); ok && v > 0 {
			q.Set("limit", strconv.Itoa(v))
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/devices"
		resp, body, err := client.doJSON(ctx, http.MethodGet, path, q, nil)
		return forwardBodyOrErr(resp, body, err)
	case "get_device_locations":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/atlas"
		resp, body, err := client.doJSON(ctx, http.MethodGet, path, nil, nil)
		return forwardBodyOrErr(resp, body, err)
	case "list_snapshots":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/snapshots"
		resp, body, err := client.doJSON(ctx, http.MethodGet, path, nil, nil)
		return forwardBodyOrErr(resp, body, err)
	case "get_latest_snapshot":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/snapshots/latestProcessed"
		resp, body, err := client.doJSON(ctx, http.MethodGet, path, nil, nil)
		return forwardBodyOrErr(resp, body, err)
	case "delete_snapshot":
		if err := requireWrite(); err != nil {
			return "", err
		}
		sid := strings.TrimSpace(getStringArg(args, "snapshot_id"))
		if sid == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("snapshot_id is required").Err()
		}
		path := "/api/snapshots/" + url.PathEscape(sid)
		resp, body, err := client.doJSON(ctx, http.MethodDelete, path, nil, nil)
		return forwardBodyOrErr(resp, body, err)
	case "list_locations":
		if networkID == "" {
			return "", errs.B().Code(errs.InvalidArgument).Msg("network_id is required").Err()
		}
		path := "/api/networks/" + url.PathEscape(networkID) + "/locations"
		resp, body, err := client.doJSON(ctx, http.MethodGet, path, nil, nil)
		return forwardBodyOrErr(resp, body, err)
	case "create_location", "update_location", "delete_location", "create_locations_bulk", "update_device_locations":
		if err := requireWrite(); err != nil {
			return "", err
		}
		return "", errs.B().Code(errs.Unimplemented).Msg("tool not implemented yet").Err()
	default:
		// Everything else is a stub for parity.
		return "", errs.B().Code(errs.Unimplemented).Msg("tool not implemented yet").Err()
	}
}

func forwardBodyOrErr(resp *http.Response, body []byte, err error) (string, error) {
	if err != nil {
		return "", errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp == nil {
		return "", errs.B().Code(errs.Unavailable).Msg("Forward request failed").Err()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errs.B().Code(errs.Unavailable).Msg("Forward request failed").Meta("upstream", strings.TrimSpace(string(body))).Err()
	}
	return string(body), nil
}

func getStringArg(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func getIntArg(m map[string]any, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case json.Number:
		i, err := t.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(t))
		return i, err == nil
	default:
		return 0, false
	}
}

func getBoolArg(m map[string]any, key string) (bool, bool) {
	if m == nil {
		return false, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return false, false
	}
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		return b, err == nil
	default:
		return false, false
	}
}

func withArgs(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
