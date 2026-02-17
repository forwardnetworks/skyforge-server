package skyforge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"encore.app/internal/containerlabvalidate"
	"encore.dev/beta/errs"
)

type mcpJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpJSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type mcpJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      any              `json:"id,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *mcpJSONRPCError `json:"error,omitempty"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

type mcpInitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities,omitempty"`
	ClientInfo      map[string]any `json:"clientInfo,omitempty"`
}

type mcpToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type ctxKey string

const ctxKeyMCPForwardCredentialID ctxKey = "mcp_forward_credential_id"

func (s *Service) handleMCPJSONRPC(ctx context.Context, user *AuthUser, ownerID string, forwardNetworkID string, req mcpJSONRPCRequest) mcpJSONRPCResponse {
	resp := mcpJSONRPCResponse{JSONRPC: "2.0", ID: req.ID}

	// Notifications (no ID) must not get a response per JSON-RPC.
	// We still build one, and the caller will drop it when ID is nil.

	method := strings.TrimSpace(req.Method)
	switch method {
	case "initialize":
		var p mcpInitializeParams
		_ = json.Unmarshal(req.Params, &p)
		version := strings.TrimSpace(p.ProtocolVersion)
		if version == "" {
			version = "2024-11-05"
		}
		out := map[string]any{
			"protocolVersion": version,
			"serverInfo": map[string]any{
				"name":    "skyforge-mcp",
				"version": "0.1.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		}
		b, _ := json.Marshal(out)
		resp.Result = b
		return resp
	case "ping":
		resp.Result = []byte(`{}`)
		return resp
	case "tools/list":
		tools := s.mcpToolsList(ownerID, forwardNetworkID)
		out := map[string]any{"tools": tools}
		b, _ := json.Marshal(out)
		resp.Result = b
		return resp
	case "tools/call":
		var p mcpToolCallParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &mcpJSONRPCError{Code: -32602, Message: "invalid params"}
			return resp
		}
		result, err := s.mcpToolsCall(ctx, user, ownerID, forwardNetworkID, strings.TrimSpace(p.Name), p.Arguments)
		if err != nil {
			// Tool errors are surfaced as a successful JSON-RPC response with isError=true.
			out := map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": err.Error()},
				},
				"isError": true,
			}
			b, _ := json.Marshal(out)
			resp.Result = b
			return resp
		}
		out := map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": result},
			},
			"isError": false,
		}
		b, _ := json.Marshal(out)
		resp.Result = b
		return resp
	default:
		resp.Error = &mcpJSONRPCError{Code: -32601, Message: "method not found"}
		return resp
	}
}

func (s *Service) mcpToolsList(ownerID, forwardNetworkID string) []mcpTool {
	// Base tools are always available.
	tools := []mcpTool{
		{
			Name:        "validate_containerlab_topology",
			Description: "Validate a containerlab topology YAML against the official containerlab JSON schema.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"yaml": map[string]any{"type": "string", "description": "containerlab topology YAML"},
				},
				"required":             []string{"yaml"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "syslog_list_events",
			Description: "List syslog inbox events for the current user.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "description": "1..1000 (default 200)"},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "snmp_list_trap_events",
			Description: "List SNMP trap inbox events for the current user.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "description": "1..1000 (default 200)"},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "webhooks_list_events",
			Description: "List webhook inbox events for the current user.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "description": "1..1000 (default 200)"},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "webhooks_get_token",
			Description: "Get the per-user webhook ingest token.",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false},
		},
		{
			Name:        "webhooks_rotate_token",
			Description: "Rotate the per-user webhook ingest token.",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false},
		},
		{
			Name:        "snmp_get_trap_token",
			Description: "Get the per-user SNMP trap routing token (community string).",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false},
		},
		{
			Name:        "snmp_rotate_trap_token",
			Description: "Rotate the per-user SNMP trap routing token (community string).",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false},
		},
	}

	if strings.TrimSpace(forwardNetworkID) != "" {
		// Forward parity tool names (mostly pass-through to Forward API). Some are stubs.
		tools = append(tools, forwardMCPToolCatalog()...)
	}
	return tools
}

func (s *Service) mcpToolsCall(ctx context.Context, user *AuthUser, ownerID, forwardNetworkID, name string, args map[string]any) (string, error) {
	switch name {
	case "validate_containerlab_topology":
		yaml, _ := args["yaml"].(string)
		errsList, err := containerlabvalidate.ValidateYAML(yaml)
		if err != nil {
			return "", err
		}
		out := map[string]any{"valid": len(errsList) == 0, "errors": errsList}
		b, _ := json.Marshal(out)
		return string(b), nil
	case "syslog_list_events":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		limit, ok := getIntArg(args, "limit")
		if !ok || limit <= 0 || limit > 1000 {
			limit = 200
		}
		evs, err := listSyslogEventsForUser(ctx, s.db, user.Username, limit)
		if err != nil {
			return "", errs.B().Code(errs.Unavailable).Msg("failed to list syslog events").Err()
		}
		b, _ := json.Marshal(map[string]any{"events": evs})
		return string(b), nil
	case "snmp_list_trap_events":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		limit, ok := getIntArg(args, "limit")
		if !ok || limit <= 0 || limit > 1000 {
			limit = 200
		}
		evs, err := listSnmpTrapEventsForUser(ctx, s.db, user.Username, limit)
		if err != nil {
			return "", errs.B().Code(errs.Unavailable).Msg("failed to list snmp trap events").Err()
		}
		b, _ := json.Marshal(map[string]any{"events": evs})
		return string(b), nil
	case "webhooks_list_events":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		limit, ok := getIntArg(args, "limit")
		if !ok || limit <= 0 || limit > 1000 {
			limit = 200
		}
		evs, err := listWebhookEventsForUser(ctx, s.db, user.Username, limit)
		if err != nil {
			return "", errs.B().Code(errs.Unavailable).Msg("failed to list webhook events").Err()
		}
		b, _ := json.Marshal(map[string]any{"events": evs})
		return string(b), nil
	case "webhooks_get_token":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		out, err := s.mcpGetOrRotateWebhookToken(ctx, user.Username, false)
		if err != nil {
			return "", err
		}
		return out, nil
	case "webhooks_rotate_token":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		out, err := s.mcpGetOrRotateWebhookToken(ctx, user.Username, true)
		if err != nil {
			return "", err
		}
		return out, nil
	case "snmp_get_trap_token":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		out, err := s.mcpGetOrRotateSnmpToken(ctx, user.Username, false)
		if err != nil {
			return "", err
		}
		return out, nil
	case "snmp_rotate_trap_token":
		if user == nil {
			return "", errs.B().Code(errs.Unauthenticated).Msg("authentication required").Err()
		}
		out, err := s.mcpGetOrRotateSnmpToken(ctx, user.Username, true)
		if err != nil {
			return "", err
		}
		return out, nil
	default:
		// Forward tools only exist on the forward endpoint.
		if strings.TrimSpace(forwardNetworkID) == "" {
			return "", errs.B().Code(errs.NotFound).Msg("tool not found").Err()
		}
		return s.mcpForwardToolsCall(ctx, user, ownerID, forwardNetworkID, name, args)
	}
}

func (s *Service) mcpAuthFromRequest(r *http.Request) (*AuthUser, error) {
	if s == nil || s.sessionManager == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	// Prefer PAT / bearer auth for non-browser clients.
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		token := strings.TrimSpace(authz[len("bearer "):])
		if token == "" {
			return nil, errs.B().Code(errs.Unauthenticated).Msg("missing token").Err()
		}
		u, err := s.authUserFromAPIToken(r.Context(), token)
		if err != nil {
			return nil, err
		}
		applySelectedRole(s.cfg, u, r.Header.Get("X-Current-Role"))
		return u, nil
	}

	claims, err := s.sessionManager.Parse(r)
	if err != nil || claims == nil {
		return nil, errs.B().Code(errs.Unauthenticated).Msg("unauthorized").Err()
	}
	u := &AuthUser{
		Username:      strings.ToLower(strings.TrimSpace(claims.Username)),
		DisplayName:   claims.DisplayName,
		Email:         claims.Email,
		Groups:        claims.Groups,
		ActorUsername: strings.ToLower(strings.TrimSpace(claims.ActorUsername)),
		Impersonating: isImpersonating(claims),
		IsAdmin:       isAdminUser(s.cfg, adminUsernameForClaims(claims)),
		SelectedRole:  "",
	}
	applySelectedRole(s.cfg, u, r.Header.Get("X-Current-Role"))
	return u, nil
}

func (s *Service) mcpHandleRPC(w http.ResponseWriter, r *http.Request, user *AuthUser, ownerID, forwardNetworkID string) {
	if s == nil || !s.cfg.MCP.Enabled {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		http.Error(w, "empty request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")

	// Batch requests are allowed by JSON-RPC; MCP clients generally send single requests.
	if body[0] == '[' {
		var reqs []mcpJSONRPCRequest
		if err := json.Unmarshal(body, &reqs); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		resps := make([]mcpJSONRPCResponse, 0, len(reqs))
		for _, req := range reqs {
			resp := s.handleMCPJSONRPC(ctx, user, ownerID, forwardNetworkID, req)
			if req.ID != nil {
				resps = append(resps, resp)
			}
		}
		_ = json.NewEncoder(w).Encode(resps)
		return
	}

	var req mcpJSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	resp := s.handleMCPJSONRPC(ctx, user, ownerID, forwardNetworkID, req)
	if req.ID == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// MCPRPC exposes a Skyforge-hosted MCP JSON-RPC endpoint (tools/list, tools/call).
//
//encore:api auth raw method=POST path=/api/mcp/rpc
func (s *Service) MCPRPC(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mcpHandleRPC(w, r, user, "", "")
}

// MCPForwardRPC exposes a Forward MCP JSON-RPC endpoint that proxies the Forward API.
//
// The Forward network is supplied via the URL path. Tool arguments that include network_id
// may omit it; it will default to :forwardNetworkId.
func (s *Service) MCPForwardRPC(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := ""
	forwardNetworkId := ""
	if pv := r.PathValue("id"); pv != "" {
		id = pv
	}
	if pv := r.PathValue("forwardNetworkId"); pv != "" {
		forwardNetworkId = pv
	}
	id = strings.TrimSpace(id)
	forwardNetworkId = strings.TrimSpace(forwardNetworkId)
	if id == "" || forwardNetworkId == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if _, err := s.ownerContextForUser(user, id); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if credID := strings.TrimSpace(r.Header.Get("X-Forward-Credential-Id")); credID != "" {
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyMCPForwardCredentialID, credID))
	}
	s.mcpHandleRPC(w, r, user, id, forwardNetworkId)
}

// MCPForwardNetworkRPC exposes a Forward MCP JSON-RPC endpoint without user-context path parameters.
//
// This is useful for connecting MCP clients to an arbitrary Forward network id, using the caller's
// saved credential sets (or user default collector config).
//
//encore:api auth raw method=POST path=/api/mcp/forward/:forwardNetworkId/rpc
func (s *Service) MCPForwardNetworkRPC(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	netID := strings.TrimSpace(r.PathValue("forwardNetworkId"))
	if netID == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if credID := strings.TrimSpace(r.Header.Get("X-Forward-Credential-Id")); credID != "" {
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyMCPForwardCredentialID, credID))
	}
	s.mcpHandleRPC(w, r, user, "", netID)
}
