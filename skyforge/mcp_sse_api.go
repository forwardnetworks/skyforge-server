package skyforge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"encore.dev/beta/errs"

	"github.com/google/uuid"
)

type mcpSSESession struct {
	ID             string
	Username       string
	WorkspaceID    string
	ForwardNetwork string
	CreatedAt      time.Time
	LastMessageAt  time.Time
	Ch             chan []byte
	Closed         chan struct{}
}

type mcpSSEHub struct {
	mu       sync.Mutex
	sessions map[string]*mcpSSESession
}

var globalMCPSSEHub = &mcpSSEHub{sessions: map[string]*mcpSSESession{}}

func (h *mcpSSEHub) create(username, workspaceID, forwardNetworkID string) *mcpSSESession {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := uuid.NewString()
	s := &mcpSSESession{
		ID:             id,
		Username:       strings.ToLower(strings.TrimSpace(username)),
		WorkspaceID:    strings.TrimSpace(workspaceID),
		ForwardNetwork: strings.TrimSpace(forwardNetworkID),
		CreatedAt:      time.Now().UTC(),
		LastMessageAt:  time.Now().UTC(),
		Ch:             make(chan []byte, 32),
		Closed:         make(chan struct{}),
	}
	h.sessions[id] = s
	return s
}

func (h *mcpSSEHub) get(id string) *mcpSSESession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[id]
}

func (h *mcpSSEHub) send(id string, msg []byte) bool {
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil {
		return false
	}
	select {
	case <-s.Closed:
		return false
	default:
	}
	select {
	case s.Ch <- msg:
		return true
	default:
		// Drop if client isn't reading; this keeps server bounded.
		return false
	}
}

func (h *mcpSSEHub) close(id string) {
	h.mu.Lock()
	s := h.sessions[id]
	delete(h.sessions, id)
	h.mu.Unlock()
	if s == nil {
		return
	}
	select {
	case <-s.Closed:
		return
	default:
		close(s.Closed)
	}
}

func sseWrite(w http.ResponseWriter, event string, data []byte) error {
	if w == nil {
		return nil
	}
	if event != "" {
		if _, err := io.WriteString(w, "event: "+event+"\n"); err != nil {
			return err
		}
	}
	// SSE requires each line to be prefixed with "data:".
	payload := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, line := range strings.Split(payload, "\n") {
		if _, err := io.WriteString(w, "data: "+line+"\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func (s *Service) mcpHandleBody(ctx context.Context, user *AuthUser, workspaceID, forwardNetworkID string, body []byte) ([]byte, bool, error) {
	if s == nil {
		return nil, false, errs.B().Code(errs.Unavailable).Msg("server unavailable").Err()
	}
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return nil, false, errs.B().Code(errs.InvalidArgument).Msg("empty request").Err()
	}
	// Batch requests.
	if body[0] == '[' {
		var reqs []mcpJSONRPCRequest
		if err := json.Unmarshal(body, &reqs); err != nil {
			return nil, false, errs.B().Code(errs.InvalidArgument).Msg("invalid json").Err()
		}
		resps := make([]mcpJSONRPCResponse, 0, len(reqs))
		for _, req := range reqs {
			resp := s.handleMCPJSONRPC(ctx, user, workspaceID, forwardNetworkID, req)
			if req.ID != nil {
				resps = append(resps, resp)
			}
		}
		if len(resps) == 0 {
			return nil, false, nil
		}
		b, _ := json.Marshal(resps)
		return b, true, nil
	}

	var req mcpJSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, false, errs.B().Code(errs.InvalidArgument).Msg("invalid json").Err()
	}
	resp := s.handleMCPJSONRPC(ctx, user, workspaceID, forwardNetworkID, req)
	if req.ID == nil {
		return nil, false, nil
	}
	b, _ := json.Marshal(resp)
	return b, true, nil
}

func (s *Service) mcpSSE(w http.ResponseWriter, r *http.Request, user *AuthUser, workspaceID, forwardNetworkID string) {
	if s == nil || !s.cfg.MCP.Enabled {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sess := globalMCPSSEHub.create(user.Username, workspaceID, forwardNetworkID)
	defer globalMCPSSEHub.close(sess.ID)

	first, _ := json.Marshal(map[string]any{"session_id": sess.ID})
	_ = sseWrite(w, "session", first)
	fl.Flush()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-sess.Closed:
			return
		case <-ticker.C:
			_, _ = io.WriteString(w, ": ping\n\n")
			fl.Flush()
		case msg := <-sess.Ch:
			_ = sseWrite(w, "message", msg)
			fl.Flush()
		}
	}
}

func (s *Service) mcpMessage(w http.ResponseWriter, r *http.Request, user *AuthUser, workspaceID, forwardNetworkID string) {
	if s == nil || !s.cfg.MCP.Enabled {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		sessionID = strings.TrimSpace(r.Header.Get("X-MCP-Session-Id"))
	}
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}
	sess := globalMCPSSEHub.get(sessionID)
	if sess == nil {
		http.Error(w, "invalid session", http.StatusNotFound)
		return
	}
	if strings.ToLower(strings.TrimSpace(sess.Username)) != strings.ToLower(strings.TrimSpace(user.Username)) ||
		strings.TrimSpace(sess.WorkspaceID) != strings.TrimSpace(workspaceID) ||
		strings.TrimSpace(sess.ForwardNetwork) != strings.TrimSpace(forwardNetworkID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if credID := strings.TrimSpace(r.Header.Get("X-Forward-Credential-Id")); credID != "" {
		ctx = context.WithValue(ctx, ctxKeyMCPForwardCredentialID, credID)
	}

	respBody, shouldSend, err := s.mcpHandleBody(ctx, user, workspaceID, forwardNetworkID, body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if shouldSend && len(respBody) > 0 {
		_ = globalMCPSSEHub.send(sessionID, respBody)
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// MCPSSE exposes an SSE-based MCP transport suitable for remote clients.
//
// Connect first to obtain a session_id:
//
//	GET /api/mcp/sse
//
// Then POST JSON-RPC payloads to:
//
//	POST /api/mcp/message?session_id=<id>
//
//encore:api auth raw method=GET path=/api/mcp/sse
func (s *Service) MCPSSE(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mcpSSE(w, r, user, "", "")
}

// MCPMessage receives JSON-RPC messages for an SSE session.
//
//encore:api auth raw method=POST path=/api/mcp/message
func (s *Service) MCPMessage(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mcpMessage(w, r, user, "", "")
}

// MCPForwardSSE exposes an SSE-based transport for Forward-scoped MCP calls.
//
//encore:api auth raw method=GET path=/api/workspaces/:id/mcp/forward/:forwardNetworkId/sse
func (s *Service) MCPForwardSSE(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	netID := strings.TrimSpace(r.PathValue("forwardNetworkId"))
	if id == "" || netID == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if _, err := s.workspaceContextForUser(user, id); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.mcpSSE(w, r, user, id, netID)
}

// MCPForwardMessage receives JSON-RPC messages for a Forward-scoped SSE session.
//
//encore:api auth raw method=POST path=/api/workspaces/:id/mcp/forward/:forwardNetworkId/message
func (s *Service) MCPForwardMessage(w http.ResponseWriter, r *http.Request) {
	user, err := s.mcpAuthFromRequest(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	netID := strings.TrimSpace(r.PathValue("forwardNetworkId"))
	if id == "" || netID == "" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if _, err := s.workspaceContextForUser(user, id); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.mcpMessage(w, r, user, id, netID)
}

// MCPForwardNetworkSSE exposes an SSE-based transport for Forward-scoped MCP calls without a workspace context.
//
//encore:api auth raw method=GET path=/api/mcp/forward/:forwardNetworkId/sse
func (s *Service) MCPForwardNetworkSSE(w http.ResponseWriter, r *http.Request) {
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
	s.mcpSSE(w, r, user, "", netID)
}

// MCPForwardNetworkMessage receives JSON-RPC messages for an unscoped Forward SSE session.
//
//encore:api auth raw method=POST path=/api/mcp/forward/:forwardNetworkId/message
func (s *Service) MCPForwardNetworkMessage(w http.ResponseWriter, r *http.Request) {
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
	s.mcpMessage(w, r, user, "", netID)
}
