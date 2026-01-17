package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

func loadWorkspacesSnapshot(ctx context.Context, svc *Service, claims *SessionClaims, all bool) ([]SkyforgeWorkspace, error) {
	if svc == nil || svc.db == nil {
		return nil, fmt.Errorf("service unavailable")
	}
	if claims == nil || strings.TrimSpace(claims.Username) == "" {
		return nil, fmt.Errorf("unauthorized")
	}

	user := &AuthUser{
		Username:    claims.Username,
		DisplayName: claims.DisplayName,
		Email:       claims.Email,
		Groups:      claims.Groups,
		IsAdmin:     isAdminForClaims(svc.cfg, claims),
	}

	if _, err := svc.ensureDefaultWorkspace(ctx, user); err != nil {
		log.Printf("default workspace ensure: %v", err)
	}
	workspaces, err := svc.workspaceStore.load()
	if err != nil {
		return nil, err
	}

	// Best-effort sync group membership like GetWorkspaces does.
	changed := false
	changedWorkspaces := make([]SkyforgeWorkspace, 0)
	for i := range workspaces {
		if role, ok := syncGroupMembershipForUser(&workspaces[i], claims); ok {
			changed = true
			changedWorkspaces = append(changedWorkspaces, workspaces[i])
			log.Printf("workspace group sync: %s -> %s (%s)", claims.Username, workspaces[i].Slug, role)
		}
	}
	if changed {
		updatedAll := true
		for _, w := range changedWorkspaces {
			if err := svc.workspaceStore.upsert(w); err != nil {
				updatedAll = false
				log.Printf("workspaces upsert after group sync (%s): %v", w.ID, err)
			}
		}
		if updatedAll {
			for _, w := range changedWorkspaces {
				syncGiteaCollaboratorsForWorkspace(svc.cfg, w)
			}
			if svc.db != nil {
				_ = notifyWorkspacesUpdatePG(ctx, svc.db, "*")
				_ = notifyDashboardUpdatePG(ctx, svc.db)
			}
		}
	}

	if !all {
		filtered := make([]SkyforgeWorkspace, 0, len(workspaces))
		for _, w := range workspaces {
			if workspaceAccessLevelForClaims(svc.cfg, w, claims) != "none" {
				filtered = append(filtered, w)
			}
		}
		workspaces = filtered
	}
	sort.Slice(workspaces, func(i, j int) bool { return workspaces[i].Name < workspaces[j].Name })

	return workspaces, nil
}

// WorkspacesEvents streams the workspace list as Server-Sent Events (SSE).
//
// Query params:
// - all=true (admin only; default false)
//
//encore:api auth raw method=GET path=/api/workspaces-events
func (s *Service) WorkspacesEvents(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil || strings.TrimSpace(claims.Username) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	all := strings.EqualFold(strings.TrimSpace(req.URL.Query().Get("all")), "true")
	if all && !isAdminForClaims(s.cfg, claims) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	write := func(format string, args ...any) {
		_, _ = fmt.Fprintf(w, format, args...)
	}

	ctx := req.Context()
	write(": ok\n\n")
	flusher.Flush()

	lastPayload := ""
	lastEventID := int64(0)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		workspaces, err := loadWorkspacesSnapshot(ctx, s, claims, all)
		if err != nil {
			write(": retry\n\n")
			flusher.Flush()
		} else {
			payloadBytes, _ := json.Marshal(map[string]any{
				"user":        claims.Username,
				"workspaces":  workspaces,
				"refreshedAt": time.Now().UTC().Format(time.RFC3339),
			})
			payload := strings.TrimSpace(string(payloadBytes))
			if payload != "" && payload != lastPayload {
				lastPayload = payload
				lastEventID++
				write("id: %d\n", lastEventID)
				write("event: snapshot\n")
				write("data: %s\n\n", payload)
				flusher.Flush()
			} else {
				write(": ping\n\n")
				flusher.Flush()
			}
		}

		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		updated := waitForWorkspacesUpdateSignal(waitCtx, s.db, claims.Username)
		cancel()
		if updated {
			continue
		}
		write(": ping\n\n")
		flusher.Flush()
	}
}
