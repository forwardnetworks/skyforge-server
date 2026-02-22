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

func loadUserScopesSnapshot(ctx context.Context, svc *Service, claims *SessionClaims, all bool) ([]UserScope, error) {
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

	if _, err := svc.ensureDefaultUserScope(ctx, user); err != nil {
		log.Printf("default user scope ensure: %v", err)
	}
	userScopes, err := svc.userScopeStore.load()
	if err != nil {
		return nil, err
	}

	// Best-effort sync group membership like GetUserScopes does.
	changed := false
	changedUserScopes := make([]UserScope, 0)
	for i := range userScopes {
		if role, ok := syncGroupMembershipForUser(&userScopes[i], claims); ok {
			changed = true
			changedUserScopes = append(changedUserScopes, userScopes[i])
			log.Printf("user-scope group sync: %s -> %s (%s)", claims.Username, userScopes[i].Slug, role)
		}
	}
	if changed {
		updatedAll := true
		for _, w := range changedUserScopes {
			if err := svc.userScopeStore.upsert(w); err != nil {
				updatedAll = false
				log.Printf("user-scope upsert after group sync (%s): %v", w.ID, err)
			}
		}
		if updatedAll {
			for _, w := range changedUserScopes {
				syncGiteaCollaboratorsForUserScope(svc.cfg, w)
			}
			if svc.db != nil {
				_ = notifyUserScopesUpdatePG(ctx, svc.db, "*")
				_ = notifyDashboardUpdatePG(ctx, svc.db)
			}
		}
	}

	if !all {
		filtered := make([]UserScope, 0, len(userScopes))
		for _, w := range userScopes {
			if userScopeAccessLevelForClaims(svc.cfg, w, claims) != "none" {
				filtered = append(filtered, w)
			}
		}
		userScopes = filtered
	}
	sort.Slice(userScopes, func(i, j int) bool { return userScopes[i].Name < userScopes[j].Name })

	return userScopes, nil
}

// UserScopesEvents streams the user-scope list as Server-Sent Events (SSE).
//
// Query params:
// - all=true (admin only; default false)
//
//encore:api auth raw method=GET path=/api/users-events
func (s *Service) UserScopesEvents(w http.ResponseWriter, req *http.Request) {
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

	stream, err := newSSEStream(w)
	if err != nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := req.Context()
	stream.comment("ok")
	stream.flush()

	// Subscribe to updates before the initial snapshot load to avoid race windows
	// where we miss a pg NOTIFY and look stale until the keep-alive.
	hub := ensurePGNotifyHub(s.db)
	updates := hub.subscribe(ctx)

	// Drain pg NOTIFY continuously to avoid the hub dropping signals while we
	// perform snapshot loads.
	reloadSignals := make(chan struct{}, 1)
	claimUser := strings.ToLower(strings.TrimSpace(claims.Username))
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case n, ok := <-updates:
				if !ok {
					return
				}
				if n.Channel != pgNotifyUserScopesChannel {
					continue
				}
				payload := strings.ToLower(strings.TrimSpace(n.Payload))
				if payload == "*" || payload == claimUser {
					select {
					case reloadSignals <- struct{}{}:
					default:
						// Coalesce.
					}
				}
			}
		}
	}()

	lastPayload := ""
	id := int64(0)
	reload := true

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		if reload {
			userScopes, err := loadUserScopesSnapshot(ctx, s, claims, all)
			if err != nil {
				stream.comment("retry")
				stream.flush()
			} else {
				payloadBytes, _ := json.Marshal(map[string]any{
					"user":        claims.Username,
					"userScopes":  userScopes,
					"refreshedAt": time.Now().UTC().Format(time.RFC3339),
				})
				payload := strings.TrimSpace(string(payloadBytes))
				if payload != "" && payload != lastPayload {
					lastPayload = payload
					id++
					stream.event(id, "snapshot", []byte(payload))
					stream.flush()
				}
			}
			reload = false
		}

		select {
		case <-ctx.Done():
			return
		case <-reloadSignals:
			reload = true
		case <-pingTicker.C:
			stream.comment("ping")
			stream.flush()
		}
	}
}
