package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type DeploymentUIEvent struct {
	ID         int64           `json:"id"`
	CreatedAt  string          `json:"createdAt"`
	CreatedBy  string          `json:"createdBy,omitempty"`
	EventType  string          `json:"eventType"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Deployment string          `json:"deploymentId,omitempty"`
}

type ListDeploymentUIEventsParams struct {
	AfterID int64 `query:"after_id"`
	Limit   int   `query:"limit"`
}

type ListDeploymentUIEventsResponse struct {
	WorkspaceID  string              `json:"workspaceId"`
	DeploymentID string              `json:"deploymentId"`
	Events       []DeploymentUIEvent `json:"events"`
}

// ListWorkspaceDeploymentUIEvents returns recent UI/graph events for a deployment.
//
//encore:api auth method=GET path=/api/workspaces/:id/deployments/:deploymentID/ui-events
func (s *Service) ListWorkspaceDeploymentUIEvents(ctx context.Context, id, deploymentID string, params *ListDeploymentUIEventsParams) (*ListDeploymentUIEventsResponse, error) {
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
	if strings.TrimSpace(deploymentID) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("deploymentID is required").Err()
	}

	limit := 200
	after := int64(0)
	if params != nil {
		if params.Limit > 0 && params.Limit <= 500 {
			limit = params.Limit
		}
		if params.AfterID > 0 {
			after = params.AfterID
		}
	}

	ctxQ, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := listDeploymentUIEventsAfter(ctxQ, s.db, pc.workspace.ID, deploymentID, after, limit)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list events").Err()
	}
	return &ListDeploymentUIEventsResponse{
		WorkspaceID:  pc.workspace.ID,
		DeploymentID: deploymentID,
		Events:       rows,
	}, nil
}

type UIEventsSSEPayload struct {
	Cursor int64               `json:"cursor"`
	Events []DeploymentUIEvent `json:"events"`
}

// DeploymentUIEventsStream streams deployment UI events as SSE.
//
//encore:api auth raw method=GET path=/api/workspaces/:id/deployments/:deploymentID/ui-events/events
func (s *Service) DeploymentUIEventsStream(w http.ResponseWriter, req *http.Request) {
	if s == nil || s.db == nil || s.sessionManager == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	claims, err := s.sessionManager.Parse(req)
	if err != nil || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	workspaceKey := strings.TrimSpace(req.PathValue("id"))
	deploymentID := strings.TrimSpace(req.PathValue("deploymentID"))
	if workspaceKey == "" || deploymentID == "" {
		// Best-effort path param extraction (PathValue is only populated when the
		// underlying mux supports it).
		parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
		// expected: api/workspaces/<id>/deployments/<deploymentID>/ui-events/events
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "workspaces":
				if workspaceKey == "" {
					workspaceKey = strings.TrimSpace(parts[i+1])
				}
			case "deployments":
				if deploymentID == "" {
					deploymentID = strings.TrimSpace(parts[i+1])
				}
			}
		}
	}
	if workspaceKey == "" || deploymentID == "" {
		http.Error(w, "invalid path params", http.StatusBadRequest)
		return
	}
	_, _, ws, err := s.loadWorkspaceByKey(workspaceKey)
	if err != nil || strings.TrimSpace(ws.ID) == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if workspaceAccessLevelForClaims(s.cfg, ws, claims) == "none" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	lastID := int64(0)
	if raw := strings.TrimSpace(req.Header.Get("Last-Event-ID")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			lastID = parsed
		}
	}

	stream, err := newSSEStream(w)
	if err != nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	stream.comment("ok")
	stream.flush()

	ctx := req.Context()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
			rows, err := listDeploymentUIEventsAfter(ctxReq, s.db, ws.ID, deploymentID, lastID, 200)
			cancel()
			if err != nil {
				stream.comment("retry")
				stream.flush()
				continue
			}
			if len(rows) == 0 {
				waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				updated := waitForDeploymentEventSignal(waitCtx, s.db, ws.ID, deploymentID)
				cancel()
				if updated {
					continue
				}
				stream.comment("ping")
				stream.flush()
				continue
			}
			for _, row := range rows {
				if row.ID > lastID {
					lastID = row.ID
				}
			}
			stream.eventJSON(lastID, "ui-events", UIEventsSSEPayload{Cursor: lastID, Events: rows})
			stream.flush()
		}
	}
}

func insertDeploymentUIEvent(ctx context.Context, db *sql.DB, workspaceID, deploymentID, createdBy, eventType string, payload any) error {
	workspaceID = strings.TrimSpace(workspaceID)
	deploymentID = strings.TrimSpace(deploymentID)
	if db == nil || workspaceID == "" || deploymentID == "" {
		return nil
	}
	createdBy = strings.TrimSpace(createdBy)
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		eventType = "event"
	}
	var raw []byte
	if payload != nil {
		raw, _ = json.Marshal(payload)
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}

	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctxReq, `
		INSERT INTO sf_deployment_ui_events (workspace_id, deployment_id, created_by, event_type, payload)
		VALUES ($1, $2, $3, $4, $5::jsonb)
	`, workspaceID, deploymentID, createdBy, eventType, string(raw))
	return err
}

func listDeploymentUIEventsAfter(ctx context.Context, db *sql.DB, workspaceID, deploymentID string, afterID int64, limit int) ([]DeploymentUIEvent, error) {
	if db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctxReq, `
		SELECT id, created_at, created_by, event_type, payload
		FROM sf_deployment_ui_events
		WHERE workspace_id=$1 AND deployment_id=$2 AND id > $3
		ORDER BY id ASC
		LIMIT $4
	`, workspaceID, deploymentID, afterID, limit)
	if err != nil {
		if isMissingDBRelation(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []DeploymentUIEvent
	for rows.Next() {
		var (
			id        int64
			createdAt time.Time
			createdBy string
			typ       string
			payload   []byte
		)
		if err := rows.Scan(&id, &createdAt, &createdBy, &typ, &payload); err != nil {
			continue
		}
		out = append(out, DeploymentUIEvent{
			ID:        id,
			CreatedAt: createdAt.UTC().Format(time.RFC3339),
			CreatedBy: strings.TrimSpace(createdBy),
			EventType: strings.TrimSpace(typ),
			Payload:   payload,
		})
	}
	return out, nil
}
