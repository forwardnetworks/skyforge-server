package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"github.com/google/uuid"
)

// ---- Assurance Studio: Saved Runs (artifacts) ----

type AssuranceStudioRun struct {
	ID string `json:"id"`

	WorkspaceID      string `json:"workspaceId"`
	NetworkRef       string `json:"networkRef"`
	ForwardNetworkID string `json:"forwardNetworkId"`
	ScenarioID       string `json:"scenarioId,omitempty"`

	Title  string `json:"title"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`

	CreatedBy  string `json:"createdBy"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt,omitempty"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type AssuranceStudioRunDetail struct {
	Run     AssuranceStudioRun          `json:"run"`
	Request AssuranceStudioScenarioSpec `json:"request"`
	Results json.RawMessage             `json:"results,omitempty"`
}

type AssuranceStudioListRunsResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	NetworkRef  string               `json:"networkRef"`
	Runs        []AssuranceStudioRun `json:"runs"`
}

type AssuranceStudioCreateRunRequest struct {
	ScenarioID string `json:"scenarioId,omitempty"`
	Title      string `json:"title,omitempty"`
	Status     string `json:"status,omitempty"` // SUCCEEDED|PARTIAL|FAILED (optional, default SUCCEEDED)
	Error      string `json:"error,omitempty"`

	Request AssuranceStudioScenarioSpec `json:"request"`
	Results json.RawMessage             `json:"results,omitempty"`
}

func validateAssuranceRunStatus(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "SUCCEEDED", nil
	}
	if s != "SUCCEEDED" && s != "PARTIAL" && s != "FAILED" {
		return "", errs.B().Code(errs.InvalidArgument).Msg("invalid status").Err()
	}
	return s, nil
}

// ListWorkspaceForwardNetworkAssuranceStudioRuns lists stored Assurance Studio run artifacts.
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/assurance/studio/runs
func (s *Service) ListWorkspaceForwardNetworkAssuranceStudioRuns(ctx context.Context, id, networkRef string) (*AssuranceStudioListRunsResponse, error) {
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

	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctxReq, `
SELECT id, workspace_id, network_ref, forward_network_id, scenario_id, title, status, COALESCE(error,''),
       created_by, started_at, finished_at, created_at, updated_at
  FROM sf_assurance_studio_runs
 WHERE workspace_id=$1 AND network_ref=$2
 ORDER BY started_at DESC
 LIMIT 50
`, pc.workspace.ID, net.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &AssuranceStudioListRunsResponse{WorkspaceID: pc.workspace.ID, NetworkRef: net.ID, Runs: []AssuranceStudioRun{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list runs").Err()
	}
	defer rows.Close()

	out := []AssuranceStudioRun{}
	for rows.Next() {
		var r AssuranceStudioRun
		var id uuid.UUID
		var netRef uuid.UUID
		var scenarioID sql.NullString
		var startedAt time.Time
		var finishedAt sql.NullTime
		var createdAt time.Time
		var updatedAt time.Time

		if err := rows.Scan(
			&id,
			&r.WorkspaceID,
			&netRef,
			&r.ForwardNetworkID,
			&scenarioID,
			&r.Title,
			&r.Status,
			&r.Error,
			&r.CreatedBy,
			&startedAt,
			&finishedAt,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode run").Err()
		}
		r.ID = id.String()
		r.NetworkRef = netRef.String()
		if scenarioID.Valid {
			r.ScenarioID = strings.TrimSpace(scenarioID.String)
		}
		r.StartedAt = startedAt.UTC().Format(time.RFC3339)
		if finishedAt.Valid {
			r.FinishedAt = finishedAt.Time.UTC().Format(time.RFC3339)
		}
		r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
		out = append(out, r)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartedAt != out[j].StartedAt {
			return out[i].StartedAt > out[j].StartedAt
		}
		return out[i].ID > out[j].ID
	})

	return &AssuranceStudioListRunsResponse{
		WorkspaceID: pc.workspace.ID,
		NetworkRef:  net.ID,
		Runs:        out,
	}, nil
}

// CreateWorkspaceForwardNetworkAssuranceStudioRun stores a run artifact (results JSON) for later review/export.
//
//encore:api auth method=POST path=/api/workspaces/:id/forward-networks/:networkRef/assurance/studio/runs
func (s *Service) CreateWorkspaceForwardNetworkAssuranceStudioRun(ctx context.Context, id, networkRef string, req *AssuranceStudioCreateRunRequest) (*AssuranceStudioRun, error) {
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
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("request required").Err()
	}

	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	status, err := validateAssuranceRunStatus(req.Status)
	if err != nil {
		return nil, err
	}
	if err := validateAssuranceScenarioSpec(&req.Request); err != nil {
		return nil, err
	}

	var scenarioUUID *uuid.UUID
	if v := strings.TrimSpace(req.ScenarioID); v != "" {
		parsed, err := uuid.Parse(v)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid scenarioId").Err()
		}

		// Ensure scenario belongs to this workspace+network.
		ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		var tmp uuid.UUID
		err = s.db.QueryRowContext(ctxReq, `
SELECT id
  FROM sf_assurance_studio_scenarios
 WHERE workspace_id=$1 AND network_ref=$2 AND id=$3
 LIMIT 1
`, pc.workspace.ID, net.ID, parsed).Scan(&tmp)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, errs.B().Code(errs.NotFound).Msg("scenario not found").Err()
			}
			if isMissingDBRelation(err) {
				return nil, errs.B().Code(errs.Unavailable).Msg("scenario store unavailable").Err()
			}
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to validate scenario").Err()
		}
		scenarioUUID = &parsed
	}

	runID := uuid.New()
	now := time.Now().UTC()
	reqJSON, _ := json.Marshal(req.Request)
	resultsJSON := []byte("{}")
	if len(req.Results) > 0 {
		resultsJSON = req.Results
	}
	const maxResultsBytes = 2 * 1024 * 1024
	errText := strings.TrimSpace(req.Error)
	if len(resultsJSON) > maxResultsBytes {
		// Avoid storing huge DB rows. Keep a stub artifact so the run still exists.
		stub, _ := json.Marshal(map[string]any{
			"truncated":         true,
			"originalSizeBytes": len(resultsJSON),
			"maxSizeBytes":      maxResultsBytes,
			"message": "Assurance Studio results were too large to store. " +
				"Try fewer demands or disable detailed collection (e.g. ACL/NF details, hops).",
		})
		resultsJSON = stub
		if errText == "" {
			errText = "results truncated (too large to store)"
		} else {
			errText = errText + "; results truncated (too large to store)"
		}
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "Assurance Studio Run"
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = s.db.ExecContext(ctxReq, `
INSERT INTO sf_assurance_studio_runs(
  id, workspace_id, network_ref, forward_network_id, scenario_id,
  title, status, error, request, results,
  created_by, started_at, finished_at, created_at, updated_at
)
VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$12,$12,$12)
`, runID, pc.workspace.ID, net.ID, net.ForwardNetworkID, scenarioUUID, title, status, errText, reqJSON, resultsJSON, strings.ToLower(strings.TrimSpace(pc.claims.Username)), now)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist run").Err()
	}

	out := &AssuranceStudioRun{
		ID:               runID.String(),
		WorkspaceID:      pc.workspace.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Title:            title,
		Status:           status,
		Error:            errText,
		CreatedBy:        strings.ToLower(strings.TrimSpace(pc.claims.Username)),
		StartedAt:        now.Format(time.RFC3339),
		FinishedAt:       now.Format(time.RFC3339),
		CreatedAt:        now.Format(time.RFC3339),
		UpdatedAt:        now.Format(time.RFC3339),
	}
	if scenarioUUID != nil {
		out.ScenarioID = scenarioUUID.String()
	}
	return out, nil
}

// GetWorkspaceForwardNetworkAssuranceStudioRun returns a stored run artifact (including results JSON).
//
//encore:api auth method=GET path=/api/workspaces/:id/forward-networks/:networkRef/assurance/studio/runs/:runId
func (s *Service) GetWorkspaceForwardNetworkAssuranceStudioRun(ctx context.Context, id, networkRef, runId string) (*AssuranceStudioRunDetail, error) {
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

	net, err := resolveWorkspaceForwardNetwork(ctx, s.db, pc.workspace.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	parsedID, err := uuid.Parse(strings.TrimSpace(runId))
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid runId").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var r AssuranceStudioRun
	var rid uuid.UUID
	var nref uuid.UUID
	var scenarioID sql.NullString
	var startedAt time.Time
	var finishedAt sql.NullTime
	var createdAt time.Time
	var updatedAt time.Time
	var reqJSON []byte
	var resultsJSON []byte

	err = s.db.QueryRowContext(ctxReq, `
SELECT id, workspace_id, network_ref, forward_network_id, scenario_id, title, status, COALESCE(error,''),
       created_by, started_at, finished_at, created_at, updated_at, request, results
  FROM sf_assurance_studio_runs
 WHERE workspace_id=$1 AND network_ref=$2 AND id=$3
 LIMIT 1
`, pc.workspace.ID, net.ID, parsedID).Scan(
		&rid, &r.WorkspaceID, &nref, &r.ForwardNetworkID, &scenarioID, &r.Title, &r.Status, &r.Error,
		&r.CreatedBy, &startedAt, &finishedAt, &createdAt, &updatedAt, &reqJSON, &resultsJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.B().Code(errs.NotFound).Msg("run not found").Err()
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load run").Err()
	}

	r.ID = rid.String()
	r.NetworkRef = nref.String()
	r.StartedAt = startedAt.UTC().Format(time.RFC3339)
	if finishedAt.Valid {
		r.FinishedAt = finishedAt.Time.UTC().Format(time.RFC3339)
	}
	r.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	r.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	if scenarioID.Valid {
		r.ScenarioID = strings.TrimSpace(scenarioID.String)
	}

	var spec AssuranceStudioScenarioSpec
	if len(reqJSON) > 0 {
		_ = json.Unmarshal(reqJSON, &spec)
	}

	return &AssuranceStudioRunDetail{
		Run:     r,
		Request: spec,
		Results: resultsJSON,
	}, nil
}
