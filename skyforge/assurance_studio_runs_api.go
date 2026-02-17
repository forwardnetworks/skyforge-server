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

	UserContextID    string `json:"userContextId"`
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
	UserContextID string               `json:"userContextId"`
	NetworkRef    string               `json:"networkRef"`
	Runs          []AssuranceStudioRun `json:"runs"`
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

// ListUserContextForwardNetworkAssuranceStudioRuns lists stored Assurance Studio run artifacts.
func (s *Service) ListUserContextForwardNetworkAssuranceStudioRuns(ctx context.Context, id, networkRef string) (*AssuranceStudioListRunsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctxReq, `
WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT r.id,
       COALESCE(r.user_id::text, r.workspace_id, ''),
       r.network_ref,
       r.forward_network_id,
       r.scenario_id,
       r.title,
       r.status,
       COALESCE(r.error,''),
       r.created_by,
       r.started_at,
       r.finished_at,
       r.created_at,
       r.updated_at
  FROM sf_assurance_studio_runs r
  LEFT JOIN me ON true
 WHERE r.network_ref=$3
   AND (
     (me.id IS NOT NULL AND r.user_id=me.id) OR
     ($2 <> '' AND r.workspace_id=$2)
   )
 ORDER BY r.started_at DESC
 LIMIT 50
`, strings.ToLower(strings.TrimSpace(pc.claims.Username)), pc.userContext.ID, net.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &AssuranceStudioListRunsResponse{UserContextID: pc.userContext.ID, NetworkRef: net.ID, Runs: []AssuranceStudioRun{}}, nil
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
			&r.UserContextID,
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
		UserContextID: pc.userContext.ID,
		NetworkRef:    net.ID,
		Runs:          out,
	}, nil
}

// CreateUserContextForwardNetworkAssuranceStudioRun stores a run artifact (results JSON) for later review/export.
func (s *Service) CreateUserContextForwardNetworkAssuranceStudioRun(ctx context.Context, id, networkRef string, req *AssuranceStudioCreateRunRequest) (*AssuranceStudioRun, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
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

		// Ensure scenario belongs to this user-context+network.
		ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		var tmp uuid.UUID
		err = s.db.QueryRowContext(ctxReq, `
SELECT id
  FROM sf_assurance_studio_scenarios
 WHERE id=$3
   AND network_ref=$2
   AND (
     (user_id=(SELECT id FROM sf_users WHERE username=$1 LIMIT 1)) OR
     ($4 <> '' AND workspace_id=$4)
   )
 LIMIT 1
`, strings.ToLower(strings.TrimSpace(pc.claims.Username)), net.ID, parsed, pc.userContext.ID).Scan(&tmp)
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
  id, user_id, workspace_id, network_ref, forward_network_id, scenario_id,
  title, status, error, request, results,
  created_by, started_at, finished_at, created_at, updated_at
)
VALUES ($1,(SELECT id FROM sf_users WHERE username=$11 LIMIT 1),$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12,$12,$12,$12)
`, runID, pc.userContext.ID, net.ID, net.ForwardNetworkID, scenarioUUID, title, status, errText, reqJSON, resultsJSON, strings.ToLower(strings.TrimSpace(pc.claims.Username)), now)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist run").Err()
	}

	out := &AssuranceStudioRun{
		ID:               runID.String(),
		UserContextID:    pc.userContext.ID,
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

// GetUserContextForwardNetworkAssuranceStudioRun returns a stored run artifact (including results JSON).
func (s *Service) GetUserContextForwardNetworkAssuranceStudioRun(ctx context.Context, id, networkRef, runId string) (*AssuranceStudioRunDetail, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
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
SELECT r.id,
       COALESCE(r.user_id::text, r.workspace_id, ''),
       r.network_ref,
       r.forward_network_id,
       r.scenario_id,
       r.title,
       r.status,
       COALESCE(r.error,''),
       r.created_by,
       r.started_at,
       r.finished_at,
       r.created_at,
       r.updated_at,
       r.request,
       r.results
  FROM sf_assurance_studio_runs r
 WHERE r.id=$3
   AND r.network_ref=$2
   AND (
     (r.user_id=(SELECT id FROM sf_users WHERE username=$1 LIMIT 1)) OR
     ($4 <> '' AND r.workspace_id=$4)
   )
 LIMIT 1
`, strings.ToLower(strings.TrimSpace(pc.claims.Username)), net.ID, parsedID, pc.userContext.ID).Scan(
		&rid, &r.UserContextID, &nref, &r.ForwardNetworkID, &scenarioID, &r.Title, &r.Status, &r.Error,
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
