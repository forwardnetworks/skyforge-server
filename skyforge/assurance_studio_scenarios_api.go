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

// ---- Assurance Studio: Saved Scenarios (user + forward-network scoped) ----

type AssuranceStudioScenarioSpec struct {
	SnapshotID    string                   `json:"snapshotId,omitempty"`
	Window        string                   `json:"window,omitempty"`        // 24h|7d|30d (optional)
	ThresholdUtil *float64                 `json:"thresholdUtil,omitempty"` // (0,1] optional
	Demands       []AssuranceTrafficDemand `json:"demands,omitempty"`

	// Optional knobs preserved for future tabs, even if not used everywhere yet.
	Routing  JSONMap `json:"routing,omitempty"`
	Capacity JSONMap `json:"capacity,omitempty"`
	Security JSONMap `json:"security,omitempty"`
	Notes    string  `json:"notes,omitempty"`
}

type AssuranceStudioScenario struct {
	ID string `json:"id"`

	UserContextID    string `json:"userContextId"`
	NetworkRef       string `json:"networkRef"` // sf_policy_report_forward_networks.id
	ForwardNetworkID string `json:"forwardNetworkId"`

	Name        string                      `json:"name"`
	Description string                      `json:"description,omitempty"`
	Spec        AssuranceStudioScenarioSpec `json:"spec"`

	CreatedBy string `json:"createdBy"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type AssuranceStudioListScenariosResponse struct {
	UserContextID string                    `json:"userContextId"`
	NetworkRef    string                    `json:"networkRef"`
	Scenarios     []AssuranceStudioScenario `json:"scenarios"`
}

type AssuranceStudioCreateScenarioRequest struct {
	Name        string                      `json:"name"`
	Description string                      `json:"description,omitempty"`
	Spec        AssuranceStudioScenarioSpec `json:"spec"`
}

type AssuranceStudioUpdateScenarioRequest struct {
	Name        string                       `json:"name,omitempty"`
	Description *string                      `json:"description,omitempty"` // nil = keep, ptr="" = clear
	Spec        *AssuranceStudioScenarioSpec `json:"spec,omitempty"`
}

func validateAssuranceScenarioSpec(spec *AssuranceStudioScenarioSpec) error {
	if spec == nil {
		return errs.B().Code(errs.InvalidArgument).Msg("spec is required").Err()
	}
	if strings.TrimSpace(spec.Window) != "" {
		w := strings.TrimSpace(spec.Window)
		if w != "24h" && w != "7d" && w != "30d" {
			return errs.B().Code(errs.InvalidArgument).Msg("invalid window").Err()
		}
	}
	if spec.ThresholdUtil != nil {
		t := *spec.ThresholdUtil
		if t <= 0 || t > 1 {
			return errs.B().Code(errs.InvalidArgument).Msg("invalid thresholdUtil").Err()
		}
	}
	if len(spec.Demands) > 200 {
		return errs.B().Code(errs.InvalidArgument).Msg("too many demands (max 200)").Err()
	}
	for i, d := range spec.Demands {
		if strings.TrimSpace(d.DstIP) == "" {
			return errs.B().Code(errs.InvalidArgument).Msg("missing dstIp at demands[" + itoa(i) + "]").Err()
		}
	}
	return nil
}

func itoa(v int) string {
	// tiny helper to avoid importing strconv in this file
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	n := v
	if n < 0 {
		n = -n
	}
	buf := make([]byte, 0, 16)
	for n > 0 {
		buf = append(buf, digits[n%10])
		n /= 10
	}
	if v < 0 {
		buf = append(buf, '-')
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func scanScenarioRow(rows *sql.Rows) (AssuranceStudioScenario, error) {
	var out AssuranceStudioScenario
	var id uuid.UUID
	var netRef uuid.UUID
	var createdAt time.Time
	var updatedAt time.Time
	var specJSON []byte
	if err := rows.Scan(
		&id,
		&out.UserContextID,
		&netRef,
		&out.ForwardNetworkID,
		&out.Name,
		&out.Description,
		&specJSON,
		&out.CreatedBy,
		&createdAt,
		&updatedAt,
	); err != nil {
		return AssuranceStudioScenario{}, err
	}
	out.ID = id.String()
	out.NetworkRef = netRef.String()
	out.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	out.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	if len(specJSON) > 0 {
		_ = json.Unmarshal(specJSON, &out.Spec)
	}
	return out, nil
}

// ListUserContextForwardNetworkAssuranceStudioScenarios lists saved scenarios for a Forward network.
func (s *Service) ListUserContextForwardNetworkAssuranceStudioScenarios(ctx context.Context, id, networkRef string) (*AssuranceStudioListScenariosResponse, error) {
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
SELECT s.id,
       COALESCE(s.user_id::text, s.workspace_id, ''),
       s.network_ref,
       s.forward_network_id,
       s.name,
       COALESCE(s.description,''),
       s.spec,
       s.created_by,
       s.created_at,
       s.updated_at
  FROM sf_assurance_studio_scenarios s
  LEFT JOIN me ON true
 WHERE s.network_ref=$3
   AND (
     (me.id IS NOT NULL AND s.user_id=me.id) OR
     ($2 <> '' AND s.workspace_id=$2)
   )
 ORDER BY s.updated_at DESC
`, strings.ToLower(strings.TrimSpace(pc.claims.Username)), pc.userContext.ID, net.ID)
	if err != nil {
		if isMissingDBRelation(err) {
			return &AssuranceStudioListScenariosResponse{UserContextID: pc.userContext.ID, NetworkRef: net.ID, Scenarios: []AssuranceStudioScenario{}}, nil
		}
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list scenarios").Err()
	}
	defer rows.Close()

	out := []AssuranceStudioScenario{}
	for rows.Next() {
		sc, err := scanScenarioRow(rows)
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode scenario").Err()
		}
		out = append(out, sc)
	}

	// Deterministic ordering: newest updated_at first, then name.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].UpdatedAt != out[j].UpdatedAt {
			return out[i].UpdatedAt > out[j].UpdatedAt
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})

	return &AssuranceStudioListScenariosResponse{
		UserContextID: pc.userContext.ID,
		NetworkRef:    net.ID,
		Scenarios:     out,
	}, nil
}

// CreateUserContextForwardNetworkAssuranceStudioScenario creates a saved scenario.
func (s *Service) CreateUserContextForwardNetworkAssuranceStudioScenario(ctx context.Context, id, networkRef string, req *AssuranceStudioCreateScenarioRequest) (*AssuranceStudioScenario, error) {
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

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	if err := validateAssuranceScenarioSpec(&req.Spec); err != nil {
		return nil, err
	}

	idUUID := uuid.New()
	now := time.Now().UTC()
	specJSON, _ := json.Marshal(req.Spec)

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = s.db.ExecContext(ctxReq, `
INSERT INTO sf_assurance_studio_scenarios(
  id, user_id, workspace_id, network_ref, forward_network_id, name, description, spec, created_by, created_at, updated_at
)
VALUES (
  $1,
  (SELECT id FROM sf_users WHERE username=$8 LIMIT 1),
  $2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$9
)
`, idUUID, pc.userContext.ID, net.ID, net.ForwardNetworkID, name, strings.TrimSpace(req.Description), specJSON, strings.ToLower(strings.TrimSpace(pc.claims.Username)), now)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create scenario").Err()
	}

	out := &AssuranceStudioScenario{
		ID:               idUUID.String(),
		UserContextID:    pc.userContext.ID,
		NetworkRef:       net.ID,
		ForwardNetworkID: net.ForwardNetworkID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Spec:             req.Spec,
		CreatedBy:        strings.ToLower(strings.TrimSpace(pc.claims.Username)),
		CreatedAt:        now.Format(time.RFC3339),
		UpdatedAt:        now.Format(time.RFC3339),
	}
	return out, nil
}

// GetUserContextForwardNetworkAssuranceStudioScenario loads a scenario.
func (s *Service) GetUserContextForwardNetworkAssuranceStudioScenario(ctx context.Context, id, networkRef, scenarioId string) (*AssuranceStudioScenario, error) {
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

	scID, err := uuid.Parse(strings.TrimSpace(scenarioId))
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid scenarioId").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctxReq, `
WITH me AS (
  SELECT id FROM sf_users WHERE username=$1 LIMIT 1
)
SELECT s.id,
       COALESCE(s.user_id::text, s.workspace_id, ''),
       s.network_ref,
       s.forward_network_id,
       s.name,
       COALESCE(s.description,''),
       s.spec,
       s.created_by,
       s.created_at,
       s.updated_at
  FROM sf_assurance_studio_scenarios s
  LEFT JOIN me ON true
 WHERE s.network_ref=$3
   AND s.id=$4
   AND (
     (me.id IS NOT NULL AND s.user_id=me.id) OR
     ($2 <> '' AND s.workspace_id=$2)
   )
 LIMIT 1
`, strings.ToLower(strings.TrimSpace(pc.claims.Username)), pc.userContext.ID, net.ID, scID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load scenario").Err()
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, errs.B().Code(errs.NotFound).Msg("scenario not found").Err()
	}
	sc, err := scanScenarioRow(rows)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to decode scenario").Err()
	}
	return &sc, nil
}

// UpdateUserContextForwardNetworkAssuranceStudioScenario updates scenario name/description/spec.
func (s *Service) UpdateUserContextForwardNetworkAssuranceStudioScenario(ctx context.Context, id, networkRef, scenarioId string, req *AssuranceStudioUpdateScenarioRequest) (*AssuranceStudioScenario, error) {
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

	scID, err := uuid.Parse(strings.TrimSpace(scenarioId))
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid scenarioId").Err()
	}

	// Load current row for merge.
	cur, err := s.GetUserContextForwardNetworkAssuranceStudioScenario(ctx, id, net.ID, scID.String())
	if err != nil {
		return nil, err
	}

	name := strings.TrimSpace(req.Name)
	if name != "" {
		cur.Name = name
	}
	if strings.TrimSpace(cur.Name) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}

	if req.Description != nil {
		cur.Description = strings.TrimSpace(*req.Description)
	}
	if req.Spec != nil {
		if err := validateAssuranceScenarioSpec(req.Spec); err != nil {
			return nil, err
		}
		cur.Spec = *req.Spec
	}

	now := time.Now().UTC()
	specJSON, _ := json.Marshal(cur.Spec)

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = s.db.ExecContext(ctxReq, `
UPDATE sf_assurance_studio_scenarios
   SET name=$1,
       description=NULLIF($2,''),
       spec=$3,
       updated_at=$4
 WHERE id=$7
   AND network_ref=$6
   AND (
     (user_id=(SELECT id FROM sf_users WHERE username=$5 LIMIT 1)) OR
     ($8 <> '' AND workspace_id=$8)
   )
`, strings.TrimSpace(cur.Name), strings.TrimSpace(cur.Description), specJSON, now, strings.ToLower(strings.TrimSpace(pc.claims.Username)), net.ID, scID, pc.userContext.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to update scenario").Err()
	}
	cur.UpdatedAt = now.Format(time.RFC3339)
	return cur, nil
}

// DeleteUserContextForwardNetworkAssuranceStudioScenario deletes a scenario.
func (s *Service) DeleteUserContextForwardNetworkAssuranceStudioScenario(ctx context.Context, id, networkRef, scenarioId string) (*PolicyReportDecisionResponse, error) {
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

	net, err := resolveUserForwardNetwork(ctx, s.db, pc.userContext.ID, pc.claims.Username, networkRef)
	if err != nil {
		return nil, err
	}

	scID, err := uuid.Parse(strings.TrimSpace(scenarioId))
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid scenarioId").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	res, err := s.db.ExecContext(ctxReq, `
DELETE FROM sf_assurance_studio_scenarios
 WHERE id=$3
   AND network_ref=$2
   AND (
     (user_id=(SELECT id FROM sf_users WHERE username=$1 LIMIT 1)) OR
     ($4 <> '' AND workspace_id=$4)
   )
`, strings.ToLower(strings.TrimSpace(pc.claims.Username)), net.ID, scID, pc.userContext.ID)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete scenario").Err()
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, errs.B().Code(errs.NotFound).Msg("scenario not found").Err()
	}

	return &PolicyReportDecisionResponse{Ok: true}, nil
}
