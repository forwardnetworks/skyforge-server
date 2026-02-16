package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func normalizePresetKind(kind string) string {
	kind = strings.ToUpper(strings.TrimSpace(kind))
	if kind == "" {
		return "PACK"
	}
	if kind != "PACK" && kind != "CUSTOM" && kind != "PATHS" {
		return ""
	}
	return kind
}

func normalizeIntervalMinutes(v int) int {
	// Guardrails: 5 minutes minimum, 1 week maximum (demo).
	if v <= 0 {
		return 24 * 60
	}
	if v < 5 {
		return 5
	}
	if v > 7*24*60 {
		return 7 * 24 * 60
	}
	return v
}

func createPolicyReportPreset(ctx context.Context, db *sql.DB, ownerID, actor string, req *PolicyReportCreatePresetRequest) (*PolicyReportPreset, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	if ownerID == "" || actor == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}
	forwardNetworkID := strings.TrimSpace(req.ForwardNetworkID)
	if forwardNetworkID == "" {
		return nil, fmt.Errorf("forwardNetworkId is required")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	kind := normalizePresetKind(req.Kind)
	if kind == "" {
		return nil, fmt.Errorf("invalid kind")
	}
	packID := strings.TrimSpace(req.PackID)
	if kind == "PACK" && packID == "" {
		return nil, fmt.Errorf("packId is required for kind=PACK")
	}
	if kind == "CUSTOM" && len(req.Checks) == 0 {
		return nil, fmt.Errorf("checks is required for kind=CUSTOM")
	}
	if kind == "PATHS" && len(req.Checks) == 0 {
		return nil, fmt.Errorf("checks is required for kind=PATHS")
	}
	if kind == "PATHS" && packID != "" {
		return nil, fmt.Errorf("packId must be empty for kind=PATHS")
	}
	interval := normalizeIntervalMinutes(req.IntervalMinutes)
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Normalize checks.
	checks := make([]PolicyReportPresetCheckSpec, 0, len(req.Checks))
	seen := map[string]bool{}
	for _, c := range req.Checks {
		cid := strings.TrimSpace(c.CheckID)
		if cid == "" {
			continue
		}
		if seen[cid] {
			return nil, fmt.Errorf("duplicate checkId: %s", cid)
		}
		seen[cid] = true
		checks = append(checks, PolicyReportPresetCheckSpec{CheckID: cid, Parameters: c.Parameters})
	}
	if kind == "CUSTOM" && len(checks) == 0 {
		return nil, fmt.Errorf("checks is required for kind=CUSTOM")
	}
	if kind == "PATHS" && len(checks) == 0 {
		return nil, fmt.Errorf("checks is required for kind=PATHS")
	}
	if kind == "PATHS" {
		if len(checks) != 1 {
			return nil, fmt.Errorf("kind=PATHS requires exactly one check")
		}
		if !strings.EqualFold(strings.TrimSpace(checks[0].CheckID), "paths-enforcement-bypass") {
			return nil, fmt.Errorf("kind=PATHS requires checkId=paths-enforcement-bypass")
		}
		if checks[0].Parameters == nil {
			return nil, fmt.Errorf("kind=PATHS requires parameters.queries")
		}
		qv, ok := checks[0].Parameters["queries"]
		if !ok {
			return nil, fmt.Errorf("kind=PATHS requires parameters.queries")
		}
		var qs []any
		if err := json.Unmarshal(qv, &qs); err != nil || len(qs) == 0 {
			return nil, fmt.Errorf("kind=PATHS requires parameters.queries as non-empty array")
		}
	}

	checksJSON, _ := json.Marshal(checks)
	queryOptionsJSON, _ := json.Marshal(req.QueryOptions)

	now := time.Now().UTC()
	var nextRunAt *time.Time
	if enabled {
		t := now.Add(1 * time.Minute) // run soon after creation
		nextRunAt = &t
	}
	id := uuid.New().String()

	out := &PolicyReportPreset{
		ID:               id,
		ForwardNetworkID: forwardNetworkID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Kind:             kind,
		PackID:           packID,
		TitleTemplate: func() string {
			// Default to the preset name so stored runs have a human-friendly title.
			if t := strings.TrimSpace(req.TitleTemplate); t != "" {
				return t
			}
			return name
		}(),
		SnapshotID:      strings.TrimSpace(req.SnapshotID),
		Checks:          checks,
		QueryOptions:    req.QueryOptions,
		MaxPerCheck:     req.MaxPerCheck,
		MaxTotal:        req.MaxTotal,
		Enabled:         enabled,
		IntervalMinutes: interval,
		NextRunAt:       nextRunAt,
		OwnerUsername:   actor,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	_, err := db.ExecContext(ctx, `
INSERT INTO sf_policy_report_presets(
  id, owner_username, forward_network_id, name, description, kind, pack_id, title_template, snapshot_id,
  checks, query_options, max_per_check, max_total, enabled, interval_minutes, next_run_at, owner_username, created_at, updated_at
)
VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
	`, out.ID, "", out.ForwardNetworkID, out.Name, out.Description, out.Kind, out.PackID, out.TitleTemplate, out.SnapshotID,
		string(checksJSON), string(queryOptionsJSON), out.MaxPerCheck, out.MaxTotal, out.Enabled, out.IntervalMinutes, out.NextRunAt, out.OwnerUsername, out.CreatedAt, out.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func updatePolicyReportPreset(ctx context.Context, db *sql.DB, ownerID, actor, presetID string, req *PolicyReportUpdatePresetRequest) (*PolicyReportPreset, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	actor = strings.ToLower(strings.TrimSpace(actor))
	presetID = strings.TrimSpace(presetID)
	if ownerID == "" || actor == "" || presetID == "" || req == nil {
		return nil, fmt.Errorf("invalid input")
	}
	forwardNetworkID := strings.TrimSpace(req.ForwardNetworkID)
	if forwardNetworkID == "" {
		return nil, fmt.Errorf("forwardNetworkId is required")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	kind := normalizePresetKind(req.Kind)
	if kind == "" {
		return nil, fmt.Errorf("invalid kind")
	}
	packID := strings.TrimSpace(req.PackID)
	if kind == "PACK" && packID == "" {
		return nil, fmt.Errorf("packId is required for kind=PACK")
	}
	if kind == "CUSTOM" && len(req.Checks) == 0 {
		return nil, fmt.Errorf("checks is required for kind=CUSTOM")
	}
	if kind == "PATHS" && len(req.Checks) == 0 {
		return nil, fmt.Errorf("checks is required for kind=PATHS")
	}
	if kind == "PATHS" && packID != "" {
		return nil, fmt.Errorf("packId must be empty for kind=PATHS")
	}
	interval := normalizeIntervalMinutes(req.IntervalMinutes)

	checks := make([]PolicyReportPresetCheckSpec, 0, len(req.Checks))
	seen := map[string]bool{}
	for _, c := range req.Checks {
		cid := strings.TrimSpace(c.CheckID)
		if cid == "" {
			continue
		}
		if seen[cid] {
			return nil, fmt.Errorf("duplicate checkId: %s", cid)
		}
		seen[cid] = true
		checks = append(checks, PolicyReportPresetCheckSpec{CheckID: cid, Parameters: c.Parameters})
	}
	if kind == "PATHS" {
		if len(checks) != 1 {
			return nil, fmt.Errorf("kind=PATHS requires exactly one check")
		}
		if !strings.EqualFold(strings.TrimSpace(checks[0].CheckID), "paths-enforcement-bypass") {
			return nil, fmt.Errorf("kind=PATHS requires checkId=paths-enforcement-bypass")
		}
		if checks[0].Parameters == nil {
			return nil, fmt.Errorf("kind=PATHS requires parameters.queries")
		}
		qv, ok := checks[0].Parameters["queries"]
		if !ok {
			return nil, fmt.Errorf("kind=PATHS requires parameters.queries")
		}
		var qs []any
		if err := json.Unmarshal(qv, &qs); err != nil || len(qs) == 0 {
			return nil, fmt.Errorf("kind=PATHS requires parameters.queries as non-empty array")
		}
	}

	checksJSON, _ := json.Marshal(checks)
	queryOptionsJSON, _ := json.Marshal(req.QueryOptions)

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	now := time.Now().UTC()

	// Preserve schedule timestamps unless enabling from disabled.
	var prevNext sql.NullTime
	var prevLastRun sql.NullString
	var prevLastAt sql.NullTime
	var prevLastErr sql.NullString
	err := db.QueryRowContext(ctx, `
SELECT next_run_at, COALESCE(last_run_id::text,''), last_run_at, COALESCE(last_error,'')
  FROM sf_policy_report_presets
 WHERE owner_username=$1 AND id=$2
`, ownerID, presetID).Scan(&prevNext, &prevLastRun, &prevLastAt, &prevLastErr)
	if err != nil {
		return nil, err
	}

	var nextRunAt *time.Time
	if enabled {
		if prevNext.Valid {
			t := prevNext.Time.UTC()
			nextRunAt = &t
		} else {
			t := now.Add(1 * time.Minute)
			nextRunAt = &t
		}
	}

	_, err = db.ExecContext(ctx, `
UPDATE sf_policy_report_presets
   SET forward_network_id=$1,
       name=$2,
       description=NULLIF($3,''),
       kind=$4,
       pack_id=$5,
       title_template=NULLIF($6,''),
       snapshot_id=$7,
       checks=$8,
       query_options=$9,
       max_per_check=$10,
       max_total=$11,
       enabled=$12,
       interval_minutes=$13,
       next_run_at=$14,
       updated_at=$15
 WHERE owner_username=$16 AND id=$17
`, forwardNetworkID, name, strings.TrimSpace(req.Description), kind, packID, func() string {
		if t := strings.TrimSpace(req.TitleTemplate); t != "" {
			return t
		}
		return name
	}(), strings.TrimSpace(req.SnapshotID),
		string(checksJSON), string(queryOptionsJSON), req.MaxPerCheck, req.MaxTotal, enabled, interval, nextRunAt, now, ownerID, presetID)
	if err != nil {
		return nil, err
	}

	var lastRunID string
	if prevLastRun.Valid {
		lastRunID = strings.TrimSpace(prevLastRun.String)
	}
	var lastRunAt *time.Time
	if prevLastAt.Valid {
		t := prevLastAt.Time.UTC()
		lastRunAt = &t
	}
	lastErr := ""
	if prevLastErr.Valid {
		lastErr = strings.TrimSpace(prevLastErr.String)
	}

	out := &PolicyReportPreset{
		ID:               presetID,
		ForwardNetworkID: forwardNetworkID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Kind:             kind,
		PackID:           packID,
		TitleTemplate: func() string {
			if t := strings.TrimSpace(req.TitleTemplate); t != "" {
				return t
			}
			return name
		}(),
		SnapshotID:      strings.TrimSpace(req.SnapshotID),
		Checks:          checks,
		QueryOptions:    req.QueryOptions,
		MaxPerCheck:     req.MaxPerCheck,
		MaxTotal:        req.MaxTotal,
		Enabled:         enabled,
		IntervalMinutes: interval,
		NextRunAt:       nextRunAt,
		LastRunID:       lastRunID,
		LastRunAt:       lastRunAt,
		LastError:       lastErr,
		OwnerUsername:   actor, // UI doesn't rely on this field for updates; keep actor for "last editor"
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	return out, nil
}

func deletePolicyReportPreset(ctx context.Context, db *sql.DB, ownerID, presetID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	presetID = strings.TrimSpace(presetID)
	if ownerID == "" || presetID == "" {
		return fmt.Errorf("invalid input")
	}
	res, err := db.ExecContext(ctx, `DELETE FROM sf_policy_report_presets WHERE owner_username=$1 AND id=$2`, ownerID, presetID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func listPolicyReportPresets(ctx context.Context, db *sql.DB, ownerID, forwardNetworkID string, enabled *bool, limit int) ([]PolicyReportPreset, error) {
	if db == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	ownerID = strings.TrimSpace(ownerID)
	forwardNetworkID = strings.TrimSpace(forwardNetworkID)
	if ownerID == "" {
		return nil, fmt.Errorf("invalid input")
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	query := `
SELECT id, owner_username, forward_network_id, name, COALESCE(description,''), kind, pack_id, COALESCE(title_template,''), snapshot_id,
       checks, query_options, max_per_check, max_total, enabled, interval_minutes,
       next_run_at, COALESCE(last_run_id::text,''), last_run_at, COALESCE(last_error,''), owner_username, created_at, updated_at
  FROM sf_policy_report_presets
 WHERE owner_username=$1`
	args := []any{ownerID}
	i := 2
	if forwardNetworkID != "" {
		query += fmt.Sprintf(" AND forward_network_id=$%d", i)
		args = append(args, forwardNetworkID)
		i++
	}
	if enabled != nil {
		query += fmt.Sprintf(" AND enabled=$%d", i)
		args = append(args, *enabled)
		i++
	}
	query += " ORDER BY updated_at DESC LIMIT $" + fmt.Sprintf("%d", i)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PolicyReportPreset
	for rows.Next() {
		var p PolicyReportPreset
		var desc, titleTmpl, lastRunID, lastErr string
		var checksJSON, queryOptionsJSON []byte
		var nextRun, lastRunAt sql.NullTime
		if err := rows.Scan(
			&p.ID, &p.OwnerUsername, &p.ForwardNetworkID, &p.Name, &desc, &p.Kind, &p.PackID, &titleTmpl, &p.SnapshotID,
			&checksJSON, &queryOptionsJSON, &p.MaxPerCheck, &p.MaxTotal, &p.Enabled, &p.IntervalMinutes,
			&nextRun, &lastRunID, &lastRunAt, &lastErr, &p.OwnerUsername, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, err
		}
		p.Description = strings.TrimSpace(desc)
		p.TitleTemplate = strings.TrimSpace(titleTmpl)
		p.LastRunID = strings.TrimSpace(lastRunID)
		p.LastError = strings.TrimSpace(lastErr)
		if nextRun.Valid {
			t := nextRun.Time.UTC()
			p.NextRunAt = &t
		}
		if lastRunAt.Valid {
			t := lastRunAt.Time.UTC()
			p.LastRunAt = &t
		}
		_ = json.Unmarshal(checksJSON, &p.Checks)
		_ = json.Unmarshal(queryOptionsJSON, &p.QueryOptions)
		out = append(out, p)
	}
	return out, nil
}
