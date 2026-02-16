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

func loadGovernanceSummary(ctx context.Context, db *sql.DB) (*GovernanceSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var resourceCount int
	var activeCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_resources`).Scan(&resourceCount); err != nil {
		if isMissingDBRelation(err) || isMissingDBColumn(err, "") {
			return &GovernanceSummary{
				ResourceCount:     0,
				ActiveResources:   0,
				UsersTracked:      0,
				CostLast30Days:    0,
				CostCurrency:      "USD",
				LastCostPeriodEnd: "",
				ProviderBreakdown: nil,
			}, nil
		}
		return nil, err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_resources WHERE status ILIKE 'active' OR status ILIKE 'running'`).Scan(&activeCount); err != nil {
		activeCount = 0
	}

	var scopeCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT owner_username) FROM sf_resources WHERE owner_username IS NOT NULL`).Scan(&scopeCount); err != nil {
		scopeCount = 0
	}

	var totalCost float64
	var lastPeriodEnd sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(cost_amount), 0)::double precision, MAX(period_end)::text FROM sf_cost_snapshots WHERE period_end >= CURRENT_DATE - INTERVAL '30 days'`).Scan(&totalCost, &lastPeriodEnd); err != nil {
		totalCost = 0
	}

	rows, err := db.QueryContext(ctx, `
SELECT provider,
       COUNT(*) AS resource_count,
       COALESCE(SUM(cost_amount), 0)::double precision AS cost_total,
       COALESCE(MAX(cost_currency), 'USD') AS currency
  FROM sf_resources r
  LEFT JOIN sf_cost_snapshots c ON c.resource_id = r.id
 GROUP BY provider
 ORDER BY provider ASC`)
	if err != nil {
		if isMissingDBRelation(err) || isMissingDBColumn(err, "") {
			return &GovernanceSummary{
				ResourceCount:     resourceCount,
				ActiveResources:   activeCount,
				UsersTracked:      scopeCount,
				CostLast30Days:    totalCost,
				CostCurrency:      "USD",
				LastCostPeriodEnd: "",
				ProviderBreakdown: nil,
			}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var breakdown []ProviderCostBreakdown
	for rows.Next() {
		var entry ProviderCostBreakdown
		if err := rows.Scan(&entry.Provider, &entry.ResourceCount, &entry.Cost, &entry.Currency); err != nil {
			return nil, err
		}
		breakdown = append(breakdown, entry)
	}

	period := ""
	if lastPeriodEnd.Valid {
		period = lastPeriodEnd.String
	}
	currency := "USD"
	if len(breakdown) > 0 && breakdown[0].Currency != "" {
		currency = breakdown[0].Currency
	}

	return &GovernanceSummary{
		ResourceCount:     resourceCount,
		ActiveResources:   activeCount,
		UsersTracked:      scopeCount,
		CostLast30Days:    totalCost,
		CostCurrency:      currency,
		LastCostPeriodEnd: period,
		ProviderBreakdown: breakdown,
	}, nil
}

func listGovernanceResources(ctx context.Context, db *sql.DB, params *GovernanceResourceQuery) ([]GovernanceResource, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	limit := params.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	query := `
SELECT r.id, r.owner_username, p.name, r.provider, r.resource_id, r.resource_type, r.name, r.region,
       r.account_id, r.owner_username, r.status, r.tags, r.metadata, r.first_seen, r.last_seen, r.updated_at
  FROM sf_resources r
  LEFT JOIN sf_owner_contexts p ON p.id = r.owner_username
 WHERE 1=1`

	var args []any
	argIndex := 1

	addFilter := func(condition string, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		query += fmt.Sprintf(" AND %s = $%d", condition, argIndex)
		args = append(args, strings.TrimSpace(value))
		argIndex++
	}

	addFilter("r.owner_username", params.OwnerUsername)
	addFilter("r.provider", params.Provider)
	addFilter("r.status", params.Status)
	addFilter("r.owner_username", strings.ToLower(strings.TrimSpace(params.Owner)))
	addFilter("r.resource_type", params.Type)

	if q := strings.TrimSpace(params.Query); q != "" {
		query += fmt.Sprintf(" AND (r.name ILIKE $%d OR r.resource_id ILIKE $%d)", argIndex, argIndex)
		args = append(args, "%"+q+"%")
		argIndex++
	}

	query += " ORDER BY r.last_seen DESC LIMIT $%d"
	query = fmt.Sprintf(query, argIndex)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMissingDBRelation(err) || isMissingDBColumn(err, "") {
			return []GovernanceResource{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var resources []GovernanceResource
	for rows.Next() {
		var record GovernanceResource
		var tags, metadata []byte
		if err := rows.Scan(
			&record.ID,
			&record.OwnerUsername,
			&record.UserName,
			&record.Provider,
			&record.ResourceID,
			&record.ResourceType,
			&record.Name,
			&record.Region,
			&record.AccountID,
			&record.Owner,
			&record.Status,
			&tags,
			&metadata,
			&record.FirstSeen,
			&record.LastSeen,
			&record.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(tags) > 0 {
			record.Tags = tags
		}
		if len(metadata) > 0 {
			record.Metadata = metadata
		}
		resources = append(resources, record)
	}
	return resources, nil
}

func listGovernanceCosts(ctx context.Context, db *sql.DB, params *GovernanceCostQuery) ([]GovernanceCostSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	limit := params.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
SELECT c.id, c.owner_username, p.name, c.resource_id, c.provider, c.period_start, c.period_end,
       c.cost_amount::double precision, c.cost_currency, c.source, c.metadata, c.created_at
  FROM sf_cost_snapshots c
  LEFT JOIN sf_owner_contexts p ON p.id = c.owner_username
 WHERE 1=1`
	var args []any
	argIndex := 1
	if strings.TrimSpace(params.OwnerUsername) != "" {
		query += fmt.Sprintf(" AND c.owner_username = $%d", argIndex)
		args = append(args, strings.TrimSpace(params.OwnerUsername))
		argIndex++
	}
	if strings.TrimSpace(params.Provider) != "" {
		query += fmt.Sprintf(" AND c.provider = $%d", argIndex)
		args = append(args, strings.TrimSpace(params.Provider))
		argIndex++
	}
	query += fmt.Sprintf(" ORDER BY c.period_end DESC LIMIT $%d", argIndex)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMissingDBRelation(err) || isMissingDBColumn(err, "") {
			return []GovernanceCostSnapshot{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var costs []GovernanceCostSnapshot
	for rows.Next() {
		var record GovernanceCostSnapshot
		var resourceID sql.NullString
		var ownerID sql.NullString
		var scopeName sql.NullString
		var metadata []byte
		var periodStart time.Time
		var periodEnd time.Time
		if err := rows.Scan(
			&record.ID,
			&ownerID,
			&scopeName,
			&resourceID,
			&record.Provider,
			&periodStart,
			&periodEnd,
			&record.Amount,
			&record.Currency,
			&record.Source,
			&metadata,
			&record.CreatedAt,
		); err != nil {
			return nil, err
		}
		if ownerID.Valid {
			record.OwnerUsername = ownerID.String
		}
		if scopeName.Valid {
			record.UserName = scopeName.String
		}
		if resourceID.Valid {
			record.ResourceID = resourceID.String
		}
		record.PeriodStart = periodStart.Format("2006-01-02")
		record.PeriodEnd = periodEnd.Format("2006-01-02")
		if len(metadata) > 0 {
			record.Metadata = metadata
		}
		costs = append(costs, record)
	}
	return costs, nil
}

func listGovernanceUsage(ctx context.Context, db *sql.DB, params *GovernanceUsageQuery) ([]GovernanceUsageSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	limit := params.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
SELECT u.id, u.owner_context_id, p.name, u.provider, u.owner_type, u.owner_username, u.metric,
       u.value::double precision, u.unit, u.metadata, u.collected_at
  FROM sf_usage_snapshots u
  LEFT JOIN sf_owner_contexts p ON p.id = u.owner_context_id
 WHERE 1=1`
	var args []any
	argIndex := 1
	if strings.TrimSpace(params.OwnerUsername) != "" {
		query += fmt.Sprintf(" AND u.owner_context_id = $%d", argIndex)
		args = append(args, strings.TrimSpace(params.OwnerUsername))
		argIndex++
	}
	if strings.TrimSpace(params.Provider) != "" {
		query += fmt.Sprintf(" AND u.provider = $%d", argIndex)
		args = append(args, strings.TrimSpace(params.Provider))
		argIndex++
	}
	if strings.TrimSpace(params.Metric) != "" {
		query += fmt.Sprintf(" AND u.metric = $%d", argIndex)
		args = append(args, strings.TrimSpace(params.Metric))
		argIndex++
	}
	query += fmt.Sprintf(" ORDER BY u.collected_at DESC LIMIT $%d", argIndex)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isMissingDBRelation(err) || isMissingDBColumn(err, "") {
			return []GovernanceUsageSnapshot{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	var usage []GovernanceUsageSnapshot
	for rows.Next() {
		var record GovernanceUsageSnapshot
		var scopeOwnerID sql.NullString
		var scopeName sql.NullString
		var ownerID sql.NullString
		var unit sql.NullString
		var metadata []byte
		if err := rows.Scan(
			&record.ID,
			&scopeOwnerID,
			&scopeName,
			&record.Provider,
			&record.UserType,
			&ownerID,
			&record.Metric,
			&record.Value,
			&unit,
			&metadata,
			&record.Collected,
		); err != nil {
			return nil, err
		}
		if scopeOwnerID.Valid {
			record.UserOwnerID = scopeOwnerID.String
		}
		if ownerID.Valid {
			record.OwnerUsername = ownerID.String
		}
		if scopeName.Valid {
			record.UserName = scopeName.String
		}
		if unit.Valid {
			record.Unit = unit.String
		}
		if len(metadata) > 0 {
			record.Metadata = metadata
		}
		usage = append(usage, record)
	}
	return usage, nil
}

func upsertGovernanceResource(ctx context.Context, db *sql.DB, input GovernanceResourceInput, observedAt time.Time, user *AuthUser) (GovernanceResource, error) {
	now := time.Now()
	if observedAt.IsZero() {
		observedAt = now
	}
	provider := strings.ToLower(strings.TrimSpace(input.Provider))
	resourceID := strings.TrimSpace(input.ResourceID)
	resourceType := strings.TrimSpace(input.ResourceType)
	if provider == "" || resourceID == "" || resourceType == "" {
		return GovernanceResource{}, fmt.Errorf("missing required resource fields")
	}
	resourceUUID := uuid.New()

	tagsJSON, _ := json.Marshal(input.Tags)
	metadataJSON, _ := json.Marshal(input.Metadata)
	ownerID := strings.TrimSpace(input.OwnerUsername)
	owner := strings.ToLower(strings.TrimSpace(input.Owner))
	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = "unknown"
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	row := db.QueryRowContext(ctx, `
INSERT INTO sf_resources (
  id, provider, resource_id, resource_type, owner_username, name, region, account_id,
  owner_username, status, tags, metadata, first_seen, last_seen, updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),
          NULLIF($9,''),$10,$11,$12,$13,$14,$15)
ON CONFLICT (provider, resource_id)
DO UPDATE SET
  resource_type=EXCLUDED.resource_type,
  owner_username=COALESCE(EXCLUDED.owner_username, sf_resources.owner_username),
  name=COALESCE(EXCLUDED.name, sf_resources.name),
  region=COALESCE(EXCLUDED.region, sf_resources.region),
  account_id=COALESCE(EXCLUDED.account_id, sf_resources.account_id),
  owner_username=COALESCE(EXCLUDED.owner_username, sf_resources.owner_username),
  status=EXCLUDED.status,
  tags=COALESCE(EXCLUDED.tags, sf_resources.tags),
  metadata=COALESCE(EXCLUDED.metadata, sf_resources.metadata),
  last_seen=EXCLUDED.last_seen,
  updated_at=EXCLUDED.updated_at
RETURNING id, owner_username, name, region, account_id, owner_username, status, tags, metadata, first_seen, last_seen, updated_at`,
		resourceUUID,
		provider,
		resourceID,
		resourceType,
		ownerID,
		strings.TrimSpace(input.Name),
		strings.TrimSpace(input.Region),
		strings.TrimSpace(input.AccountID),
		owner,
		status,
		string(tagsJSON),
		string(metadataJSON),
		observedAt,
		observedAt,
		now,
	)

	var record GovernanceResource
	record.Provider = provider
	record.ResourceID = resourceID
	record.ResourceType = resourceType
	record.AccountID = strings.TrimSpace(input.AccountID)
	record.OwnerUsername = ownerID
	record.Name = strings.TrimSpace(input.Name)
	record.Region = strings.TrimSpace(input.Region)
	record.Owner = owner
	record.Status = status
	record.Tags = tagsJSON
	record.Metadata = metadataJSON

	var tagsOut, metaOut []byte
	if err := row.Scan(
		&record.ID,
		&record.OwnerUsername,
		&record.Name,
		&record.Region,
		&record.AccountID,
		&record.Owner,
		&record.Status,
		&tagsOut,
		&metaOut,
		&record.FirstSeen,
		&record.LastSeen,
		&record.UpdatedAt,
	); err != nil {
		return GovernanceResource{}, err
	}
	if len(tagsOut) > 0 {
		record.Tags = tagsOut
	}
	if len(metaOut) > 0 {
		record.Metadata = metaOut
	}

	eventType := strings.TrimSpace(input.EventType)
	if eventType == "" {
		eventType = "observed"
	}
	_ = insertGovernanceResourceEvent(ctx, db, record.ID, record.OwnerUsername, eventType, input.Metadata, user)

	return record, nil
}

func insertGovernanceResourceEvent(ctx context.Context, db *sql.DB, resourceID string, ownerID string, eventType string, metadata map[string]string, user *AuthUser) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	eventID := uuid.New().String()
	detailsJSON, _ := json.Marshal(metadata)
	actor := ""
	actorIsAdmin := false
	impersonated := ""
	if user != nil {
		actor = user.Username
		actorIsAdmin = user.IsAdmin
	}
	writeAuditEvent(ctx, db, actor, actorIsAdmin, impersonated, "governance.resource."+eventType, ownerID, string(detailsJSON))
	_, err := db.ExecContext(ctx, `
INSERT INTO sf_resource_events (
  id, resource_id, event_type, actor_username, actor_is_admin, impersonated_username, owner_username, details
) VALUES ($1,$2,$3,NULLIF($4,''),$5,NULLIF($6,''),NULLIF($7,''),$8)`,
		eventID, resourceID, eventType, actor, actorIsAdmin, impersonated, ownerID, string(detailsJSON),
	)
	return err
}

func insertGovernanceCost(ctx context.Context, db *sql.DB, input GovernanceCostInput) (GovernanceCostSnapshot, error) {
	provider := strings.ToLower(strings.TrimSpace(input.Provider))
	if provider == "" || strings.TrimSpace(input.PeriodStart) == "" || strings.TrimSpace(input.PeriodEnd) == "" {
		return GovernanceCostSnapshot{}, fmt.Errorf("missing cost fields")
	}
	periodStart, err := time.Parse("2006-01-02", input.PeriodStart)
	if err != nil {
		return GovernanceCostSnapshot{}, fmt.Errorf("invalid period_start")
	}
	periodEnd, err := time.Parse("2006-01-02", input.PeriodEnd)
	if err != nil {
		return GovernanceCostSnapshot{}, fmt.Errorf("invalid period_end")
	}
	currency := strings.TrimSpace(input.Currency)
	if currency == "" {
		currency = "USD"
	}
	metadataJSON, _ := json.Marshal(input.Metadata)
	ownerID := strings.TrimSpace(input.OwnerUsername)
	resourceID := strings.TrimSpace(input.ResourceID)
	if resourceID != "" {
		if _, err := uuid.Parse(resourceID); err != nil {
			resourceID = ""
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	id := uuid.New().String()
	var record GovernanceCostSnapshot
	record.ID = id
	record.OwnerUsername = ownerID
	record.ResourceID = resourceID
	record.Provider = provider
	record.PeriodStart = periodStart.Format("2006-01-02")
	record.PeriodEnd = periodEnd.Format("2006-01-02")
	record.Amount = input.Amount
	record.Currency = currency
	record.Source = strings.TrimSpace(input.Source)
	record.Metadata = metadataJSON
	record.CreatedAt = time.Now()

	_, err = db.ExecContext(ctx, `
INSERT INTO sf_cost_snapshots (
  id, resource_id, owner_username, provider, period_start, period_end,
  cost_amount, cost_currency, source, metadata
) VALUES ($1,NULLIF($2,''),NULLIF($3,''),$4,$5,$6,$7,$8,NULLIF($9,''),$10)`,
		id, resourceID, ownerID, provider, periodStart, periodEnd, input.Amount, currency, record.Source, string(metadataJSON),
	)
	return record, err
}

func insertGovernanceUsage(ctx context.Context, db *sql.DB, input GovernanceUsageInput) (GovernanceUsageSnapshot, error) {
	provider := strings.ToLower(strings.TrimSpace(input.Provider))
	if provider == "" || strings.TrimSpace(input.UserType) == "" || strings.TrimSpace(input.Metric) == "" {
		return GovernanceUsageSnapshot{}, fmt.Errorf("missing usage fields")
	}
	metadataJSON, _ := json.Marshal(input.Metadata)
	scopeOwnerID := strings.TrimSpace(input.OwnerContextID)
	ownerID := strings.TrimSpace(input.OwnerUsername)
	if scopeOwnerID == "" {
		scopeOwnerID = ownerID
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	id := uuid.New().String()
	var record GovernanceUsageSnapshot
	record.ID = id
	record.UserOwnerID = scopeOwnerID
	record.Provider = provider
	record.UserType = strings.TrimSpace(input.UserType)
	record.OwnerUsername = ownerID
	record.Metric = strings.TrimSpace(input.Metric)
	record.Value = input.Value
	record.Unit = strings.TrimSpace(input.Unit)
	record.Metadata = metadataJSON
	record.Collected = time.Now()

	_, err := db.ExecContext(ctx, `
INSERT INTO sf_usage_snapshots (
  id, owner_context_id, provider, owner_type, owner_username, metric, value, unit, metadata
) VALUES ($1,NULLIF($2,''),$3,$4,NULLIF($5,''),$6,$7,NULLIF($8,''),$9)`,
		id, scopeOwnerID, provider, record.UserType, ownerID, record.Metric, input.Value, record.Unit, string(metadataJSON),
	)
	return record, err
}
