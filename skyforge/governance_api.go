package skyforge

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type GovernanceSummary struct {
	ResourceCount       int                     `json:"resourceCount"`
	ActiveResources     int                     `json:"activeResources"`
	UserContextsTracked int                     `json:"userContextsTracked"`
	CostLast30Days      float64                 `json:"costLast30Days"`
	CostCurrency        string                  `json:"costCurrency"`
	LastCostPeriodEnd   string                  `json:"lastCostPeriodEnd,omitempty"`
	ProviderBreakdown   []ProviderCostBreakdown `json:"providerBreakdown"`
}

type ProviderCostBreakdown struct {
	Provider      string  `json:"provider"`
	ResourceCount int     `json:"resourceCount"`
	Cost          float64 `json:"cost"`
	Currency      string  `json:"currency"`
}

type GovernanceResource struct {
	ID            string          `json:"id"`
	UserContextID string          `json:"userContextId,omitempty"`
	WorkspaceName string          `json:"userContextName,omitempty"`
	Provider      string          `json:"provider"`
	ResourceID    string          `json:"resourceId"`
	ResourceType  string          `json:"resourceType"`
	Name          string          `json:"name,omitempty"`
	Region        string          `json:"region,omitempty"`
	AccountID     string          `json:"accountId,omitempty"`
	Owner         string          `json:"owner,omitempty"`
	Status        string          `json:"status,omitempty"`
	Tags          json.RawMessage `json:"tags,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	FirstSeen     time.Time       `json:"firstSeen"`
	LastSeen      time.Time       `json:"lastSeen"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

type GovernanceCostSnapshot struct {
	ID            string          `json:"id"`
	UserContextID string          `json:"userContextId,omitempty"`
	WorkspaceName string          `json:"userContextName,omitempty"`
	ResourceID    string          `json:"resourceId,omitempty"`
	Provider      string          `json:"provider"`
	PeriodStart   string          `json:"periodStart"`
	PeriodEnd     string          `json:"periodEnd"`
	Amount        float64         `json:"amount"`
	Currency      string          `json:"currency"`
	Source        string          `json:"source,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
}

type GovernanceUsageSnapshot struct {
	ID            string          `json:"id"`
	UserContextID string          `json:"userContextId,omitempty"`
	WorkspaceName string          `json:"userContextName,omitempty"`
	Provider      string          `json:"provider"`
	ScopeType     string          `json:"subjectType"`
	ScopeID       string          `json:"subjectId,omitempty"`
	Metric        string          `json:"metric"`
	Value         float64         `json:"value"`
	Unit          string          `json:"unit,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	Collected     time.Time       `json:"collectedAt"`
}

type GovernanceResourceIngestRequest struct {
	Source     string                    `json:"source,omitempty"`
	ObservedAt string                    `json:"observedAt,omitempty"`
	Resources  []GovernanceResourceInput `json:"resources"`
}

type GovernanceResourceInput struct {
	UserContextID string            `json:"userContextId,omitempty"`
	Provider      string            `json:"provider"`
	ResourceID    string            `json:"resourceId"`
	ResourceType  string            `json:"resourceType"`
	Name          string            `json:"name,omitempty"`
	Region        string            `json:"region,omitempty"`
	AccountID     string            `json:"accountId,omitempty"`
	Owner         string            `json:"owner,omitempty"`
	Status        string            `json:"status,omitempty"`
	EventType     string            `json:"eventType,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type GovernanceCostIngestRequest struct {
	Snapshots []GovernanceCostInput `json:"snapshots"`
}

type GovernanceCostInput struct {
	UserContextID string            `json:"userContextId,omitempty"`
	ResourceID    string            `json:"resourceId,omitempty"`
	Provider      string            `json:"provider"`
	PeriodStart   string            `json:"periodStart"`
	PeriodEnd     string            `json:"periodEnd"`
	Amount        float64           `json:"amount"`
	Currency      string            `json:"currency,omitempty"`
	Source        string            `json:"source,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type GovernanceUsageIngestRequest struct {
	Snapshots []GovernanceUsageInput `json:"snapshots"`
}

type GovernanceUsageInput struct {
	UserContextID string            `json:"userContextId,omitempty"`
	Provider      string            `json:"provider"`
	ScopeType     string            `json:"subjectType"`
	ScopeID       string            `json:"subjectId,omitempty"`
	Metric        string            `json:"metric"`
	Value         float64           `json:"value"`
	Unit          string            `json:"unit,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type GovernanceResourceQuery struct {
	UserContextID string `query:"user_context_id" encore:"optional"`
	Provider      string `query:"provider" encore:"optional"`
	Status        string `query:"status" encore:"optional"`
	Owner         string `query:"owner" encore:"optional"`
	Type          string `query:"type" encore:"optional"`
	Query         string `query:"q" encore:"optional"`
	Limit         int    `query:"limit" encore:"optional"`
}

type GovernanceCostQuery struct {
	UserContextID string `query:"user_context_id" encore:"optional"`
	Provider      string `query:"provider" encore:"optional"`
	Limit         int    `query:"limit" encore:"optional"`
}

type GovernanceUsageQuery struct {
	UserContextID string `query:"user_context_id" encore:"optional"`
	Provider      string `query:"provider" encore:"optional"`
	Metric        string `query:"metric" encore:"optional"`
	Limit         int    `query:"limit" encore:"optional"`
}

type GovernanceResourcesResponse struct {
	Resources []GovernanceResource `json:"resources"`
}

type GovernanceCostResponse struct {
	Costs []GovernanceCostSnapshot `json:"costs"`
}

type GovernanceUsageResponse struct {
	Usage []GovernanceUsageSnapshot `json:"usage"`
}

type GovernanceSyncResponse struct {
	ResourceCount int      `json:"resourceCount"`
	UsageCount    int      `json:"usageCount"`
	Warnings      []string `json:"warnings,omitempty"`
}

func requireAdmin() (*AuthUser, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("admin access required").Err()
	}
	return user, nil
}

// GetGovernanceSummary returns governance summary metrics (admin only).
//
//encore:api auth method=GET path=/api/admin/governance/summary tag:admin
func (s *Service) GetGovernanceSummary(ctx context.Context) (*GovernanceSummary, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	summary, err := loadGovernanceSummary(ctx, s.db)
	if err != nil {
		rlog.Warn("governance summary load failed", "error", err)
		// Governance is optional; return an empty snapshot instead of hard-failing the UI.
		return &GovernanceSummary{
			ResourceCount:       0,
			ActiveResources:     0,
			UserContextsTracked: 0,
			CostLast30Days:      0,
			CostCurrency:        "USD",
			LastCostPeriodEnd:   "",
			ProviderBreakdown:   nil,
		}, nil
	}
	return summary, nil
}

// ListGovernanceResources lists tracked resources (admin only).
//
//encore:api auth method=GET path=/api/admin/governance/resources tag:admin
func (s *Service) ListGovernanceResources(ctx context.Context, params *GovernanceResourceQuery) (*GovernanceResourcesResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if params == nil {
		params = &GovernanceResourceQuery{}
	}
	resources, err := listGovernanceResources(ctx, s.db, params)
	if err != nil {
		rlog.Warn("governance resources load failed", "error", err)
		return &GovernanceResourcesResponse{Resources: []GovernanceResource{}}, nil
	}
	return &GovernanceResourcesResponse{Resources: resources}, nil
}

// ListGovernanceCosts lists cost snapshots (admin only).
//
//encore:api auth method=GET path=/api/admin/governance/costs tag:admin
func (s *Service) ListGovernanceCosts(ctx context.Context, params *GovernanceCostQuery) (*GovernanceCostResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if params == nil {
		params = &GovernanceCostQuery{}
	}
	costs, err := listGovernanceCosts(ctx, s.db, params)
	if err != nil {
		rlog.Warn("governance costs load failed", "error", err)
		return &GovernanceCostResponse{Costs: []GovernanceCostSnapshot{}}, nil
	}
	return &GovernanceCostResponse{Costs: costs}, nil
}

// ListGovernanceUsage lists usage snapshots (admin only).
//
//encore:api auth method=GET path=/api/admin/governance/usage tag:admin
func (s *Service) ListGovernanceUsage(ctx context.Context, params *GovernanceUsageQuery) (*GovernanceUsageResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	if _, err := requireAdmin(); err != nil {
		return nil, err
	}
	if params == nil {
		params = &GovernanceUsageQuery{}
	}
	usage, err := listGovernanceUsage(ctx, s.db, params)
	if err != nil {
		rlog.Warn("governance usage load failed", "error", err)
		return &GovernanceUsageResponse{Usage: []GovernanceUsageSnapshot{}}, nil
	}
	return &GovernanceUsageResponse{Usage: usage}, nil
}

// IngestGovernanceResources ingests resource inventory (admin only).
//
//encore:api auth method=POST path=/api/admin/governance/resources/ingest tag:admin
func (s *Service) IngestGovernanceResources(ctx context.Context, params *GovernanceResourceIngestRequest) (*GovernanceResourcesResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	user, err := requireAdmin()
	if err != nil {
		return nil, err
	}
	if params == nil || len(params.Resources) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("no resources provided").Err()
	}

	var observedAt time.Time
	if strings.TrimSpace(params.ObservedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, params.ObservedAt)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid observedAt timestamp").Err()
		}
		observedAt = parsed
	}

	resources := make([]GovernanceResource, 0, len(params.Resources))
	for _, input := range params.Resources {
		record, err := upsertGovernanceResource(ctx, s.db, input, observedAt, user)
		if err != nil {
			rlog.Warn("governance resource ingest failed", "resource", input.ResourceID, "error", err)
			continue
		}
		resources = append(resources, record)
	}

	details, _ := json.Marshal(map[string]any{
		"source":  strings.TrimSpace(params.Source),
		"count":   len(resources),
		"attempt": len(params.Resources),
	})
	writeAuditEvent(ctx, s.db, user.Username, user.IsAdmin, "", "governance.resources.ingest", "", string(details))

	return &GovernanceResourcesResponse{Resources: resources}, nil
}

// IngestGovernanceCosts ingests cost snapshots (admin only).
//
//encore:api auth method=POST path=/api/admin/governance/costs/ingest tag:admin
func (s *Service) IngestGovernanceCosts(ctx context.Context, params *GovernanceCostIngestRequest) (*GovernanceCostResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	user, err := requireAdmin()
	if err != nil {
		return nil, err
	}
	if params == nil || len(params.Snapshots) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("no cost snapshots provided").Err()
	}
	costs := make([]GovernanceCostSnapshot, 0, len(params.Snapshots))
	for _, input := range params.Snapshots {
		record, err := insertGovernanceCost(ctx, s.db, input)
		if err != nil {
			rlog.Warn("governance cost ingest failed", "provider", input.Provider, "error", err)
			continue
		}
		costs = append(costs, record)
	}
	details, _ := json.Marshal(map[string]any{
		"count": len(costs),
	})
	writeAuditEvent(ctx, s.db, user.Username, user.IsAdmin, "", "governance.costs.ingest", "", string(details))
	return &GovernanceCostResponse{Costs: costs}, nil
}

// IngestGovernanceUsage ingests usage snapshots (admin only).
//
//encore:api auth method=POST path=/api/admin/governance/usage/ingest tag:admin
func (s *Service) IngestGovernanceUsage(ctx context.Context, params *GovernanceUsageIngestRequest) (*GovernanceUsageResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	user, err := requireAdmin()
	if err != nil {
		return nil, err
	}
	if params == nil || len(params.Snapshots) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("no usage snapshots provided").Err()
	}
	usage := make([]GovernanceUsageSnapshot, 0, len(params.Snapshots))
	for _, input := range params.Snapshots {
		record, err := insertGovernanceUsage(ctx, s.db, input)
		if err != nil {
			rlog.Warn("governance usage ingest failed", "metric", input.Metric, "error", err)
			continue
		}
		usage = append(usage, record)
	}
	details, _ := json.Marshal(map[string]any{
		"count": len(usage),
	})
	writeAuditEvent(ctx, s.db, user.Username, user.IsAdmin, "", "governance.usage.ingest", "", string(details))
	return &GovernanceUsageResponse{Usage: usage}, nil
}

// SyncGovernanceSources refreshes inventory from known sources (admin only).
//
//encore:api auth method=POST path=/api/admin/governance/sync tag:admin
func (s *Service) SyncGovernanceSources(ctx context.Context) (*GovernanceSyncResponse, error) {
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("governance store unavailable").Err()
	}
	user, err := requireAdmin()
	if err != nil {
		return nil, err
	}

	resp := &GovernanceSyncResponse{}
	// EVE health/stats removed; governance sync no longer ingests EVE server resources.

	details, _ := json.Marshal(map[string]any{
		"resources": resp.ResourceCount,
		"usage":     resp.UsageCount,
		"warnings":  resp.Warnings,
	})
	writeAuditEvent(ctx, s.db, user.Username, user.IsAdmin, "", "governance.sync", "", string(details))
	return resp, nil
}
