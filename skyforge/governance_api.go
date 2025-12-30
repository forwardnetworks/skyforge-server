package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

type GovernanceSummary struct {
	ResourceCount     int                     `json:"resourceCount"`
	ActiveResources   int                     `json:"activeResources"`
	ProjectsTracked   int                     `json:"projectsTracked"`
	CostLast30Days    float64                 `json:"costLast30Days"`
	CostCurrency      string                  `json:"costCurrency"`
	LastCostPeriodEnd string                  `json:"lastCostPeriodEnd,omitempty"`
	ProviderBreakdown []ProviderCostBreakdown `json:"providerBreakdown"`
}

type ProviderCostBreakdown struct {
	Provider      string  `json:"provider"`
	ResourceCount int     `json:"resourceCount"`
	Cost          float64 `json:"cost"`
	Currency      string  `json:"currency"`
}

type GovernanceResource struct {
	ID           string          `json:"id"`
	ProjectID    string          `json:"projectId,omitempty"`
	ProjectName  string          `json:"projectName,omitempty"`
	Provider     string          `json:"provider"`
	ResourceID   string          `json:"resourceId"`
	ResourceType string          `json:"resourceType"`
	Name         string          `json:"name,omitempty"`
	Region       string          `json:"region,omitempty"`
	AccountID    string          `json:"accountId,omitempty"`
	Owner        string          `json:"owner,omitempty"`
	Status       string          `json:"status,omitempty"`
	Tags         json.RawMessage `json:"tags,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	FirstSeen    time.Time       `json:"firstSeen"`
	LastSeen     time.Time       `json:"lastSeen"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}

type GovernanceCostSnapshot struct {
	ID          string          `json:"id"`
	ProjectID   string          `json:"projectId,omitempty"`
	ProjectName string          `json:"projectName,omitempty"`
	ResourceID  string          `json:"resourceId,omitempty"`
	Provider    string          `json:"provider"`
	PeriodStart string          `json:"periodStart"`
	PeriodEnd   string          `json:"periodEnd"`
	Amount      float64         `json:"amount"`
	Currency    string          `json:"currency"`
	Source      string          `json:"source,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"createdAt"`
}

type GovernanceUsageSnapshot struct {
	ID          string          `json:"id"`
	ProjectID   string          `json:"projectId,omitempty"`
	ProjectName string          `json:"projectName,omitempty"`
	Provider    string          `json:"provider"`
	ScopeType   string          `json:"scopeType"`
	ScopeID     string          `json:"scopeId,omitempty"`
	Metric      string          `json:"metric"`
	Value       float64         `json:"value"`
	Unit        string          `json:"unit,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	Collected   time.Time       `json:"collectedAt"`
}

type GovernanceResourceIngestRequest struct {
	Source     string                    `json:"source,omitempty"`
	ObservedAt string                    `json:"observedAt,omitempty"`
	Resources  []GovernanceResourceInput `json:"resources"`
}

type GovernanceResourceInput struct {
	ProjectID    string            `json:"projectId,omitempty"`
	Provider     string            `json:"provider"`
	ResourceID   string            `json:"resourceId"`
	ResourceType string            `json:"resourceType"`
	Name         string            `json:"name,omitempty"`
	Region       string            `json:"region,omitempty"`
	AccountID    string            `json:"accountId,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Status       string            `json:"status,omitempty"`
	EventType    string            `json:"eventType,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type GovernanceCostIngestRequest struct {
	Snapshots []GovernanceCostInput `json:"snapshots"`
}

type GovernanceCostInput struct {
	ProjectID   string            `json:"projectId,omitempty"`
	ResourceID  string            `json:"resourceId,omitempty"`
	Provider    string            `json:"provider"`
	PeriodStart string            `json:"periodStart"`
	PeriodEnd   string            `json:"periodEnd"`
	Amount      float64           `json:"amount"`
	Currency    string            `json:"currency,omitempty"`
	Source      string            `json:"source,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type GovernanceUsageIngestRequest struct {
	Snapshots []GovernanceUsageInput `json:"snapshots"`
}

type GovernanceUsageInput struct {
	ProjectID string            `json:"projectId,omitempty"`
	Provider  string            `json:"provider"`
	ScopeType string            `json:"scopeType"`
	ScopeID   string            `json:"scopeId,omitempty"`
	Metric    string            `json:"metric"`
	Value     float64           `json:"value"`
	Unit      string            `json:"unit,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type GovernanceResourceQuery struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Provider  string `query:"provider" encore:"optional"`
	Status    string `query:"status" encore:"optional"`
	Owner     string `query:"owner" encore:"optional"`
	Type      string `query:"type" encore:"optional"`
	Query     string `query:"q" encore:"optional"`
	Limit     int    `query:"limit" encore:"optional"`
}

type GovernanceCostQuery struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Provider  string `query:"provider" encore:"optional"`
	Limit     int    `query:"limit" encore:"optional"`
}

type GovernanceUsageQuery struct {
	ProjectID string `query:"project_id" encore:"optional"`
	Provider  string `query:"provider" encore:"optional"`
	Metric    string `query:"metric" encore:"optional"`
	Limit     int    `query:"limit" encore:"optional"`
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
		return nil, errs.B().Code(errs.Internal).Msg("failed to load governance summary").Err()
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
	resources, err := listGovernanceResources(ctx, s.db, params)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load resources").Err()
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
	costs, err := listGovernanceCosts(ctx, s.db, params)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load costs").Err()
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
	usage, err := listGovernanceUsage(ctx, s.db, params)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load usage").Err()
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

	details, _ := json.Marshal(map[string]interface{}{
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
	details, _ := json.Marshal(map[string]interface{}{
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
	details, _ := json.Marshal(map[string]interface{}{
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

	stats, err := s.GetEveStats(ctx, &EveStatsParams{})
	if err != nil {
		resp.Warnings = append(resp.Warnings, "eve stats unavailable")
	} else {
		fmtFloat := func(v *float64) string {
			if v == nil {
				return ""
			}
			return fmt.Sprintf("%.2f", *v)
		}
		fmtInt := func(v *int) string {
			if v == nil {
				return ""
			}
			return fmt.Sprintf("%d", *v)
		}
		fmtInt64 := func(v *int64) string {
			if v == nil {
				return ""
			}
			return fmt.Sprintf("%d", *v)
		}
		for _, server := range stats.Servers {
			input := GovernanceResourceInput{
				Provider:     "eve",
				ResourceID:   server.Name,
				ResourceType: "lab-server",
				Name:         server.Name,
				Status:       strings.ToLower(strings.TrimSpace(server.Status)),
				Metadata: map[string]string{
					"version":       server.Version,
					"cpu_percent":   fmtFloat(server.CpuPercent),
					"mem_percent":   fmtFloat(server.MemPercent),
					"disk_percent":  fmtFloat(server.DiskPercent),
					"vcpu":          fmtInt(server.VCPU),
					"mem_total":     fmtInt64(server.MemTotal),
					"disk_free":     fmtFloat(server.DiskAvailable),
					"qemu_nodes":    fmtInt(server.QemuNodes),
					"dynamips":      fmtInt(server.DynamipsNodes),
					"vpcs":          fmtInt(server.VpcsNodes),
					"docker_nodes":  fmtInt(server.DockerNodes),
					"cluster_nodes": fmtInt(server.ClusterNodes),
					"cluster_up":    fmtInt(server.ClusterOnline),
					"error":         server.Error,
				},
			}
			if _, err := upsertGovernanceResource(ctx, s.db, input, time.Now(), user); err != nil {
				resp.Warnings = append(resp.Warnings, "failed to ingest eve server "+server.Name)
				continue
			}
			resp.ResourceCount++
			metrics := make([]GovernanceUsageInput, 0, 5)
			if server.CpuPercent != nil {
				metrics = append(metrics, GovernanceUsageInput{Provider: "eve", ScopeType: "server", ScopeID: server.Name, Metric: "cpu_percent", Value: *server.CpuPercent, Unit: "%"})
			}
			if server.MemPercent != nil {
				metrics = append(metrics, GovernanceUsageInput{Provider: "eve", ScopeType: "server", ScopeID: server.Name, Metric: "mem_percent", Value: *server.MemPercent, Unit: "%"})
			}
			if server.DiskPercent != nil {
				metrics = append(metrics, GovernanceUsageInput{Provider: "eve", ScopeType: "server", ScopeID: server.Name, Metric: "disk_percent", Value: *server.DiskPercent, Unit: "%"})
			}
			if server.QemuNodes != nil {
				metrics = append(metrics, GovernanceUsageInput{Provider: "eve", ScopeType: "server", ScopeID: server.Name, Metric: "qemu_nodes", Value: float64(*server.QemuNodes), Unit: "count"})
			}
			if server.DockerNodes != nil {
				metrics = append(metrics, GovernanceUsageInput{Provider: "eve", ScopeType: "server", ScopeID: server.Name, Metric: "docker_nodes", Value: float64(*server.DockerNodes), Unit: "count"})
			}
			for _, metric := range metrics {
				if _, err := insertGovernanceUsage(ctx, s.db, metric); err == nil {
					resp.UsageCount++
				}
			}
		}
	}

	details, _ := json.Marshal(map[string]interface{}{
		"resources": resp.ResourceCount,
		"usage":     resp.UsageCount,
		"warnings":  resp.Warnings,
	})
	writeAuditEvent(ctx, s.db, user.Username, user.IsAdmin, "", "governance.sync", "", string(details))
	return resp, nil
}
