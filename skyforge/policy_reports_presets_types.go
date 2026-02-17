package skyforge

import "time"

type PolicyReportPreset struct {
	ID               string                        `json:"id"`
	UserContextID    string                        `json:"userContextId"`
	ForwardNetworkID string                        `json:"forwardNetworkId"`
	Name             string                        `json:"name"`
	Description      string                        `json:"description,omitempty"`
	Kind             string                        `json:"kind"` // PACK | CUSTOM | PATHS
	PackID           string                        `json:"packId,omitempty"`
	TitleTemplate    string                        `json:"titleTemplate,omitempty"`
	SnapshotID       string                        `json:"snapshotId,omitempty"`
	Checks           []PolicyReportPresetCheckSpec `json:"checks,omitempty"`
	QueryOptions     JSONMap                       `json:"queryOptions,omitempty"` // stored as jsonb
	MaxPerCheck      int                           `json:"maxPerCheck,omitempty"`
	MaxTotal         int                           `json:"maxTotal,omitempty"`
	Enabled          bool                          `json:"enabled"`
	IntervalMinutes  int                           `json:"intervalMinutes"`
	NextRunAt        *time.Time                    `json:"nextRunAt,omitempty"`
	LastRunID        string                        `json:"lastRunId,omitempty"`
	LastRunAt        *time.Time                    `json:"lastRunAt,omitempty"`
	LastError        string                        `json:"lastError,omitempty"`
	OwnerUsername    string                        `json:"ownerUsername"`
	CreatedAt        time.Time                     `json:"createdAt"`
	UpdatedAt        time.Time                     `json:"updatedAt"`
}

type PolicyReportPresetCheckSpec struct {
	CheckID    string  `json:"checkId"`
	Parameters JSONMap `json:"parameters,omitempty"`
}

type PolicyReportCreatePresetRequest struct {
	ForwardNetworkID string                        `json:"forwardNetworkId"`
	Name             string                        `json:"name"`
	Description      string                        `json:"description,omitempty"`
	Kind             string                        `json:"kind,omitempty"` // PACK | CUSTOM | PATHS (default PACK)
	PackID           string                        `json:"packId,omitempty"`
	TitleTemplate    string                        `json:"titleTemplate,omitempty"`
	SnapshotID       string                        `json:"snapshotId,omitempty"`
	Checks           []PolicyReportPresetCheckSpec `json:"checks,omitempty"`
	QueryOptions     JSONMap                       `json:"queryOptions,omitempty"`
	MaxPerCheck      int                           `json:"maxPerCheck,omitempty"`
	MaxTotal         int                           `json:"maxTotal,omitempty"`
	Enabled          *bool                         `json:"enabled,omitempty"`
	IntervalMinutes  int                           `json:"intervalMinutes,omitempty"`
}

// NOTE: Encore requires API request types to be named structs (not type aliases).
// Keep update semantics aligned with create.
type PolicyReportUpdatePresetRequest struct {
	ForwardNetworkID string                        `json:"forwardNetworkId"`
	Name             string                        `json:"name"`
	Description      string                        `json:"description,omitempty"`
	Kind             string                        `json:"kind,omitempty"` // PACK | CUSTOM | PATHS (default PACK)
	PackID           string                        `json:"packId,omitempty"`
	TitleTemplate    string                        `json:"titleTemplate,omitempty"`
	SnapshotID       string                        `json:"snapshotId,omitempty"`
	Checks           []PolicyReportPresetCheckSpec `json:"checks,omitempty"`
	QueryOptions     JSONMap                       `json:"queryOptions,omitempty"`
	MaxPerCheck      int                           `json:"maxPerCheck,omitempty"`
	MaxTotal         int                           `json:"maxTotal,omitempty"`
	Enabled          *bool                         `json:"enabled,omitempty"`
	IntervalMinutes  int                           `json:"intervalMinutes,omitempty"`
}

type PolicyReportListPresetsResponse struct {
	Presets []PolicyReportPreset `json:"presets"`
}

type PolicyReportRunPresetResponse struct {
	Preset  PolicyReportPreset                  `json:"preset"`
	Run     PolicyReportRun                     `json:"run"`
	Checks  []PolicyReportRunCheck              `json:"checks"`
	Results map[string]*PolicyReportNQEResponse `json:"results,omitempty"`
}
