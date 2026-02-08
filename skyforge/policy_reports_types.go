package skyforge

// Policy Reports is a small "governance/reporting" demo that runs parameterized NQE
// checks against a Forward network/snapshot. It is intentionally self-contained so it
// can ship as part of the Skyforge server image (embedded assets).

import "encoding/json"

type PolicyReportCatalogParam struct {
	Name        string          `yaml:"name" json:"name"`
	Type        string          `yaml:"type" json:"type"`
	Default     json.RawMessage `yaml:"default,omitempty" json:"default,omitempty"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool            `yaml:"required,omitempty" json:"required,omitempty"`
}

type PolicyReportCatalogCheck struct {
	ID          string                     `yaml:"id" json:"id"`
	Title       string                     `yaml:"title,omitempty" json:"title,omitempty"`
	Category    string                     `yaml:"category,omitempty" json:"category,omitempty"`
	Severity    string                     `yaml:"severity,omitempty" json:"severity,omitempty"`
	Description string                     `yaml:"description,omitempty" json:"description,omitempty"`
	Params      []PolicyReportCatalogParam `yaml:"params,omitempty" json:"params,omitempty"`
}

type PolicyReportCatalog struct {
	Version string                     `yaml:"version,omitempty" json:"version,omitempty"`
	Checks  []PolicyReportCatalogCheck `yaml:"checks,omitempty" json:"checks,omitempty"`
}

type PolicyReportPackCheck struct {
	ID         string  `yaml:"id" json:"id"`
	Parameters JSONMap `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type PolicyReportPack struct {
	ID          string                  `yaml:"id" json:"id"`
	Title       string                  `yaml:"title,omitempty" json:"title,omitempty"`
	Description string                  `yaml:"description,omitempty" json:"description,omitempty"`
	Checks      []PolicyReportPackCheck `yaml:"checks,omitempty" json:"checks,omitempty"`
}

type PolicyReportPacks struct {
	Version string             `yaml:"version,omitempty" json:"version,omitempty"`
	Packs   []PolicyReportPack `yaml:"packs,omitempty" json:"packs,omitempty"`
}

type PolicyReportNQERequest struct {
	NetworkID    string  `json:"networkId"`
	SnapshotID   string  `json:"snapshotId,omitempty"`
	Query        string  `json:"query"`
	Parameters   JSONMap `json:"parameters,omitempty"`
	QueryOptions JSONMap `json:"queryOptions,omitempty"`
}

type PolicyReportNQEResponse struct {
	SnapshotID string          `json:"snapshotId,omitempty"`
	Total      int             `json:"total"`
	Results    json.RawMessage `json:"results"`
}

type PolicyReportSnapshotsRequest struct {
	NetworkID  string `query:"networkId"`
	MaxResults int    `query:"maxResults" encore:"optional"`
	SnapshotID string `query:"snapshotId" encore:"optional"`
}

type PolicyReportSnapshotsResponse struct {
	Body json.RawMessage `json:"body"`
}

type PolicyReportRunCheckRequest struct {
	NetworkID    string  `json:"networkId"`
	SnapshotID   string  `json:"snapshotId,omitempty"`
	CheckID      string  `json:"checkId"`
	Parameters   JSONMap `json:"parameters,omitempty"`
	QueryOptions JSONMap `json:"queryOptions,omitempty"`
}

type PolicyReportRunPackRequest struct {
	NetworkID    string  `json:"networkId"`
	SnapshotID   string  `json:"snapshotId,omitempty"`
	PackID       string  `json:"packId"`
	QueryOptions JSONMap `json:"queryOptions,omitempty"`
}

type PolicyReportRunPackResponse struct {
	PackID     string                              `json:"packId"`
	NetworkID  string                              `json:"networkId"`
	SnapshotID string                              `json:"snapshotId,omitempty"`
	Results    map[string]*PolicyReportNQEResponse `json:"results"`
}

type PolicyReportPackDeltaRequest struct {
	NetworkID           string  `json:"networkId"`
	PackID              string  `json:"packId"`
	BaselineSnapshotID  string  `json:"baselineSnapshotId"`
	CompareSnapshotID   string  `json:"compareSnapshotId"`
	QueryOptions        JSONMap `json:"queryOptions,omitempty"`
	MaxSamplesPerBucket int     `json:"maxSamplesPerBucket,omitempty"`
}

type PolicyReportPackDeltaCheck struct {
	CheckID        string          `json:"checkId"`
	BaselineTotal  int             `json:"baselineTotal"`
	CompareTotal   int             `json:"compareTotal"`
	NewCount       int             `json:"newCount"`
	ResolvedCount  int             `json:"resolvedCount"`
	ChangedCount   int             `json:"changedCount"`
	NewSamples     json.RawMessage `json:"newSamples,omitempty"`
	OldSamples     json.RawMessage `json:"oldSamples,omitempty"`
	ChangedSamples json.RawMessage `json:"changedSamples,omitempty"`
}

type PolicyReportPackDeltaResponse struct {
	PackID             string                       `json:"packId"`
	NetworkID          string                       `json:"networkId"`
	BaselineSnapshotID string                       `json:"baselineSnapshotId"`
	CompareSnapshotID  string                       `json:"compareSnapshotId"`
	Checks             []PolicyReportPackDeltaCheck `json:"checks"`
}
