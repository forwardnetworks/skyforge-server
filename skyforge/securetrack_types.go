package skyforge

// SecureTrack is a small "security workflow" demo that runs parameterized NQE checks
// against a Forward network/snapshot. It is intentionally self-contained so it can
// ship as part of the Skyforge server image (embedded assets).

import "encoding/json"

type SecureTrackCatalogParam struct {
	Name        string          `yaml:"name" json:"name"`
	Type        string          `yaml:"type" json:"type"`
	Default     json.RawMessage `yaml:"default,omitempty" json:"default,omitempty"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool            `yaml:"required,omitempty" json:"required,omitempty"`
}

type SecureTrackCatalogCheck struct {
	ID          string                    `yaml:"id" json:"id"`
	Title       string                    `yaml:"title,omitempty" json:"title,omitempty"`
	Category    string                    `yaml:"category,omitempty" json:"category,omitempty"`
	Severity    string                    `yaml:"severity,omitempty" json:"severity,omitempty"`
	Description string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Params      []SecureTrackCatalogParam `yaml:"params,omitempty" json:"params,omitempty"`
}

type SecureTrackCatalog struct {
	Version string                    `yaml:"version,omitempty" json:"version,omitempty"`
	Checks  []SecureTrackCatalogCheck `yaml:"checks,omitempty" json:"checks,omitempty"`
}

type SecureTrackPackCheck struct {
	ID         string  `yaml:"id" json:"id"`
	Parameters JSONMap `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

type SecureTrackPack struct {
	ID          string                 `yaml:"id" json:"id"`
	Title       string                 `yaml:"title,omitempty" json:"title,omitempty"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Checks      []SecureTrackPackCheck `yaml:"checks,omitempty" json:"checks,omitempty"`
}

type SecureTrackPacks struct {
	Version string            `yaml:"version,omitempty" json:"version,omitempty"`
	Packs   []SecureTrackPack `yaml:"packs,omitempty" json:"packs,omitempty"`
}

type SecureTrackNQERequest struct {
	NetworkID    string  `json:"networkId"`
	SnapshotID   string  `json:"snapshotId,omitempty"`
	Query        string  `json:"query"`
	Parameters   JSONMap `json:"parameters,omitempty"`
	QueryOptions JSONMap `json:"queryOptions,omitempty"`
}

type SecureTrackNQEResponse struct {
	SnapshotID string          `json:"snapshotId,omitempty"`
	Total      int             `json:"total"`
	Results    json.RawMessage `json:"results"`
}

type SecureTrackSnapshotsRequest struct {
	NetworkID  string `query:"networkId"`
	MaxResults int    `query:"maxResults" encore:"optional"`
	SnapshotID string `query:"snapshotId" encore:"optional"`
}

type SecureTrackSnapshotsResponse struct {
	Body json.RawMessage `json:"body"`
}

type SecureTrackRunCheckRequest struct {
	NetworkID    string  `json:"networkId"`
	SnapshotID   string  `json:"snapshotId,omitempty"`
	CheckID      string  `json:"checkId"`
	Parameters   JSONMap `json:"parameters,omitempty"`
	QueryOptions JSONMap `json:"queryOptions,omitempty"`
}

type SecureTrackRunPackRequest struct {
	NetworkID  string `json:"networkId"`
	SnapshotID string `json:"snapshotId,omitempty"`
	PackID     string `json:"packId"`
}

type SecureTrackRunPackResponse struct {
	PackID     string                             `json:"packId"`
	NetworkID  string                             `json:"networkId"`
	SnapshotID string                             `json:"snapshotId,omitempty"`
	Results    map[string]*SecureTrackNQEResponse `json:"results"`
}
