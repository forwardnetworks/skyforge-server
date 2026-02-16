package skyforge

import (
	"encoding/json"
	"time"
)

type PolicyReportRun struct {
	ID               string          `json:"id"`
	OwnerUsername    string          `json:"ownerUsername"`
	ForwardNetworkID string          `json:"forwardNetworkId"`
	SnapshotID       string          `json:"snapshotId,omitempty"`
	PackID           string          `json:"packId"`
	Title            string          `json:"title,omitempty"`
	Status           string          `json:"status"`
	Error            string          `json:"error,omitempty"`
	CreatedBy        string          `json:"createdBy"`
	StartedAt        time.Time       `json:"startedAt"`
	FinishedAt       *time.Time      `json:"finishedAt,omitempty"`
	Request          json.RawMessage `json:"request,omitempty"`
}

type PolicyReportRunCheck struct {
	RunID   string `json:"runId"`
	CheckID string `json:"checkId"`
	Total   int    `json:"total"`
}

type PolicyReportRunFinding struct {
	RunID     string          `json:"runId"`
	CheckID   string          `json:"checkId"`
	FindingID string          `json:"findingId"`
	RiskScore int             `json:"riskScore"`
	AssetKey  string          `json:"assetKey,omitempty"`
	Finding   json.RawMessage `json:"finding,omitempty"`
}

type PolicyReportFindingAgg struct {
	OwnerUsername    string          `json:"ownerUsername"`
	ForwardNetworkID string          `json:"forwardNetworkId"`
	CheckID          string          `json:"checkId"`
	FindingID        string          `json:"findingId"`
	Status           string          `json:"status"`
	RiskScore        int             `json:"riskScore"`
	AssetKey         string          `json:"assetKey,omitempty"`
	Finding          json.RawMessage `json:"finding,omitempty"`
	FirstSeenAt      time.Time       `json:"firstSeenAt"`
	LastSeenAt       time.Time       `json:"lastSeenAt"`
	ResolvedAt       *time.Time      `json:"resolvedAt,omitempty"`
	LastRunID        string          `json:"lastRunId,omitempty"`
}

type PolicyReportCreateRunRequest struct {
	ForwardNetworkID string  `json:"forwardNetworkId"`
	SnapshotID       string  `json:"snapshotId,omitempty"`
	PackID           string  `json:"packId"`
	QueryOptions     JSONMap `json:"queryOptions,omitempty"`
	MaxPerCheck      int     `json:"maxPerCheck,omitempty"`
	MaxTotal         int     `json:"maxTotal,omitempty"`
}

type PolicyReportCreateRunResponse struct {
	Run     PolicyReportRun                     `json:"run"`
	Checks  []PolicyReportRunCheck              `json:"checks"`
	Results map[string]*PolicyReportNQEResponse `json:"results,omitempty"`
}

type PolicyReportListRunsResponse struct {
	Runs []PolicyReportRun `json:"runs"`
}

type PolicyReportGetRunResponse struct {
	Run    PolicyReportRun        `json:"run"`
	Checks []PolicyReportRunCheck `json:"checks"`
}

type PolicyReportListRunFindingsResponse struct {
	Findings []PolicyReportRunFinding `json:"findings"`
}

type PolicyReportListFindingsResponse struct {
	Findings []PolicyReportFindingAgg `json:"findings"`
}

type PolicyReportCustomRunCheckSpec struct {
	CheckID    string  `json:"checkId"`
	Parameters JSONMap `json:"parameters,omitempty"`
}

type PolicyReportCreateCustomRunRequest struct {
	ForwardNetworkID string                           `json:"forwardNetworkId"`
	SnapshotID       string                           `json:"snapshotId,omitempty"`
	PackID           string                           `json:"packId,omitempty"`
	Title            string                           `json:"title,omitempty"`
	Checks           []PolicyReportCustomRunCheckSpec `json:"checks"`
	QueryOptions     JSONMap                          `json:"queryOptions,omitempty"`
	MaxPerCheck      int                              `json:"maxPerCheck,omitempty"`
	MaxTotal         int                              `json:"maxTotal,omitempty"`
}

type PolicyReportCreateCustomRunResponse struct {
	Run     PolicyReportRun                     `json:"run"`
	Checks  []PolicyReportRunCheck              `json:"checks"`
	Results map[string]*PolicyReportNQEResponse `json:"results,omitempty"`
}
