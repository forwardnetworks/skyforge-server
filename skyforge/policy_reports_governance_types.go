package skyforge

import (
	"encoding/json"
	"time"
)

type PolicyReportRecertCampaign struct {
	ID             string     `json:"id"`
	WorkspaceID    string     `json:"workspaceId"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	ForwardNetwork string     `json:"forwardNetworkId"`
	SnapshotID     string     `json:"snapshotId,omitempty"`
	PackID         string     `json:"packId"`
	Status         string     `json:"status"`
	DueAt          *time.Time `json:"dueAt,omitempty"`
	CreatedBy      string     `json:"createdBy"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

type PolicyReportRecertCampaignCounts struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Attested int `json:"attested"`
	Waived   int `json:"waived"`
}

type PolicyReportRecertCampaignWithCounts struct {
	Campaign PolicyReportRecertCampaign       `json:"campaign"`
	Counts   PolicyReportRecertCampaignCounts `json:"counts"`
}

type PolicyReportRecertAssignment struct {
	ID              string          `json:"id"`
	CampaignID      string          `json:"campaignId"`
	WorkspaceID     string          `json:"workspaceId"`
	FindingID       string          `json:"findingId"`
	CheckID         string          `json:"checkId"`
	Assignee        string          `json:"assigneeUsername,omitempty"`
	Status          string          `json:"status"`
	Justification   string          `json:"justification,omitempty"`
	AttestedAt      *time.Time      `json:"attestedAt,omitempty"`
	Finding         json.RawMessage `json:"finding,omitempty"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	CheckTitle      string          `json:"checkTitle,omitempty"`
	CheckCategory   string          `json:"checkCategory,omitempty"`
	CheckSeverity   string          `json:"checkSeverity,omitempty"`
	FindingRisk     int             `json:"findingRiskScore,omitempty"`
	FindingReasons  []string        `json:"findingRiskReasons,omitempty"`
	FindingAssetKey string          `json:"findingAssetKey,omitempty"`
}

type PolicyReportException struct {
	ID            string     `json:"id"`
	WorkspaceID   string     `json:"workspaceId"`
	ForwardNetwork string    `json:"forwardNetworkId"`
	FindingID     string     `json:"findingId"`
	CheckID       string     `json:"checkId"`
	Status        string     `json:"status"`
	Justification string     `json:"justification"`
	TicketURL     string     `json:"ticketUrl,omitempty"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	CreatedBy     string     `json:"createdBy"`
	ApprovedBy    string     `json:"approvedBy,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type PolicyReportAuditEvent struct {
	ID          int64           `json:"id"`
	WorkspaceID string          `json:"workspaceId"`
	Actor       string          `json:"actorUsername"`
	Action      string          `json:"action"`
	Details     json.RawMessage `json:"details"`
	CreatedAt   time.Time       `json:"createdAt"`
}

type PolicyReportCreateRecertCampaignRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	ForwardNetwork string `json:"forwardNetworkId"`
	SnapshotID     string `json:"snapshotId,omitempty"`
	PackID         string `json:"packId"`
	DueAt          string `json:"dueAt,omitempty"` // RFC3339
}

type PolicyReportListRecertCampaignsRequest struct {
	Status string `query:"status" encore:"optional"`
	Limit  int    `query:"limit" encore:"optional"`
}

type PolicyReportListRecertCampaignsResponse struct {
	Campaigns []PolicyReportRecertCampaignWithCounts `json:"campaigns"`
}

type PolicyReportGenerateRecertAssignmentsRequest struct {
	AssigneeUsername string  `json:"assigneeUsername,omitempty"`
	MaxPerCheck      int     `json:"maxPerCheck,omitempty"`
	MaxTotal         int     `json:"maxTotal,omitempty"`
	QueryOptions     JSONMap `json:"queryOptions,omitempty"`
}

type PolicyReportGenerateRecertAssignmentsResponse struct {
	CampaignID string `json:"campaignId"`
	Created    int    `json:"created"`
}

type PolicyReportListRecertAssignmentsRequest struct {
	CampaignID string `query:"campaignId" encore:"optional"`
	Status     string `query:"status" encore:"optional"`
	Assignee   string `query:"assignee" encore:"optional"`
	Limit      int    `query:"limit" encore:"optional"`
}

type PolicyReportListRecertAssignmentsResponse struct {
	Assignments []PolicyReportRecertAssignment `json:"assignments"`
}

type PolicyReportAttestAssignmentRequest struct {
	Justification string `json:"justification,omitempty"`
}

type PolicyReportCreateExceptionRequest struct {
	ForwardNetwork string `json:"forwardNetworkId"`
	FindingID     string `json:"findingId"`
	CheckID       string `json:"checkId"`
	Justification string `json:"justification"`
	TicketURL     string `json:"ticketUrl,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"` // RFC3339
}

type PolicyReportListExceptionsRequest struct {
	ForwardNetwork string `query:"forwardNetworkId" encore:"optional"`
	Status string `query:"status" encore:"optional"`
	Limit  int    `query:"limit" encore:"optional"`
}

type PolicyReportListExceptionsResponse struct {
	Exceptions []PolicyReportException `json:"exceptions"`
}

type PolicyReportDecisionResponse struct {
	Ok bool `json:"ok"`
}
