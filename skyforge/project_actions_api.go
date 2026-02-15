package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

// SyncWorkspace syncs resources for a single workspace.
//
//encore:api auth method=POST path=/api/workspaces/:id/sync
func (s *Service) SyncWorkspace(ctx context.Context, id string) (*workspaceSyncReport, error) {
	_ = ctx
	_ = id
	return nil, errs.B().Code(errs.FailedPrecondition).Msg("workspace sync is no longer supported").Err()
}

type WorkspaceMembersRequest struct {
	IsPublic     *bool    `json:"isPublic,omitempty"`
	Owners       []string `json:"owners"`
	OwnerGroups  []string `json:"ownerGroups"`
	Editors      []string `json:"editors"`
	EditorGroups []string `json:"editorGroups"`
	Viewers      []string `json:"viewers"`
	ViewerGroups []string `json:"viewerGroups"`
}

// UpdateWorkspaceMembers updates workspace membership.
//
//encore:api auth method=PUT path=/api/workspaces/:id/members
func (s *Service) UpdateWorkspaceMembers(ctx context.Context, id string, req *WorkspaceMembersRequest) (*SkyforgeWorkspace, error) {
	_ = ctx
	_ = id
	_ = req
	return nil, errs.B().Code(errs.FailedPrecondition).Msg("workspace sharing configuration has moved to resource shares").Err()
}

type WorkspaceNetlabConfigResponse struct {
	WorkspaceID   string   `json:"workspaceId"`
	NetlabServer  string   `json:"netlabServer"`
	NetlabServers []string `json:"netlabServers"`
}

type WorkspaceNetlabConfigRequest struct {
	NetlabServer string `json:"netlabServer"`
}

// GetWorkspaceNetlab returns the workspace's netlab server selection.
//
//encore:api auth method=GET path=/api/workspaces/:id/netlab
func (s *Service) GetWorkspaceNetlab(ctx context.Context, id string) (*WorkspaceNetlabConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	_ = ctx
	return &WorkspaceNetlabConfigResponse{
		WorkspaceID:   pc.workspace.ID,
		NetlabServer:  pc.workspace.NetlabServer,
		NetlabServers: []string{},
	}, nil
}

// UpdateWorkspaceNetlab updates the workspace's netlab server selection.
//
//encore:api auth method=PUT path=/api/workspaces/:id/netlab
func (s *Service) UpdateWorkspaceNetlab(ctx context.Context, id string, req *WorkspaceNetlabConfigRequest) (*SkyforgeWorkspace, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	next := strings.TrimSpace(req.NetlabServer)
	if next != "" {
		serverID, ok := parseWorkspaceServerRef(next)
		if !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer must be a workspace server (ws:...)").Err()
		}
		if s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getWorkspaceNetlabServerByID(ctx, s.db, s.box, pc.workspace.ID, serverID)
		if err != nil || rec == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown netlabServer").Err()
		}
	}
	pc.workspace.NetlabServer = next
	if err := s.workspaceStore.upsert(pc.workspace); err != nil {
		log.Printf("workspace upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist netlab server").Err()
	}
	if s.db != nil {
		_ = notifyWorkspacesUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.netlab.update", pc.workspace.ID, fmt.Sprintf("netlabServer=%s", next))
	}
	return &pc.workspace, nil
}

type WorkspaceAWSStaticGetResponse struct {
	Configured     bool   `json:"configured"`
	AccessKeyLast4 string `json:"accessKeyLast4,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type WorkspaceAWSStaticPutRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

type WorkspaceAWSStaticStatusResponse struct {
	Status string `json:"status"`
}

type WorkspaceAWSSSOUpdateRequest struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

type WorkspaceAWSSSOUpdateResponse struct {
	Status    string `json:"status"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

// PutWorkspaceAWSSSOConfig stores the AWS SSO account/role for the workspace.
//
//encore:api auth method=PUT path=/api/workspaces/:id/cloud/aws-sso
func (s *Service) PutWorkspaceAWSSSOConfig(ctx context.Context, id string, req *WorkspaceAWSSSOUpdateRequest) (*WorkspaceAWSSSOUpdateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	accountID := strings.TrimSpace(req.AccountID)
	roleName := strings.TrimSpace(req.RoleName)
	if accountID == "" || roleName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("accountId and roleName are required").Err()
	}
	region := strings.TrimSpace(req.Region)
	if region == "" && pc.workspace.AWSRegion == "" && s.cfg.AwsSSORegion != "" {
		region = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	if region != "" {
		pc.workspace.AWSRegion = region
	}
	pc.workspace.AWSAccountID = accountID
	pc.workspace.AWSRoleName = roleName
	pc.workspace.AWSAuthMethod = "sso"
	if err := s.workspaceStore.upsert(pc.workspace); err != nil {
		log.Printf("workspace upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist aws sso config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("accountId=%s roleName=%s", accountID, roleName)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.aws-sso.set", pc.workspace.ID, details)
	}
	return &WorkspaceAWSSSOUpdateResponse{
		Status:    "ok",
		AccountID: accountID,
		RoleName:  roleName,
		Region:    pc.workspace.AWSRegion,
	}, nil
}

// GetWorkspaceAWSStatic returns AWS static credential status.
//
//encore:api auth method=GET path=/api/workspaces/:id/cloud/aws-static
func (s *Service) GetWorkspaceAWSStatic(ctx context.Context, id string) (*WorkspaceAWSStaticGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getWorkspaceAWSStaticCredentials(ctx, s.db, box, pc.workspace.ID)
	if err != nil {
		log.Printf("aws static get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load aws static credentials").Err()
	}
	akidLast4 := ""
	updatedAt := ""
	if rec != nil {
		if len(rec.AccessKeyID) >= 4 {
			akidLast4 = rec.AccessKeyID[len(rec.AccessKeyID)-4:]
		}
		if !rec.UpdatedAt.IsZero() {
			updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	return &WorkspaceAWSStaticGetResponse{
		Configured:     rec != nil && rec.AccessKeyID != "" && rec.SecretAccessKey != "",
		AccessKeyLast4: akidLast4,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutWorkspaceAWSStatic stores AWS static credentials.
//
//encore:api auth method=PUT path=/api/workspaces/:id/cloud/aws-static
func (s *Service) PutWorkspaceAWSStatic(ctx context.Context, id string, req *WorkspaceAWSStaticPutRequest) (*WorkspaceAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := putWorkspaceAWSStaticCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.workspace.ID, req.AccessKeyID, req.SecretAccessKey, req.SessionToken); err != nil {
		log.Printf("aws static put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.aws-static.set", pc.workspace.ID, "")
	}
	return &WorkspaceAWSStaticStatusResponse{Status: "ok"}, nil
}

// DeleteWorkspaceAWSStatic clears AWS static credentials.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/cloud/aws-static
func (s *Service) DeleteWorkspaceAWSStatic(ctx context.Context, id string) (*WorkspaceAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := deleteWorkspaceAWSStaticCredentials(ctx, s.db, pc.workspace.ID); err != nil {
		log.Printf("aws static delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.aws-static.clear", pc.workspace.ID, "")
	}
	return &WorkspaceAWSStaticStatusResponse{Status: "ok"}, nil
}

type WorkspaceAzureCredentialGetResponse struct {
	Configured     bool   `json:"configured"`
	TenantID       string `json:"tenantId,omitempty"`
	ClientID       string `json:"clientId,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type WorkspaceAzureCredentialPutRequest struct {
	TenantID       string `json:"tenantId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

type WorkspaceAzureCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetWorkspaceAzureCredentials returns Azure service principal status.
//
//encore:api auth method=GET path=/api/workspaces/:id/cloud/azure
func (s *Service) GetWorkspaceAzureCredentials(ctx context.Context, id string) (*WorkspaceAzureCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getWorkspaceAzureCredentials(ctx, s.db, box, pc.workspace.ID)
	if err != nil {
		log.Printf("azure get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load azure credentials").Err()
	}
	updatedAt := ""
	tenantID := ""
	clientID := ""
	subscriptionID := ""
	if rec != nil {
		tenantID = rec.TenantID
		clientID = rec.ClientID
		subscriptionID = rec.SubscriptionID
		if !rec.UpdatedAt.IsZero() {
			updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	return &WorkspaceAzureCredentialGetResponse{
		Configured:     rec != nil && rec.ClientID != "" && rec.ClientSecret != "",
		TenantID:       tenantID,
		ClientID:       clientID,
		SubscriptionID: subscriptionID,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutWorkspaceAzureCredentials stores Azure service principal credentials.
//
//encore:api auth method=PUT path=/api/workspaces/:id/cloud/azure
func (s *Service) PutWorkspaceAzureCredentials(ctx context.Context, id string, req *WorkspaceAzureCredentialPutRequest) (*WorkspaceAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cred := azureServicePrincipal{
		TenantID:       req.TenantID,
		ClientID:       req.ClientID,
		ClientSecret:   req.ClientSecret,
		SubscriptionID: req.SubscriptionID,
	}
	if err := putWorkspaceAzureCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.workspace.ID, cred); err != nil {
		log.Printf("azure put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.azure.set", pc.workspace.ID, "")
	}
	return &WorkspaceAzureCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteWorkspaceAzureCredentials clears Azure credentials.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/cloud/azure
func (s *Service) DeleteWorkspaceAzureCredentials(ctx context.Context, id string) (*WorkspaceAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := deleteWorkspaceAzureCredentials(ctx, s.db, pc.workspace.ID); err != nil {
		log.Printf("azure delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.azure.clear", pc.workspace.ID, "")
	}
	return &WorkspaceAzureCredentialStatusResponse{Status: "ok"}, nil
}

type WorkspaceGCPCredentialGetResponse struct {
	Configured          bool   `json:"configured"`
	ClientEmail         string `json:"clientEmail,omitempty"`
	WorkspaceID         string `json:"workspaceId,omitempty"`
	SelectedWorkspaceID string `json:"selectedWorkspaceId,omitempty"`
	UpdatedAt           string `json:"updatedAt,omitempty"`
}

type WorkspaceGCPCredentialPutRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	WorkspaceID        string `json:"workspaceId,omitempty"`
}

type WorkspaceGCPCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetWorkspaceGCPCredentials returns GCP service account status.
//
//encore:api auth method=GET path=/api/workspaces/:id/cloud/gcp
func (s *Service) GetWorkspaceGCPCredentials(ctx context.Context, id string) (*WorkspaceGCPCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	box := newSecretBox(s.cfg.SessionSecret)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getWorkspaceGCPCredentials(ctx, s.db, box, pc.workspace.ID)
	if err != nil {
		log.Printf("gcp get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load gcp credentials").Err()
	}
	updatedAt := ""
	clientEmail := ""
	projectID := ""
	selectedProjectID := ""
	if rec != nil {
		if payload, err := parseGCPServiceAccountJSON(rec.ServiceAccountJSON); err == nil {
			clientEmail = payload.ClientEmail
			projectID = payload.ProjectID
		}
		selectedProjectID = rec.ProjectIDOverride
		if !rec.UpdatedAt.IsZero() {
			updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	return &WorkspaceGCPCredentialGetResponse{
		Configured:          rec != nil && rec.ServiceAccountJSON != "",
		ClientEmail:         clientEmail,
		WorkspaceID:         projectID,
		SelectedWorkspaceID: selectedProjectID,
		UpdatedAt:           updatedAt,
	}, nil
}

// PutWorkspaceGCPCredentials stores GCP service account JSON.
//
//encore:api auth method=PUT path=/api/workspaces/:id/cloud/gcp
func (s *Service) PutWorkspaceGCPCredentials(ctx context.Context, id string, req *WorkspaceGCPCredentialPutRequest) (*WorkspaceGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	if req == nil || strings.TrimSpace(req.ServiceAccountJSON) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("serviceAccountJson is required").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := putWorkspaceGCPCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.workspace.ID, req.ServiceAccountJSON, req.WorkspaceID); err != nil {
		log.Printf("gcp put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.gcp.set", pc.workspace.ID, "")
	}
	return &WorkspaceGCPCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteWorkspaceGCPCredentials clears GCP credentials.
//
//encore:api auth method=DELETE path=/api/workspaces/:id/cloud/gcp
func (s *Service) DeleteWorkspaceGCPCredentials(ctx context.Context, id string) (*WorkspaceGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("cloud credentials are unavailable (db not configured)").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := deleteWorkspaceGCPCredentials(ctx, s.db, pc.workspace.ID); err != nil {
		log.Printf("gcp delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "workspace.cloud.gcp.clear", pc.workspace.ID, "")
	}
	return &WorkspaceGCPCredentialStatusResponse{Status: "ok"}, nil
}
