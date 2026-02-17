package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

// SyncUserContext syncs resources for a single user context.
//
//encore:api auth method=POST path=/api/user-contexts/:id/sync
func (s *Service) SyncUserContext(ctx context.Context, id string) (*userContextSyncReport, error) {
	userContextSyncManualRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		userContextSyncFailures.Add(1)
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		userContextSyncFailures.Add(1)
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		userContextSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report := syncUserContextResources(ctx, s.cfg, &pc.userContext)
	if report.Updated {
		if err := s.userContextStore.upsert(pc.userContext); err != nil {
			log.Printf("user context upsert after sync: %v", err)
			userContextSyncFailures.Add(1)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist sync").Err()
		}
		if s.db != nil {
			_ = notifyUserContextsUpdatePG(ctx, s.db, "*")
			_ = notifyDashboardUpdatePG(ctx, s.db)
		}
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("updated=%t errors=%d", report.Updated, len(report.Errors))
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.sync.manual", pc.userContext.ID, details)
	}
	if len(report.Errors) > 0 {
		userContextSyncErrors.Add(1)
	}
	return &report, nil
}

type UserContextMembersRequest struct {
	IsPublic     *bool    `json:"isPublic,omitempty"`
	Owners       []string `json:"owners"`
	OwnerGroups  []string `json:"ownerGroups"`
	Editors      []string `json:"editors"`
	EditorGroups []string `json:"editorGroups"`
	Viewers      []string `json:"viewers"`
	ViewerGroups []string `json:"viewerGroups"`
}

// UpdateUserContextMembers updates user-context membership.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/members
func (s *Service) UpdateUserContextMembers(ctx context.Context, id string, req *UserContextMembersRequest) (*SkyforgeWorkspace, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	nextOwners := normalizeUsernameList(req.Owners)
	nextOwnerGroups := normalizeGroupList(req.OwnerGroups)
	nextEditors := normalizeUsernameList(req.Editors)
	nextEditorGroups := normalizeGroupList(req.EditorGroups)
	nextViewers := normalizeUsernameList(req.Viewers)
	nextViewerGroups := normalizeGroupList(req.ViewerGroups)
	if len(nextOwners) == 0 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("owners is required").Err()
	}
	if pc.access != "admin" && !containsUser(nextOwners, user.Username) && !strings.EqualFold(pc.userContext.CreatedBy, user.Username) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("you cannot remove yourself from owners").Err()
	}
	if req.IsPublic != nil {
		pc.userContext.IsPublic = *req.IsPublic
	}
	pc.userContext.Owners = nextOwners
	pc.userContext.OwnerGroups = nextOwnerGroups
	pc.userContext.Editors = nextEditors
	pc.userContext.EditorGroups = nextEditorGroups
	pc.userContext.Viewers = nextViewers
	pc.userContext.ViewerGroups = nextViewerGroups
	if err := s.userContextStore.upsert(pc.userContext); err != nil {
		log.Printf("user context upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist members").Err()
	}
	if s.db != nil {
		_ = notifyUserContextsUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"user.members.update",
			pc.userContext.ID,
			fmt.Sprintf("owners=%d ownerGroups=%d editors=%d editorGroups=%d viewers=%d viewerGroups=%d", len(pc.userContext.Owners), len(pc.userContext.OwnerGroups), len(pc.userContext.Editors), len(pc.userContext.EditorGroups), len(pc.userContext.Viewers), len(pc.userContext.ViewerGroups)),
		)
	}
	syncGiteaCollaboratorsForUserContext(s.cfg, pc.userContext)
	return &pc.userContext, nil
}

type UserContextNetlabConfigResponse struct {
	UserContextID string   `json:"userContextId"`
	NetlabServer  string   `json:"netlabServer"`
	NetlabServers []string `json:"netlabServers"`
}

type UserContextNetlabConfigRequest struct {
	NetlabServer string `json:"netlabServer"`
}

// GetUserContextNetlab returns the user-context netlab server selection.
//
//encore:api auth method=GET path=/api/user-contexts/:id/netlab
func (s *Service) GetUserContextNetlab(ctx context.Context, id string) (*UserContextNetlabConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	_ = ctx
	return &UserContextNetlabConfigResponse{
		UserContextID: pc.userContext.ID,
		NetlabServer:  pc.userContext.NetlabServer,
		NetlabServers: []string{},
	}, nil
}

// UpdateUserContextNetlab updates the user-context netlab server selection.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/netlab
func (s *Service) UpdateUserContextNetlab(ctx context.Context, id string, req *UserContextNetlabConfigRequest) (*SkyforgeWorkspace, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
		serverID, ok := parseUserContextServerRef(next)
		if !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer must be a user-context server (ws:...)").Err()
		}
		if s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getUserContextNetlabServerByID(ctx, s.db, s.box, pc.userContext.ID, serverID)
		if err != nil || rec == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown netlabServer").Err()
		}
	}
	pc.userContext.NetlabServer = next
	if err := s.userContextStore.upsert(pc.userContext); err != nil {
		log.Printf("user context upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist netlab server").Err()
	}
	if s.db != nil {
		_ = notifyUserContextsUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.netlab.update", pc.userContext.ID, fmt.Sprintf("netlabServer=%s", next))
	}
	return &pc.userContext, nil
}

type UserContextAWSStaticGetResponse struct {
	Configured     bool   `json:"configured"`
	AccessKeyLast4 string `json:"accessKeyLast4,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserContextAWSStaticPutRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

type UserContextAWSStaticStatusResponse struct {
	Status string `json:"status"`
}

type UserContextAWSSSOUpdateRequest struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

type UserContextAWSSSOUpdateResponse struct {
	Status    string `json:"status"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

// PutUserContextAWSSSOConfig stores the AWS SSO account/role for the user context.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/cloud/aws-sso
func (s *Service) PutUserContextAWSSSOConfig(ctx context.Context, id string, req *UserContextAWSSSOUpdateRequest) (*UserContextAWSSSOUpdateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if region == "" && pc.userContext.AWSRegion == "" && s.cfg.AwsSSORegion != "" {
		region = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	if region != "" {
		pc.userContext.AWSRegion = region
	}
	pc.userContext.AWSAccountID = accountID
	pc.userContext.AWSRoleName = roleName
	pc.userContext.AWSAuthMethod = "sso"
	if err := s.userContextStore.upsert(pc.userContext); err != nil {
		log.Printf("user context upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist aws sso config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("accountId=%s roleName=%s", accountID, roleName)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.aws-sso.set", pc.userContext.ID, details)
	}
	return &UserContextAWSSSOUpdateResponse{
		Status:    "ok",
		AccountID: accountID,
		RoleName:  roleName,
		Region:    pc.userContext.AWSRegion,
	}, nil
}

// GetUserContextAWSStatic returns AWS static credential status.
//
//encore:api auth method=GET path=/api/user-contexts/:id/cloud/aws-static
func (s *Service) GetUserContextAWSStatic(ctx context.Context, id string) (*UserContextAWSStaticGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	rec, err := getUserContextAWSStaticCredentials(ctx, s.db, box, pc.userContext.ID)
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
	return &UserContextAWSStaticGetResponse{
		Configured:     rec != nil && rec.AccessKeyID != "" && rec.SecretAccessKey != "",
		AccessKeyLast4: akidLast4,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutUserContextAWSStatic stores AWS static credentials.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/cloud/aws-static
func (s *Service) PutUserContextAWSStatic(ctx context.Context, id string, req *UserContextAWSStaticPutRequest) (*UserContextAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if err := putUserContextAWSStaticCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userContext.ID, req.AccessKeyID, req.SecretAccessKey, req.SessionToken); err != nil {
		log.Printf("aws static put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.aws-static.set", pc.userContext.ID, "")
	}
	return &UserContextAWSStaticStatusResponse{Status: "ok"}, nil
}

// DeleteUserContextAWSStatic clears AWS static credentials.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/cloud/aws-static
func (s *Service) DeleteUserContextAWSStatic(ctx context.Context, id string) (*UserContextAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if err := deleteUserContextAWSStaticCredentials(ctx, s.db, pc.userContext.ID); err != nil {
		log.Printf("aws static delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.aws-static.clear", pc.userContext.ID, "")
	}
	return &UserContextAWSStaticStatusResponse{Status: "ok"}, nil
}

type UserContextAzureCredentialGetResponse struct {
	Configured     bool   `json:"configured"`
	TenantID       string `json:"tenantId,omitempty"`
	ClientID       string `json:"clientId,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserContextAzureCredentialPutRequest struct {
	TenantID       string `json:"tenantId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

type UserContextAzureCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetUserContextAzureCredentials returns Azure service principal status.
//
//encore:api auth method=GET path=/api/user-contexts/:id/cloud/azure
func (s *Service) GetUserContextAzureCredentials(ctx context.Context, id string) (*UserContextAzureCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	rec, err := getUserContextAzureCredentials(ctx, s.db, box, pc.userContext.ID)
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
	return &UserContextAzureCredentialGetResponse{
		Configured:     rec != nil && rec.ClientID != "" && rec.ClientSecret != "",
		TenantID:       tenantID,
		ClientID:       clientID,
		SubscriptionID: subscriptionID,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutUserContextAzureCredentials stores Azure service principal credentials.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/cloud/azure
func (s *Service) PutUserContextAzureCredentials(ctx context.Context, id string, req *UserContextAzureCredentialPutRequest) (*UserContextAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if err := putUserContextAzureCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userContext.ID, cred); err != nil {
		log.Printf("azure put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.azure.set", pc.userContext.ID, "")
	}
	return &UserContextAzureCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteUserContextAzureCredentials clears Azure credentials.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/cloud/azure
func (s *Service) DeleteUserContextAzureCredentials(ctx context.Context, id string) (*UserContextAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if err := deleteUserContextAzureCredentials(ctx, s.db, pc.userContext.ID); err != nil {
		log.Printf("azure delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.azure.clear", pc.userContext.ID, "")
	}
	return &UserContextAzureCredentialStatusResponse{Status: "ok"}, nil
}

type UserContextGCPCredentialGetResponse struct {
	Configured        bool   `json:"configured"`
	ClientEmail       string `json:"clientEmail,omitempty"`
	UserContextID     string `json:"userContextId,omitempty"`
	SelectedProjectID string `json:"selectedWorkspaceId,omitempty"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
}

type UserContextGCPCredentialPutRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	UserContextID      string `json:"userContextId,omitempty"`
}

type UserContextGCPCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetUserContextGCPCredentials returns GCP service account status.
//
//encore:api auth method=GET path=/api/user-contexts/:id/cloud/gcp
func (s *Service) GetUserContextGCPCredentials(ctx context.Context, id string) (*UserContextGCPCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	rec, err := getUserContextGCPCredentials(ctx, s.db, box, pc.userContext.ID)
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
	return &UserContextGCPCredentialGetResponse{
		Configured:        rec != nil && rec.ServiceAccountJSON != "",
		ClientEmail:       clientEmail,
		UserContextID:     projectID,
		SelectedProjectID: selectedProjectID,
		UpdatedAt:         updatedAt,
	}, nil
}

// PutUserContextGCPCredentials stores GCP service account JSON.
//
//encore:api auth method=PUT path=/api/user-contexts/:id/cloud/gcp
func (s *Service) PutUserContextGCPCredentials(ctx context.Context, id string, req *UserContextGCPCredentialPutRequest) (*UserContextGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if err := putUserContextGCPCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userContext.ID, req.ServiceAccountJSON, req.UserContextID); err != nil {
		log.Printf("gcp put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.gcp.set", pc.userContext.ID, "")
	}
	return &UserContextGCPCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteUserContextGCPCredentials clears GCP credentials.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/cloud/gcp
func (s *Service) DeleteUserContextGCPCredentials(ctx context.Context, id string) (*UserContextGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	if err := deleteUserContextGCPCredentials(ctx, s.db, pc.userContext.ID); err != nil {
		log.Printf("gcp delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user.cloud.gcp.clear", pc.userContext.ID, "")
	}
	return &UserContextGCPCredentialStatusResponse{Status: "ok"}, nil
}
