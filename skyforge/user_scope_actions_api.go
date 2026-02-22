package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

// SyncUserScope syncs resources for a single user scope.
//
//encore:api auth method=POST path=/api/users/:id/sync
func (s *Service) SyncUserScope(ctx context.Context, id string) (*userScopeSyncReport, error) {
	userScopeSyncManualRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		userScopeSyncFailures.Add(1)
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		userScopeSyncFailures.Add(1)
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		userScopeSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report := syncUserScopeResources(ctx, s.cfg, &pc.userScope)
	if report.Updated {
		if err := s.userScopeStore.upsert(pc.userScope); err != nil {
			log.Printf("user-scope upsert after sync: %v", err)
			userScopeSyncFailures.Add(1)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist sync").Err()
		}
		if s.db != nil {
			_ = notifyUserScopesUpdatePG(ctx, s.db, "*")
			_ = notifyDashboardUpdatePG(ctx, s.db)
		}
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("updated=%t errors=%d", report.Updated, len(report.Errors))
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.sync.manual", pc.userScope.ID, details)
	}
	if len(report.Errors) > 0 {
		userScopeSyncErrors.Add(1)
	}
	return &report, nil
}

type UserScopeMembersRequest struct {
	IsPublic     *bool    `json:"isPublic,omitempty"`
	Owners       []string `json:"owners"`
	OwnerGroups  []string `json:"ownerGroups"`
	Editors      []string `json:"editors"`
	EditorGroups []string `json:"editorGroups"`
	Viewers      []string `json:"viewers"`
	ViewerGroups []string `json:"viewerGroups"`
}

// UpdateUserScopeMembers updates user-scope membership.
//
//encore:api auth method=PUT path=/api/users/:id/members
func (s *Service) UpdateUserScopeMembers(ctx context.Context, id string, req *UserScopeMembersRequest) (*UserScope, error) {
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
	if pc.access != "admin" && !containsUser(nextOwners, user.Username) && !strings.EqualFold(pc.userScope.CreatedBy, user.Username) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("you cannot remove yourself from owners").Err()
	}
	if req.IsPublic != nil {
		pc.userScope.IsPublic = *req.IsPublic
	}
	pc.userScope.Owners = nextOwners
	pc.userScope.OwnerGroups = nextOwnerGroups
	pc.userScope.Editors = nextEditors
	pc.userScope.EditorGroups = nextEditorGroups
	pc.userScope.Viewers = nextViewers
	pc.userScope.ViewerGroups = nextViewerGroups
	if err := s.userScopeStore.upsert(pc.userScope); err != nil {
		log.Printf("user-scope upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist members").Err()
	}
	if s.db != nil {
		_ = notifyUserScopesUpdatePG(ctx, s.db, "*")
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
			"user-scope.members.update",
			pc.userScope.ID,
			fmt.Sprintf("owners=%d ownerGroups=%d editors=%d editorGroups=%d viewers=%d viewerGroups=%d", len(pc.userScope.Owners), len(pc.userScope.OwnerGroups), len(pc.userScope.Editors), len(pc.userScope.EditorGroups), len(pc.userScope.Viewers), len(pc.userScope.ViewerGroups)),
		)
	}
	syncGiteaCollaboratorsForUserScope(s.cfg, pc.userScope)
	return &pc.userScope, nil
}

type UserScopeNetlabConfigResponse struct {
	UserScopeID   string   `json:"userId"`
	NetlabServer  string   `json:"netlabServer"`
	NetlabServers []string `json:"netlabServers"`
}

type UserScopeNetlabConfigRequest struct {
	NetlabServer string `json:"netlabServer"`
}

// GetUserScopeNetlab returns the user-scope netlab server selection.
//
//encore:api auth method=GET path=/api/users/:id/netlab
func (s *Service) GetUserScopeNetlab(ctx context.Context, id string) (*UserScopeNetlabConfigResponse, error) {
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
	return &UserScopeNetlabConfigResponse{
		UserScopeID:   pc.userScope.ID,
		NetlabServer:  pc.userScope.NetlabServer,
		NetlabServers: []string{},
	}, nil
}

// UpdateUserScopeNetlab updates the user-scope netlab server selection.
//
//encore:api auth method=PUT path=/api/users/:id/netlab
func (s *Service) UpdateUserScopeNetlab(ctx context.Context, id string, req *UserScopeNetlabConfigRequest) (*UserScope, error) {
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
		serverID, ok := parseUserServerRef(next)
		if !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer must be a user server (user:...)").Err()
		}
		if s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getUserNetlabServerByID(ctx, s.db, s.box, pc.claims.Username, serverID)
		if err != nil || rec == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown netlabServer").Err()
		}
	}
	pc.userScope.NetlabServer = next
	if err := s.userScopeStore.upsert(pc.userScope); err != nil {
		log.Printf("user-scope upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist netlab server").Err()
	}
	if s.db != nil {
		_ = notifyUserScopesUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.netlab.update", pc.userScope.ID, fmt.Sprintf("netlabServer=%s", next))
	}
	return &pc.userScope, nil
}

type UserScopeAWSStaticGetResponse struct {
	Configured     bool   `json:"configured"`
	AccessKeyLast4 string `json:"accessKeyLast4,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserScopeAWSStaticPutRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

type UserScopeAWSStaticStatusResponse struct {
	Status string `json:"status"`
}

type UserScopeAWSSSOUpdateRequest struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

type UserScopeAWSSSOUpdateResponse struct {
	Status    string `json:"status"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

// PutUserScopeAWSSSOConfig stores the AWS SSO environment/role for the user scope.
//
//encore:api auth method=PUT path=/api/users/:id/cloud/aws-sso
func (s *Service) PutUserScopeAWSSSOConfig(ctx context.Context, id string, req *UserScopeAWSSSOUpdateRequest) (*UserScopeAWSSSOUpdateResponse, error) {
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
	if region == "" && pc.userScope.AWSRegion == "" && s.cfg.AwsSSORegion != "" {
		region = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	if region != "" {
		pc.userScope.AWSRegion = region
	}
	pc.userScope.AWSAccountID = accountID
	pc.userScope.AWSRoleName = roleName
	pc.userScope.AWSAuthMethod = "sso"
	if err := s.userScopeStore.upsert(pc.userScope); err != nil {
		log.Printf("user-scope upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist aws sso config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("accountId=%s roleName=%s", accountID, roleName)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.aws-sso.set", pc.userScope.ID, details)
	}
	return &UserScopeAWSSSOUpdateResponse{
		Status:    "ok",
		AccountID: accountID,
		RoleName:  roleName,
		Region:    pc.userScope.AWSRegion,
	}, nil
}

// GetUserScopeAWSStatic returns AWS static credential status.
//
//encore:api auth method=GET path=/api/users/:id/cloud/aws-static
func (s *Service) GetUserScopeAWSStatic(ctx context.Context, id string) (*UserScopeAWSStaticGetResponse, error) {
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
	rec, err := getUserScopeAWSStaticCredentials(ctx, s.db, box, pc.userScope.ID)
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
	return &UserScopeAWSStaticGetResponse{
		Configured:     rec != nil && rec.AccessKeyID != "" && rec.SecretAccessKey != "",
		AccessKeyLast4: akidLast4,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutUserScopeAWSStatic stores AWS static credentials.
//
//encore:api auth method=PUT path=/api/users/:id/cloud/aws-static
func (s *Service) PutUserScopeAWSStatic(ctx context.Context, id string, req *UserScopeAWSStaticPutRequest) (*UserScopeAWSStaticStatusResponse, error) {
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
	if err := putUserScopeAWSStaticCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userScope.ID, req.AccessKeyID, req.SecretAccessKey, req.SessionToken); err != nil {
		log.Printf("aws static put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.aws-static.set", pc.userScope.ID, "")
	}
	return &UserScopeAWSStaticStatusResponse{Status: "ok"}, nil
}

// DeleteUserScopeAWSStatic clears AWS static credentials.
//
//encore:api auth method=DELETE path=/api/users/:id/cloud/aws-static
func (s *Service) DeleteUserScopeAWSStatic(ctx context.Context, id string) (*UserScopeAWSStaticStatusResponse, error) {
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
	if err := deleteUserScopeAWSStaticCredentials(ctx, s.db, pc.userScope.ID); err != nil {
		log.Printf("aws static delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.aws-static.clear", pc.userScope.ID, "")
	}
	return &UserScopeAWSStaticStatusResponse{Status: "ok"}, nil
}

type UserScopeAzureCredentialGetResponse struct {
	Configured     bool   `json:"configured"`
	TenantID       string `json:"tenantId,omitempty"`
	ClientID       string `json:"clientId,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserScopeAzureCredentialPutRequest struct {
	TenantID       string `json:"tenantId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

type UserScopeAzureCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetUserScopeAzureCredentials returns Azure service principal status.
//
//encore:api auth method=GET path=/api/users/:id/cloud/azure
func (s *Service) GetUserScopeAzureCredentials(ctx context.Context, id string) (*UserScopeAzureCredentialGetResponse, error) {
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
	rec, err := getUserScopeAzureCredentials(ctx, s.db, box, pc.userScope.ID)
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
	return &UserScopeAzureCredentialGetResponse{
		Configured:     rec != nil && rec.ClientID != "" && rec.ClientSecret != "",
		TenantID:       tenantID,
		ClientID:       clientID,
		SubscriptionID: subscriptionID,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutUserScopeAzureCredentials stores Azure service principal credentials.
//
//encore:api auth method=PUT path=/api/users/:id/cloud/azure
func (s *Service) PutUserScopeAzureCredentials(ctx context.Context, id string, req *UserScopeAzureCredentialPutRequest) (*UserScopeAzureCredentialStatusResponse, error) {
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
	if err := putUserScopeAzureCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userScope.ID, cred); err != nil {
		log.Printf("azure put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.azure.set", pc.userScope.ID, "")
	}
	return &UserScopeAzureCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteUserScopeAzureCredentials clears Azure credentials.
//
//encore:api auth method=DELETE path=/api/users/:id/cloud/azure
func (s *Service) DeleteUserScopeAzureCredentials(ctx context.Context, id string) (*UserScopeAzureCredentialStatusResponse, error) {
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
	if err := deleteUserScopeAzureCredentials(ctx, s.db, pc.userScope.ID); err != nil {
		log.Printf("azure delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.azure.clear", pc.userScope.ID, "")
	}
	return &UserScopeAzureCredentialStatusResponse{Status: "ok"}, nil
}

type UserScopeGCPCredentialGetResponse struct {
	Configured          bool   `json:"configured"`
	ClientEmail         string `json:"clientEmail,omitempty"`
	UserScopeID         string `json:"userId,omitempty"`
	SelectedUserScopeID string `json:"selectedUserScopeId,omitempty"`
	UpdatedAt           string `json:"updatedAt,omitempty"`
}

type UserScopeGCPCredentialPutRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	UserScopeID        string `json:"userId,omitempty"`
}

type UserScopeGCPCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetUserScopeGCPCredentials returns GCP service identity status.
//
//encore:api auth method=GET path=/api/users/:id/cloud/gcp
func (s *Service) GetUserScopeGCPCredentials(ctx context.Context, id string) (*UserScopeGCPCredentialGetResponse, error) {
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
	rec, err := getUserScopeGCPCredentials(ctx, s.db, box, pc.userScope.ID)
	if err != nil {
		log.Printf("gcp get: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load gcp credentials").Err()
	}
	updatedAt := ""
	clientEmail := ""
	providerProjectID := ""
	selectedProjectID := ""
	if rec != nil {
		if payload, err := parseGCPServiceAccountJSON(rec.ServiceAccountJSON); err == nil {
			clientEmail = payload.ClientEmail
			providerProjectID = payload.ProjectID
		}
		selectedProjectID = rec.ProjectIDOverride
		if !rec.UpdatedAt.IsZero() {
			updatedAt = rec.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	return &UserScopeGCPCredentialGetResponse{
		Configured:          rec != nil && rec.ServiceAccountJSON != "",
		ClientEmail:         clientEmail,
		UserScopeID:         providerProjectID,
		SelectedUserScopeID: selectedProjectID,
		UpdatedAt:           updatedAt,
	}, nil
}

// PutUserScopeGCPCredentials stores GCP service identity JSON.
//
//encore:api auth method=PUT path=/api/users/:id/cloud/gcp
func (s *Service) PutUserScopeGCPCredentials(ctx context.Context, id string, req *UserScopeGCPCredentialPutRequest) (*UserScopeGCPCredentialStatusResponse, error) {
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
	if err := putUserScopeGCPCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.userScope.ID, req.ServiceAccountJSON, req.UserScopeID); err != nil {
		log.Printf("gcp put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.gcp.set", pc.userScope.ID, "")
	}
	return &UserScopeGCPCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteUserScopeGCPCredentials clears GCP credentials.
//
//encore:api auth method=DELETE path=/api/users/:id/cloud/gcp
func (s *Service) DeleteUserScopeGCPCredentials(ctx context.Context, id string) (*UserScopeGCPCredentialStatusResponse, error) {
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
	if err := deleteUserScopeGCPCredentials(ctx, s.db, pc.userScope.ID); err != nil {
		log.Printf("gcp delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "user-scope.cloud.gcp.clear", pc.userScope.ID, "")
	}
	return &UserScopeGCPCredentialStatusResponse{Status: "ok"}, nil
}
