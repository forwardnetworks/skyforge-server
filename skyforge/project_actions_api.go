package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

// SyncOwnerContext syncs resources for a single owner context.
//
// Deprecated public route removed: /sync
func (s *Service) SyncOwnerContext(ctx context.Context, id string) (*userSyncReport, error) {
	_ = ctx
	_ = id
	return nil, errs.B().Code(errs.FailedPrecondition).Msg("shared context sync is no longer supported").Err()
}

type UserMembersRequest struct {
	IsPublic     *bool    `json:"isPublic,omitempty"`
	Owners       []string `json:"owners"`
	OwnerGroups  []string `json:"ownerGroups"`
	Editors      []string `json:"editors"`
	EditorGroups []string `json:"editorGroups"`
	Viewers      []string `json:"viewers"`
	ViewerGroups []string `json:"viewerGroups"`
}

// UpdateOwnerMembers updates owner membership.
//
// Deprecated public route removed: /members
func (s *Service) UpdateOwnerMembers(ctx context.Context, id string, req *UserMembersRequest) (*SkyforgeUserContext, error) {
	_ = ctx
	_ = id
	_ = req
	return nil, errs.B().Code(errs.FailedPrecondition).Msg("sharing is disabled; resources are per-user only").Err()
}

type UserNetlabConfigResponse struct {
	OwnerUsername string   `json:"ownerUsername"`
	NetlabServer  string   `json:"netlabServer"`
	NetlabServers []string `json:"netlabServers"`
}

type UserNetlabConfigRequest struct {
	NetlabServer string `json:"netlabServer"`
}

// GetOwnerNetlab returns the owner netlab server selection.
func (s *Service) GetOwnerNetlab(ctx context.Context, id string) (*UserNetlabConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	_ = ctx
	return &UserNetlabConfigResponse{
		OwnerUsername: pc.context.ID,
		NetlabServer:  pc.context.NetlabServer,
		NetlabServers: []string{},
	}, nil
}

// UpdateOwnerNetlab updates the owner netlab server selection.
func (s *Service) UpdateOwnerNetlab(ctx context.Context, id string, req *UserNetlabConfigRequest) (*SkyforgeUserContext, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
			return nil, errs.B().Code(errs.InvalidArgument).Msg("netlabServer must reference a user server (user:... or legacy ws:...)").Err()
		}
		if s.db == nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
		}
		rec, err := getUserNetlabServerByID(ctx, s.db, s.box, pc.context.ID, serverID)
		if err != nil || rec == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown netlabServer").Err()
		}
	}
	pc.context.NetlabServer = next
	if err := s.ownerContextStore.upsert(pc.context); err != nil {
		log.Printf("context upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist netlab server").Err()
	}
	if s.db != nil {
		_ = notifyUsersUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.netlab.update", pc.context.ID, fmt.Sprintf("netlabServer=%s", next))
	}
	return &pc.context, nil
}

type UserAWSStaticGetResponse struct {
	Configured     bool   `json:"configured"`
	AccessKeyLast4 string `json:"accessKeyLast4,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserAWSStaticPutRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

type UserAWSStaticStatusResponse struct {
	Status string `json:"status"`
}

type UserAWSSSOUpdateRequest struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

type UserAWSSSOUpdateResponse struct {
	Status    string `json:"status"`
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
	Region    string `json:"region,omitempty"`
}

// PutOwnerAWSSSOConfig stores the AWS SSO account/role for the owner context.
func (s *Service) PutOwnerAWSSSOConfig(ctx context.Context, id string, req *UserAWSSSOUpdateRequest) (*UserAWSSSOUpdateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if region == "" && pc.context.AWSRegion == "" && s.cfg.AwsSSORegion != "" {
		region = strings.TrimSpace(s.cfg.AwsSSORegion)
	}
	if region != "" {
		pc.context.AWSRegion = region
	}
	pc.context.AWSAccountID = accountID
	pc.context.AWSRoleName = roleName
	pc.context.AWSAuthMethod = "sso"
	if err := s.ownerContextStore.upsert(pc.context); err != nil {
		log.Printf("context upsert: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist aws sso config").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("accountId=%s roleName=%s", accountID, roleName)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.aws-sso.set", pc.context.ID, details)
	}
	return &UserAWSSSOUpdateResponse{
		Status:    "ok",
		AccountID: accountID,
		RoleName:  roleName,
		Region:    pc.context.AWSRegion,
	}, nil
}

// GetOwnerAWSStatic returns AWS static credential status.
func (s *Service) GetOwnerAWSStatic(ctx context.Context, id string) (*UserAWSStaticGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	rec, err := getOwnerAWSStaticCredentials(ctx, s.db, box, pc.context.ID)
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
	return &UserAWSStaticGetResponse{
		Configured:     rec != nil && rec.AccessKeyID != "" && rec.SecretAccessKey != "",
		AccessKeyLast4: akidLast4,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutOwnerAWSStatic stores AWS static credentials.
func (s *Service) PutOwnerAWSStatic(ctx context.Context, id string, req *UserAWSStaticPutRequest) (*UserAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := putOwnerAWSStaticCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.context.ID, req.AccessKeyID, req.SecretAccessKey, req.SessionToken); err != nil {
		log.Printf("aws static put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.aws-static.set", pc.context.ID, "")
	}
	return &UserAWSStaticStatusResponse{Status: "ok"}, nil
}

// DeleteOwnerAWSStatic clears AWS static credentials.
func (s *Service) DeleteOwnerAWSStatic(ctx context.Context, id string) (*UserAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := deleteOwnerAWSStaticCredentials(ctx, s.db, pc.context.ID); err != nil {
		log.Printf("aws static delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.aws-static.clear", pc.context.ID, "")
	}
	return &UserAWSStaticStatusResponse{Status: "ok"}, nil
}

type UserAzureCredentialGetResponse struct {
	Configured     bool   `json:"configured"`
	TenantID       string `json:"tenantId,omitempty"`
	ClientID       string `json:"clientId,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type UserAzureCredentialPutRequest struct {
	TenantID       string `json:"tenantId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

type UserAzureCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetOwnerAzureCredentials returns Azure service principal status.
func (s *Service) GetOwnerAzureCredentials(ctx context.Context, id string) (*UserAzureCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	rec, err := getOwnerAzureCredentials(ctx, s.db, box, pc.context.ID)
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
	return &UserAzureCredentialGetResponse{
		Configured:     rec != nil && rec.ClientID != "" && rec.ClientSecret != "",
		TenantID:       tenantID,
		ClientID:       clientID,
		SubscriptionID: subscriptionID,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutOwnerAzureCredentials stores Azure service principal credentials.
func (s *Service) PutOwnerAzureCredentials(ctx context.Context, id string, req *UserAzureCredentialPutRequest) (*UserAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := putOwnerAzureCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.context.ID, cred); err != nil {
		log.Printf("azure put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.azure.set", pc.context.ID, "")
	}
	return &UserAzureCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteOwnerAzureCredentials clears Azure credentials.
func (s *Service) DeleteOwnerAzureCredentials(ctx context.Context, id string) (*UserAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := deleteOwnerAzureCredentials(ctx, s.db, pc.context.ID); err != nil {
		log.Printf("azure delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.azure.clear", pc.context.ID, "")
	}
	return &UserAzureCredentialStatusResponse{Status: "ok"}, nil
}

type UserGCPCredentialGetResponse struct {
	Configured        bool   `json:"configured"`
	ClientEmail       string `json:"clientEmail,omitempty"`
	OwnerUsername     string `json:"ownerUsername,omitempty"`
	SelectedProjectID string `json:"selectedProjectId,omitempty"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
}

type UserGCPCredentialPutRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	OwnerUsername      string `json:"ownerUsername,omitempty"`
}

type UserGCPCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetOwnerGCPCredentials returns GCP service account status.
func (s *Service) GetOwnerGCPCredentials(ctx context.Context, id string) (*UserGCPCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	rec, err := getOwnerGCPCredentials(ctx, s.db, box, pc.context.ID)
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
	return &UserGCPCredentialGetResponse{
		Configured:        rec != nil && rec.ServiceAccountJSON != "",
		ClientEmail:       clientEmail,
		OwnerUsername:     projectID,
		SelectedProjectID: selectedProjectID,
		UpdatedAt:         updatedAt,
	}, nil
}

// PutOwnerGCPCredentials stores GCP service account JSON.
func (s *Service) PutOwnerGCPCredentials(ctx context.Context, id string, req *UserGCPCredentialPutRequest) (*UserGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := putOwnerGCPCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.context.ID, req.ServiceAccountJSON, req.OwnerUsername); err != nil {
		log.Printf("gcp put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.gcp.set", pc.context.ID, "")
	}
	return &UserGCPCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteOwnerGCPCredentials clears GCP credentials.
func (s *Service) DeleteOwnerGCPCredentials(ctx context.Context, id string) (*UserGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	if err := deleteOwnerGCPCredentials(ctx, s.db, pc.context.ID); err != nil {
		log.Printf("gcp delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "context.cloud.gcp.clear", pc.context.ID, "")
	}
	return &UserGCPCredentialStatusResponse{Status: "ok"}, nil
}
