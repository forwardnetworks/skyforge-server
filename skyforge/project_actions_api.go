package skyforge

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

// SyncProject syncs resources for a single project.
//
//encore:api auth method=POST path=/api/projects/:id/sync
func (s *Service) SyncProject(ctx context.Context, id string) (*projectSyncReport, error) {
	projectSyncManualRequests.Add(1)
	user, err := requireAuthUser()
	if err != nil {
		projectSyncFailures.Add(1)
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		projectSyncFailures.Add(1)
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		projectSyncFailures.Add(1)
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report := syncProjectResources(ctx, s.cfg, &pc.project)
	if report.Updated {
		pc.projects[pc.idx] = pc.project
		if err := s.projectStore.save(pc.projects); err != nil {
			log.Printf("projects save after sync: %v", err)
			projectSyncFailures.Add(1)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist sync").Err()
		}
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		details := fmt.Sprintf("updated=%t errors=%d", report.Updated, len(report.Errors))
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.sync.manual", pc.project.ID, details)
	}
	if len(report.Errors) > 0 {
		projectSyncProjectErrors.Add(1)
	}
	return &report, nil
}

// SyncProjectV1 syncs resources for a single project (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/sync
func (s *Service) SyncProjectV1(ctx context.Context, id string) (*projectSyncReport, error) {
	return s.SyncProject(ctx, id)
}

type ProjectMembersRequest struct {
	IsPublic     *bool    `json:"isPublic,omitempty"`
	Owners       []string `json:"owners"`
	OwnerGroups  []string `json:"ownerGroups"`
	Editors      []string `json:"editors"`
	EditorGroups []string `json:"editorGroups"`
	Viewers      []string `json:"viewers"`
	ViewerGroups []string `json:"viewerGroups"`
}

// UpdateProjectMembers updates project membership.
//
//encore:api auth method=PUT path=/api/projects/:id/members
func (s *Service) UpdateProjectMembers(ctx context.Context, id string, req *ProjectMembersRequest) (*SkyforgeProject, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if pc.access != "admin" && !containsUser(nextOwners, user.Username) && !strings.EqualFold(pc.project.CreatedBy, user.Username) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("you cannot remove yourself from owners").Err()
	}
	if req.IsPublic != nil {
		pc.project.IsPublic = *req.IsPublic
	}
	pc.project.Owners = nextOwners
	pc.project.OwnerGroups = nextOwnerGroups
	pc.project.Editors = nextEditors
	pc.project.EditorGroups = nextEditorGroups
	pc.project.Viewers = nextViewers
	pc.project.ViewerGroups = nextViewerGroups
	pc.projects[pc.idx] = pc.project
	if err := s.projectStore.save(pc.projects); err != nil {
		log.Printf("projects save: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist members").Err()
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
			"project.members.update",
			pc.project.ID,
			fmt.Sprintf("owners=%d ownerGroups=%d editors=%d editorGroups=%d viewers=%d viewerGroups=%d", len(pc.project.Owners), len(pc.project.OwnerGroups), len(pc.project.Editors), len(pc.project.EditorGroups), len(pc.project.Viewers), len(pc.project.ViewerGroups)),
		)
	}
	syncGiteaCollaboratorsForProject(s.cfg, pc.project)
	return &pc.project, nil
}

// UpdateProjectMembersV1 updates project membership (v1 alias).
//
//encore:api auth method=PUT path=/api/v1/projects/:id/members
func (s *Service) UpdateProjectMembersV1(ctx context.Context, id string, req *ProjectMembersRequest) (*SkyforgeProject, error) {
	return s.UpdateProjectMembers(ctx, id, req)
}

type ProjectEveConfigResponse struct {
	ProjectID    string   `json:"projectId"`
	EveServer    string   `json:"eveServer"`
	EveServers   []string `json:"eveServers"`
	SemaphorePID int      `json:"semaphorePid"`
}

type ProjectEveConfigRequest struct {
	EveServer string `json:"eveServer"`
}

// GetProjectEve returns the project's EVE server selection.
//
//encore:api auth method=GET path=/api/projects/:id/eve
func (s *Service) GetProjectEve(ctx context.Context, id string) (*ProjectEveConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	_ = ctx
	return &ProjectEveConfigResponse{
		ProjectID:    pc.project.ID,
		EveServer:    pc.project.EveServer,
		EveServers:   eveServerNames(s.cfg.EveServers),
		SemaphorePID: pc.project.SemaphoreProjectID,
	}, nil
}

// UpdateProjectEve updates the project's EVE server selection.
//
//encore:api auth method=PUT path=/api/projects/:id/eve
func (s *Service) UpdateProjectEve(ctx context.Context, id string, req *ProjectEveConfigRequest) (*SkyforgeProject, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	next := strings.TrimSpace(req.EveServer)
	if next != "" && eveServerByName(s.cfg.EveServers, next) == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown eveServer").Err()
	}
	pc.project.EveServer = next
	pc.projects[pc.idx] = pc.project
	if err := s.projectStore.save(pc.projects); err != nil {
		log.Printf("projects save: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist eve server").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.eve.update", pc.project.ID, fmt.Sprintf("eveServer=%s", next))
	}
	return &pc.project, nil
}

// GetProjectEveV1 returns the project's EVE server selection (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/eve
func (s *Service) GetProjectEveV1(ctx context.Context, id string) (*ProjectEveConfigResponse, error) {
	return s.GetProjectEve(ctx, id)
}

// UpdateProjectEveV1 updates the project's EVE server selection (v1 alias).
//
//encore:api auth method=PUT path=/api/v1/projects/:id/eve
func (s *Service) UpdateProjectEveV1(ctx context.Context, id string, req *ProjectEveConfigRequest) (*SkyforgeProject, error) {
	return s.UpdateProjectEve(ctx, id, req)
}

type ProjectNetlabConfigResponse struct {
	ProjectID     string   `json:"projectId"`
	NetlabServer  string   `json:"netlabServer"`
	NetlabServers []string `json:"netlabServers"`
	SemaphorePID  int      `json:"semaphorePid"`
}

type ProjectNetlabConfigRequest struct {
	NetlabServer string `json:"netlabServer"`
}

// GetProjectNetlab returns the project's netlab server selection.
//
//encore:api auth method=GET path=/api/projects/:id/netlab
func (s *Service) GetProjectNetlab(ctx context.Context, id string) (*ProjectNetlabConfigResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access != "admin" && pc.access != "owner" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	_ = ctx
	return &ProjectNetlabConfigResponse{
		ProjectID:     pc.project.ID,
		NetlabServer:  pc.project.NetlabServer,
		NetlabServers: netlabServerNamesForConfig(s.cfg),
		SemaphorePID:  pc.project.SemaphoreProjectID,
	}, nil
}

// UpdateProjectNetlab updates the project's netlab server selection.
//
//encore:api auth method=PUT path=/api/projects/:id/netlab
func (s *Service) UpdateProjectNetlab(ctx context.Context, id string, req *ProjectNetlabConfigRequest) (*SkyforgeProject, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if next != "" && netlabServerByNameForConfig(s.cfg, next) == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown netlabServer").Err()
	}
	pc.project.NetlabServer = next
	pc.projects[pc.idx] = pc.project
	if err := s.projectStore.save(pc.projects); err != nil {
		log.Printf("projects save: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist netlab server").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.netlab.update", pc.project.ID, fmt.Sprintf("netlabServer=%s", next))
	}
	return &pc.project, nil
}

// GetProjectNetlabV1 returns the project's netlab server selection (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/netlab
func (s *Service) GetProjectNetlabV1(ctx context.Context, id string) (*ProjectNetlabConfigResponse, error) {
	return s.GetProjectNetlab(ctx, id)
}

// UpdateProjectNetlabV1 updates the project's netlab server selection (v1 alias).
//
//encore:api auth method=PUT path=/api/v1/projects/:id/netlab
func (s *Service) UpdateProjectNetlabV1(ctx context.Context, id string, req *ProjectNetlabConfigRequest) (*SkyforgeProject, error) {
	return s.UpdateProjectNetlab(ctx, id, req)
}

type ProjectEveLabResponse struct {
	ProjectID   string `json:"projectId"`
	ProjectSlug string `json:"projectSlug"`
	Owner       string `json:"owner"`
	EveServer   string `json:"eveServer"`
	LabPath     string `json:"labPath"`
	Exists      bool   `json:"exists"`
	Created     bool   `json:"created"`
}

// GetProjectEveLab returns EVE lab state for the project.
//
//encore:api auth method=GET path=/api/projects/:id/eve/lab
func (s *Service) GetProjectEveLab(ctx context.Context, id string) (*ProjectEveLabResponse, error) {
	return s.handleProjectEveLab(ctx, id, false)
}

// CreateProjectEveLab creates an EVE lab for the project.
//
//encore:api auth method=POST path=/api/projects/:id/eve/lab
func (s *Service) CreateProjectEveLab(ctx context.Context, id string) (*ProjectEveLabResponse, error) {
	return s.handleProjectEveLab(ctx, id, true)
}

// GetProjectEveLabV1 returns EVE lab state for the project (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/eve/lab
func (s *Service) GetProjectEveLabV1(ctx context.Context, id string) (*ProjectEveLabResponse, error) {
	return s.GetProjectEveLab(ctx, id)
}

// CreateProjectEveLabV1 creates an EVE lab for the project (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/eve/lab
func (s *Service) CreateProjectEveLabV1(ctx context.Context, id string) (*ProjectEveLabResponse, error) {
	return s.CreateProjectEveLab(ctx, id)
}

func (s *Service) handleProjectEveLab(ctx context.Context, id string, create bool) (*ProjectEveLabResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if create && pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	owner := projectPrimaryOwner(pc.project)
	if owner == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("project owner is required").Err()
	}
	eveServerName := strings.TrimSpace(pc.project.EveServer)
	var server *EveServerConfig
	for i := range s.cfg.EveServers {
		if eveServerName == "" || strings.EqualFold(s.cfg.EveServers[i].Name, eveServerName) {
			server = &s.cfg.EveServers[i]
			break
		}
	}
	if server == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("no eve-ng servers configured").Err()
	}
	labsPath := strings.TrimSpace(server.LabsPath)
	if labsPath == "" {
		labsPath = strings.TrimSpace(s.cfg.Labs.EveLabsPath)
	}
	labPath := eveLabPathForProject(labsPath, owner, pc.project.Slug)
	exists := false
	created := false

	if create {
		path, existed, err := ensureEveLabViaSSH(ctx, s.cfg.Labs, *server, owner, pc.project.Slug)
		if err != nil {
			log.Printf("ensure eve lab: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to create lab").Err()
		}
		labPath = path
		exists = true
		created = !existed
	} else if labPath != "" && strings.TrimSpace(s.cfg.Labs.EveSSHKeyFile) != "" {
		if ok, _, err := eveLabExistsViaSSH(ctx, s.cfg.Labs, *server, owner, pc.project.Slug); err == nil {
			exists = ok
		}
	}

	return &ProjectEveLabResponse{
		ProjectID:   pc.project.ID,
		ProjectSlug: pc.project.Slug,
		Owner:       owner,
		EveServer:   server.Name,
		LabPath:     labPath,
		Exists:      exists,
		Created:     created,
	}, nil
}

type ProjectAWSStaticGetResponse struct {
	Configured     bool   `json:"configured"`
	AccessKeyLast4 string `json:"accessKeyLast4,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type ProjectAWSStaticPutRequest struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken,omitempty"`
}

type ProjectAWSStaticStatusResponse struct {
	Status string `json:"status"`
}

// GetProjectAWSStatic returns AWS static credential status.
//
//encore:api auth method=GET path=/api/projects/:id/cloud/aws-static
func (s *Service) GetProjectAWSStatic(ctx context.Context, id string) (*ProjectAWSStaticGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	rec, err := getProjectAWSStaticCredentials(ctx, s.db, box, pc.project.ID)
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
	return &ProjectAWSStaticGetResponse{
		Configured:     rec != nil && rec.AccessKeyID != "" && rec.SecretAccessKey != "",
		AccessKeyLast4: akidLast4,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutProjectAWSStatic stores AWS static credentials.
//
//encore:api auth method=PUT path=/api/projects/:id/cloud/aws-static
func (s *Service) PutProjectAWSStatic(ctx context.Context, id string, req *ProjectAWSStaticPutRequest) (*ProjectAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := putProjectAWSStaticCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.project.ID, req.AccessKeyID, req.SecretAccessKey, req.SessionToken); err != nil {
		log.Printf("aws static put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.cloud.aws-static.set", pc.project.ID, "")
	}
	return &ProjectAWSStaticStatusResponse{Status: "ok"}, nil
}

// DeleteProjectAWSStatic clears AWS static credentials.
//
//encore:api auth method=DELETE path=/api/projects/:id/cloud/aws-static
func (s *Service) DeleteProjectAWSStatic(ctx context.Context, id string) (*ProjectAWSStaticStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := deleteProjectAWSStaticCredentials(ctx, s.db, pc.project.ID); err != nil {
		log.Printf("aws static delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete aws static credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.cloud.aws-static.clear", pc.project.ID, "")
	}
	return &ProjectAWSStaticStatusResponse{Status: "ok"}, nil
}

// GetProjectAWSStaticV1 returns AWS static credential status (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/cloud/aws-static
func (s *Service) GetProjectAWSStaticV1(ctx context.Context, id string) (*ProjectAWSStaticGetResponse, error) {
	return s.GetProjectAWSStatic(ctx, id)
}

// PutProjectAWSStaticV1 stores AWS static credentials (v1 alias).
//
//encore:api auth method=PUT path=/api/v1/projects/:id/cloud/aws-static
func (s *Service) PutProjectAWSStaticV1(ctx context.Context, id string, req *ProjectAWSStaticPutRequest) (*ProjectAWSStaticStatusResponse, error) {
	return s.PutProjectAWSStatic(ctx, id, req)
}

// DeleteProjectAWSStaticV1 clears AWS static credentials (v1 alias).
//
//encore:api auth method=DELETE path=/api/v1/projects/:id/cloud/aws-static
func (s *Service) DeleteProjectAWSStaticV1(ctx context.Context, id string) (*ProjectAWSStaticStatusResponse, error) {
	return s.DeleteProjectAWSStatic(ctx, id)
}

type ProjectAzureCredentialGetResponse struct {
	Configured     bool   `json:"configured"`
	TenantID       string `json:"tenantId,omitempty"`
	ClientID       string `json:"clientId,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
}

type ProjectAzureCredentialPutRequest struct {
	TenantID       string `json:"tenantId"`
	ClientID       string `json:"clientId"`
	ClientSecret   string `json:"clientSecret"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
}

type ProjectAzureCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetProjectAzureCredentials returns Azure service principal status.
//
//encore:api auth method=GET path=/api/projects/:id/cloud/azure
func (s *Service) GetProjectAzureCredentials(ctx context.Context, id string) (*ProjectAzureCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	rec, err := getProjectAzureCredentials(ctx, s.db, box, pc.project.ID)
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
	return &ProjectAzureCredentialGetResponse{
		Configured:     rec != nil && rec.ClientID != "" && rec.ClientSecret != "",
		TenantID:       tenantID,
		ClientID:       clientID,
		SubscriptionID: subscriptionID,
		UpdatedAt:      updatedAt,
	}, nil
}

// PutProjectAzureCredentials stores Azure service principal credentials.
//
//encore:api auth method=PUT path=/api/projects/:id/cloud/azure
func (s *Service) PutProjectAzureCredentials(ctx context.Context, id string, req *ProjectAzureCredentialPutRequest) (*ProjectAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := putProjectAzureCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.project.ID, cred); err != nil {
		log.Printf("azure put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.cloud.azure.set", pc.project.ID, "")
	}
	return &ProjectAzureCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteProjectAzureCredentials clears Azure credentials.
//
//encore:api auth method=DELETE path=/api/projects/:id/cloud/azure
func (s *Service) DeleteProjectAzureCredentials(ctx context.Context, id string) (*ProjectAzureCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := deleteProjectAzureCredentials(ctx, s.db, pc.project.ID); err != nil {
		log.Printf("azure delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete azure credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.cloud.azure.clear", pc.project.ID, "")
	}
	return &ProjectAzureCredentialStatusResponse{Status: "ok"}, nil
}

// GetProjectAzureCredentialsV1 returns Azure credential status (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/cloud/azure
func (s *Service) GetProjectAzureCredentialsV1(ctx context.Context, id string) (*ProjectAzureCredentialGetResponse, error) {
	return s.GetProjectAzureCredentials(ctx, id)
}

// PutProjectAzureCredentialsV1 stores Azure credentials (v1 alias).
//
//encore:api auth method=PUT path=/api/v1/projects/:id/cloud/azure
func (s *Service) PutProjectAzureCredentialsV1(ctx context.Context, id string, req *ProjectAzureCredentialPutRequest) (*ProjectAzureCredentialStatusResponse, error) {
	return s.PutProjectAzureCredentials(ctx, id, req)
}

// DeleteProjectAzureCredentialsV1 clears Azure credentials (v1 alias).
//
//encore:api auth method=DELETE path=/api/v1/projects/:id/cloud/azure
func (s *Service) DeleteProjectAzureCredentialsV1(ctx context.Context, id string) (*ProjectAzureCredentialStatusResponse, error) {
	return s.DeleteProjectAzureCredentials(ctx, id)
}

type ProjectGCPCredentialGetResponse struct {
	Configured        bool   `json:"configured"`
	ClientEmail       string `json:"clientEmail,omitempty"`
	ProjectID         string `json:"projectId,omitempty"`
	SelectedProjectID string `json:"selectedProjectId,omitempty"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
}

type ProjectGCPCredentialPutRequest struct {
	ServiceAccountJSON string `json:"serviceAccountJson"`
	ProjectID          string `json:"projectId,omitempty"`
}

type ProjectGCPCredentialStatusResponse struct {
	Status string `json:"status"`
}

// GetProjectGCPCredentials returns GCP service account status.
//
//encore:api auth method=GET path=/api/projects/:id/cloud/gcp
func (s *Service) GetProjectGCPCredentials(ctx context.Context, id string) (*ProjectGCPCredentialGetResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	rec, err := getProjectGCPCredentials(ctx, s.db, box, pc.project.ID)
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
	return &ProjectGCPCredentialGetResponse{
		Configured:        rec != nil && rec.ServiceAccountJSON != "",
		ClientEmail:       clientEmail,
		ProjectID:         projectID,
		SelectedProjectID: selectedProjectID,
		UpdatedAt:         updatedAt,
	}, nil
}

// PutProjectGCPCredentials stores GCP service account JSON.
//
//encore:api auth method=PUT path=/api/projects/:id/cloud/gcp
func (s *Service) PutProjectGCPCredentials(ctx context.Context, id string, req *ProjectGCPCredentialPutRequest) (*ProjectGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := putProjectGCPCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), pc.project.ID, req.ServiceAccountJSON, req.ProjectID); err != nil {
		log.Printf("gcp put: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to store gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.cloud.gcp.set", pc.project.ID, "")
	}
	return &ProjectGCPCredentialStatusResponse{Status: "ok"}, nil
}

// DeleteProjectGCPCredentials clears GCP credentials.
//
//encore:api auth method=DELETE path=/api/projects/:id/cloud/gcp
func (s *Service) DeleteProjectGCPCredentials(ctx context.Context, id string) (*ProjectGCPCredentialStatusResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	if err := deleteProjectGCPCredentials(ctx, s.db, pc.project.ID); err != nil {
		log.Printf("gcp delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete gcp credentials").Err()
	}
	{
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(ctx, s.db, actor, actorIsAdmin, impersonated, "project.cloud.gcp.clear", pc.project.ID, "")
	}
	return &ProjectGCPCredentialStatusResponse{Status: "ok"}, nil
}

// GetProjectGCPCredentialsV1 returns GCP credential status (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/cloud/gcp
func (s *Service) GetProjectGCPCredentialsV1(ctx context.Context, id string) (*ProjectGCPCredentialGetResponse, error) {
	return s.GetProjectGCPCredentials(ctx, id)
}

// PutProjectGCPCredentialsV1 stores GCP credentials (v1 alias).
//
//encore:api auth method=PUT path=/api/v1/projects/:id/cloud/gcp
func (s *Service) PutProjectGCPCredentialsV1(ctx context.Context, id string, req *ProjectGCPCredentialPutRequest) (*ProjectGCPCredentialStatusResponse, error) {
	return s.PutProjectGCPCredentials(ctx, id, req)
}

// DeleteProjectGCPCredentialsV1 clears GCP credentials (v1 alias).
//
//encore:api auth method=DELETE path=/api/v1/projects/:id/cloud/gcp
func (s *Service) DeleteProjectGCPCredentialsV1(ctx context.Context, id string) (*ProjectGCPCredentialStatusResponse, error) {
	return s.DeleteProjectGCPCredentials(ctx, id)
}
