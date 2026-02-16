package skyforge

import "context"

// ListNetlabServers returns netlab server configs for the authenticated user.
//
//encore:api auth method=GET path=/api/netlab/servers
func (s *Service) ListNetlabServers(ctx context.Context) (*UserNetlabServersResponse, error) {
	return s.ListUserNetlabServers(ctx)
}

// UpsertNetlabServer upserts one netlab server config for the authenticated user.
//
//encore:api auth method=PUT path=/api/netlab/servers
func (s *Service) UpsertNetlabServer(ctx context.Context, payload *UserNetlabServerConfig) (*UserNetlabServerConfig, error) {
	return s.UpsertUserNetlabServer(ctx, payload)
}

// DeleteNetlabServer deletes one netlab server config for the authenticated user.
//
//encore:api auth method=DELETE path=/api/netlab/servers/:serverID
func (s *Service) DeleteNetlabServer(ctx context.Context, serverID string) error {
	return s.DeleteUserNetlabServer(ctx, serverID)
}

// GetNetlabServerHealth probes netlab server health for the authenticated user.
//
//encore:api auth method=GET path=/api/netlab/servers/:serverID/health
func (s *Service) GetNetlabServerHealth(ctx context.Context, serverID string) (*UserOwnerServerHealthResponse, error) {
	return s.GetUserNetlabServerHealth(ctx, personalOwnerRouteKey, serverID)
}

// ListEveServers returns EVE server configs for the authenticated user.
//
//encore:api auth method=GET path=/api/eve/servers
func (s *Service) ListEveServers(ctx context.Context) (*UserEveServersResponse, error) {
	return s.ListUserEveServers(ctx)
}

// UpsertEveServer upserts one EVE server config for the authenticated user.
//
//encore:api auth method=PUT path=/api/eve/servers
func (s *Service) UpsertEveServer(ctx context.Context, payload *UserEveServerConfig) (*UserEveServerConfig, error) {
	return s.UpsertUserEveServer(ctx, payload)
}

// DeleteEveServer deletes one EVE server config for the authenticated user.
//
//encore:api auth method=DELETE path=/api/eve/servers/:serverID
func (s *Service) DeleteEveServer(ctx context.Context, serverID string) error {
	return s.DeleteUserEveServer(ctx, serverID)
}

// ListEveLabs lists EVE labs for the authenticated user.
//
//encore:api auth method=GET path=/api/eve/labs
func (s *Service) ListEveLabs(ctx context.Context, req *UserEveLabsRequest) (*UserEveLabsResponse, error) {
	return s.ListUserEveLabs(ctx, personalOwnerRouteKey, req)
}

// ImportEveLab imports an EVE lab into a deployment for the authenticated user.
//
//encore:api auth method=POST path=/api/eve/import
func (s *Service) ImportEveLab(ctx context.Context, req *UserEveImportRequest) (*UserDeployment, error) {
	return s.ImportUserEveLab(ctx, personalOwnerRouteKey, req)
}

// ConvertEveLab converts an EVE lab to topology YAML for the authenticated user.
//
//encore:api auth method=POST path=/api/eve/convert
func (s *Service) ConvertEveLab(ctx context.Context, req *UserEveConvertRequest) (*UserEveConvertResponse, error) {
	return s.ConvertUserEveLab(ctx, personalOwnerRouteKey, req)
}

// GetNetlabTemplates returns netlab templates for the authenticated user.
//
//encore:api auth method=GET path=/api/netlab/templates
func (s *Service) GetNetlabTemplates(ctx context.Context, req *UserNetlabTemplatesRequest) (*UserNetlabTemplatesResponse, error) {
	return s.GetUserNetlabTemplates(ctx, personalOwnerRouteKey, req)
}

// GetNetlabTemplate returns one netlab template file.
//
//encore:api auth method=GET path=/api/netlab/template
func (s *Service) GetNetlabTemplate(ctx context.Context, req *UserNetlabTemplateRequest) (*UserNetlabTemplateResponse, error) {
	return s.GetUserNetlabTemplate(ctx, personalOwnerRouteKey, req)
}

// ValidateNetlabTemplate validates netlab template expansion.
//
//encore:api auth method=POST path=/api/netlab/validate
func (s *Service) ValidateNetlabTemplate(ctx context.Context, req *UserNetlabValidateRequest) (*UserRunResponse, error) {
	return s.ValidateUserNetlabTemplate(ctx, personalOwnerRouteKey, req)
}

// SyncBlueprintCatalog syncs the user's default blueprint catalog into the personal repo.
//
//encore:api auth method=POST path=/api/blueprints/sync
func (s *Service) SyncBlueprintCatalog(ctx context.Context) (*BlueprintSyncResponse, error) {
	return s.SyncUserBlueprint(ctx, personalOwnerRouteKey)
}

// GetContainerlabTemplates returns containerlab templates for the authenticated user.
//
//encore:api auth method=GET path=/api/containerlab/templates
func (s *Service) GetContainerlabTemplates(ctx context.Context, req *UserContainerlabTemplatesRequest) (*UserContainerlabTemplatesResponse, error) {
	return s.GetUserContainerlabTemplates(ctx, personalOwnerRouteKey, req)
}

// GetContainerlabTemplate returns one containerlab template file.
//
//encore:api auth method=GET path=/api/containerlab/template
func (s *Service) GetContainerlabTemplate(ctx context.Context, req *UserContainerlabTemplateRequest) (*UserContainerlabTemplateResponse, error) {
	return s.GetUserContainerlabTemplate(ctx, personalOwnerRouteKey, req)
}

// GetTerraformTemplates returns terraform templates for the authenticated user.
//
//encore:api auth method=GET path=/api/terraform/templates
func (s *Service) GetTerraformTemplates(ctx context.Context, req *UserTerraformTemplatesRequest) (*UserTerraformTemplatesResponse, error) {
	return s.GetUserTerraformTemplates(ctx, personalOwnerRouteKey, req)
}

// UpdateSettings updates user settings for the authenticated user.
//
//encore:api auth method=PUT path=/api/settings
func (s *Service) UpdateSettings(ctx context.Context, req *UserSettingsRequest) (*OwnerContextSettingsResponse, error) {
	return s.UpdateUserSettings(ctx, personalOwnerRouteKey, req)
}

// ListArtifacts lists artifacts for the authenticated user.
//
//encore:api auth method=GET path=/api/artifacts
func (s *Service) ListArtifacts(ctx context.Context, params *UserArtifactsListParams) (*UserArtifactsListResponse, error) {
	return s.ListUserArtifacts(ctx, personalOwnerRouteKey, params)
}

// DownloadArtifact downloads one artifact payload for the authenticated user.
//
//encore:api auth method=GET path=/api/artifacts/download
func (s *Service) DownloadArtifact(ctx context.Context, params *UserArtifactDownloadParams) (*UserArtifactDownloadResponse, error) {
	return s.DownloadUserArtifact(ctx, personalOwnerRouteKey, params)
}

// PutArtifactObject writes one artifact object for the authenticated user.
//
//encore:api auth method=POST path=/api/artifacts/object
func (s *Service) PutArtifactObject(ctx context.Context, req *UserArtifactPutObjectRequest) (*UserArtifactPutObjectResponse, error) {
	return s.PutUserArtifactObject(ctx, personalOwnerRouteKey, req)
}

// DeleteArtifactObject deletes one artifact object for the authenticated user.
//
//encore:api auth method=DELETE path=/api/artifacts/object
func (s *Service) DeleteArtifactObject(ctx context.Context, params *UserArtifactDeleteParams) (*UserArtifactDeleteResponse, error) {
	return s.DeleteUserArtifactObject(ctx, personalOwnerRouteKey, params)
}

// CreateArtifactFolder creates an artifact folder prefix for the authenticated user.
//
//encore:api auth method=POST path=/api/artifacts/folder
func (s *Service) CreateArtifactFolder(ctx context.Context, req *UserArtifactCreateFolderRequest) (*UserArtifactCreateFolderResponse, error) {
	return s.CreateUserArtifactFolder(ctx, personalOwnerRouteKey, req)
}

// UploadArtifact uploads content and returns stored key metadata for the authenticated user.
//
//encore:api auth method=POST path=/api/artifacts/upload
func (s *Service) UploadArtifact(ctx context.Context, req *UserArtifactUploadRequest) (*UserArtifactUploadResponse, error) {
	return s.UploadUserArtifact(ctx, personalOwnerRouteKey, req)
}

// ListVariableGroups lists variable groups for the authenticated user.
//
//encore:api auth method=GET path=/api/variable-groups
func (s *Service) ListVariableGroups(ctx context.Context) (*UserVariableGroupListResponse, error) {
	return s.ListUserVariableGroups(ctx)
}

// CreateVariableGroup creates a variable group for the authenticated user.
//
//encore:api auth method=POST path=/api/variable-groups
func (s *Service) CreateVariableGroup(ctx context.Context, req *UserVariableGroupUpsertRequest) (*UserVariableGroup, error) {
	return s.CreateUserVariableGroup(ctx, req)
}

// UpdateVariableGroup updates a variable group for the authenticated user.
//
//encore:api auth method=PUT path=/api/variable-groups/:groupID
func (s *Service) UpdateVariableGroup(ctx context.Context, groupID int, req *UserVariableGroupUpsertRequest) (*UserVariableGroup, error) {
	return s.UpdateUserVariableGroup(ctx, groupID, req)
}

// DeleteVariableGroup deletes a variable group for the authenticated user.
//
//encore:api auth method=DELETE path=/api/variable-groups/:groupID
func (s *Service) DeleteVariableGroup(ctx context.Context, groupID int) (*UserVariableGroupListResponse, error) {
	return s.DeleteUserVariableGroup(ctx, groupID)
}
