package skyforge

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"gopkg.in/yaml.v3"
)

type CreateContainerlabDeploymentFromYAMLRequest struct {
	// Name becomes the Skyforge deployment name (and drives the containerlab lab name).
	Name string `json:"name"`

	// NetlabServer is a workspace netlab server ref (e.g. "ws:<id>").
	// If omitted, we fall back to the workspace default.
	NetlabServer string `json:"netlabServer,omitempty"`

	// TopologyYAML is the raw containerlab topology YAML.
	TopologyYAML string `json:"topologyYAML"`

	// TemplatesDir is where we store the YAML inside the workspace repo.
	// Default: "containerlab/designer".
	TemplatesDir string `json:"templatesDir,omitempty"`

	// Template is the filename to write under TemplatesDir.
	// Default: "<deployment-name>.clab.yml".
	Template string `json:"template,omitempty"`

	// AutoDeploy queues an initial "create" action after creating the deployment.
	// Default: true.
	AutoDeploy *bool `json:"autoDeploy,omitempty"`
}

type CreateContainerlabDeploymentFromYAMLResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Deployment  *WorkspaceDeployment `json:"deployment,omitempty"`
	Run         JSONMap              `json:"run,omitempty"`
	Note        string               `json:"note,omitempty"`
}

type CreateClabernetesDeploymentFromYAMLRequest struct {
	// Name becomes the Skyforge deployment name (and drives the clabernetes lab name).
	Name string `json:"name"`

	// TopologyYAML is the raw containerlab topology YAML.
	TopologyYAML string `json:"topologyYAML"`

	// TemplatesDir is where we store the YAML inside the workspace repo.
	// Default: "containerlab/designer".
	TemplatesDir string `json:"templatesDir,omitempty"`

	// Template is the filename to write under TemplatesDir.
	// Default: "<deployment-name>.clab.yml".
	Template string `json:"template,omitempty"`

	// AutoDeploy queues an initial "create" action after creating the deployment.
	// Default: true.
	AutoDeploy *bool `json:"autoDeploy,omitempty"`
}

type CreateClabernetesDeploymentFromYAMLResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Deployment  *WorkspaceDeployment `json:"deployment,omitempty"`
	Run         JSONMap              `json:"run,omitempty"`
	Note        string               `json:"note,omitempty"`
}

type SaveContainerlabTopologyYAMLRequest struct {
	// Name drives the default filename.
	Name string `json:"name"`

	// TopologyYAML is the raw containerlab topology YAML.
	TopologyYAML string `json:"topologyYAML"`

	// TemplatesDir is where we store the YAML inside the workspace repo.
	// Default: "containerlab/designer".
	//
	// For this endpoint, TemplatesDir must be under "containerlab/".
	TemplatesDir string `json:"templatesDir,omitempty"`

	// Template is the filename to write under TemplatesDir.
	// Default: "<normalized-name>.clab.yml".
	Template string `json:"template,omitempty"`
}

type SaveContainerlabTopologyYAMLResponse struct {
	WorkspaceID  string `json:"workspaceId"`
	Branch       string `json:"branch"`
	TemplatesDir string `json:"templatesDir"`
	Template     string `json:"template"`
	FilePath     string `json:"filePath"`
}

type SaveNetlabTopologyYAMLRequest struct {
	// Name drives the default filename.
	Name string `json:"name"`

	// TopologyYAML is the raw netlab topology YAML.
	TopologyYAML string `json:"topologyYAML"`

	// TemplatesDir is where we store the YAML inside the workspace repo.
	// Default: "netlab/designer".
	//
	// For this endpoint, TemplatesDir must be under "netlab/" or "blueprints/netlab/".
	TemplatesDir string `json:"templatesDir,omitempty"`

	// Template is the filename to write under TemplatesDir.
	// Default: "<normalized-name>.yml".
	Template string `json:"template,omitempty"`
}

type SaveNetlabTopologyYAMLResponse struct {
	WorkspaceID  string `json:"workspaceId"`
	Branch       string `json:"branch"`
	TemplatesDir string `json:"templatesDir"`
	Template     string `json:"template"`
	FilePath     string `json:"filePath"`
}

type CreateDeploymentFromTemplateRequest struct {
	// Name becomes the Skyforge deployment name (and drives the lab name).
	Name string `json:"name"`

	// TemplateSource is the repository scope to resolve templates from.
	// For now, only "workspace" is supported by this endpoint.
	TemplateSource string `json:"templateSource,omitempty"`

	// TemplatesDir is the repo-relative directory containing the YAML.
	// Default: "containerlab/designer".
	TemplatesDir string `json:"templatesDir,omitempty"`

	// Template is the filename under TemplatesDir.
	Template string `json:"template"`

	// AutoDeploy queues an initial "create" action after creating the deployment.
	// Default: true.
	AutoDeploy *bool `json:"autoDeploy,omitempty"`
}

type CreateDeploymentFromTemplateResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Deployment  *WorkspaceDeployment `json:"deployment,omitempty"`
	Run         JSONMap              `json:"run,omitempty"`
	Note        string               `json:"note,omitempty"`
}

type CreateContainerlabDeploymentFromTemplateRequest struct {
	CreateDeploymentFromTemplateRequest

	// NetlabServer is a workspace netlab server ref (e.g. "ws:<id>").
	// If omitted, we fall back to the workspace default.
	NetlabServer string `json:"netlabServer,omitempty"`
}

// CreateContainerlabDeploymentFromYAML persists a containerlab topology YAML into the workspace repo,
// creates a "containerlab" deployment referencing that template, and (optionally) queues an initial deploy.
//
// NOTE: containerlab is BYOS mode (requires a workspace netlabServer selection).
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments-designer/containerlab/from-yaml
func (s *Service) CreateContainerlabDeploymentFromYAML(ctx context.Context, id string, req *CreateContainerlabDeploymentFromYAMLRequest) (*CreateContainerlabDeploymentFromYAMLResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}
	topologyYAML := strings.TrimSpace(req.TopologyYAML)
	if topologyYAML == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML is required").Err()
	}
	if len(topologyYAML) > (1 << 20) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML too large").Err()
	}

	// Basic validation: require `topology` key.
	{
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(topologyYAML), &parsed); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if parsed == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if _, ok := parsed["topology"]; !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("YAML missing required 'topology' section").Err()
		}
	}

	templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "containerlab/designer"
	}
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}

	template := strings.Trim(strings.TrimSpace(req.Template), "/")
	if template == "" {
		template = name + ".clab.yml"
	}
	if !strings.HasSuffix(template, ".yml") && !strings.HasSuffix(template, ".yaml") {
		template = template + ".yml"
	}
	if strings.Contains(template, "/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a filename").Err()
	}

	branch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	filePath := path.Join(templatesDir, template)
	content := strings.TrimRight(topologyYAML, "\n") + "\n"
	commitMsg := fmt.Sprintf("lab: add containerlab topology (%s)", name)
	{
		ctxWrite, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = ctxWrite
		if err := ensureGiteaFile(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, filePath, content, commitMsg, branch, pc.claims); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to write topology into workspace repo").Err()
		}
	}

	netlabServer := strings.TrimSpace(req.NetlabServer)
	if netlabServer == "" {
		netlabServer = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}

	cfg, err := toJSONMap(map[string]any{
		"netlabServer":   netlabServer,
		"templateSource": "workspace",
		"templatesDir":   templatesDir,
		"template":       template,
	})
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
	}
	dep, err := s.CreateWorkspaceDeployment(ctx, id, &WorkspaceDeploymentCreateRequest{
		Name:   name,
		Type:   "containerlab",
		Config: cfg,
	})
	if err != nil {
		return nil, err
	}

	auto := true
	if req.AutoDeploy != nil {
		auto = *req.AutoDeploy
	}
	if !auto {
		return &CreateContainerlabDeploymentFromYAMLResponse{
			WorkspaceID: pc.workspace.ID,
			Deployment:  dep,
			Note:        "deployment created; deploy not queued",
		}, nil
	}

	actionResp, err := s.RunWorkspaceDeploymentAction(ctx, id, dep.ID, &WorkspaceDeploymentOpRequest{Action: "create"})
	if err != nil {
		return nil, err
	}

	return &CreateContainerlabDeploymentFromYAMLResponse{
		WorkspaceID: pc.workspace.ID,
		Deployment:  actionResp.Deployment,
		Run:         actionResp.Run,
	}, nil
}

// CreateClabernetesDeploymentFromYAML persists a containerlab topology YAML into the workspace repo,
// creates a "clabernetes" deployment referencing that template, and (optionally) queues an initial deploy.
//
// This is the first-class in-cluster mode (no netlab server required).
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments-designer/clabernetes/from-yaml
func (s *Service) CreateClabernetesDeploymentFromYAML(ctx context.Context, id string, req *CreateClabernetesDeploymentFromYAMLRequest) (*CreateClabernetesDeploymentFromYAMLResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}
	topologyYAML := strings.TrimSpace(req.TopologyYAML)
	if topologyYAML == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML is required").Err()
	}
	if len(topologyYAML) > (1 << 20) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML too large").Err()
	}

	// Basic validation: require `topology` key.
	{
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(topologyYAML), &parsed); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if parsed == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if _, ok := parsed["topology"]; !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("YAML missing required 'topology' section").Err()
		}
	}

	templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "containerlab/designer"
	}
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}

	template := strings.Trim(strings.TrimSpace(req.Template), "/")
	if template == "" {
		template = name + ".clab.yml"
	}
	if !strings.HasSuffix(template, ".yml") && !strings.HasSuffix(template, ".yaml") {
		template = template + ".yml"
	}
	if strings.Contains(template, "/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a filename").Err()
	}

	branch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	filePath := path.Join(templatesDir, template)
	content := strings.TrimRight(topologyYAML, "\n") + "\n"
	commitMsg := fmt.Sprintf("lab: add clabernetes topology (%s)", name)
	{
		ctxWrite, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = ctxWrite
		if err := ensureGiteaFile(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, filePath, content, commitMsg, branch, pc.claims); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to write topology into workspace repo").Err()
		}
	}

	cfg, err := toJSONMap(map[string]any{
		"templateSource": "workspace",
		"templatesDir":   templatesDir,
		"template":       template,
	})
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
	}
	dep, err := s.CreateWorkspaceDeployment(ctx, id, &WorkspaceDeploymentCreateRequest{
		Name:   name,
		Type:   "clabernetes",
		Config: cfg,
	})
	if err != nil {
		return nil, err
	}

	auto := true
	if req.AutoDeploy != nil {
		auto = *req.AutoDeploy
	}
	if !auto {
		return &CreateClabernetesDeploymentFromYAMLResponse{
			WorkspaceID: pc.workspace.ID,
			Deployment:  dep,
			Note:        "deployment created; deploy not queued",
		}, nil
	}

	actionResp, err := s.RunWorkspaceDeploymentAction(ctx, id, dep.ID, &WorkspaceDeploymentOpRequest{Action: "create"})
	if err != nil {
		return nil, err
	}

	return &CreateClabernetesDeploymentFromYAMLResponse{
		WorkspaceID: pc.workspace.ID,
		Deployment:  actionResp.Deployment,
		Run:         actionResp.Run,
	}, nil
}

// SaveContainerlabTopologyYAML writes a containerlab topology YAML into the user's workspace repo so it can be
// deployed later (e.g. by creating a deployment referencing the file).
//
//encore:api auth method=POST path=/api/workspaces/:id/containerlab/topologies
func (s *Service) SaveContainerlabTopologyYAML(ctx context.Context, id string, req *SaveContainerlabTopologyYAMLRequest) (*SaveContainerlabTopologyYAMLResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}
	topologyYAML := strings.TrimSpace(req.TopologyYAML)
	if topologyYAML == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML is required").Err()
	}
	if len(topologyYAML) > (1 << 20) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML too large").Err()
	}

	// Basic validation: require `topology` key.
	{
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(topologyYAML), &parsed); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if parsed == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if _, ok := parsed["topology"]; !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("YAML missing required 'topology' section").Err()
		}
	}

	templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "containerlab/designer"
	}
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}
	if templatesDir != "containerlab" && !strings.HasPrefix(templatesDir, "containerlab/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be under 'containerlab/'").Err()
	}

	template := strings.Trim(strings.TrimSpace(req.Template), "/")
	if template == "" {
		template = name + ".clab.yml"
	}
	if !strings.HasSuffix(template, ".yml") && !strings.HasSuffix(template, ".yaml") {
		template = template + ".yml"
	}
	if strings.Contains(template, "/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a filename").Err()
	}

	branch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	filePath := path.Join(templatesDir, template)
	content := strings.TrimRight(topologyYAML, "\n") + "\n"
	commitMsg := fmt.Sprintf("lab: save containerlab topology (%s)", name)
	{
		ctxWrite, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = ctxWrite
		if err := ensureGiteaFile(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, filePath, content, commitMsg, branch, pc.claims); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to write topology into workspace repo").Err()
		}
	}

	return &SaveContainerlabTopologyYAMLResponse{
		WorkspaceID:  pc.workspace.ID,
		Branch:       branch,
		TemplatesDir: templatesDir,
		Template:     template,
		FilePath:     filePath,
	}, nil
}

// SaveNetlabTopologyYAML writes a netlab topology YAML into the user's workspace repo so it can be
// validated/deployed later (for example by creating a deployment referencing the file).
//
//encore:api auth method=POST path=/api/workspaces/:id/netlab/topologies
func (s *Service) SaveNetlabTopologyYAML(ctx context.Context, id string, req *SaveNetlabTopologyYAMLRequest) (*SaveNetlabTopologyYAMLResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}
	topologyYAML := strings.TrimSpace(req.TopologyYAML)
	if topologyYAML == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML is required").Err()
	}
	if len(topologyYAML) > (1 << 20) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("topologyYAML too large").Err()
	}

	{
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(topologyYAML), &parsed); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
		if parsed == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid YAML").Err()
		}
	}

	templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "netlab/designer"
	}
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}
	if templatesDir != "netlab" &&
		!strings.HasPrefix(templatesDir, "netlab/") &&
		templatesDir != "blueprints/netlab" &&
		!strings.HasPrefix(templatesDir, "blueprints/netlab/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be under 'netlab/' or 'blueprints/netlab/'").Err()
	}

	template := strings.Trim(strings.TrimSpace(req.Template), "/")
	if template == "" {
		template = name + ".yml"
	}
	if !strings.HasSuffix(template, ".yml") && !strings.HasSuffix(template, ".yaml") {
		template = template + ".yml"
	}
	if strings.Contains(template, "/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a filename").Err()
	}

	branch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	filePath := path.Join(templatesDir, template)
	content := strings.TrimRight(topologyYAML, "\n") + "\n"
	commitMsg := fmt.Sprintf("lab: save netlab topology (%s)", name)
	{
		ctxWrite, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_ = ctxWrite
		if err := ensureGiteaFile(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, filePath, content, commitMsg, branch, pc.claims); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to write topology into workspace repo").Err()
		}
	}

	return &SaveNetlabTopologyYAMLResponse{
		WorkspaceID:  pc.workspace.ID,
		Branch:       branch,
		TemplatesDir: templatesDir,
		Template:     template,
		FilePath:     filePath,
	}, nil
}

// CreateClabernetesDeploymentFromTemplate creates a clabernetes deployment pointing at an existing workspace template YAML
// (no YAML commit step).
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments-designer/clabernetes/from-template
func (s *Service) CreateClabernetesDeploymentFromTemplate(ctx context.Context, id string, req *CreateDeploymentFromTemplateRequest) (*CreateDeploymentFromTemplateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}

	templateSource := strings.ToLower(strings.TrimSpace(req.TemplateSource))
	if templateSource == "" {
		templateSource = "workspace"
	}
	if templateSource != "workspace" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templateSource must be 'workspace'").Err()
	}

	templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "containerlab/designer"
	}
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}
	if templatesDir != "containerlab" && !strings.HasPrefix(templatesDir, "containerlab/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be under 'containerlab/'").Err()
	}

	template := strings.Trim(strings.TrimSpace(req.Template), "/")
	if template == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}
	if strings.Contains(template, "/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a filename").Err()
	}
	if !strings.HasSuffix(template, ".yml") && !strings.HasSuffix(template, ".yaml") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a .yml/.yaml file").Err()
	}

	// Confirm the file exists and is a plausible containerlab topology.
	branch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	filePath := path.Join(templatesDir, template)
	{
		body, err := readGiteaFileBytes(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, filePath, branch)
		if err != nil {
			return nil, errs.B().Code(errs.NotFound).Msg("template not found in workspace repo").Err()
		}
		var parsed map[string]any
		if err := yaml.Unmarshal(body, &parsed); err != nil || parsed == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is not valid YAML").Err()
		}
		if _, ok := parsed["topology"]; !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template missing required 'topology' section").Err()
		}
	}

	cfg, err := toJSONMap(map[string]any{
		"templateSource": templateSource,
		"templatesDir":   templatesDir,
		"template":       template,
	})
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
	}
	dep, err := s.CreateWorkspaceDeployment(ctx, id, &WorkspaceDeploymentCreateRequest{
		Name:   name,
		Type:   "clabernetes",
		Config: cfg,
	})
	if err != nil {
		return nil, err
	}

	auto := true
	if req.AutoDeploy != nil {
		auto = *req.AutoDeploy
	}
	if !auto {
		return &CreateDeploymentFromTemplateResponse{
			WorkspaceID: pc.workspace.ID,
			Deployment:  dep,
			Note:        "deployment created; deploy not queued",
		}, nil
	}
	actionResp, err := s.RunWorkspaceDeploymentAction(ctx, id, dep.ID, &WorkspaceDeploymentOpRequest{Action: "create"})
	if err != nil {
		return nil, err
	}
	return &CreateDeploymentFromTemplateResponse{
		WorkspaceID: pc.workspace.ID,
		Deployment:  actionResp.Deployment,
		Run:         actionResp.Run,
	}, nil
}

// CreateContainerlabDeploymentFromTemplate creates a containerlab (BYOS) deployment pointing at an existing workspace template YAML
// (no YAML commit step).
//
//encore:api auth method=POST path=/api/workspaces/:id/deployments-designer/containerlab/from-template
func (s *Service) CreateContainerlabDeploymentFromTemplate(ctx context.Context, id string, req *CreateContainerlabDeploymentFromTemplateRequest) (*CreateDeploymentFromTemplateResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}

	name, err := normalizeDeploymentName(req.Name)
	if err != nil {
		return nil, err
	}

	templateSource := strings.ToLower(strings.TrimSpace(req.TemplateSource))
	if templateSource == "" {
		templateSource = "workspace"
	}
	if templateSource != "workspace" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templateSource must be 'workspace'").Err()
	}

	templatesDir := strings.Trim(strings.TrimSpace(req.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "containerlab/designer"
	}
	if !isSafeRelativePath(templatesDir) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
	}
	if templatesDir != "containerlab" && !strings.HasPrefix(templatesDir, "containerlab/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be under 'containerlab/'").Err()
	}

	template := strings.Trim(strings.TrimSpace(req.Template), "/")
	if template == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template is required").Err()
	}
	if strings.Contains(template, "/") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a filename").Err()
	}
	if !strings.HasSuffix(template, ".yml") && !strings.HasSuffix(template, ".yaml") {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("template must be a .yml/.yaml file").Err()
	}

	branch := strings.TrimSpace(pc.workspace.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	filePath := path.Join(templatesDir, template)
	{
		body, err := readGiteaFileBytes(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, filePath, branch)
		if err != nil {
			return nil, errs.B().Code(errs.NotFound).Msg("template not found in workspace repo").Err()
		}
		var parsed map[string]any
		if err := yaml.Unmarshal(body, &parsed); err != nil || parsed == nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template is not valid YAML").Err()
		}
		if _, ok := parsed["topology"]; !ok {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("template missing required 'topology' section").Err()
		}
	}

	netlabServer := strings.TrimSpace(req.NetlabServer)
	if netlabServer == "" {
		netlabServer = strings.TrimSpace(pc.workspace.NetlabServer)
	}
	if netlabServer == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab server selection is required").Err()
	}

	cfg, err := toJSONMap(map[string]any{
		"netlabServer":   netlabServer,
		"templateSource": templateSource,
		"templatesDir":   templatesDir,
		"template":       template,
	})
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
	}
	dep, err := s.CreateWorkspaceDeployment(ctx, id, &WorkspaceDeploymentCreateRequest{
		Name:   name,
		Type:   "containerlab",
		Config: cfg,
	})
	if err != nil {
		return nil, err
	}

	auto := true
	if req.AutoDeploy != nil {
		auto = *req.AutoDeploy
	}
	if !auto {
		return &CreateDeploymentFromTemplateResponse{
			WorkspaceID: pc.workspace.ID,
			Deployment:  dep,
			Note:        "deployment created; deploy not queued",
		}, nil
	}
	actionResp, err := s.RunWorkspaceDeploymentAction(ctx, id, dep.ID, &WorkspaceDeploymentOpRequest{Action: "create"})
	if err != nil {
		return nil, err
	}
	return &CreateDeploymentFromTemplateResponse{
		WorkspaceID: pc.workspace.ID,
		Deployment:  actionResp.Deployment,
		Run:         actionResp.Run,
	}, nil
}
