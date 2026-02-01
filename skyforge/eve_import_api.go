package skyforge

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"encore.dev/beta/errs"

	"encore.app/internal/eveapi"
	"gopkg.in/yaml.v3"
)

type WorkspaceEveLabsRequest struct {
	Server    string `query:"server" encore:"optional"`
	Path      string `query:"path" encore:"optional"`
	Recursive bool   `query:"recursive" encore:"optional"`
}

type WorkspaceEveLabsResponse struct {
	WorkspaceID string          `json:"workspaceId"`
	Server      string          `json:"server"`
	Labs        []EveLabSummary `json:"labs"`
	Folders     []EveFolderInfo `json:"folders,omitempty"`
}

type EveLabSummary struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Folder string `json:"folder,omitempty"`
	MTime  string `json:"mtime,omitempty"`
	UMTime int64  `json:"umtime,omitempty"`
	Shared int    `json:"shared,omitempty"`
	Lock   bool   `json:"lock,omitempty"`
}

type EveFolderInfo struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	MTime string `json:"mtime,omitempty"`
}

// ListWorkspaceEveLabs returns EVE-NG labs for import.
//
//encore:api auth method=GET path=/api/workspaces/:id/eve/labs
func (s *Service) ListWorkspaceEveLabs(ctx context.Context, id string, req *WorkspaceEveLabsRequest) (*WorkspaceEveLabsResponse, error) {
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
	serverRef := ""
	if req != nil {
		serverRef = strings.TrimSpace(req.Server)
	}
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := s.resolveEveServerConfig(ctx, pc, serverRef)
	if err != nil {
		return nil, err
	}
	client, err := eveClientForServer(server)
	if err != nil {
		return nil, err
	}
	listPath := ""
	if req != nil {
		listPath = strings.TrimSpace(req.Path)
	}
	if listPath == "/" {
		listPath = ""
	}
	if req != nil && req.Recursive {
		labs, err := listEveLabsRecursive(ctx, client, listPath)
		if err != nil {
			return nil, err
		}
		sort.Slice(labs, func(i, j int) bool {
			return labs[i].Path < labs[j].Path
		})
		return &WorkspaceEveLabsResponse{WorkspaceID: pc.workspace.ID, Server: serverRef, Labs: labs}, nil
	}
	listing, err := client.ListFolder(ctx, listPath)
	if err != nil {
		return nil, err
	}
	resp := &WorkspaceEveLabsResponse{WorkspaceID: pc.workspace.ID, Server: serverRef}
	for _, lab := range listing.Labs {
		labPath := strings.TrimPrefix(strings.TrimSpace(lab.Path), "/")
		resp.Labs = append(resp.Labs, EveLabSummary{
			Name:   strings.TrimSpace(strings.TrimSuffix(lab.File, path.Ext(lab.File))),
			Path:   labPath,
			Folder: strings.TrimPrefix(path.Dir(labPath), "/"),
			MTime:  strings.TrimSpace(lab.MTime),
			UMTime: lab.UMTime,
			Shared: lab.Shared,
			Lock:   lab.Lock,
		})
	}
	for _, folder := range listing.Folders {
		if strings.TrimSpace(folder.Name) == ".." {
			continue
		}
		resp.Folders = append(resp.Folders, EveFolderInfo{
			Name:  strings.TrimSpace(folder.Name),
			Path:  strings.TrimPrefix(strings.TrimSpace(folder.Path), "/"),
			MTime: strings.TrimSpace(folder.MTime),
		})
	}
	return resp, nil
}

type WorkspaceEveImportRequest struct {
	Server         string `json:"server,omitempty"`
	LabPath        string `json:"labPath"`
	DeploymentName string `json:"deploymentName,omitempty"`
}

// ImportWorkspaceEveLab registers an existing EVE-NG lab as a deployment.
//
//encore:api auth method=POST path=/api/workspaces/:id/eve/import
func (s *Service) ImportWorkspaceEveLab(ctx context.Context, id string, req *WorkspaceEveImportRequest) (*WorkspaceDeployment, error) {
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
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	labPath := normalizeEveLabPath(req.LabPath)
	if labPath == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("labPath is required").Err()
	}
	serverRef := strings.TrimSpace(req.Server)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := s.resolveEveServerConfig(ctx, pc, serverRef)
	if err != nil {
		return nil, err
	}
	client, err := eveClientForServer(server)
	if err != nil {
		return nil, err
	}
	labInfo, err := client.GetLab(ctx, labPath)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.DeploymentName)
	if name == "" {
		name = strings.TrimSpace(labInfo.Name)
	}
	if name == "" {
		name = strings.TrimSpace(strings.TrimSuffix(path.Base(labPath), path.Ext(labPath)))
	}
	name, err = normalizeDeploymentName(name)
	if err != nil {
		return nil, err
	}

	cfg, err := toJSONMap(map[string]any{
		"eveServer": serverRef,
		"labPath":   labPath,
		"imported":  true,
	})
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
	}
	return s.CreateWorkspaceDeployment(ctx, id, &WorkspaceDeploymentCreateRequest{
		Name:   name,
		Type:   "eve_ng",
		Config: cfg,
	})
}

type WorkspaceEveConvertRequest struct {
	Server             string `json:"server,omitempty"`
	LabPath            string `json:"labPath"`
	OutputDir          string `json:"outputDir,omitempty"`
	OutputFile         string `json:"outputFile,omitempty"`
	CreateDeployment   bool   `json:"createDeployment,omitempty"`
	ContainerlabServer string `json:"containerlabServer,omitempty"`
}

type WorkspaceEveConvertResponse struct {
	WorkspaceID string               `json:"workspaceId"`
	Path        string               `json:"path"`
	Deployment  *WorkspaceDeployment `json:"deployment,omitempty"`
	Warnings    []string             `json:"warnings,omitempty"`
}

// ConvertWorkspaceEveLab exports an EVE-NG lab into a Containerlab template.
//
//encore:api auth method=POST path=/api/workspaces/:id/eve/convert
func (s *Service) ConvertWorkspaceEveLab(ctx context.Context, id string, req *WorkspaceEveConvertRequest) (*WorkspaceEveConvertResponse, error) {
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
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	labPath := normalizeEveLabPath(req.LabPath)
	if labPath == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("labPath is required").Err()
	}
	serverRef := strings.TrimSpace(req.Server)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	server, err := s.resolveEveServerConfig(ctx, pc, serverRef)
	if err != nil {
		return nil, err
	}
	client, err := eveClientForServer(server)
	if err != nil {
		return nil, err
	}

	labInfo, err := client.GetLab(ctx, labPath)
	if err != nil {
		return nil, err
	}
	labName := strings.TrimSpace(labInfo.Name)
	if labName == "" {
		labName = strings.TrimSpace(strings.TrimSuffix(path.Base(labPath), path.Ext(labPath)))
	}

	nodes, err := client.ListNodes(ctx, labPath)
	if err != nil {
		return nil, err
	}
	networks, err := client.ListNetworks(ctx, labPath)
	if err != nil {
		return nil, err
	}
	lab := eveLabSnapshot{
		Name:     labName,
		Path:     labPath,
		Nodes:    nodes,
		Networks: networks,
	}
	warnings, err := lab.loadInterfaces(ctx, client)
	if err != nil {
		return nil, err
	}

	outputDir := strings.Trim(strings.TrimSpace(req.OutputDir), "/")
	if outputDir == "" {
		outputDir = "blueprints/containerlab/eve-ng-imports"
	}
	outputFile := strings.TrimSpace(req.OutputFile)
	if outputFile == "" {
		outputFile = slugify(labName) + ".yaml"
	}
	if !strings.HasSuffix(outputFile, ".yml") && !strings.HasSuffix(outputFile, ".yaml") {
		outputFile += ".yaml"
	}
	if !isSafeRelativePath(outputDir) || !isSafeRelativePath(outputFile) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("output path must be a safe repo-relative path").Err()
	}
	fullPath := path.Join(outputDir, outputFile)
	if !isSafeRelativePath(fullPath) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("output path must be a safe repo-relative path").Err()
	}

	cfg, err := renderContainerlabFromEve(lab)
	if err != nil {
		return nil, err
	}
	payload, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode containerlab yaml").Err()
	}

	if err := ensureGiteaFile(s.cfg, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo, fullPath, string(payload), fmt.Sprintf("import eve-ng %s", labName), pc.workspace.DefaultBranch, pc.claims); err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to write containerlab template").Err()
	}

	resp := &WorkspaceEveConvertResponse{
		WorkspaceID: pc.workspace.ID,
		Path:        fullPath,
		Warnings:    warnings,
	}

	if req.CreateDeployment {
		containerlabServer := strings.TrimSpace(req.ContainerlabServer)
		if containerlabServer == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("containerlabServer is required to create a deployment").Err()
		}
		depName, err := normalizeDeploymentName(labName)
		if err != nil {
			return nil, err
		}
		depCfg, err := toJSONMap(map[string]any{
			"netlabServer":   containerlabServer,
			"templateSource": "workspace",
			"templatesDir":   outputDir,
			"template":       outputFile,
		})
		if err != nil {
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode deployment config").Err()
		}
		dep, err := s.CreateWorkspaceDeployment(ctx, id, &WorkspaceDeploymentCreateRequest{
			Name:   depName,
			Type:   "containerlab",
			Config: depCfg,
		})
		if err != nil {
			return nil, err
		}
		resp.Deployment = dep
	}

	return resp, nil
}

func eveClientForServer(server *EveServerConfig) (*eveapi.Client, error) {
	if server == nil {
		return nil, fmt.Errorf("eve-ng server is required")
	}
	if strings.TrimSpace(server.APIURL) == "" {
		return nil, fmt.Errorf("eve-ng api url is required")
	}
	if strings.TrimSpace(server.APIUser) == "" || strings.TrimSpace(server.APIPassword) == "" {
		return nil, fmt.Errorf("eve-ng api credentials are required")
	}
	return eveapi.New(server.APIURL, server.APIUser, server.APIPassword, server.SkipTLSVerify)
}

func listEveLabsRecursive(ctx context.Context, client *eveapi.Client, root string) ([]EveLabSummary, error) {
	seen := map[string]bool{}
	labs := []EveLabSummary{}
	var walk func(string) error
	walk = func(folder string) error {
		folder = strings.Trim(strings.TrimSpace(folder), "/")
		if seen[folder] {
			return nil
		}
		seen[folder] = true
		listing, err := client.ListFolder(ctx, folder)
		if err != nil {
			return err
		}
		for _, lab := range listing.Labs {
			labPath := strings.TrimPrefix(strings.TrimSpace(lab.Path), "/")
			labs = append(labs, EveLabSummary{
				Name:   strings.TrimSpace(strings.TrimSuffix(lab.File, path.Ext(lab.File))),
				Path:   labPath,
				Folder: strings.TrimPrefix(path.Dir(labPath), "/"),
				MTime:  strings.TrimSpace(lab.MTime),
				UMTime: lab.UMTime,
				Shared: lab.Shared,
				Lock:   lab.Lock,
			})
		}
		for _, sub := range listing.Folders {
			name := strings.TrimSpace(sub.Name)
			if name == "" || name == ".." {
				continue
			}
			subPath := strings.TrimPrefix(strings.TrimSpace(sub.Path), "/")
			if err := walk(subPath); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return labs, nil
}

func normalizeEveLabPath(raw string) string {
	raw = strings.TrimSpace(raw)
	return strings.Trim(raw, "/")
}

type eveLabSnapshot struct {
	Name       string
	Path       string
	Nodes      map[string]eveapi.NodeInfo
	Interfaces map[int]eveapi.NodeInterfaces
	Networks   *eveapi.LabNetworks
}

type eveEndpoint struct {
	NodeID      int
	InterfaceID int
	Name        string
	EthName     string
}

func (lab *eveLabSnapshot) loadInterfaces(ctx context.Context, client *eveapi.Client) ([]string, error) {
	if lab == nil {
		return nil, fmt.Errorf("lab snapshot required")
	}
	warnings := []string{}
	lab.Interfaces = make(map[int]eveapi.NodeInterfaces)
	for _, node := range lab.Nodes {
		iface, err := client.ListNodeInterfaces(ctx, lab.Path, node.ID)
		if err != nil {
			return nil, err
		}
		lab.Interfaces[node.ID] = *iface
	}
	for _, node := range lab.Nodes {
		t := strings.ToLower(strings.TrimSpace(node.Type))
		if t == "" {
			continue
		}
		if t != "docker" && t != "qemu" && t != "iol" {
			warnings = append(warnings, fmt.Sprintf("node %s uses type %s; manual mapping may be required", node.Name, t))
		}
	}
	return warnings, nil
}

type containerlabConfig struct {
	Name     string               `yaml:"name"`
	Topology containerlabTopology `yaml:"topology"`
}

type containerlabTopology struct {
	Nodes map[string]containerlabNode `yaml:"nodes"`
	Links []containerlabLink          `yaml:"links,omitempty"`
}

type containerlabNode struct {
	Kind   string            `yaml:"kind,omitempty"`
	Image  string            `yaml:"image,omitempty"`
	Labels map[string]string `yaml:"labels,omitempty"`
}

type containerlabLink struct {
	Endpoints []string `yaml:"endpoints"`
}

func renderContainerlabFromEve(lab eveLabSnapshot) (containerlabConfig, error) {
	cfg := containerlabConfig{Name: slugify(lab.Name)}
	cfg.Topology.Nodes = map[string]containerlabNode{}
	cfg.Topology.Links = []containerlabLink{}

	// Build node interface maps.
	interfaceMap := map[int]map[int]string{}
	nodeNameMap := map[int]string{}
	for _, node := range lab.Nodes {
		safeName := slugify(node.Name)
		if safeName == "" {
			safeName = fmt.Sprintf("node-%d", node.ID)
		}
		safeName = fmt.Sprintf("%s-%d", safeName, node.ID)
		nodeNameMap[node.ID] = safeName

		labels := map[string]string{
			"eve_ng.node_id":   fmt.Sprintf("%d", node.ID),
			"eve_ng.node_type": strings.TrimSpace(node.Type),
			"eve_ng.template":  strings.TrimSpace(node.Template),
			"eve_ng.image":     strings.TrimSpace(node.Image),
		}
		cfg.Topology.Nodes[safeName] = containerlabNode{
			Kind:   "linux",
			Image:  "IMAGE_REQUIRED",
			Labels: labels,
		}

		iface := lab.Interfaces[node.ID]
		keys := make([]int, 0, len(iface.Ethernet))
		for k := range iface.Ethernet {
			if id, err := strconv.Atoi(k); err == nil {
				keys = append(keys, id)
			}
		}
		sort.Ints(keys)
		ifMap := map[int]string{}
		for idx, key := range keys {
			ifMap[key] = fmt.Sprintf("eth%d", idx)
		}
		interfaceMap[node.ID] = ifMap
	}

	networkEndpoints := map[int][]eveEndpoint{}
	for _, node := range lab.Nodes {
		iface := lab.Interfaces[node.ID]
		for k, entry := range iface.Ethernet {
			id, err := strconv.Atoi(k)
			if err != nil {
				continue
			}
			ethName := interfaceMap[node.ID][id]
			if ethName == "" {
				continue
			}
			networkEndpoints[entry.NetworkID] = append(networkEndpoints[entry.NetworkID], eveEndpoint{
				NodeID:      node.ID,
				InterfaceID: id,
				Name:        entry.Name,
				EthName:     ethName,
			})
		}
	}

	bridgeCount := 0
	for networkID, endpoints := range networkEndpoints {
		if len(endpoints) == 0 {
			continue
		}
		bridgeCount++
		bridgeName := fmt.Sprintf("net-%d", networkID)
		if bridgeCount == 1 {
			bridgeName = "net-bridge"
		}
		cfg.Topology.Nodes[bridgeName] = containerlabNode{
			Kind: "bridge",
			Labels: map[string]string{
				"eve_ng.network_id":   fmt.Sprintf("%d", networkID),
				"eve_ng.network_name": strings.TrimSpace(lab.networkName(networkID)),
			},
		}
		for idx, endpoint := range endpoints {
			bridgePort := fmt.Sprintf("eth%d", idx)
			cfg.Topology.Links = append(cfg.Topology.Links, containerlabLink{
				Endpoints: []string{
					fmt.Sprintf("%s:%s", nodeNameMap[endpoint.NodeID], endpoint.EthName),
					fmt.Sprintf("%s:%s", bridgeName, bridgePort),
				},
			})
		}
	}

	return cfg, nil
}

func (lab *eveLabSnapshot) networkName(id int) string {
	if lab == nil || lab.Networks == nil {
		return ""
	}
	key := fmt.Sprintf("%d", id)
	return lab.Networks.Ethernet[key]
}
