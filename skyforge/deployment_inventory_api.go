package skyforge

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type DeploymentInventoryNode struct {
	ID      string `json:"id"`
	Kind    string `json:"kind,omitempty"`
	MgmtIP  string `json:"mgmtIp,omitempty"`
	SSHPort int    `json:"sshPort,omitempty"`
}

type DeploymentInventoryResponse struct {
	GeneratedAt   string                    `json:"generatedAt"`
	OwnerUsername string                    `json:"ownerUsername"`
	DeploymentID  string                    `json:"deploymentId"`
	Format        string                    `json:"format"`
	Nodes         []DeploymentInventoryNode `json:"nodes,omitempty"`
	CSV           string                    `json:"csv,omitempty"`
}

type DeploymentInventoryParams struct {
	Format string `query:"format"` // json|csv
}

// GetUserDeploymentInventory returns a simple inventory of nodes and management IPs.
func (s *Service) GetUserDeploymentInventory(ctx context.Context, id, deploymentID string, params *DeploymentInventoryParams) (*DeploymentInventoryResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	dep, err := s.getUserDeployment(ctx, pc.context.ID, deploymentID)
	if err != nil {
		return nil, err
	}
	typ := strings.ToLower(strings.TrimSpace(dep.Type))
	taskType := ""
	switch typ {
	case "containerlab":
		// Topology is fetched from containerlab post-deploy, but we still store artifacts;
		// use the topology API which knows how to derive it.
		taskType = ""
	case "netlab-c9s":
		taskType = "netlab-c9s-run"
	case "clabernetes":
		taskType = "clabernetes-run"
	case "eve_ng":
		taskType = "eve-ng-run"
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("inventory is not available for this deployment type").Err()
	}

	var topo *DeploymentTopologyResponse
	if taskType == "" {
		topo, err = s.GetUserDeploymentTopology(ctx, id, deploymentID)
	} else {
		topo, err = s.getDeploymentTopologyFromLatestTaskArtifact(ctx, pc, dep, taskType)
	}
	if err != nil {
		return nil, err
	}

	nodes := make([]DeploymentInventoryNode, 0, len(topo.Nodes))
	for _, n := range topo.Nodes {
		sshPort := 22
		nodes = append(nodes, DeploymentInventoryNode{
			ID:      strings.TrimSpace(n.ID),
			Kind:    strings.TrimSpace(n.Kind),
			MgmtIP:  strings.TrimSpace(n.MgmtIP),
			SSHPort: sshPort,
		})
	}

	format := "json"
	if params != nil && strings.TrimSpace(params.Format) != "" {
		format = strings.ToLower(strings.TrimSpace(params.Format))
	}

	resp := &DeploymentInventoryResponse{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		OwnerUsername: pc.context.ID,
		DeploymentID:  deploymentID,
		Format:        format,
	}

	if format == "csv" {
		var b strings.Builder
		w := csv.NewWriter(&b)
		_ = w.Write([]string{"name", "kind", "mgmt_ip", "ssh_port"})
		for _, n := range nodes {
			_ = w.Write([]string{n.ID, n.Kind, n.MgmtIP, fmt.Sprintf("%d", n.SSHPort)})
		}
		w.Flush()
		resp.CSV = b.String()
		return resp, nil
	}

	resp.Nodes = nodes
	return resp, nil
}
