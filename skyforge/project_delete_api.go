package skyforge

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type WorkspaceDeleteParams struct {
	DryRun        string `query:"dry_run" encore:"optional"`
	DryRunAlt     string `query:"dryRun" encore:"optional"`
	Force         string `query:"force" encore:"optional"`
	Confirm       string `query:"confirm" encore:"optional"`
	InventoryOnly string `query:"inventory_only" encore:"optional"`
}

type WorkspaceDeleteResponse struct {
	DryRun               bool               `json:"dryRun,omitempty"`
	DeleteMode           string             `json:"deleteMode,omitempty"`
	RequireForce         bool               `json:"requireForce,omitempty"`
	GiteaOwner           string             `json:"giteaOwner,omitempty"`
	GiteaRepo            string             `json:"giteaRepo,omitempty"`
	TerraformStateKey    string             `json:"terraformStateKey,omitempty"`
	TerraformStatePrefix string             `json:"terraformStatePrefix,omitempty"`
	Status               string             `json:"status,omitempty"`
	Workspace            *WorkspaceDeleteItem `json:"workspace,omitempty"`
}

type WorkspaceDeleteItem struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// DeleteWorkspace deletes a workspace and its backing resources.
//
//encore:api auth method=DELETE path=/api/workspaces/:id
func (s *Service) DeleteWorkspace(ctx context.Context, id string, params *WorkspaceDeleteParams) (*WorkspaceDeleteResponse, error) {
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
	dryRun := false
	force := false
	confirm := ""
	inventoryOnly := false
	if params != nil {
		dryRun = strings.EqualFold(params.DryRun, "true") || strings.EqualFold(params.DryRunAlt, "true")
		force = strings.EqualFold(params.Force, "true")
		confirm = strings.TrimSpace(params.Confirm)
		inventoryOnly = strings.EqualFold(params.InventoryOnly, "true")
	}
	deleteMode := strings.ToLower(strings.TrimSpace(s.cfg.Workspaces.DeleteMode))
	if deleteMode == "dry-run" && !force {
		dryRun = true
	}
	statePrefix := strings.SplitN(pc.workspace.TerraformStateKey, "/", 2)[0] + "/"
	if dryRun {
		return &WorkspaceDeleteResponse{
			DryRun:               true,
			DeleteMode:           deleteMode,
			RequireForce:         deleteMode == "dry-run",
			GiteaOwner:           pc.workspace.GiteaOwner,
			GiteaRepo:            pc.workspace.GiteaRepo,
			TerraformStateKey:    pc.workspace.TerraformStateKey,
			TerraformStatePrefix: statePrefix,
		}, nil
	}
	if confirm == "" || (!strings.EqualFold(confirm, pc.workspace.Slug) && !strings.EqualFold(confirm, pc.workspace.ID)) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("delete requires confirm=<workspace slug>").Err()
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
			"workspace.delete",
			pc.workspace.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", pc.workspace.Slug, pc.workspace.GiteaOwner, pc.workspace.GiteaRepo),
		)
	}
	if !inventoryOnly {
		resp, body, err := giteaDo(s.cfg, http.MethodDelete, fmt.Sprintf("/repos/%s/%s", url.PathEscape(pc.workspace.GiteaOwner), url.PathEscape(pc.workspace.GiteaRepo)), nil)
		if err != nil {
			log.Printf("gitea delete repo: %v", err)
		} else if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			log.Printf("gitea delete repo failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		{
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := deleteTerraformStatePrefix(ctx, s.cfg, "terraform-state", statePrefix); err != nil {
				log.Printf("object storage delete state prefix %s: %v", statePrefix, err)
			}
			if err := deleteWorkspaceArtifacts(ctx, pc.workspace.ID); err != nil {
				log.Printf("delete workspace artifacts %s: %v", pc.workspace.ID, err)
			}
		}
	}
	pc.workspaces = append(pc.workspaces[:pc.idx], pc.workspaces[pc.idx+1:]...)
	if err := s.workspaceStore.save(pc.workspaces); err != nil {
		log.Printf("workspaces save: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist workspace deletion").Err()
	}
	return &WorkspaceDeleteResponse{
		DeleteMode: func() string {
			if inventoryOnly {
				return "inventory-only"
			}
			return "full"
		}(),
		Status: "deleted",
		Workspace: &WorkspaceDeleteItem{
			ID:   pc.workspace.ID,
			Slug: pc.workspace.Slug,
			Name: pc.workspace.Name,
		},
	}, nil
}
