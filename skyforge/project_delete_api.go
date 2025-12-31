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

type ProjectDeleteParams struct {
	DryRun        string `query:"dry_run" encore:"optional"`
	DryRunAlt     string `query:"dryRun" encore:"optional"`
	Force         string `query:"force" encore:"optional"`
	Confirm       string `query:"confirm" encore:"optional"`
	InventoryOnly string `query:"inventory_only" encore:"optional"`
}

type ProjectDeleteResponse struct {
	DryRun               bool               `json:"dryRun,omitempty"`
	DeleteMode           string             `json:"deleteMode,omitempty"`
	RequireForce         bool               `json:"requireForce,omitempty"`
	GiteaOwner           string             `json:"giteaOwner,omitempty"`
	GiteaRepo            string             `json:"giteaRepo,omitempty"`
	TerraformStateKey    string             `json:"terraformStateKey,omitempty"`
	TerraformStatePrefix string             `json:"terraformStatePrefix,omitempty"`
	Status               string             `json:"status,omitempty"`
	Project              *ProjectDeleteItem `json:"project,omitempty"`
}

type ProjectDeleteItem struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// DeleteProject deletes a project and its backing resources.
//
//encore:api auth method=DELETE path=/api/workspaces/:id
func (s *Service) DeleteProject(ctx context.Context, id string, params *ProjectDeleteParams) (*ProjectDeleteResponse, error) {
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
	deleteMode := strings.ToLower(strings.TrimSpace(s.cfg.Projects.DeleteMode))
	if deleteMode == "dry-run" && !force {
		dryRun = true
	}
	statePrefix := strings.SplitN(pc.project.TerraformStateKey, "/", 2)[0] + "/"
	if dryRun {
		return &ProjectDeleteResponse{
			DryRun:               true,
			DeleteMode:           deleteMode,
			RequireForce:         deleteMode == "dry-run",
			GiteaOwner:           pc.project.GiteaOwner,
			GiteaRepo:            pc.project.GiteaRepo,
			TerraformStateKey:    pc.project.TerraformStateKey,
			TerraformStatePrefix: statePrefix,
		}, nil
	}
	if confirm == "" || (!strings.EqualFold(confirm, pc.project.Slug) && !strings.EqualFold(confirm, pc.project.ID)) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("delete requires confirm=<project slug>").Err()
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
			"project.delete",
			pc.project.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", pc.project.Slug, pc.project.GiteaOwner, pc.project.GiteaRepo),
		)
	}
	if !inventoryOnly {
		resp, body, err := giteaDo(s.cfg, http.MethodDelete, fmt.Sprintf("/repos/%s/%s", url.PathEscape(pc.project.GiteaOwner), url.PathEscape(pc.project.GiteaRepo)), nil)
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
			if err := deleteProjectArtifacts(ctx, pc.project.ID); err != nil {
				log.Printf("delete project artifacts %s: %v", pc.project.ID, err)
			}
		}
	}
	pc.projects = append(pc.projects[:pc.idx], pc.projects[pc.idx+1:]...)
	if err := s.projectStore.save(pc.projects); err != nil {
		log.Printf("projects save: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist project deletion").Err()
	}
	return &ProjectDeleteResponse{
		DeleteMode: func() string {
			if inventoryOnly {
				return "inventory-only"
			}
			return "full"
		}(),
		Status: "deleted",
		Project: &ProjectDeleteItem{
			ID:   pc.project.ID,
			Slug: pc.project.Slug,
			Name: pc.project.Name,
		},
	}, nil
}
