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

type UserContextDeleteParams struct {
	DryRun        string `query:"dry_run" encore:"optional"`
	DryRunAlt     string `query:"dryRun" encore:"optional"`
	Force         string `query:"force" encore:"optional"`
	Confirm       string `query:"confirm" encore:"optional"`
	InventoryOnly string `query:"inventory_only" encore:"optional"`
}

type UserContextDeleteResponse struct {
	DryRun               bool                   `json:"dryRun,omitempty"`
	DeleteMode           string                 `json:"deleteMode,omitempty"`
	RequireForce         bool                   `json:"requireForce,omitempty"`
	GiteaOwner           string                 `json:"giteaOwner,omitempty"`
	GiteaRepo            string                 `json:"giteaRepo,omitempty"`
	TerraformStateKey    string                 `json:"terraformStateKey,omitempty"`
	TerraformStatePrefix string                 `json:"terraformStatePrefix,omitempty"`
	Status               string                 `json:"status,omitempty"`
	UserContext          *UserContextDeleteItem `json:"userContext,omitempty"`
}

type UserContextDeleteItem struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// DeleteUserContext deletes a user context and its backing resources.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id
func (s *Service) DeleteUserContext(ctx context.Context, id string, params *UserContextDeleteParams) (*UserContextDeleteResponse, error) {
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
	deleteMode := strings.ToLower(strings.TrimSpace(s.cfg.UserContexts.DeleteMode))
	if deleteMode == "dry-run" && !force {
		dryRun = true
	}
	statePrefix := strings.SplitN(pc.userContext.TerraformStateKey, "/", 2)[0] + "/"
	if dryRun {
		return &UserContextDeleteResponse{
			DryRun:               true,
			DeleteMode:           deleteMode,
			RequireForce:         deleteMode == "dry-run",
			GiteaOwner:           pc.userContext.GiteaOwner,
			GiteaRepo:            pc.userContext.GiteaRepo,
			TerraformStateKey:    pc.userContext.TerraformStateKey,
			TerraformStatePrefix: statePrefix,
		}, nil
	}
	if confirm == "" || (!strings.EqualFold(confirm, pc.userContext.Slug) && !strings.EqualFold(confirm, pc.userContext.ID)) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("delete requires confirm=<user-context slug>").Err()
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
			"user-context.delete",
			pc.userContext.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", pc.userContext.Slug, pc.userContext.GiteaOwner, pc.userContext.GiteaRepo),
		)
	}
	if !inventoryOnly {
		resp, body, err := giteaDo(s.cfg, http.MethodDelete, fmt.Sprintf("/repos/%s/%s", url.PathEscape(pc.userContext.GiteaOwner), url.PathEscape(pc.userContext.GiteaRepo)), nil)
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
			if err := deleteUserContextArtifacts(ctx, s.cfg, pc.userContext.ID); err != nil {
				log.Printf("delete user-context artifacts %s: %v", pc.userContext.ID, err)
			}
		}
	}
	pc.userContexts = append(pc.userContexts[:pc.idx], pc.userContexts[pc.idx+1:]...)
	if err := s.userContextStore.delete(pc.userContext.ID); err != nil {
		log.Printf("user-context delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist user-context deletion").Err()
	}
	if s.db != nil {
		_ = notifyUserContextsUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	return &UserContextDeleteResponse{
		DeleteMode: func() string {
			if inventoryOnly {
				return "inventory-only"
			}
			return "full"
		}(),
		Status: "deleted",
		UserContext: &UserContextDeleteItem{
			ID:   pc.userContext.ID,
			Slug: pc.userContext.Slug,
			Name: pc.userContext.Name,
		},
	}, nil
}
