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

type UserScopeDeleteParams struct {
	DryRun        string `query:"dry_run" encore:"optional"`
	DryRunAlt     string `query:"dryRun" encore:"optional"`
	Force         string `query:"force" encore:"optional"`
	Confirm       string `query:"confirm" encore:"optional"`
	InventoryOnly string `query:"inventory_only" encore:"optional"`
}

type UserScopeDeleteResponse struct {
	DryRun               bool                 `json:"dryRun,omitempty"`
	DeleteMode           string               `json:"deleteMode,omitempty"`
	RequireForce         bool                 `json:"requireForce,omitempty"`
	GiteaOwner           string               `json:"giteaOwner,omitempty"`
	GiteaRepo            string               `json:"giteaRepo,omitempty"`
	TerraformStateKey    string               `json:"terraformStateKey,omitempty"`
	TerraformStatePrefix string               `json:"terraformStatePrefix,omitempty"`
	Status               string               `json:"status,omitempty"`
	UserScope            *UserScopeDeleteItem `json:"userScope,omitempty"`
}

type UserScopeDeleteItem struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// DeleteUserScope deletes a user scope and its backing resources.
//
//encore:api auth method=DELETE path=/api/users/:id
func (s *Service) DeleteUserScope(ctx context.Context, id string, params *UserScopeDeleteParams) (*UserScopeDeleteResponse, error) {
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
	deleteMode := strings.ToLower(strings.TrimSpace(s.cfg.UserScopes.DeleteMode))
	if deleteMode == "dry-run" && !force {
		dryRun = true
	}
	statePrefix := strings.SplitN(pc.userScope.TerraformStateKey, "/", 2)[0] + "/"
	if dryRun {
		return &UserScopeDeleteResponse{
			DryRun:               true,
			DeleteMode:           deleteMode,
			RequireForce:         deleteMode == "dry-run",
			GiteaOwner:           pc.userScope.GiteaOwner,
			GiteaRepo:            pc.userScope.GiteaRepo,
			TerraformStateKey:    pc.userScope.TerraformStateKey,
			TerraformStatePrefix: statePrefix,
		}, nil
	}
	if confirm == "" || (!strings.EqualFold(confirm, pc.userScope.Slug) && !strings.EqualFold(confirm, pc.userScope.ID)) {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("delete requires confirm=<user scope slug>").Err()
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
			"user-scope.delete",
			pc.userScope.ID,
			fmt.Sprintf("slug=%s repo=%s/%s", pc.userScope.Slug, pc.userScope.GiteaOwner, pc.userScope.GiteaRepo),
		)
	}
	if !inventoryOnly {
		resp, body, err := giteaDo(s.cfg, http.MethodDelete, fmt.Sprintf("/repos/%s/%s", url.PathEscape(pc.userScope.GiteaOwner), url.PathEscape(pc.userScope.GiteaRepo)), nil)
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
			if err := deleteWorkspaceArtifacts(ctx, s.cfg, pc.userScope.ID); err != nil {
				log.Printf("delete user-scope artifacts %s: %v", pc.userScope.ID, err)
			}
		}
	}
	pc.userScopes = append(pc.userScopes[:pc.idx], pc.userScopes[pc.idx+1:]...)
	if err := s.userScopeStore.delete(pc.userScope.ID); err != nil {
		log.Printf("user-scope delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to persist user-scope deletion").Err()
	}
	if s.db != nil {
		_ = notifyWorkspacesUpdatePG(ctx, s.db, "*")
		_ = notifyDashboardUpdatePG(ctx, s.db)
	}
	return &UserScopeDeleteResponse{
		DeleteMode: func() string {
			if inventoryOnly {
				return "inventory-only"
			}
			return "full"
		}(),
		Status: "deleted",
		UserScope: &UserScopeDeleteItem{
			ID:   pc.userScope.ID,
			Slug: pc.userScope.Slug,
			Name: pc.userScope.Name,
		},
	}, nil
}
