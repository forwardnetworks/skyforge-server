package taskengine

import (
	"context"
	"fmt"
	"path"
	"strings"

	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
)

const (
	defaultBlueprintCatalog = "skyforge/blueprints"
	netlabCatalogRepo       = "netlab-labs"
	cloudCatalogRepo        = "cloud-labs"
)

type userBootstrapTaskSpec struct {
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
}

func ensureLabCatalogRepos(cfg skyforgecore.Config) error {
	owner := strings.TrimSpace(cfg.UserScopes.GiteaUsername)
	if owner == "" {
		return fmt.Errorf("gitea username not configured")
	}
	if err := ensureGiteaRepo(cfg, owner, netlabCatalogRepo, cfg.UserScopes.GiteaRepoPrivate); err != nil {
		return err
	}
	if err := ensureGiteaRepo(cfg, owner, cloudCatalogRepo, cfg.UserScopes.GiteaRepoPrivate); err != nil {
		return err
	}
	return nil
}

func (e *Engine) dispatchUserBootstrapTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}
	var specIn userBootstrapTaskSpec
	_ = decodeTaskSpec(task, &specIn)

	username := strings.TrimSpace(specIn.Username)
	if username == "" {
		username = strings.TrimSpace(task.CreatedBy)
	}
	if username == "" {
		return fmt.Errorf("username missing")
	}
	displayName := strings.TrimSpace(specIn.DisplayName)
	if displayName == "" {
		displayName = username
	}
	email := strings.TrimSpace(specIn.Email)
	if email == "" && strings.TrimSpace(e.cfg.CorpEmailDomain) != "" {
		email = fmt.Sprintf("%s@%s", username, strings.TrimSpace(e.cfg.CorpEmailDomain))
	}

	if err := taskdispatch.WithTaskStep(ctx, e.db, task.ID, "gitea.ensure_user", func() error {
		return ensureGiteaUserFromProfile(e.cfg, username, displayName, email)
	}); err != nil {
		return err
	}

	_ = taskdispatch.WithTaskStep(ctx, e.db, task.ID, "gitea.ensure_catalogs", func() error {
		if err := ensureLabCatalogRepos(e.cfg); err != nil {
			log.Errorf("gitea.ensure_catalogs: %v", err)
		}
		if err := ensureBlueprintCatalogRepo(e.cfg, defaultBlueprintCatalog); err != nil {
			log.Errorf("gitea.ensure_catalogs: ensureBlueprintCatalogRepo: %v", err)
		}
		return nil
	})

	log.Infof("User bootstrap completed for %s", username)
	return nil
}

func (e *Engine) dispatchUserScopeBootstrapTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	if log == nil {
		log = noopLogger{}
	}
	ws, err := e.loadUserScopeByKey(ctx, task.UserScopeID)
	if err != nil {
		return err
	}
	owner := strings.TrimSpace(ws.GiteaOwner)
	repo := strings.TrimSpace(ws.GiteaRepo)
	if owner == "" || repo == "" {
		return fmt.Errorf("gitea owner/repo not configured for user scope")
	}

	branch := strings.TrimSpace(ws.DefaultBranch)
	if branch == "" {
		branch = "main"
	}

	stateKey := strings.TrimSpace(ws.TerraformStateKey)
	if stateKey == "" {
		stateKey = fmt.Sprintf("tf-%s/primary.tfstate", strings.TrimSpace(ws.Slug))
	}
	storageEndpoint := strings.TrimSpace(e.cfg.UserScopes.ObjectStorageEndpoint)
	if storageEndpoint == "" {
		storageEndpoint = "minio:9000"
	}
	if !strings.Contains(storageEndpoint, "://") {
		storageEndpoint = "http://" + storageEndpoint
	}
	backendTF := fmt.Sprintf(`terraform {
  backend "s3" {
    endpoint                    = "%s"
    bucket                      = "terraform-state"
    key                         = "%s"
    region                      = "us-east-1"
    skip_region_validation      = true
    skip_credentials_validation = true
    use_path_style              = true
  }
}
`, storageEndpoint, stateKey)

	desc := strings.TrimSpace(ws.Name)
	if desc == "" {
		desc = "Provisioned by Skyforge."
	}
	readme := fmt.Sprintf("# %s\n\n%s\n", strings.TrimSpace(ws.Name), desc)

	playbookYML := `- name: Skyforge placeholder playbook
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Placeholder
      debug:
        msg: "Replace playbook.yml with your Ansible automation."
`

	if err := taskdispatch.WithTaskStep(ctx, e.db, task.ID, "user_scope.seed_repo", func() error {
		if err := ensureGiteaFile(e.cfg, owner, repo, "backend.tf", backendTF, "chore: configure terraform backend", branch, nil); err != nil {
			return err
		}
		if err := ensureGiteaFile(e.cfg, owner, repo, "README.md", readme, "docs: add README", branch, nil); err != nil {
			return err
		}
		if err := ensureGiteaFile(e.cfg, owner, repo, "playbook.yml", playbookYML, "chore: add placeholder ansible playbook", branch, nil); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	blueprint := strings.TrimSpace(ws.Blueprint)
	if blueprint == "" {
		blueprint = defaultBlueprintCatalog
	}
	if err := taskdispatch.WithTaskStep(ctx, e.db, task.ID, "user_scope.sync_blueprints", func() error {
		if err := ensureBlueprintCatalogRepo(e.cfg, blueprint); err != nil {
			return err
		}
		sourceOwner, sourceRepo, ok := parseGiteaBlueprintSlug(blueprint)
		if !ok {
			return fmt.Errorf("unsupported blueprint repo format")
		}
		sourceBranch := e.giteaDefaultBranch(sourceOwner, sourceRepo)
		destRoot := "blueprints"
		expected := []string{"containerlab", "netlab", "terraform"}
		for _, dir := range expected {
			if err := e.syncGiteaDirectoryWithSourceToTarget(ctx, sourceOwner, sourceRepo, owner, repo, dir, path.Join(destRoot, dir), sourceBranch, branch); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	log.Infof("User-scope bootstrap completed for %s/%s", owner, repo)
	return nil
}
