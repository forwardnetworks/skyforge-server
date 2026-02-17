package skyforge

import (
	"context"

	"encore.dev/beta/errs"
)

type ContextDeleteParams struct {
	DryRun        string `query:"dry_run" encore:"optional"`
	DryRunAlt     string `query:"dryRun" encore:"optional"`
	Force         string `query:"force" encore:"optional"`
	Confirm       string `query:"confirm" encore:"optional"`
	InventoryOnly string `query:"inventory_only" encore:"optional"`
}

type ContextDeleteResponse struct {
	DryRun               bool               `json:"dryRun,omitempty"`
	DeleteMode           string             `json:"deleteMode,omitempty"`
	RequireForce         bool               `json:"requireForce,omitempty"`
	GiteaOwner           string             `json:"giteaOwner,omitempty"`
	GiteaRepo            string             `json:"giteaRepo,omitempty"`
	TerraformStateKey    string             `json:"terraformStateKey,omitempty"`
	TerraformStatePrefix string             `json:"terraformStatePrefix,omitempty"`
	Status               string             `json:"status,omitempty"`
	Context              *ContextDeleteItem `json:"context,omitempty"`
}

type ContextDeleteItem struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// DeleteOwnerContext deletes a user context and its backing resources.
//
// Deprecated public route removed.
func (s *Service) DeleteOwnerContext(ctx context.Context, id string, params *ContextDeleteParams) (*ContextDeleteResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	_ = user
	_ = id
	_ = params
	return nil, errs.B().Code(errs.FailedPrecondition).Msg("shared context management has been removed; per-user context is automatic").Err()
}
