package skyforge

import "time"

// SkyforgeWorkspace is the user-facing user-context object stored in Postgres and returned by the API.
//
// NOTE: This type must live in the service package (not a type alias to an internal package)
// to satisfy Encore's API schema rules.
type SkyforgeWorkspace struct {
	ID                         string    `json:"id"`
	Slug                       string    `json:"slug"`
	Name                       string    `json:"name"`
	Description                string    `json:"description,omitempty"`
	CreatedAt                  time.Time `json:"createdAt"`
	CreatedBy                  string    `json:"createdBy"`
	IsPublic                   bool      `json:"isPublic"`
	Owners                     []string  `json:"owners,omitempty"`
	OwnerGroups                []string  `json:"ownerGroups,omitempty"`
	Editors                    []string  `json:"editors,omitempty"`
	EditorGroups               []string  `json:"editorGroups,omitempty"`
	Viewers                    []string  `json:"viewers,omitempty"`
	ViewerGroups               []string  `json:"viewerGroups,omitempty"`
	Blueprint                  string    `json:"blueprint,omitempty"`
	DefaultBranch              string    `json:"defaultBranch,omitempty"`
	AllowExternalTemplateRepos bool      `json:"allowExternalTemplateRepos,omitempty"`
	// EVE-NG deployments require an endpoint. This flag enables configuring a per-user-context EVE server.
	AllowCustomEveServers          bool                   `json:"allowCustomEveServers,omitempty"`
	AllowCustomNetlabServers       bool                   `json:"allowCustomNetlabServers,omitempty"`
	AllowCustomContainerlabServers bool                   `json:"allowCustomContainerlabServers,omitempty"`
	ExternalTemplateRepos          []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
	TerraformStateKey              string                 `json:"terraformStateKey,omitempty"`
	TerraformInitTemplateID        int                    `json:"terraformInitTemplateId,omitempty"`
	TerraformPlanTemplateID        int                    `json:"terraformPlanTemplateId,omitempty"`
	TerraformApplyTemplateID       int                    `json:"terraformApplyTemplateId,omitempty"`
	AnsibleRunTemplateID           int                    `json:"ansibleRunTemplateId,omitempty"`
	NetlabRunTemplateID            int                    `json:"netlabRunTemplateId,omitempty"`
	EveNgRunTemplateID             int                    `json:"eveNgRunTemplateId,omitempty"`
	ContainerlabRunTemplateID      int                    `json:"containerlabRunTemplateId,omitempty"`
	AWSAccountID                   string                 `json:"awsAccountId,omitempty"`
	AWSRoleName                    string                 `json:"awsRoleName,omitempty"`
	AWSRegion                      string                 `json:"awsRegion,omitempty"`
	AWSAuthMethod                  string                 `json:"awsAuthMethod,omitempty"`
	ArtifactsBucket                string                 `json:"artifactsBucket,omitempty"`
	EveServer                      string                 `json:"eveServer,omitempty"`
	NetlabServer                   string                 `json:"netlabServer,omitempty"`
	GiteaOwner                     string                 `json:"giteaOwner"`
	GiteaRepo                      string                 `json:"giteaRepo"`
}

type ExternalTemplateRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Repo          string `json:"repo"` // gitea owner/repo
	DefaultBranch string `json:"defaultBranch,omitempty"`
}
