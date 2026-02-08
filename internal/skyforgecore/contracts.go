package skyforgecore

// This file defines stability contracts used across services and the UI.
// Treat these constants as API/DB compatibility boundaries.

const (
	HeaderAPIVersion = "X-Skyforge-API-Version"
	HeaderBuild      = "X-Skyforge-Build"

	// Bump when making intentionally breaking API/SSE payload changes.
	APIVersion = "1"
)

const (
	TaskTypeUserBootstrap      = "user-bootstrap"
	TaskTypeWorkspaceBootstrap = "workspace-bootstrap"

	TaskTypeNetlabRun      = "netlab-run"
	TaskTypeNetlabC9sRun   = "netlab-c9s-run"
	TaskTypeNetlabValidate = "netlab-validate"
	TaskTypeContainerlab   = "containerlab-run"
	TaskTypeClabernetes    = "clabernetes-run"
	TaskTypeForwardInit    = "forward-init"
	TaskTypeForwardSync    = "forward-sync"
	TaskTypeCapacityRollup = "capacity-rollup"
	TaskTypeCapacityRollupForwardNetwork = "capacity-rollup-forward-network"
	TaskTypeTerraformPref  = "terraform-"
)

const (
	SSEEventOutput   = "output"
	SSEEventSnapshot = "snapshot"
)
