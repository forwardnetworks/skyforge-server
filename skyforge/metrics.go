package skyforge

import "encore.dev/metrics"

var (
	loginAttempts = metrics.NewCounter[uint64]("skyforge_login_attempts_total", metrics.CounterConfig{})
	loginFailures = metrics.NewCounter[uint64]("skyforge_login_failures_total", metrics.CounterConfig{})

	artifactUploads   = metrics.NewCounter[uint64]("skyforge_artifact_uploads_total", metrics.CounterConfig{})
	artifactDownloads = metrics.NewCounter[uint64]("skyforge_artifact_downloads_total", metrics.CounterConfig{})

	runListRequests     = metrics.NewCounter[uint64]("skyforge_runs_list_requests_total", metrics.CounterConfig{})
	runCreateRequests   = metrics.NewCounter[uint64]("skyforge_runs_create_requests_total", metrics.CounterConfig{})
	runOutputRequests   = metrics.NewCounter[uint64]("skyforge_runs_output_requests_total", metrics.CounterConfig{})
	runErrors           = metrics.NewCounter[uint64]("skyforge_runs_errors_total", metrics.CounterConfig{})
	netlabRunsRequests  = metrics.NewCounter[uint64]("skyforge_netlab_runs_requests_total", metrics.CounterConfig{})
	labsUserRequests    = metrics.NewCounter[uint64]("skyforge_labs_user_requests_total", metrics.CounterConfig{})
	labsRunningRequests = metrics.NewCounter[uint64]("skyforge_labs_running_requests_total", metrics.CounterConfig{})
	labsErrors          = metrics.NewCounter[uint64]("skyforge_labs_errors_total", metrics.CounterConfig{})

	projectSyncManualRequests = metrics.NewCounter[uint64]("skyforge_project_sync_manual_requests_total", metrics.CounterConfig{})
	projectSyncAdminRequests  = metrics.NewCounter[uint64]("skyforge_project_sync_admin_requests_total", metrics.CounterConfig{})
	projectSyncFailures       = metrics.NewCounter[uint64]("skyforge_project_sync_failures_total", metrics.CounterConfig{})
	projectSyncProjectErrors  = metrics.NewCounter[uint64]("skyforge_project_sync_project_errors_total", metrics.CounterConfig{})
	projectSyncBackgroundRuns = metrics.NewCounter[uint64]("skyforge_project_sync_background_runs_total", metrics.CounterConfig{})
)
