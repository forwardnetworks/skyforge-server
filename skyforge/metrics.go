package skyforge

import "encore.dev/metrics"

type taskTypeLabels struct {
	TaskType string
}

type taskFinishLabels struct {
	TaskType string
	Status   string
}

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

	workspaceSyncManualRequests = metrics.NewCounter[uint64]("skyforge_workspace_sync_manual_requests_total", metrics.CounterConfig{})
	workspaceSyncAdminRequests  = metrics.NewCounter[uint64]("skyforge_workspace_sync_admin_requests_total", metrics.CounterConfig{})
	workspaceSyncFailures       = metrics.NewCounter[uint64]("skyforge_workspace_sync_failures_total", metrics.CounterConfig{})
	workspaceSyncErrors         = metrics.NewCounter[uint64]("skyforge_workspace_sync_errors_total", metrics.CounterConfig{})
	workspaceSyncBackgroundRuns = metrics.NewCounter[uint64]("skyforge_workspace_sync_background_runs_total", metrics.CounterConfig{})

	taskQueuedTotal   = metrics.NewCounterGroup[taskTypeLabels, uint64]("skyforge_tasks_queued_total", metrics.CounterConfig{})
	taskStartedTotal  = metrics.NewCounterGroup[taskTypeLabels, uint64]("skyforge_tasks_started_total", metrics.CounterConfig{})
	taskFinishedTotal = metrics.NewCounterGroup[taskFinishLabels, uint64]("skyforge_tasks_finished_total", metrics.CounterConfig{})

	taskQueueLatencySecondsLast  = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_task_queue_latency_seconds_last", metrics.GaugeConfig{})
	taskRunDurationSecondsLast   = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_task_run_duration_seconds_last", metrics.GaugeConfig{})
	taskQueueLatencySecondsTotal = metrics.NewCounterGroup[taskTypeLabels, float64]("skyforge_task_queue_latency_seconds_total", metrics.CounterConfig{})
	taskRunDurationSecondsTotal  = metrics.NewCounterGroup[taskTypeLabels, float64]("skyforge_task_run_duration_seconds_total", metrics.CounterConfig{})

	taskQueuedCurrentTotal          = metrics.NewGauge[float64]("skyforge_tasks_queued_current_total", metrics.GaugeConfig{})
	taskRunningCurrentTotal         = metrics.NewGauge[float64]("skyforge_tasks_running_current_total", metrics.GaugeConfig{})
	taskQueuedOldestAgeSecondsTotal = metrics.NewGauge[float64]("skyforge_tasks_queued_oldest_age_seconds_total", metrics.GaugeConfig{})

	taskQueuedCurrent          = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_queued_current", metrics.GaugeConfig{})
	taskQueuedOldestAgeSeconds = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_queued_oldest_age_seconds", metrics.GaugeConfig{})
	taskRunningCurrent         = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_running_current", metrics.GaugeConfig{})
)
