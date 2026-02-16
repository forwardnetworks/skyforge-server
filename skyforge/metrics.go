package skyforge

import (
	"encore.dev/metrics"
)

type taskTypeLabels struct {
	TaskType string
}

type taskFinishLabels struct {
	TaskType string
	Status   string
}

type taskQueueTopicLabels struct {
	Topic string
}

type forwardMetricsSyncSourceLabels struct {
	Source string
}

type userRouteUsageLabels struct {
	Mode string
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

	userSyncManualRequests = metrics.NewCounter[uint64]("skyforge_user_sync_manual_requests_total", metrics.CounterConfig{})
	userSyncAdminRequests  = metrics.NewCounter[uint64]("skyforge_user_sync_admin_requests_total", metrics.CounterConfig{})
	userSyncFailures       = metrics.NewCounter[uint64]("skyforge_user_sync_failures_total", metrics.CounterConfig{})
	userSyncErrors         = metrics.NewCounter[uint64]("skyforge_user_sync_errors_total", metrics.CounterConfig{})
	userSyncBackgroundRuns = metrics.NewCounter[uint64]("skyforge_user_sync_background_runs_total", metrics.CounterConfig{})

	forwardMetricsSnapshotsStored = metrics.NewCounter[uint64]("skyforge_forward_metrics_snapshots_stored_total", metrics.CounterConfig{})
)

var (
	taskQueuedTotal   = metrics.NewCounterGroup[taskTypeLabels, uint64]("skyforge_tasks_queued_total", metrics.CounterConfig{})
	taskStartedTotal  = metrics.NewCounterGroup[taskTypeLabels, uint64]("skyforge_tasks_started_total", metrics.CounterConfig{})
	taskFinishedTotal = metrics.NewCounterGroup[taskFinishLabels, uint64]("skyforge_tasks_finished_total", metrics.CounterConfig{})

	taskQueueLatencySecondsLast  = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_task_queue_latency_seconds_last", metrics.GaugeConfig{})
	taskRunDurationSecondsLast   = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_task_run_duration_seconds_last", metrics.GaugeConfig{})
	taskQueueLatencySecondsTotal = metrics.NewCounterGroup[taskTypeLabels, float64]("skyforge_task_queue_latency_seconds_total", metrics.CounterConfig{})
	taskRunDurationSecondsTotal  = metrics.NewCounterGroup[taskTypeLabels, float64]("skyforge_task_run_duration_seconds_total", metrics.CounterConfig{})

	taskQueuedCurrentTotal           = metrics.NewGauge[float64]("skyforge_tasks_queued_current_total", metrics.GaugeConfig{})
	taskRunningCurrentTotal          = metrics.NewGauge[float64]("skyforge_tasks_running_current_total", metrics.GaugeConfig{})
	taskQueuedOldestAgeSecondsTotal  = metrics.NewGauge[float64]("skyforge_tasks_queued_oldest_age_seconds_total", metrics.GaugeConfig{})
	taskRunningOldestAgeSecondsTotal = metrics.NewGauge[float64]("skyforge_tasks_running_oldest_age_seconds_total", metrics.GaugeConfig{})

	taskQueuedCurrent           = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_queued_current", metrics.GaugeConfig{})
	taskQueuedOldestAgeSeconds  = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_queued_oldest_age_seconds", metrics.GaugeConfig{})
	taskRunningCurrent          = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_running_current", metrics.GaugeConfig{})
	taskRunningOldestAgeSeconds = metrics.NewGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_running_oldest_age_seconds", metrics.GaugeConfig{})

	taskWorkersAliveCurrent        = metrics.NewGauge[float64]("skyforge_task_workers_alive_current", metrics.GaugeConfig{})
	taskWorkersHeartbeatAgeSeconds = metrics.NewGauge[float64]("skyforge_task_workers_heartbeat_age_seconds", metrics.GaugeConfig{})

	taskQueuePublishFailuresTotal = metrics.NewCounterGroup[taskQueueTopicLabels, uint64]("skyforge_task_queue_publish_failures_total", metrics.CounterConfig{})

	forwardMetricsSyncRunsTotal     = metrics.NewCounterGroup[forwardMetricsSyncSourceLabels, uint64]("skyforge_forward_metrics_sync_runs_total", metrics.CounterConfig{})
	forwardMetricsSyncFailuresTotal = metrics.NewCounterGroup[forwardMetricsSyncSourceLabels, uint64]("skyforge_forward_metrics_sync_failures_total", metrics.CounterConfig{})
	forwardMetricsLastRunUnix       = metrics.NewGaugeGroup[forwardMetricsSyncSourceLabels, float64]("skyforge_forward_metrics_sync_last_run_unix", metrics.GaugeConfig{})

	userRouteUsageTotal    = metrics.NewCounterGroup[userRouteUsageLabels, uint64]("skyforge_user_route_usage_total", metrics.CounterConfig{})
	userRouteRejectedTotal = metrics.NewCounterGroup[userRouteUsageLabels, uint64]("skyforge_user_route_rejected_total", metrics.CounterConfig{})
)
