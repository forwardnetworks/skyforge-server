package skyforge

import (
	"os"

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

func newCounter[V metrics.Value](name string, cfg metrics.CounterConfig) *metrics.Counter[V] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return metrics.NewCounter[V](name, cfg)
}

func newGauge[V metrics.Value](name string, cfg metrics.GaugeConfig) *metrics.Gauge[V] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return metrics.NewGauge[V](name, cfg)
}

func newCounterGroup[L metrics.Labels, V metrics.Value](name string, cfg metrics.CounterConfig) *metrics.CounterGroup[L, V] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return metrics.NewCounterGroup[L, V](name, cfg)
}

func newGaugeGroup[L metrics.Labels, V metrics.Value](name string, cfg metrics.GaugeConfig) *metrics.GaugeGroup[L, V] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return metrics.NewGaugeGroup[L, V](name, cfg)
}

var (
	loginAttempts = newCounter[uint64]("skyforge_login_attempts_total", metrics.CounterConfig{})
	loginFailures = newCounter[uint64]("skyforge_login_failures_total", metrics.CounterConfig{})

	artifactUploads   = newCounter[uint64]("skyforge_artifact_uploads_total", metrics.CounterConfig{})
	artifactDownloads = newCounter[uint64]("skyforge_artifact_downloads_total", metrics.CounterConfig{})

	runListRequests     = newCounter[uint64]("skyforge_runs_list_requests_total", metrics.CounterConfig{})
	runCreateRequests   = newCounter[uint64]("skyforge_runs_create_requests_total", metrics.CounterConfig{})
	runOutputRequests   = newCounter[uint64]("skyforge_runs_output_requests_total", metrics.CounterConfig{})
	runErrors           = newCounter[uint64]("skyforge_runs_errors_total", metrics.CounterConfig{})
	netlabRunsRequests  = newCounter[uint64]("skyforge_netlab_runs_requests_total", metrics.CounterConfig{})
	labsUserRequests    = newCounter[uint64]("skyforge_labs_user_requests_total", metrics.CounterConfig{})
	labsRunningRequests = newCounter[uint64]("skyforge_labs_running_requests_total", metrics.CounterConfig{})
	labsErrors          = newCounter[uint64]("skyforge_labs_errors_total", metrics.CounterConfig{})

	workspaceSyncManualRequests = newCounter[uint64]("skyforge_workspace_sync_manual_requests_total", metrics.CounterConfig{})
	workspaceSyncAdminRequests  = newCounter[uint64]("skyforge_workspace_sync_admin_requests_total", metrics.CounterConfig{})
	workspaceSyncFailures       = newCounter[uint64]("skyforge_workspace_sync_failures_total", metrics.CounterConfig{})
	workspaceSyncErrors         = newCounter[uint64]("skyforge_workspace_sync_errors_total", metrics.CounterConfig{})
	workspaceSyncBackgroundRuns = newCounter[uint64]("skyforge_workspace_sync_background_runs_total", metrics.CounterConfig{})
)

var (
	taskQueuedTotal   = newCounterGroup[taskTypeLabels, uint64]("skyforge_tasks_queued_total", metrics.CounterConfig{})
	taskStartedTotal  = newCounterGroup[taskTypeLabels, uint64]("skyforge_tasks_started_total", metrics.CounterConfig{})
	taskFinishedTotal = newCounterGroup[taskFinishLabels, uint64]("skyforge_tasks_finished_total", metrics.CounterConfig{})

	taskQueueLatencySecondsLast  = newGaugeGroup[taskTypeLabels, float64]("skyforge_task_queue_latency_seconds_last", metrics.GaugeConfig{})
	taskRunDurationSecondsLast   = newGaugeGroup[taskTypeLabels, float64]("skyforge_task_run_duration_seconds_last", metrics.GaugeConfig{})
	taskQueueLatencySecondsTotal = newCounterGroup[taskTypeLabels, float64]("skyforge_task_queue_latency_seconds_total", metrics.CounterConfig{})
	taskRunDurationSecondsTotal  = newCounterGroup[taskTypeLabels, float64]("skyforge_task_run_duration_seconds_total", metrics.CounterConfig{})

	taskQueuedCurrentTotal           = newGauge[float64]("skyforge_tasks_queued_current_total", metrics.GaugeConfig{})
	taskRunningCurrentTotal          = newGauge[float64]("skyforge_tasks_running_current_total", metrics.GaugeConfig{})
	taskQueuedOldestAgeSecondsTotal  = newGauge[float64]("skyforge_tasks_queued_oldest_age_seconds_total", metrics.GaugeConfig{})
	taskRunningOldestAgeSecondsTotal = newGauge[float64]("skyforge_tasks_running_oldest_age_seconds_total", metrics.GaugeConfig{})

	taskQueuedCurrent           = newGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_queued_current", metrics.GaugeConfig{})
	taskQueuedOldestAgeSeconds  = newGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_queued_oldest_age_seconds", metrics.GaugeConfig{})
	taskRunningCurrent          = newGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_running_current", metrics.GaugeConfig{})
	taskRunningOldestAgeSeconds = newGaugeGroup[taskTypeLabels, float64]("skyforge_tasks_running_oldest_age_seconds", metrics.GaugeConfig{})

	taskWorkersAliveCurrent        = newGauge[float64]("skyforge_task_workers_alive_current", metrics.GaugeConfig{})
	taskWorkersHeartbeatAgeSeconds = newGauge[float64]("skyforge_task_workers_heartbeat_age_seconds", metrics.GaugeConfig{})

	taskQueuePublishFailuresTotal = newCounterGroup[taskQueueTopicLabels, uint64]("skyforge_task_queue_publish_failures_total", metrics.CounterConfig{})
)
