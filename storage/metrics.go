package storage

import (
	"os"

	"encore.dev/metrics"
)

func newCounter[V metrics.Value](name string, cfg metrics.CounterConfig) *metrics.Counter[V] {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return metrics.NewCounter[V](name, cfg)
}

var (
	storageUploadRequests   = newCounter[uint64]("skyforge_storage_upload_requests_total", metrics.CounterConfig{})
	storageDownloadRequests = newCounter[uint64]("skyforge_storage_download_requests_total", metrics.CounterConfig{})
	storageDeleteRequests   = newCounter[uint64]("skyforge_storage_delete_requests_total", metrics.CounterConfig{})

	storageUploadBytes   = newCounter[uint64]("skyforge_storage_upload_bytes_total", metrics.CounterConfig{})
	storageDownloadBytes = newCounter[uint64]("skyforge_storage_download_bytes_total", metrics.CounterConfig{})

	storageErrors = newCounter[uint64]("skyforge_storage_errors_total", metrics.CounterConfig{})
)
