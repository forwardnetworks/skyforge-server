package storage

import "encore.dev/metrics"

var (
 	storageUploadRequests   = metrics.NewCounter[uint64]("skyforge_storage_upload_requests_total", metrics.CounterConfig{})
 	storageDownloadRequests = metrics.NewCounter[uint64]("skyforge_storage_download_requests_total", metrics.CounterConfig{})
 	storageDeleteRequests   = metrics.NewCounter[uint64]("skyforge_storage_delete_requests_total", metrics.CounterConfig{})

 	storageUploadBytes   = metrics.NewCounter[uint64]("skyforge_storage_upload_bytes_total", metrics.CounterConfig{})
 	storageDownloadBytes = metrics.NewCounter[uint64]("skyforge_storage_download_bytes_total", metrics.CounterConfig{})

	storageErrors = metrics.NewCounter[uint64]("skyforge_storage_errors_total", metrics.CounterConfig{})
)
