package storage

import "encore.dev/types/uuid"

// UploadParams defines the parameters for file upload.
type UploadParams struct {
	Filename string `json:"filename"`
	FileData string `json:"fileData"` // base64 encoded file data
}

// UploadResponse defines the response for file upload.
type UploadResponse struct {
	ID       uuid.UUID `json:"id"`
	Filename string    `json:"filename"`
}

// DownloadResponse defines the response for file download.
type DownloadResponse struct {
	FileData string `json:"fileData"` // base64 encoded file data
}
