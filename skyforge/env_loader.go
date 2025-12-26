package skyforge

import (
	"bytes"
	"log"
	"os"
)

func loadSecretFromFile(envKey string) string {
	path := os.Getenv(envKey)
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read secret file %s: %v", path, err)
	}
	return string(bytes.TrimSpace(data))
}
