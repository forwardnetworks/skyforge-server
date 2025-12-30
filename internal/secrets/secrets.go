package secrets

import (
	"os"
	"path/filepath"
	"strings"
)

// ReadSecretFromEnvOrFile reads a secret from env or a file in /run/secrets.
func ReadSecretFromEnvOrFile(key, secretName string) (string, error) {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val, nil
	}
	if file := strings.TrimSpace(os.Getenv(key + "_FILE")); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	if strings.TrimSpace(secretName) == "" {
		return "", nil
	}
	data, err := os.ReadFile(filepath.Join("/run/secrets", secretName))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
