package skyforge

import (
	"os"
	"path/filepath"
	"strings"
)

func init() {
	loadDockerSecrets("/run/secrets")
}

func loadDockerSecrets(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		value, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		trimmed := strings.TrimSpace(string(value))
		if trimmed == "" {
			continue
		}
		envKey := normalizeEnvKey(name)
		if os.Getenv(envKey) != "" {
			continue
		}
		_ = os.Setenv(envKey, trimmed)
	}
}

func normalizeEnvKey(name string) string {
	upper := strings.ToUpper(name)
	var b strings.Builder
	b.Grow(len(upper))
	for _, ch := range upper {
		if (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			b.WriteRune(ch)
			continue
		}
		b.WriteRune('_')
	}
	return b.String()
}
