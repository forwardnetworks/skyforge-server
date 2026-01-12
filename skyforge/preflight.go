package skyforge

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ensureWritableDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("dir is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "skyforge-preflight-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil {
		return err
	}
	return nil
}

func ensureWritableSubdir(parent, child string) (string, error) {
	parent = strings.TrimSpace(parent)
	child = strings.Trim(strings.TrimSpace(child), string(filepath.Separator))
	if parent == "" {
		return "", fmt.Errorf("parent dir is empty")
	}
	if child == "" {
		return "", fmt.Errorf("child dir is empty")
	}
	dir := filepath.Join(parent, child)
	return dir, ensureWritableDir(dir)
}
