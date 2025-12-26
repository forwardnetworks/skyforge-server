package skyforge

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const (
	netlabCatalogRepo = "netlab-labs"
	cloudCatalogRepo  = "cloud-labs"
)

var (
	labBootstrapMu    sync.Mutex
	labUserBootstrap  = map[string]time.Time{}
	labCatalogChecked bool
)

func cacheLDAPPassword(username, password string, ttl time.Duration) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return
	}
	ldapPasswordCache.mu.Lock()
	defer ldapPasswordCache.mu.Unlock()
	if ldapPasswordCache.items == nil {
		ldapPasswordCache.items = map[string]passwordCacheEntry{}
	}
	ldapPasswordCache.items[strings.ToLower(username)] = passwordCacheEntry{
		password:  password,
		expiresAt: time.Now().Add(ttl),
	}
}

func getCachedLDAPPassword(username string) (string, bool) {
	ldapPasswordCache.mu.Lock()
	defer ldapPasswordCache.mu.Unlock()
	if ldapPasswordCache.items == nil {
		return "", false
	}
	entry, ok := ldapPasswordCache.items[strings.ToLower(username)]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		delete(ldapPasswordCache.items, strings.ToLower(username))
		return "", false
	}
	return entry.password, true
}

func clearCachedLDAPPassword(username string) {
	ldapPasswordCache.mu.Lock()
	defer ldapPasswordCache.mu.Unlock()
	if ldapPasswordCache.items == nil {
		return
	}
	delete(ldapPasswordCache.items, strings.ToLower(username))
}

func (s *Service) bootstrapUserLabs(username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	labBootstrapMu.Lock()
	if last, ok := labUserBootstrap[username]; ok && time.Since(last) < 30*time.Minute {
		labBootstrapMu.Unlock()
		return
	}
	labUserBootstrap[username] = time.Now()
	labBootstrapMu.Unlock()

	if err := ensureLabCatalogRepos(s.cfg); err != nil {
		log.Printf("labs bootstrap: catalog ensure failed: %v", err)
	}
	if err := ensureUserLabWorkspace(ctx, s.cfg, username); err != nil {
		log.Printf("labs bootstrap: user workspace failed: %v", err)
	}
}

func ensureLabCatalogRepos(cfg Config) error {
	labBootstrapMu.Lock()
	if labCatalogChecked {
		labBootstrapMu.Unlock()
		return nil
	}
	labCatalogChecked = true
	labBootstrapMu.Unlock()

	owner := strings.TrimSpace(cfg.Projects.GiteaUsername)
	if owner == "" {
		return fmt.Errorf("gitea username not configured")
	}
	if err := ensureGiteaRepo(cfg, owner, netlabCatalogRepo); err != nil {
		return err
	}
	if err := ensureGiteaRepo(cfg, owner, cloudCatalogRepo); err != nil {
		return err
	}
	return nil
}

func ensureUserLabWorkspace(ctx context.Context, cfg Config, username string) error {
	base := filepath.Join("/home/openvscode-server/project/users", username, "labs")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	owner := strings.TrimSpace(cfg.Projects.GiteaUsername)
	password := strings.TrimSpace(cfg.Projects.GiteaPassword)
	if owner == "" || password == "" {
		return fmt.Errorf("gitea credentials not configured")
	}

	netlabDest := filepath.Join(base, netlabCatalogRepo)
	cloudDest := filepath.Join(base, cloudCatalogRepo)
	giteaBase := normalizeGiteaBaseURL(cfg.GiteaBaseURL)
	if giteaBase == "" {
		return fmt.Errorf("gitea base URL not configured")
	}
	netlabURL := fmt.Sprintf("%s/%s/%s.git", giteaBase, owner, netlabCatalogRepo)
	cloudURL := fmt.Sprintf("%s/%s/%s.git", giteaBase, owner, cloudCatalogRepo)

	if err := cloneIfMissing(ctx, netlabURL, netlabDest, owner, password); err != nil {
		return err
	}
	if err := cloneIfMissing(ctx, cloudURL, cloudDest, owner, password); err != nil {
		return err
	}
	return nil
}

func cloneIfMissing(ctx context.Context, repoURL, dest, username, password string) error {
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		return nil
	}
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	_, err := git.PlainCloneContext(ctx, dest, false, &git.CloneOptions{
		URL:   repoURL,
		Depth: 1,
		Auth: &githttp.BasicAuth{
			Username: username,
			Password: password,
		},
	})
	return err
}

type passwordCacheEntry struct {
	password  string
	expiresAt time.Time
}

var ldapPasswordCache struct {
	mu    sync.Mutex
	items map[string]passwordCacheEntry
}
