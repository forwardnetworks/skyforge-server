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

var ldapPasswordBox *secretBox

func ldapPasswordRedisKey(username string) string {
	return "skyforge:ldap-password:" + strings.ToLower(strings.TrimSpace(username))
}

func cacheLDAPPassword(username, password string, ttl time.Duration) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return
	}
	ldapPasswordCache.mu.Lock()
	if ldapPasswordCache.items == nil {
		ldapPasswordCache.items = map[string]passwordCacheEntry{}
	}
	ldapPasswordCache.items[strings.ToLower(username)] = passwordCacheEntry{
		password:  password,
		expiresAt: time.Now().Add(ttl),
	}
	ldapPasswordCache.mu.Unlock()

	if redisClient == nil || ldapPasswordBox == nil {
		return
	}
	enc, err := ldapPasswordBox.encrypt(password)
	if err != nil || strings.TrimSpace(enc) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	_ = redisClient.Set(ctx, ldapPasswordRedisKey(username), enc, ttl).Err()
	cancel()
}

func getCachedLDAPPassword(username string) (string, bool) {
	ldapPasswordCache.mu.Lock()
	defer ldapPasswordCache.mu.Unlock()
	if ldapPasswordCache.items == nil {
		ldapPasswordCache.items = map[string]passwordCacheEntry{}
	}
	entry, ok := ldapPasswordCache.items[strings.ToLower(username)]
	if !ok {
		if redisClient == nil || ldapPasswordBox == nil {
			return "", false
		}
		ldapPasswordCache.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		raw, err := redisClient.Get(ctx, ldapPasswordRedisKey(username)).Result()
		cancel()
		ldapPasswordCache.mu.Lock()
		if err != nil || strings.TrimSpace(raw) == "" {
			return "", false
		}
		plaintext, err := ldapPasswordBox.decrypt(raw)
		if err != nil || strings.TrimSpace(plaintext) == "" {
			return "", false
		}
		// Cache in-memory briefly to reduce Redis churn; the Redis entry remains the source of truth.
		ldapPasswordCache.items[strings.ToLower(username)] = passwordCacheEntry{
			password:  plaintext,
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		return plaintext, true
	}
	if time.Now().After(entry.expiresAt) {
		delete(ldapPasswordCache.items, strings.ToLower(username))
		return "", false
	}
	return entry.password, true
}

func clearCachedLDAPPassword(username string) {
	ldapPasswordCache.mu.Lock()
	if ldapPasswordCache.items == nil {
		ldapPasswordCache.mu.Unlock()
		return
	}
	delete(ldapPasswordCache.items, strings.ToLower(username))
	ldapPasswordCache.mu.Unlock()
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_ = redisClient.Del(ctx, ldapPasswordRedisKey(username)).Err()
		cancel()
	}
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

	if err := ensureUserHomeWorkspace(s.cfg, username); err != nil {
		log.Printf("user bootstrap: home workspace failed: %v", err)
	}
	if err := ensureLabCatalogRepos(s.cfg); err != nil {
		log.Printf("labs bootstrap: catalog ensure failed: %v", err)
	}
	if err := ensureUserLabWorkspace(ctx, s.cfg, username); err != nil {
		log.Printf("labs bootstrap: user workspace failed: %v", err)
	}
}

func ensureUserHomeWorkspace(cfg Config, username string) error {
	username = strings.TrimSpace(username)
	if !isValidUsername(username) {
		return fmt.Errorf("invalid username")
	}
	base := filepath.Join("/home/openvscode-server/project/users", username)
	home := filepath.Join(base, "home")
	filesDir := filepath.Join(home, "files")
	anonymousDir := filepath.Join(home, "anonymous")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(anonymousDir, 0o755); err != nil {
		return err
	}
	readme := filepath.Join(home, "README.md")
	if _, err := os.Stat(readme); err == nil {
		return nil
	}
	hostHint := strings.TrimSpace(cfg.GiteaBaseURL)
	if hostHint == "" {
		hostHint = "/"
	}
	baseURL := strings.TrimRight(hostHint, "/")
	if baseURL == "" {
		baseURL = "/"
	}
	content := fmt.Sprintf(
		"# Skyforge Workspace (user: %s)\n\n"+
			"This folder is your personal \"home\" inside Skyforge's VS Code.\n\n"+
			"## Git\n"+
			"- Use this directory for your own clones and branches.\n"+
			"- Skyforge may also sync project repos elsewhere in the workspace as a read-only mirror.\n\n"+
			"## Files (S3 / MinIO)\n"+
			"Skyforge exposes an S3-compatible bucket via the same hostname at /files/.\n\n"+
			"- Upload (example):\n"+
			"  curl -T ./myfile.bin \"%s/files/users/%s/myfile.bin\"\n"+
			"- Download (example):\n"+
			"  curl -o ./myfile.bin \"%s/files/users/%s/myfile.bin\"\n\n"+
			"Notes:\n"+
			"- Files from S3 are mirrored into /workspace/users/%s/s3 (download-only).\n"+
			"- Do not edit files inside the mirror; upload to S3 instead.\n"+
			"- Anonymous file drop lands in the same bucket; place shared artifacts under \"anonymous/\" or \"files/\" as needed.\n",
		username,
		baseURL,
		username,
		baseURL,
		username,
		username,
	)
	return os.WriteFile(readme, []byte(content), 0o644)
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
	giteaBase := giteaInternalBaseURL(cfg)
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
