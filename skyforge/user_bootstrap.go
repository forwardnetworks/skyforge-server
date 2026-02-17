package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	netlabCatalogRepo = "netlab-labs"
	cloudCatalogRepo  = "cloud-labs"
)

var ldapPasswordBox *secretBox

func cacheLDAPPassword(db *sql.DB, username, password string, ttl time.Duration) {
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

	if ldapPasswordBox == nil {
		return
	}
	enc, err := ldapPasswordBox.encrypt(password)
	if err != nil || strings.TrimSpace(enc) == "" {
		return
	}
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_ = upsertLDAPPasswordCache(ctx, db, strings.TrimSpace(username), enc, time.Now().Add(ttl))
		cancel()
		return
	}

	_ = db
}

func getCachedLDAPPassword(db *sql.DB, username string) (string, bool) {
	ldapPasswordCache.mu.Lock()
	defer ldapPasswordCache.mu.Unlock()
	if ldapPasswordCache.items == nil {
		ldapPasswordCache.items = map[string]passwordCacheEntry{}
	}
	entry, ok := ldapPasswordCache.items[strings.ToLower(username)]
	if !ok {
		if ldapPasswordBox == nil {
			return "", false
		}
		ldapPasswordCache.mu.Unlock()
		raw := ""
		if db != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			raw, _, ok, _ = getLDAPPasswordCache(ctx, db, strings.TrimSpace(username))
			cancel()
			if !ok || strings.TrimSpace(raw) == "" {
				ldapPasswordCache.mu.Lock()
				return "", false
			}
		} else {
			ldapPasswordCache.mu.Lock()
			return "", false
		}
		ldapPasswordCache.mu.Lock()
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

func clearCachedLDAPPassword(db *sql.DB, username string) {
	ldapPasswordCache.mu.Lock()
	if ldapPasswordCache.items == nil {
		ldapPasswordCache.mu.Unlock()
		return
	}
	delete(ldapPasswordCache.items, strings.ToLower(username))
	ldapPasswordCache.mu.Unlock()
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_ = deleteLDAPPasswordCache(ctx, db, strings.TrimSpace(username))
		cancel()
	}
}

func (s *Service) bootstrapUserLabs(username string) {
	// Legacy: the old implementation wrote to a shared filesystem (per-user "home" + cloned repos).
	// Skyforge runs multi-replica now and should remain stateless; Coder user contexts should
	// manage per-user home directories independently. Keep this as a no-op for compatibility.
	_ = username
}

func ensureLabCatalogRepos(cfg Config) error {
	owner := strings.TrimSpace(cfg.Scopes.GiteaUsername)
	if owner == "" {
		return fmt.Errorf("gitea username not configured")
	}
	if err := ensureGiteaRepo(cfg, owner, netlabCatalogRepo, cfg.Scopes.GiteaRepoPrivate); err != nil {
		return err
	}
	if err := ensureGiteaRepo(cfg, owner, cloudCatalogRepo, cfg.Scopes.GiteaRepoPrivate); err != nil {
		return err
	}
	return nil
}

type passwordCacheEntry struct {
	password  string
	expiresAt time.Time
}

var ldapPasswordCache struct {
	mu    sync.Mutex
	items map[string]passwordCacheEntry
}
