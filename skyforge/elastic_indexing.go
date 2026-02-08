package skyforge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"encore.dev/rlog"

	elasticint "encore.app/integrations/elastic"
)

type elasticUserPrefixCacheEntry struct {
	prefix    string
	expiresAt time.Time
}

func (s *Service) elasticIndexingEnabled() bool {
	if s == nil {
		return false
	}
	if !s.cfg.Features.ElasticEnabled {
		return false
	}
	return strings.TrimSpace(s.cfg.Elastic.URL) != ""
}

func (s *Service) getElasticClient() (*elasticint.Client, error) {
	if !s.elasticIndexingEnabled() {
		return nil, nil
	}
	s.elasticOnce.Do(func() {
		s.elasticClient, s.elasticInitErr = elasticint.New(s.cfg.Elastic.URL, s.cfg.Elastic.IndexPrefix)
		if s.elasticInitErr != nil {
			rlog.Error("elastic init failed", "error", s.elasticInitErr)
		}
	})
	if s.elasticInitErr != nil {
		return nil, s.elasticInitErr
	}
	return s.elasticClient, nil
}

func normalizeElasticIndexingMode(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", "instance":
		return "instance"
	case "per_user", "per-user", "peruser":
		return "per_user"
	default:
		return "instance"
	}
}

func sanitizeElasticUserComponent(username string) string {
	// Elasticsearch index naming rules are strict. We keep this conservative and
	// predictable so index names are stable across releases.
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(username))
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune('-')
		default:
			// Replace any other rune with '-'.
			b.WriteRune('-')
		}
	}
	out := b.String()
	out = strings.Trim(out, "-")
	if out == "" {
		return "user"
	}
	return out
}

func (s *Service) getElasticBaseIndexPrefixForUser(ctx context.Context, username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", nil
	}

	// Default base prefix from instance config.
	base := strings.TrimSpace(s.cfg.Elastic.IndexPrefix)
	if base == "" {
		base = "skyforge"
	}

	// No DB => can't load overrides.
	if s.db == nil {
		return base, nil
	}

	// Cache: reduces DB load for high-volume syslog/ingest.
	now := time.Now()
	s.elasticUserPrefixCacheMu.Lock()
	if s.elasticUserPrefixCache == nil {
		s.elasticUserPrefixCache = map[string]elasticUserPrefixCacheEntry{}
	}
	if ent, ok := s.elasticUserPrefixCache[username]; ok && now.Before(ent.expiresAt) {
		s.elasticUserPrefixCacheMu.Unlock()
		if strings.TrimSpace(ent.prefix) != "" {
			return ent.prefix, nil
		}
		return base, nil
	}
	s.elasticUserPrefixCacheMu.Unlock()

	// Best-effort DB lookup.
	var v sql.NullString
	ctxDB, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := s.db.QueryRowContext(ctxDB, `SELECT index_prefix FROM sf_user_elastic_config WHERE username=$1`, username).Scan(&v)
	if err != nil {
		if err == sql.ErrNoRows || isMissingDBRelation(err) {
			// Cache the miss.
			s.elasticUserPrefixCacheMu.Lock()
			s.elasticUserPrefixCache[username] = elasticUserPrefixCacheEntry{prefix: "", expiresAt: now.Add(5 * time.Minute)}
			s.elasticUserPrefixCacheMu.Unlock()
			return base, nil
		}
		return base, err
	}
	override := strings.TrimSpace(v.String)
	s.elasticUserPrefixCacheMu.Lock()
	s.elasticUserPrefixCache[username] = elasticUserPrefixCacheEntry{prefix: override, expiresAt: now.Add(5 * time.Minute)}
	s.elasticUserPrefixCacheMu.Unlock()
	if override != "" {
		return override, nil
	}
	return base, nil
}

// indexElasticAsync is best-effort. It never returns an error to the caller.
func (s *Service) indexElasticAsync(username, category string, receivedAt time.Time, doc any) {
	if !s.elasticIndexingEnabled() {
		return
	}
	client, err := s.getElasticClient()
	if err != nil || client == nil {
		return
	}
	mode := normalizeElasticIndexingMode(s.cfg.Elastic.IndexingMode)

	// Per-user mode requires an explicit owner/username to avoid cross-tenant leakage.
	username = strings.ToLower(strings.TrimSpace(username))
	if mode == "per_user" && username == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		switch mode {
		case "per_user":
			base, err := s.getElasticBaseIndexPrefixForUser(ctx, username)
			if err != nil {
				rlog.Error("elastic index prefix lookup failed", "username", username, "error", err)
				return
			}
			u := sanitizeElasticUserComponent(username)
			effectivePrefix := fmt.Sprintf("%s-u-%s", strings.TrimSpace(base), u)
			if err := client.IndexDailyWithPrefix(ctx, effectivePrefix, category, receivedAt, doc); err != nil {
				rlog.Error("elastic index failed", "category", category, "username", username, "error", err)
			}
		default:
			if err := client.IndexDaily(ctx, category, receivedAt, doc); err != nil {
				rlog.Error("elastic index failed", "category", category, "error", err)
			}
		}
	}()
}
