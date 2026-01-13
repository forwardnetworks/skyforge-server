package skyforge

import (
	"context"
	"strings"
	"time"
)

func redisNetlabTemplatesKey(cfg Config, owner, repo, branch, dir string) string {
	prefix := strings.TrimSpace(cfg.Redis.KeyPrefix)
	if prefix == "" {
		prefix = "skyforge"
	}
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	branch = strings.TrimSpace(branch)
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	dir = strings.ReplaceAll(dir, "/", "|")
	return prefix + ":netlab-templates:" + owner + ":" + repo + ":" + branch + ":" + dir
}

func invalidateNetlabTemplatesCacheForRepoBranch(cfg Config, owner, repo, branch string) {
	if redisClient == nil {
		return
	}
	prefix := strings.TrimSpace(cfg.Redis.KeyPrefix)
	if prefix == "" {
		prefix = "skyforge"
	}
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	branch = strings.TrimSpace(branch)
	if owner == "" || repo == "" || branch == "" {
		return
	}

	pattern := prefix + ":netlab-templates:" + owner + ":" + repo + ":" + branch + ":*"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var cursor uint64
	keys := make([]string, 0, 64)
	for {
		out, next, err := redisClient.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return
		}
		keys = append(keys, out...)
		cursor = next
		if cursor == 0 || len(keys) > 1000 {
			break
		}
	}
	if len(keys) == 0 {
		return
	}
	_ = redisClient.Del(ctx, keys...).Err()
}
