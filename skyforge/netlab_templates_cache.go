package skyforge

import (
	"context"
	"strings"
	"time"
)

func invalidateNetlabTemplatesCacheForRepoBranch(_ Config, owner, repo, branch string) {
	if envDisableEncoreCache() {
		return
	}
	caches := getEncoreCachesSafe()
	if caches == nil {
		return
	}
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	branch = strings.TrimSpace(branch)
	if owner == "" || repo == "" || branch == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, _ = caches.netlabTemplatesVer.Increment(ctx, netlabTemplatesVersionKey{Owner: owner, Repo: repo, Branch: branch}, 1)
}
