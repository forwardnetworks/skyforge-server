package skyforge

import (
	"os"
	"strings"
	"time"

	"encore.dev/storage/cache"
)

type giteaDefaultBranchKey struct {
	Owner string
	Repo  string
}

type netlabTemplatesVersionKey struct {
	Owner  string
	Repo   string
	Branch string
}

type netlabTemplatesKey struct {
	Owner   string
	Repo    string
	Branch  string
	Version int64
	Dir     string
}

type encoreCaches struct {
	giteaDefaultBranch  *cache.StringKeyspace[giteaDefaultBranchKey]
	netlabTemplates     *cache.StringKeyspace[netlabTemplatesKey]
	netlabTemplatesLock *cache.StringKeyspace[netlabTemplatesKey]
	netlabTemplatesVer  *cache.IntKeyspace[netlabTemplatesVersionKey]
}

var encoreCacheCluster = cache.NewCluster("default", cache.ClusterConfig{})

var encoreCachesInst = &encoreCaches{
	giteaDefaultBranch: cache.NewStringKeyspace[giteaDefaultBranchKey](encoreCacheCluster, cache.KeyspaceConfig{
		KeyPattern:    "gitea/default-branch/:Owner/:Repo",
		DefaultExpiry: cache.ExpireIn(10 * time.Minute),
	}),
	netlabTemplates: cache.NewStringKeyspace[netlabTemplatesKey](encoreCacheCluster, cache.KeyspaceConfig{
		KeyPattern:    "netlab/templates/:Owner/:Repo/:Branch/:Version/:Dir",
		DefaultExpiry: cache.ExpireIn(10 * time.Minute),
	}),
	netlabTemplatesLock: cache.NewStringKeyspace[netlabTemplatesKey](encoreCacheCluster, cache.KeyspaceConfig{
		KeyPattern:    "netlab/templates-lock/:Owner/:Repo/:Branch/:Version/:Dir",
		DefaultExpiry: cache.ExpireIn(10 * time.Second),
	}),
	netlabTemplatesVer: cache.NewIntKeyspace[netlabTemplatesVersionKey](encoreCacheCluster, cache.KeyspaceConfig{
		KeyPattern: "netlab/templates-version/:Owner/:Repo/:Branch",
	}),
}

func getEncoreCachesSafe() *encoreCaches { return encoreCachesInst }

func cacheDirKey(dir string) string {
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	dir = strings.ReplaceAll(dir, "/", "|")
	return dir
}

func envDisableEncoreCache() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SKYFORGE_DISABLE_ENCORE_CACHE")), "true")
}
