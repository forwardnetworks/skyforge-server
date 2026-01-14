package skyforge

import (
	"os"
	"strings"
	"sync"
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

var (
	encoreCachesOnce sync.Once
	encoreCachesInst *encoreCaches
)

func initEncoreCaches() *encoreCaches {
	cluster := cache.NewCluster("default", cache.ClusterConfig{})
	return &encoreCaches{
		giteaDefaultBranch: cache.NewStringKeyspace[giteaDefaultBranchKey](cluster, cache.KeyspaceConfig{
			KeyPattern:    "gitea/default-branch/:Owner/:Repo",
			DefaultExpiry: cache.ExpireIn(10 * time.Minute),
		}),
		netlabTemplates: cache.NewStringKeyspace[netlabTemplatesKey](cluster, cache.KeyspaceConfig{
			KeyPattern:    "netlab/templates/:Owner/:Repo/:Branch/:Version/:Dir",
			DefaultExpiry: cache.ExpireIn(10 * time.Minute),
		}),
		netlabTemplatesLock: cache.NewStringKeyspace[netlabTemplatesKey](cluster, cache.KeyspaceConfig{
			KeyPattern:    "netlab/templates-lock/:Owner/:Repo/:Branch/:Version/:Dir",
			DefaultExpiry: cache.ExpireIn(10 * time.Second),
		}),
		netlabTemplatesVer: cache.NewIntKeyspace[netlabTemplatesVersionKey](cluster, cache.KeyspaceConfig{
			KeyPattern: "netlab/templates-version/:Owner/:Repo/:Branch",
		}),
	}
}

func getEncoreCachesSafe() *encoreCaches {
	encoreCachesOnce.Do(func() {
		defer func() {
			if recover() != nil {
				encoreCachesInst = nil
			}
		}()
		encoreCachesInst = initEncoreCaches()
	})
	return encoreCachesInst
}

func cacheDirKey(dir string) string {
	dir = strings.Trim(strings.TrimSpace(dir), "/")
	dir = strings.ReplaceAll(dir, "/", "|")
	return dir
}

func envDisableEncoreCache() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SKYFORGE_DISABLE_ENCORE_CACHE")), "true")
}
