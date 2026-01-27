package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encore.app/integrations/gitea"
)

func main() {
	var (
		srcDir            = flag.String("src", "", "Path to local blueprints directory (default: ../blueprints relative to server/)")
		giteaAPIURL       = flag.String("gitea-api-url", getenv("GITEA_API_URL", ""), "Gitea API URL (e.g. https://skyforge.local.forwardnetworks.com/git/api/v1)")
		giteaUsername     = flag.String("gitea-username", getenv("GITEA_USERNAME", ""), "Gitea username (e.g. skyforge)")
		giteaPassword     = flag.String("gitea-password", getenv("GITEA_PASSWORD", ""), "Gitea password")
		giteaPasswordFile = flag.String("gitea-password-file", getenv("GITEA_PASSWORD_FILE", ""), "Path to file containing Gitea password (alternative to --gitea-password)")
		skipTLSVerify     = flag.Bool("skip-tls-verify", getenvBool("GITEA_SKIP_TLS_VERIFY", false), "Skip TLS verification when calling Gitea (intended for internal/self-signed deployments)")
		owner             = flag.String("owner", getenv("GITEA_OWNER", "skyforge"), "Repo owner/org (default: skyforge)")
		repo              = flag.String("repo", getenv("GITEA_REPO", "blueprints"), "Repo name (default: blueprints)")
		branch            = flag.String("branch", getenv("GITEA_BRANCH", "main"), "Target branch (default: main)")
		include           = flag.String("include", getenv("GITEA_BLUEPRINT_DIRS", "containerlab,netlab,terraform"), "Comma-separated list of subdirectories to sync (default: containerlab,netlab,terraform)")
		dryRun            = flag.Bool("dry-run", false, "Print planned updates without writing to Gitea")
	)
	flag.Parse()

	if strings.TrimSpace(*srcDir) == "" {
		*srcDir = filepath.Clean(filepath.Join("..", "blueprints"))
	}

	apiURL := strings.TrimSpace(*giteaAPIURL)
	if apiURL == "" {
		fatalf("missing --gitea-api-url (or GITEA_API_URL)")
	}
	apiURL = strings.TrimRight(apiURL, "/")
	if !strings.HasSuffix(apiURL, "/api/v1") {
		apiURL += "/api/v1"
	}

	username := strings.TrimSpace(*giteaUsername)
	password := strings.TrimSpace(*giteaPassword)
	if password == "" && strings.TrimSpace(*giteaPasswordFile) != "" {
		raw, err := os.ReadFile(strings.TrimSpace(*giteaPasswordFile))
		if err != nil {
			fatalf("read gitea password file: %v", err)
		}
		password = strings.TrimSpace(string(raw))
	}
	if username == "" || password == "" {
		fatalf("missing gitea credentials (--gitea-username/--gitea-password or GITEA_USERNAME/GITEA_PASSWORD)")
	}

	targetOwner := strings.TrimSpace(*owner)
	targetRepo := strings.TrimSpace(*repo)
	targetBranch := strings.TrimSpace(*branch)
	if targetOwner == "" || targetRepo == "" {
		fatalf("missing --owner/--repo")
	}
	if targetBranch == "" {
		targetBranch = "main"
	}

	client := gitea.New(gitea.Config{
		APIURL:        apiURL,
		Username:      username,
		Password:      password,
		Timeout:       30 * time.Second,
		RepoPrivate:   false,
		SkipTLSVerify: *skipTLSVerify,
	})

	fmt.Printf("Ensuring repo %s/%s exists…\n", targetOwner, targetRepo)
	if err := client.EnsureRepo(targetOwner, targetRepo); err != nil {
		fatalf("ensure repo: %v", err)
	}
	if err := client.SetRepoPrivate(targetOwner, targetRepo, false); err != nil {
		fatalf("set repo public: %v", err)
	}

	includeDirs := splitCSV(*include)
	if len(includeDirs) == 0 {
		fatalf("no directories to sync (empty --include)")
	}

	total := 0
	for _, dir := range includeDirs {
		localRoot := filepath.Join(*srcDir, dir)
		info, err := os.Stat(localRoot)
		if err != nil {
			fatalf("missing directory %s: %v", localRoot, err)
		}
		if !info.IsDir() {
			fatalf("%s is not a directory", localRoot)
		}
		fmt.Printf("Syncing %s/ → %s/%s/%s/\n", localRoot, targetOwner, targetRepo, dir)
		if err := filepath.WalkDir(localRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := entry.Name()
			if entry.IsDir() {
				if name == ".git" {
					return fs.SkipDir
				}
				return nil
			}
			if name == ".DS_Store" {
				return nil
			}
			rel, err := filepath.Rel(*srcDir, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			contentBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			total++
			if *dryRun {
				fmt.Printf("[dry-run] %s\n", rel)
				return nil
			}
			if err := client.EnsureFile(targetOwner, targetRepo, rel, string(contentBytes), "sync: "+rel, targetBranch, nil); err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			return nil
		}); err != nil {
			fatalf("sync %s: %v", dir, err)
		}
	}

	fmt.Printf("Done. Synced %d files to %s/%s.\n", total, targetOwner, targetRepo)
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func splitCSV(raw string) []string {
	parts := []string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		item = strings.TrimPrefix(item, "/")
		item = strings.TrimSuffix(item, "/")
		if item == "" {
			continue
		}
		parts = append(parts, item)
	}
	return parts
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
