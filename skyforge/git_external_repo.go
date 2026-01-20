package skyforge

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func isGitURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	return strings.Contains(raw, "://") || strings.HasPrefix(raw, "git@")
}

type gitAuthEnv struct {
	Env          []string
	CleanupFiles []string
}

func (g gitAuthEnv) cleanup() {
	for _, p := range g.CleanupFiles {
		_ = os.Remove(p)
	}
}

func buildGitAuthEnv(ctx context.Context, creds *userGitCredentials, repoURL string) (gitAuthEnv, string, error) {
	repoURL = strings.TrimSpace(repoURL)
	outURL := repoURL

	env := os.Environ()
	env = append(env, "GIT_TERMINAL_PROMPT=0")

	var cleanup []string

	if strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://") {
		username := strings.TrimSpace(creds.HTTPSUsername)
		token := strings.TrimSpace(creds.HTTPSToken)
		if token != "" {
			parsed, err := url.Parse(repoURL)
			if err != nil {
				return gitAuthEnv{}, "", fmt.Errorf("invalid repo url")
			}
			if username == "" {
				username = "token"
			}
			parsed.User = url.UserPassword(username, token)
			outURL = parsed.String()
		}
		return gitAuthEnv{Env: env, CleanupFiles: cleanup}, outURL, nil
	}

	// SSH URL: use per-user deploy key.
	privKey := strings.TrimSpace(creds.SSHPrivateKey)
	if privKey == "" {
		return gitAuthEnv{}, "", fmt.Errorf("ssh deploy key is not configured")
	}
	keyFile, err := os.CreateTemp("", "skyforge-git-key-*")
	if err != nil {
		return gitAuthEnv{}, "", err
	}
	if err := keyFile.Chmod(0o600); err != nil {
		_ = keyFile.Close()
		return gitAuthEnv{}, "", err
	}
	if _, err := keyFile.WriteString(privKey); err != nil {
		_ = keyFile.Close()
		return gitAuthEnv{}, "", err
	}
	_ = keyFile.Close()
	cleanup = append(cleanup, keyFile.Name())

	sshCmd := fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", shellEscapeArg(keyFile.Name()))
	env = append(env, "GIT_SSH_COMMAND="+sshCmd)

	_ = ctx
	return gitAuthEnv{Env: env, CleanupFiles: cleanup}, outURL, nil
}

func shellEscapeArg(s string) string {
	// Minimal: wrap in single quotes and escape existing quotes.
	return "'" + strings.ReplaceAll(s, "'", `'\'"\'"\'`) + "'"
}

func gitLsRemoteHead(ctx context.Context, env []string, repoURL, branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	ref := "HEAD"
	if branch != "" {
		ref = "refs/heads/" + branch
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", repoURL, ref)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(out))
	if len(parts) == 0 {
		return "", fmt.Errorf("no ref found")
	}
	return strings.TrimSpace(parts[0]), nil
}

func gitCloneShallow(ctx context.Context, env []string, repoURL, branch string) (string, error) {
	tmp, err := os.MkdirTemp("", "skyforge-git-clone-*")
	if err != nil {
		return "", err
	}
	branch = strings.TrimSpace(branch)
	args := []string{"clone", "--depth", "1"}
	if branch != "" {
		args = append(args, "--branch", branch, "--single-branch")
	}
	args = append(args, repoURL, tmp)

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(tmp)
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git clone failed: %s", msg)
	}
	return tmp, nil
}

func listRepoYAMLTemplates(ctx context.Context, creds *userGitCredentials, repoURL, branch, dir string) (headSHA string, templates []string, _ error) {
	auth, urlWithCreds, err := buildGitAuthEnv(ctx, creds, repoURL)
	if err != nil {
		return "", nil, err
	}
	defer auth.cleanup()

	head, err := gitLsRemoteHead(ctx, auth.Env, urlWithCreds, branch)
	if err != nil {
		head = ""
	}

	cloneDir, err := gitCloneShallow(ctx, auth.Env, urlWithCreds, branch)
	if err != nil {
		return head, nil, err
	}
	defer os.RemoveAll(cloneDir)

	dir = strings.Trim(strings.TrimSpace(dir), "/")
	root := cloneDir
	if dir != "" {
		root = filepath.Join(cloneDir, filepath.FromSlash(dir))
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return head, nil, err
	}
	out := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := strings.TrimSpace(ent.Name())
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		out = append(out, name)
	}
	return head, out, nil
}

func readRepoFileBytes(ctx context.Context, creds *userGitCredentials, repoURL, branch, filePath string) ([]byte, error) {
	auth, urlWithCreds, err := buildGitAuthEnv(ctx, creds, repoURL)
	if err != nil {
		return nil, err
	}
	defer auth.cleanup()
	cloneDir, err := gitCloneShallow(ctx, auth.Env, urlWithCreds, branch)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cloneDir)

	filePath = strings.TrimPrefix(strings.TrimSpace(filePath), "/")
	if filePath == "" {
		return nil, fmt.Errorf("file path required")
	}
	abs := filepath.Join(cloneDir, filepath.FromSlash(filePath))
	return os.ReadFile(abs)
}
