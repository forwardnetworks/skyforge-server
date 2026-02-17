package skyforge

import (
	"fmt"
	"net/url"
	"strings"

	"encore.dev/beta/errs"
	"github.com/google/uuid"
)

func validateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return "", fmt.Errorf("invalid url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("url must be http(s)")
	}
	return strings.TrimRight(raw, "/"), nil
}

func validateExternalTemplateRepos(repos []ExternalTemplateRepo) ([]ExternalTemplateRepo, error) {
	if len(repos) > 20 {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("too many external template repos").Err()
	}
	seenIDs := map[string]bool{}
	out := make([]ExternalTemplateRepo, 0, len(repos))
	for _, repo := range repos {
		id := strings.TrimSpace(repo.ID)
		if id == "" {
			id = uuid.NewString()
		}
		if seenIDs[id] {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("duplicate external template repo id").Err()
		}
		seenIDs[id] = true

		name := strings.TrimSpace(repo.Name)
		if name == "" {
			name = id
		}
		ref := strings.Trim(strings.TrimSpace(repo.Repo), "/")
		if ref == "" {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("external template repo is required").Err()
		}
		if strings.Contains(ref, " ") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo").Err()
		}
		if strings.Contains(ref, "://") || strings.HasPrefix(ref, "git@") {
			if strings.Contains(ref, "\n") || strings.Contains(ref, "\r") {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo").Err()
			}
		} else {
			parts := strings.Split(ref, "/")
			if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("external template repo must be of form owner/repo or a git URL").Err()
			}
			if !isValidUsername(parts[0]) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo owner").Err()
			}
			if !isSafeRelativePath(parts[1]) {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo name").Err()
			}
			ref = strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
		}
		branch := strings.TrimSpace(repo.DefaultBranch)
		if strings.Contains(branch, " ") || strings.Contains(branch, "/..") {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid external template repo branch").Err()
		}
		out = append(out, ExternalTemplateRepo{
			ID:            id,
			Name:          name,
			Repo:          ref,
			DefaultBranch: branch,
		})
	}
	return out, nil
}
