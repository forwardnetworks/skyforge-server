package skyforge

import (
	"context"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"gopkg.in/yaml.v3"
)

func clabernetesUserContextNamespace(workspaceSlug string) string {
	workspaceSlug = strings.TrimSpace(workspaceSlug)
	if workspaceSlug == "" {
		return "ws"
	}
	return sanitizeKubeNameFallback("ws-"+workspaceSlug, "ws")
}

func clabernetesTopologyName(labName string) string {
	labName = strings.TrimSpace(labName)
	if labName == "" {
		return "topology"
	}
	return sanitizeKubeNameFallback(labName, "topology")
}

func (s *Service) runClabernetesDeploymentAction(
	ctx context.Context,
	pc *userContext,
	dep *UserDeployment,
	envJSON JSONMap,
	action string,
	templateSource string,
	templateRepo string,
	templatesDir string,
	template string,
	labName string,
	k8sNamespace string,
) (*UserContextRunResponse, error) {
	if pc == nil || dep == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("deployment context unavailable").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	policy, _ := loadGovernancePolicy(ctx, s.db)

	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "", "deploy", "create", "start", "up":
		action = "deploy"
	case "destroy", "delete", "down", "stop":
		action = "destroy"
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid clabernetes action (use deploy or destroy)").Err()
	}

	labName = strings.TrimSpace(labName)
	if labName == "" {
		labName = containerlabLabName(pc.userContext.Slug, dep.Name)
	}
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesUserContextNamespace(pc.userContext.Slug)
	}
	topologyName := clabernetesTopologyName(labName)

	topologyYAML := ""
	if action == "deploy" {
		template = strings.TrimSpace(template)
		if template == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("clabernetes template is required").Err()
		}
		templatesDir = normalizeContainerlabTemplatesDir(templateSource, templatesDir)
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		filePath := path.Join(templatesDir, template)
		var body []byte
		// External repos can be either a Gitea owner/repo or a full git URL.
		if strings.ToLower(strings.TrimSpace(templateSource)) == "external" {
			found := externalTemplateRepoByIDForContext(pc, strings.TrimSpace(templateRepo))
			if found == nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg("unknown external repo").Err()
			}
			repoRef := strings.TrimSpace(found.Repo)
			branch := strings.TrimSpace(found.DefaultBranch)
			if branch == "" {
				branch = "main"
			}
			if isGitURL(repoRef) {
				if s.db == nil || s.box == nil {
					return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
				}
				creds, err := ensureUserGitDeployKey(ctx, s.db, s.box, pc.claims.Username)
				if err != nil {
					return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
				}
				got, err := readRepoFileBytes(ctx, creds, repoRef, branch, filePath)
				if err != nil {
					log.Printf("clabernetes external template read: %v", err)
					return nil, errs.B().Code(errs.Unavailable).Msg("failed to read clabernetes template").Err()
				}
				body = got
			} else {
				ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, templateSource, templateRepo)
				if err != nil {
					return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
				}
				got, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, filePath, ref.Branch)
				if err != nil {
					log.Printf("clabernetes template read: %v", err)
					return nil, errs.B().Code(errs.Unavailable).Msg("failed to read clabernetes template").Err()
				}
				body = got
			}
		} else {
			ref, err := resolveTemplateRepoForProject(s.cfg, pc, policy, templateSource, templateRepo)
			if err != nil {
				return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
			}
			got, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, filePath, ref.Branch)
			if err != nil {
				log.Printf("clabernetes template read: %v", err)
				return nil, errs.B().Code(errs.Unavailable).Msg("failed to read clabernetes template").Err()
			}
			body = got
		}
		var topo map[string]any
		if err := yaml.Unmarshal(body, &topo); err != nil {
			log.Printf("clabernetes template parse: %v", err)
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid containerlab topology").Err()
		}
		if topo == nil {
			topo = map[string]any{}
		}
		topo["name"] = labName
		topologyBytes, err := yaml.Marshal(topo)
		if err != nil {
			log.Printf("clabernetes template encode: %v", err)
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode topology").Err()
		}
		topologyYAML = string(topologyBytes)
	}

	message := strings.TrimSpace(fmt.Sprintf("Skyforge clabernetes run (%s)", pc.claims.Username))
	{
		auditCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			auditCtx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"user-context.run.clabernetes",
			pc.userContext.ID,
			fmt.Sprintf("action=%s namespace=%s topology=%s", action, k8sNamespace, topologyName),
		)
	}

	envAny, _ := fromJSONMap(envJSON)
	envMap := parseEnvMap(envAny)

	meta, err := toJSONMap(map[string]any{
		"action":       action,
		"deployment":   dep.Name,
		"deploymentID": dep.ID,
		"template":     template,
		"labName":      labName,
		"namespace":    k8sNamespace,
		"topologyName": topologyName,
		"spec": map[string]any{
			"action":       action,
			"namespace":    k8sNamespace,
			"topologyName": topologyName,
			"labName":      labName,
			"template":     template,
			"topologyYAML": topologyYAML,
			"environment":  envMap,
		},
	})
	if err != nil {
		log.Printf("clabernetes meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}

	allowActive := action == "destroy"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.userContext.ID, &dep.ID, "clabernetes-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.userContext.ID, &dep.ID, "clabernetes-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}

	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("clabernetes task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &UserContextRunResponse{
		UserContextID: pc.userContext.ID,
		Task:          taskJSON,
		User:          pc.claims.Username,
	}, nil
}
