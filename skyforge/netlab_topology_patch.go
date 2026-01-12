package skyforge

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func patchNetlabTopologyToolsYAML(in []byte, disabled map[string]bool) ([]byte, bool, error) {
	if len(in) == 0 || len(disabled) == 0 {
		return in, false, nil
	}
	var topo map[string]any
	if err := yaml.Unmarshal(in, &topo); err != nil {
		return nil, false, err
	}
	if topo == nil {
		return in, false, nil
	}
	rawTools, ok := topo["tools"]
	if !ok {
		return in, false, nil
	}
	tools, ok := rawTools.(map[string]any)
	if !ok || tools == nil {
		return in, false, nil
	}
	changed := false
	for tool := range disabled {
		if _, ok := tools[tool]; ok {
			delete(tools, tool)
			changed = true
		}
	}
	if !changed {
		return in, false, nil
	}
	if len(tools) == 0 {
		delete(topo, "tools")
	} else {
		topo["tools"] = tools
	}
	out, err := yaml.Marshal(topo)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (s *Service) patchNetlabTopologyOnRunner(ctx context.Context, spec netlabRunSpec, disabled map[string]bool, log *taskLogger) error {
	if s == nil {
		return fmt.Errorf("service unavailable")
	}
	if len(disabled) == 0 {
		return nil
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(spec.Template) == "" {
		return nil
	}
	templatesDir := strings.Trim(strings.TrimSpace(spec.TemplatesDir), "/")
	if templatesDir == "" {
		templatesDir = "netlab"
	}
	if !isSafeRelativePath(templatesDir) {
		return fmt.Errorf("templatesDir must be a safe repo-relative path")
	}

	ref, err := resolveTemplateRepoForProject(s.cfg, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo)
	if err != nil {
		return err
	}
	repoPath := path.Join(templatesDir, strings.TrimSpace(spec.Template))
	body, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, repoPath, ref.Branch)
	if err != nil {
		return err
	}
	patched, changed, err := patchNetlabTopologyToolsYAML(body, disabled)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	sshCfg := NetlabConfig{
		SSHHost:    strings.TrimSpace(spec.Server.SSHHost),
		SSHUser:    strings.TrimSpace(spec.Server.SSHUser),
		SSHKeyFile: strings.TrimSpace(spec.Server.SSHKeyFile),
		StateRoot:  "/",
	}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return err
	}
	defer client.Close()

	topologyRel := strings.TrimSpace(spec.TopologyPath)
	if topologyRel == "" {
		return fmt.Errorf("topology path unavailable")
	}
	abs := path.Join(strings.TrimSpace(spec.WorkspaceDir), topologyRel)
	if _, err := runSSHCommand(client, fmt.Sprintf("install -d -m 0755 %q", path.Dir(abs)), 10*time.Second); err != nil {
		return err
	}
	if _, err := runSSHCommandWithInput(client, fmt.Sprintf("cat > %q", abs), patched, 15*time.Second); err != nil {
		return err
	}
	_, _ = runSSHCommand(client, fmt.Sprintf("chmod 0644 %q >/dev/null 2>&1 || true", abs), 5*time.Second)
	if log != nil {
		log.Infof("Netlab: disabled tools in topology: %s", strings.Join(sortedKeys(disabled), ", "))
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if !v {
			continue
		}
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
